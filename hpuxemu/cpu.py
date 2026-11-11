"""cpu.py - the PA-RISC interpreter in Python: the readable reference the Rust CPU
(rust/hppa32-jit) is written to agree with, and the CPU of the Python emulator.

Model (the one QEMU's hppa target uses, which is what Linux/hppa programs were tested on;
docs/CPU.md explains it and lists every choice made where the architecture says
"undefined"):

- 32 general registers of 64 bits (PA 2.0 width, so that 32-bit "narrow" programs using the
  PA 2.0 instructions work; a PA 1.1 program never sees the upper halves), 32 floating
  point registers of 64 bits (fr0 is the status register; the single-precision halves
  frXL/frXR are the upper/lower 32 bits), SAR, the carry/borrow bits as QEMU keeps them
  (`cb` = the xor of operands and result, carry = its bit 32), PSW[V] for `ds`,
  PSW[N] (nullify the next instruction), the instruction address queue IAOQ_Front/Back
  with privilege level 3 in the low two bits, cr26/cr27.
- One instruction per `step()`: fetch at IAOQ_Front, execute unless PSW[N], advance the
  queue; branches put their target in IAOQ_Back, so the delay slot executes first.
- Memory is a `Memory` object: `read(addr, n)`, `write(addr, bytes)`, with `MemFault`
  for an unmapped or protected access. Addresses are 32-bit (narrow mode); space
  registers are not modelled (every quadrant is the process's own).
- Floating point in Python's doubles: single-precision arithmetic is computed in double
  and rounded (exact for + - * / sqrt); the rounding mode is round-to-nearest only.
  Exception flags are not tracked beyond what `fcmp`/`ftest` need (the C bit and CQ).

Exits: `run()` returns a tuple (kind, ...): ('syscall', pc) when the gateway page is
reached, ('break', im5, im13), ('illegal', pc, word), ('fault', addr, write, pc),
('hook', pc), ('count',), ('trap', pc) for a conditional trap, ('priv', pc).
"""
import math
import struct

from .decode import decode

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF
GATEWAY = 0xC0000000  # the HP-UX system call gateway page (sr7 space, offset 0xC0000004)

PA_DEFAULT_NAN_D = 0x7FF4000000000000
PA_DEFAULT_NAN_S = 0x7FA00000


class MemFault(Exception):
    def __init__(self, addr, write):
        Exception.__init__(self, 'memory fault at %#x (%s)' % (addr, 'write' if write else 'read'))
        self.addr = addr
        self.write = write


class Memory:
    """A paged 32-bit address space: a dict of 4 KB pages, with per-page protection
    (bit 0 read, bit 1 write, bit 2 execute). Big-endian helpers."""
    PAGE = 4096

    def __init__(self):
        self.pages = {}
        self.prot = {}

    def map(self, addr, size, prot=7, data=None):
        start = addr & ~(self.PAGE - 1)
        end = (addr + size + self.PAGE - 1) & ~(self.PAGE - 1)
        for p in range(start, end, self.PAGE):
            if p not in self.pages:
                self.pages[p] = bytearray(self.PAGE)
            self.prot[p] = prot
        if data is not None:
            self.write(addr, data)

    def unmap(self, addr, size):
        start = addr & ~(self.PAGE - 1)
        end = (addr + size + self.PAGE - 1) & ~(self.PAGE - 1)
        for p in range(start, end, self.PAGE):
            self.pages.pop(p, None)
            self.prot.pop(p, None)

    def protect(self, addr, size, prot):
        start = addr & ~(self.PAGE - 1)
        end = (addr + size + self.PAGE - 1) & ~(self.PAGE - 1)
        for p in range(start, end, self.PAGE):
            if p in self.pages:
                self.prot[p] = prot

    def is_mapped(self, addr):
        return (addr & ~(self.PAGE - 1)) in self.pages

    def read(self, addr, n):
        addr &= M32
        p = addr & ~(self.PAGE - 1)
        o = addr - p
        page = self.pages.get(p)
        if page is None or not (self.prot[p] & 1):
            raise MemFault(addr, False)
        if o + n <= self.PAGE:
            return bytes(page[o:o + n])
        out = bytearray(page[o:])
        a = p + self.PAGE
        while len(out) < n:
            page = self.pages.get(a)
            if page is None or not (self.prot[a] & 1):
                raise MemFault(a, False)
            take = min(n - len(out), self.PAGE)
            out += page[:take]
            a += self.PAGE
        return bytes(out)

    def write(self, addr, data):
        addr &= M32
        n = len(data)
        p = addr & ~(self.PAGE - 1)
        o = addr - p
        page = self.pages.get(p)
        if page is None or not (self.prot[p] & 2):
            raise MemFault(addr, True)
        if o + n <= self.PAGE:
            page[o:o + n] = data
            return
        first = self.PAGE - o
        page[o:] = data[:first]
        a = p + self.PAGE
        done = first
        while done < n:
            page = self.pages.get(a)
            if page is None or not (self.prot[a] & 2):
                raise MemFault(a, True)
            take = min(n - done, self.PAGE)
            page[:take] = data[done:done + take]
            done += take
            a += self.PAGE

    def fetch(self, addr):
        addr &= M32
        p = addr & ~(self.PAGE - 1)
        page = self.pages.get(p)
        if page is None or not (self.prot[p] & 4):
            raise MemFault(addr, False)
        o = addr - p
        return (page[o] << 24) | (page[o + 1] << 16) | (page[o + 2] << 8) | page[o + 3]

    def read32(self, addr):
        return struct.unpack('>I', self.read(addr, 4))[0]

    def read64(self, addr):
        return struct.unpack('>Q', self.read(addr, 8))[0]

    def write32(self, addr, v):
        self.write(addr, struct.pack('>I', v & M32))

    def write64(self, addr, v):
        self.write(addr, struct.pack('>Q', v & M64))

    def read_cstr(self, addr, limit=65536):
        out = bytearray()
        while len(out) < limit:
            b = self.read(addr, 1)
            if b == b'\0':
                break
            out += b
            addr += 1
        return bytes(out)


class Exit(Exception):
    def __init__(self, info):
        Exception.__init__(self, repr(info))
        self.info = info


def sext32(v):
    v &= M32
    return v - (1 << 32) if v & 0x80000000 else v


def sext64(v):
    v &= M64
    return v - (1 << 64) if v & (1 << 63) else v


def deposit64(base, pos, length, val):
    mask = ((1 << length) - 1) << pos
    return (base & ~mask & M64) | ((val << pos) & mask)


def extract64(v, pos, length):
    return (v >> pos) & ((1 << length) - 1)


def sextract64(v, pos, length):
    x = (v >> pos) & ((1 << length) - 1)
    return x - (1 << length) if x & (1 << (length - 1)) else x


# ---- floating point helpers (Python doubles) -----------------------------------------

def f64_from_bits(b):
    return struct.unpack('>d', struct.pack('>Q', b & M64))[0]


def f64_to_bits(f):
    return struct.unpack('>Q', struct.pack('>d', f))[0]


def f32_from_bits(b):
    return struct.unpack('>f', struct.pack('>I', b & M32))[0]


def f32_to_bits(f):
    """round a double to single precision; overflow becomes infinity"""
    try:
        return struct.unpack('>I', struct.pack('>f', f))[0]
    except OverflowError:
        return 0xFF800000 if f < 0 else 0x7F800000


def round_fraction(exact, single):
    """Round a nonzero Fraction once, to nearest-even, to a double (or a single when
    `single`; the result is returned as a double that is exactly that single). Overflow
    gives an infinity, tiny values a subnormal or zero."""
    p, emin, emax = (24, -126, 127) if single else (53, -1022, 1023)
    neg = exact < 0
    num, den = abs(exact.numerator), exact.denominator
    e = num.bit_length() - den.bit_length()
    if num < den << e if e >= 0 else (num << -e) < den:
        e -= 1
    # now 2^e <= |exact| < 2^(e+1)
    if e < emin:
        e = emin
    shift = p - 1 - e
    if shift >= 0:
        q, rem = divmod(num << shift, den)
    else:
        q, rem = divmod(num, den << -shift)
    half = (den << -shift) if shift < 0 else den
    twice = rem * 2
    if twice > half or (twice == half and q & 1):
        q += 1
    if q == 1 << p:
        q >>= 1
        e += 1
    if e > emax:
        r = float('inf')
    else:
        r = math.ldexp(q, e - (p - 1))
    return -r if neg else r


def is_nan_bits64(b):
    return (b & 0x7FF0000000000000) == 0x7FF0000000000000 and (b & 0x000FFFFFFFFFFFFF) != 0


def is_nan_bits32(b):
    return (b & 0x7F800000) == 0x7F800000 and (b & 0x007FFFFF) != 0


def quiet64(b):
    """a NaN operand propagated as a quiet NaN (PA-RISC: signalling = fraction MSB set,
    so quieting clears that bit and sets the next)"""
    return (b & ~0x0008000000000000) | 0x0004000000000000


def quiet32(b):
    return (b & ~0x00400000) | 0x00200000


class Cpu:
    def __init__(self, mem, pa20=False):
        self.mem = mem
        self.pa20 = pa20
        self.gr = [0] * 32
        self.fr = [0] * 32
        self.sar = 0
        self.cr = [0] * 32
        self.psw_n = False
        self.psw_cb = 0
        self.psw_cb_msb = 0
        self.psw_v = 0
        self.iaoq_f = 0
        self.iaoq_b = 4
        self.priv = 3
        self.hooks = set()
        self.gateway_hook = True
        self.icount = 0
        self.decoded = {}
        self._target = None
        self._nullify = False
        self._link = None
        self.trace = None

    # -- registers ---------------------------------------------------------------------
    def set_pc(self, pc):
        self.iaoq_f = (pc & ~3) | self.priv
        self.iaoq_b = self.iaoq_f + 4
        self.psw_n = False

    @property
    def pc(self):
        return self.iaoq_f & ~3

    def fr0_shadow(self):
        return self.fr[0] >> 32

    def set_fr0_shadow(self, v):
        self.fr[0] = ((v & M32) << 32) | (self.fr[0] & M32)

    # -- running -----------------------------------------------------------------------
    def run(self, max_insns=None):
        """Run until an exit; returns the exit tuple."""
        try:
            count = 0
            step = self.step
            while True:
                step()
                count += 1
                if max_insns is not None and count >= max_insns:
                    return ('count',)
        except Exit as e:
            return e.info
        except MemFault as e:
            return ('fault', e.addr, e.write, self.pc)

    def flush_decode(self, addr=None, size=None):
        if addr is None:
            self.decoded = {}
        else:
            for a in range(addr & ~3, addr + size, 4):
                self.decoded.pop(a, None)

    def step(self):
        pc = self.iaoq_f & ~3
        if pc >= GATEWAY and pc < GATEWAY + 0x1000 and self.gateway_hook:
            raise Exit(('syscall', pc))
        if self.hooks and pc in self.hooks:
            raise Exit(('hook', pc))
        insn = self.decoded.get(pc)
        if insn is None:
            word = self.mem.fetch(pc)
            insn = decode(word, self.pa20)
            self.decoded[pc] = insn
        self.icount += 1
        if self.trace:
            self.trace(self, pc, insn)
        self._target = None
        self._nullify = False
        if self.psw_n:
            self.psw_n = False
        else:
            getattr(self, 'op_' + insn.op)(insn)
            self.psw_n = self._nullify
        self.iaoq_f = self.iaoq_b
        if self._target is not None:
            self.iaoq_b = self._target & M32
        else:
            self.iaoq_b = (self.iaoq_b + 4) & M32
        self.gr[0] = 0

    # -- helpers -----------------------------------------------------------------------
    def setg(self, r, v):
        if r:
            self.gr[r] = v & M64

    def branch(self, target):
        self._target = target

    def link(self, l):
        if l:
            self.gr[l] = (self.iaoq_b + 4) & M32

    def ibranch_priv(self, dest):
        # privilege 3 is the minimum and never increases
        return (dest | 3) & M32

    # conditions (QEMU translate.c do_cond and friends; `d` = 64-bit condition)
    def cond(self, cf, d, res, uv, sv):
        c = cf >> 1
        if d:
            neg = lambda x: bool(x & (1 << 63))
            zero = lambda x: (x & M64) == 0
        else:
            neg = lambda x: bool(x & (1 << 31))
            zero = lambda x: (x & M32) == 0
        if c == 0:
            r = False
        elif c == 1:
            r = zero(res)
        elif c == 2:
            r = neg(res ^ sv)
        elif c == 3:
            r = neg(res ^ sv) or zero(res)
        elif c == 4:
            r = uv == 0
        elif c == 5:
            r = uv == 0 or zero(res)
        elif c == 6:
            r = neg(sv)
        else:
            r = bool(res & 1)
        return (not r) if cf & 1 else r

    def sub_cond(self, cf, d, res, in1, in2, sv):
        c = cf >> 1
        if c in (1, 2, 3, 4, 5):
            if d:
                a, b = in1 & M64, in2 & M64
                sa, sb = sext64(a), sext64(b)
            else:
                a, b = in1 & M32, in2 & M32
                sa, sb = sext32(a), sext32(b)
            r = {1: a == b, 2: sa < sb, 3: sa <= sb, 4: a < b, 5: a <= b}[c]
            return (not r) if cf & 1 else r
        return self.cond(cf, d, res, None, sv)

    def log_cond(self, cf, d, res):
        c = cf >> 1
        if c in (0, 4, 5, 6):
            return bool(cf & 1)
        if d:
            r = res & M64
            s = sext64(r)
        else:
            r = res & M32
            s = sext32(r)
        if c == 1:
            v = r == 0
        elif c == 2:
            v = s < 0
        elif c == 3:
            v = s <= 0
        else:
            v = bool(r & 1)
        return (not v) if cf & 1 else v

    def sed_cond(self, c3, d, res):
        c = c3 & 3
        if c == 3:
            c = 7
        f = (c3 >> 2) & 1
        return self.log_cond(c * 2 + f, d, res)

    def unit_zero_cond(self, cf, d, res):
        c = cf >> 1
        d_repl = 0x0000000100000001 if d else 1
        ones = sgns = 0
        if c == 1:
            if d:
                ones = d_repl
                sgns = d_repl << 31
        elif c == 2:
            ones = (d_repl * 0x01010101) & M64
            sgns = (ones << 7) & M64
        elif c == 3:
            ones = (d_repl * 0x00010001) & M64
            sgns = (ones << 15) & M64
        if ones == 0:
            return bool(cf & 1)
        tmp = ((res - ones) & ~res) & M64
        r = (tmp & sgns) != 0
        return (not r) if cf & 1 else r

    def carry(self, d):
        if d:
            return self.psw_cb_msb & 1
        return (self.psw_cb >> 32) & 1

    def add_sv(self, res, in1, in2, orig_in1, shift, d):
        sv = ((res ^ in1) & ~(in1 ^ in2)) & M64
        if shift == 1:
            tmp = ((orig_in1 + orig_in1) ^ orig_in1) & M64
            sv |= tmp
        elif shift > 1:
            sign_bit = 63 if d else 31
            tmp = ((sextract64(orig_in1, sign_bit, 1) & M64) ^ orig_in1) & M64
            tmp = extract64(tmp, sign_bit - shift, shift)
            if tmp != 0:
                sv = M64
        return sv

    def add_uv(self, cb, cb_msb, in1, shift, d):
        c = cb_msb & 1 if d else (cb >> 32) & 1
        if shift == 0:
            return c
        tmp = extract64(in1, (63 if d else 31) - shift, shift)
        return tmp | c

    def sub_sv(self, res, in1, in2):
        return ((res ^ in1) & (in1 ^ in2)) & M64

    def do_add(self, rt, orig_in1, in2, shift, is_l, is_tsv, is_tc, is_c, cf, d):
        c = cf >> 1
        in1 = (orig_in1 << shift) & M64 if shift else orig_in1
        full = in1 + in2
        if is_c:
            full += self.carry(d)
        dest = full & M64
        cb_msb = full >> 64
        cb = (in1 ^ in2 ^ dest) & M64
        sv = None
        if is_tsv or c in (2, 3, 6):
            sv = self.add_sv(dest, in1, in2, orig_in1, shift, d)
            if is_tsv and self.cond(12, d, None, None, sv):
                raise Exit(('overflow', self.pc))
        uv = None
        if c in (4, 5):
            uv = self.add_uv(cb, cb_msb, orig_in1, shift, d)
        res = self.cond(cf, d, dest, uv, sv)
        if is_tc and res:
            raise Exit(('trap', self.pc))
        if not is_l:
            self.psw_cb = cb
            self.psw_cb_msb = cb_msb
        self.setg(rt, dest)
        self._nullify = res and not is_tc

    def do_sub(self, rt, in1, in2, is_tsv, is_b, is_tc, cf, d):
        c = cf >> 1
        if is_b:
            full = in1 + (~in2 & M64) + self.carry(d)
            dest = full & M64
            cb_msb = full >> 64
            cb = ((~in2 & M64) ^ in1 ^ dest) & M64
        else:
            full = in1 + (~in2 & M64) + 1
            dest = full & M64
            cb_msb = full >> 64
            cb = ((~(in1 ^ in2)) ^ dest) & M64
        sv = None
        if is_tsv or c in (2, 3, 6):
            sv = self.sub_sv(dest, in1, in2)
            if is_tsv and self.cond(12, d, None, None, sv):
                raise Exit(('overflow', self.pc))
        if not is_b:
            res = self.sub_cond(cf, d, dest, in1, in2, sv)
        else:
            res = self.cond(cf, d, dest, cb_msb & 1 if d else (cb >> 32) & 1, sv)
        if is_tc and res:
            raise Exit(('trap', self.pc))
        self.psw_cb = cb
        self.psw_cb_msb = cb_msb
        self.setg(rt, dest)
        self._nullify = res and not is_tc

    def do_unit_addsub(self, rt, in1, in2, cf, d, is_tc, is_add):
        c = cf >> 1
        test_cb = 0
        if c == 4:
            test_cb = 0x8888888888888888
        elif c == 5:
            if d:
                test_cb = 0x8000000080000000
            else:
                cf &= 1
        elif c == 6:
            test_cb = 0x8080808080808080
        elif c == 7:
            test_cb = 0x8000800080008000
        if not d:
            test_cb &= M32
        if not test_cb:
            dest = (in1 + in2) & M64 if is_add else (in1 - in2) & M64
            res = self.unit_zero_cond(cf, d, dest)
        else:
            if is_add:
                full = in1 + in2
                dest = full & M64
                cb = (in1 ^ in2 ^ dest) & M64
            else:
                full = in1 + (~in2 & M64) + 1
                dest = full & M64
                cb = ((~(in1 ^ in2)) ^ dest) & M64
            if d:
                cb_msb = full >> 64
                cb = ((cb >> 1) | ((cb_msb & 1) << 63)) & M64
            else:
                cb = cb >> 1
            r = (cb & test_cb) != 0
            res = (not r) if cf & 1 else r
        if is_tc and res:
            raise Exit(('trap', self.pc))
        self.setg(rt, dest)
        self._nullify = res and not is_tc

    # effective address and base update (QEMU form_gva)
    def ea(self, i):
        base = self.gr[i.b]
        x = i.fields.get('x', 0)
        if x:
            ofs = (base + (self.gr[x] << (i.size if i.scale else 0))) & M64
        elif i.disp or i.m:
            ofs = (base + i.disp) & M64
        else:
            ofs = base
        addr = (base if i.m > 0 else ofs) & M32
        return addr, ofs

    # -- system ------------------------------------------------------------------------
    def op_illegal(self, i):
        raise Exit(('illegal', self.pc, i.word))

    def op_priv(self, i):
        raise Exit(('priv', self.pc, i.word))

    def op_pa20mm(self, i):
        raise Exit(('illegal', self.pc, i.word))

    def op_break(self, i):
        raise Exit(('break', i.im5, i.im13, self.pc))

    def op_nop(self, i):
        pass

    def op_nop_addrx(self, i):
        # fdc,m / pdc,m: base modification still happens
        if i.x:
            self.setg(i.b, self.gr[i.b] + self.gr[i.x])

    def op_sync(self, i):
        pass

    def op_mfia(self, i):
        self.setg(i.t, self.iaoq_f & ~3)

    def op_mfsp(self, i):
        self.setg(i.t, 0)

    def op_mtsp(self, i):
        pass  # space registers are not modelled

    def op_ldsid(self, i):
        self.setg(i.t, 0)

    def op_mfctl(self, i):
        if i.r == 11:
            self.setg(i.t, self.sar if i.e else self.sar & 31)
        elif i.r in (26, 27):
            self.setg(i.t, self.cr[i.r])
        elif i.r == 16:
            self.setg(i.t, self.icount & M32)  # interval timer: instructions
        else:
            raise Exit(('priv', self.pc, i.word))

    def op_mtctl(self, i):
        if i.t == 11:
            self.sar = self.gr[i.r] & (63 if self.pa20 else 31)
        else:
            raise Exit(('priv', self.pc, i.word))

    def op_mtsarcm(self, i):
        self.sar = (~self.gr[i.r]) & (63 if self.pa20 else 31)

    def op_mtsm(self, i):
        raise Exit(('priv', self.pc, i.word))

    def op_probe(self, i):
        # probe for read/write access: 1 if the page is mapped with that right
        addr = self.gr[i.b] & M32
        p = addr & ~(Memory.PAGE - 1)
        prot = self.mem.prot.get(p, 0)
        ok = (prot & 2) if i.write else (prot & 1)
        self.setg(i.t, 1 if ok else 0)

    def op_lci(self, i):
        self.setg(i.t, 0)

    # -- arithmetic --------------------------------------------------------------------
    def op_add(self, i):
        self.do_add(i.t, self.gr[i.r1], self.gr[i.r2], i.sh, i.l, i.tsv, 0, i.c, i.cf, i.d)

    def op_sub(self, i):
        self.do_sub(i.t, self.gr[i.r1], self.gr[i.r2], i.tsv, i.b, i.tc, i.cf, i.d)

    def op_addi(self, i):
        if i.tc and i.cf == 1:
            raise Exit(('trap', self.pc))
        self.do_add(i.t, i.i & M64, self.gr[i.r], 0, 0, i.tsv, i.tc, 0, i.cf, 0)

    def op_subi(self, i):
        self.do_sub(i.t, i.i & M64, self.gr[i.r], i.tsv, 0, 0, i.cf, 0)

    def _log(self, i, fn):
        dest = fn(self.gr[i.r1], self.gr[i.r2]) & M64
        self.setg(i.t, dest)
        self._nullify = self.log_cond(i.cf, i.d, dest)

    def op_and(self, i):
        self._log(i, lambda a, b: a & b)

    def op_andcm(self, i):
        self._log(i, lambda a, b: a & ~b)

    def op_or(self, i):
        self._log(i, lambda a, b: a | b)

    def op_xor(self, i):
        self._log(i, lambda a, b: a ^ b)

    def op_uxor(self, i):
        dest = (self.gr[i.r1] ^ self.gr[i.r2]) & M64
        self.setg(i.t, dest)
        self._nullify = self.unit_zero_cond(i.cf, i.d, dest)

    def op_cmpclr(self, i):
        in1, in2 = self.gr[i.r1], self.gr[i.r2]
        dest = (in1 - in2) & M64
        sv = self.sub_sv(dest, in1, in2) if (i.cf >> 1) in (2, 3, 6) else None
        self._nullify = self.sub_cond(i.cf, i.d, dest, in1, in2, sv)
        self.setg(i.t, 0)

    def op_cmpiclr(self, i):
        in1, in2 = i.i & M64, self.gr[i.r]
        dest = (in1 - in2) & M64
        sv = self.sub_sv(dest, in1, in2) if (i.cf >> 1) in (2, 3, 6) else None
        self._nullify = self.sub_cond(i.cf, i.d, dest, in1, in2, sv)
        self.setg(i.t, 0)

    def op_uaddcm(self, i):
        if i.cf == 0:
            self.setg(i.t, self.gr[i.r1] + (~self.gr[i.r2] & M64))
            return
        self.do_unit_addsub(i.t, self.gr[i.r1], ~self.gr[i.r2] & M64, i.cf, i.d, i.tc, True)

    def op_dcor(self, i):
        tmp = ((self.psw_cb >> 4) | ((self.psw_cb_msb & 1) << 60)) & M64
        if not i.i:
            tmp = ~tmp & M64
        tmp = (tmp & 0x1111111111111111) * 6 & M64
        self.do_unit_addsub(i.t, self.gr[i.r], tmp, i.cf, i.d, False, bool(i.i))

    def op_ds(self, i):
        in1, in2 = self.gr[i.r1], self.gr[i.r2]
        add1 = (in1 + in1 + self.carry(False)) & M64
        addc = sextract64(self.psw_v, 31, 1) & M64
        add2 = (in2 ^ addc) & M64
        addc &= 1
        full = add1 + add2 + addc
        dest = full & M64
        self.psw_cb_msb = full >> 64
        self.setg(i.t, dest)
        self.psw_cb = (add1 ^ add2 ^ dest) & M64
        self.psw_v = ((self.psw_cb >> 1) ^ in2) & M64
        if i.cf:
            c = i.cf >> 1
            sv = uv = None
            if c in (2, 3, 6):
                sv = self.add_sv(dest, add1, add2, in1, 1, False)
            elif c in (4, 5):
                uv = self.add_uv(self.psw_cb, 0, in1, 1, False)
            self._nullify = self.cond(i.cf, False, dest, uv, sv)

    def op_ldil(self, i):
        self.setg(i.t, i.i & M32)

    def op_addil(self, i):
        self.setg(1, self.gr[i.r] + i.i)

    def op_ldo(self, i):
        self.setg(i.t, (self.gr[i.b] if i.b else 0) + i.i)

    # -- loads and stores --------------------------------------------------------------
    def op_ld(self, i):
        addr, ofs = self.ea(i)
        n = 1 << i.size
        v = int.from_bytes(self.mem.read(addr, n), 'big')
        if i.m:
            self.setg(i.b, ofs)
        self.setg(i.t, v)

    def op_st(self, i):
        addr, ofs = self.ea(i)
        n = 1 << i.size
        self.mem.write(addr, (self.gr[i.t] & ((1 << (8 * n)) - 1)).to_bytes(n, 'big'))
        if i.m:
            self.setg(i.b, ofs)

    def op_ldc(self, i):
        addr, ofs = self.ea(i)
        n = 1 << i.size
        if addr & (n - 1):
            raise Exit(('unaligned', addr, self.pc))
        # a load-and-clear needs a writable word: it faults as a write
        try:
            v = int.from_bytes(self.mem.read(addr, n), 'big')
        except MemFault as e:
            raise MemFault(e.addr, True)
        self.mem.write(addr, bytes(n))
        if i.m:
            self.setg(i.b, ofs)
        self.setg(i.t, v)

    def op_stby(self, i):
        addr, ofs = self.ea(i)
        val = self.gr[i.r] & M32
        a3 = addr & 3
        base = addr & ~3
        if not i.a:
            # stby,b: the bytes from the address to the end of the word
            if a3 == 0:
                self.mem.write(base, val.to_bytes(4, 'big'))
            elif a3 == 1:
                self.mem.write(base + 1, ((val >> 16) & 0xFF).to_bytes(1, 'big') + (val & 0xFFFF).to_bytes(2, 'big'))
            elif a3 == 2:
                self.mem.write(base + 2, (val & 0xFFFF).to_bytes(2, 'big'))
            else:
                self.mem.write(base + 3, (val & 0xFF).to_bytes(1, 'big'))
        else:
            # stby,e: the bytes before the address
            if a3 == 0:
                self.mem.read(base, 1)  # nothing stored, access checked
            elif a3 == 1:
                self.mem.write(base, ((val >> 24) & 0xFF).to_bytes(1, 'big'))
            elif a3 == 2:
                self.mem.write(base, ((val >> 16) & 0xFFFF).to_bytes(2, 'big'))
            else:
                self.mem.write(base, ((val >> 16) & 0xFFFF).to_bytes(2, 'big') + ((val >> 8) & 0xFF).to_bytes(1, 'big'))
        if i.m:
            self.setg(i.b, ofs & ~3)

    def op_stdby(self, i):
        raise Exit(('illegal', self.pc, i.word))

    def op_fldw(self, i):
        addr, ofs = self.ea(i)
        v = int.from_bytes(self.mem.read(addr, 4), 'big')
        if i.m:
            self.setg(i.b, ofs)
        self.set_frw(i.t, v)

    def op_fstw(self, i):
        addr, ofs = self.ea(i)
        self.mem.write(addr, self.frw(i.t).to_bytes(4, 'big'))
        if i.m:
            self.setg(i.b, ofs)

    def op_fldd(self, i):
        addr, ofs = self.ea(i)
        v = int.from_bytes(self.mem.read(addr, 8), 'big')
        if i.m:
            self.setg(i.b, ofs)
        self.fr[i.t] = v

    def op_fstd(self, i):
        addr, ofs = self.ea(i)
        self.mem.write(addr, self.fr[i.t].to_bytes(8, 'big'))
        if i.m:
            self.setg(i.b, ofs)

    def frw(self, n):
        """single-precision register n (0-31 = left half, 32-63 = right half)"""
        if n >= 32:
            return self.fr[n - 32] & M32
        return self.fr[n] >> 32

    def set_frw(self, n, v):
        v &= M32
        if n >= 32:
            self.fr[n - 32] = (self.fr[n - 32] & ~M32) | v
        else:
            self.fr[n] = (self.fr[n] & M32) | (v << 32)

    # -- branches ----------------------------------------------------------------------
    def cbranch(self, disp, is_n, taken):
        if taken:
            self.branch((self.iaoq_f + 8 + disp) & M32)
            self._nullify = bool(is_n and disp >= 0)
        else:
            self._nullify = bool(is_n and disp < 0)

    def op_bl(self, i):
        self.link(i.l)
        self.branch((self.iaoq_f + 8 + i.disp) & M32)
        self._nullify = bool(i.n)

    def op_b_gate(self, i):
        if i.l:
            self.setg(i.l, (self.iaoq_b + 4) & M32)
        self.branch((self.iaoq_f + 8 + i.disp) & M32)
        self._nullify = bool(i.n)

    def op_blr(self, i):
        if i.x:
            self.link(i.l)
            self.branch((self.iaoq_f + 8 + ((self.gr[i.x] << 3) & M32)) & M32)
            self._nullify = bool(i.n)
        else:
            self.link(i.l)
            self.branch((self.iaoq_f + 8) & M32)
            self._nullify = bool(i.n)

    def op_bv(self, i):
        dest = self.gr[i.b]
        if i.x:
            dest = dest + (self.gr[i.x] << 3)
        self.branch(self.ibranch_priv(dest))
        self._nullify = bool(i.n)

    def op_bve(self, i):
        dest = self.ibranch_priv(self.gr[i.b])
        self.link(i.l)
        self.branch(dest)
        self._nullify = bool(i.n)

    def op_be(self, i):
        dest = self.ibranch_priv(self.gr[i.b] + i.disp)
        self.link(i.l)
        self.branch(dest)
        self._nullify = bool(i.n)

    def op_cmpb(self, i):
        self._cmpb(self.gr[i.r1], self.gr[i.r2], i)

    def op_cmpbi(self, i):
        self._cmpb(i.i & M64, self.gr[i.r], i)

    def _cmpb(self, in1, in2, i):
        dest = (in1 - in2) & M64
        sv = self.sub_sv(dest, in1, in2) if i.c in (2, 3, 6) else None
        taken = self.sub_cond(i.c * 2 + i.f, i.d, dest, in1, in2, sv)
        self.cbranch(i.disp, i.n, taken)

    def op_addb(self, i):
        self._addb(self.gr[i.r1], i.r2, i)

    def op_addbi(self, i):
        self._addb(i.i & M64, i.r, i)

    def _addb(self, in1, r, i):
        in2 = self.gr[r]
        full = in1 + in2
        dest = full & M64
        c = i.c
        cb_cond = sv = None
        if c in (4, 5):
            cb = (in1 ^ in2 ^ dest) & M64
            cb_cond = (cb >> 32) & 1
        if c in (2, 3, 6):
            sv = self.add_sv(dest, in1, in2, in1, 0, False)
        taken = self.cond(c * 2 + i.f, False, dest, cb_cond, sv)
        self.setg(r, dest)
        self.cbranch(i.disp, i.n, taken)

    def op_bb_sar(self, i):
        v = self.gr[i.r]
        if i.d:
            bit = (v << self.sar) & (1 << 63)
        else:
            bit = (v << (self.sar | 32)) & (1 << 63)
        taken = (bit == 0) if i.c else (bit != 0)
        self.cbranch(i.disp, i.n, taken)

    def op_bb_imm(self, i):
        p = i.p | (0 if i.d else 32)
        bit = self.gr[i.r] & (1 << (63 - p))
        taken = (bit == 0) if i.c else (bit != 0)
        self.cbranch(i.disp, i.n, taken)

    def op_movb(self, i):
        dest = self.gr[i.r1]
        self.setg(i.r2, dest)
        self.cbranch(i.disp, i.n, self.sed_cond(i.c, False, dest))

    def op_movbi(self, i):
        dest = i.i & M64
        self.setg(i.r, dest)
        self.cbranch(i.disp, i.n, self.sed_cond(i.c, False, dest))

    # -- shift, extract, deposit -------------------------------------------------------
    def op_shrp_sar(self, i):
        src2 = self.gr[i.r2]
        if i.r1 == 0:
            if i.d:
                dest = src2 >> self.sar
            else:
                dest = (src2 & M32) >> (self.sar & 31)
        elif i.r1 == i.r2:
            if i.d:
                s = self.sar & 63
                dest = ((src2 >> s) | (src2 << (64 - s))) & M64 if s else src2
            else:
                s = self.sar & 31
                v = src2 & M32
                dest = ((v >> s) | (v << (32 - s))) & M32 if s else v
        else:
            src1 = self.gr[i.r1]
            if i.d:
                n = self.sar ^ 63
                dest = ((src2 >> self.sar) | (((src1 << n) & M64) << 1)) & M64
            else:
                t = ((src1 & M32) << 32) | (src2 & M32)
                dest = (t >> (self.sar & 31)) & M64
        self.setg(i.t, dest)
        self._nullify = self.sed_cond(i.c, i.d, dest)

    def op_shrp_imm(self, i):
        width = 64 if i.d else 32
        sa = width - 1 - i.cpos
        t2 = self.gr[i.r2]
        if i.r1 == 0:
            dest = extract64(t2, sa, width - sa)
        elif i.d:
            dest = ((t2 >> sa) | ((self.gr[i.r1] << (64 - sa)) & M64)) & M64 if sa else t2
        else:
            t = ((self.gr[i.r1] & M32) << 32) | (t2 & M32)
            dest = (t >> sa) & M32
        self.setg(i.t, dest)
        self._nullify = self.sed_cond(i.c, i.d, dest)

    def op_extr_sar(self, i):
        widthm1 = 63 if i.d else 31
        src = self.gr[i.r]
        tmp = (self.sar & widthm1) ^ widthm1
        if i.se:
            if not i.d:
                src = sext32(src) & M64
            dest = sextract64((sext64(src) >> tmp) & M64, 0, i.len) & M64
        else:
            if not i.d:
                src &= M32
            dest = extract64(src >> tmp, 0, i.len)
        self.setg(i.t, dest)
        self._nullify = self.sed_cond(i.c, i.d, dest)

    def op_extr_imm(self, i):
        width = 64 if i.d else 32
        ln = i.len
        cpos = width - 1 - i.pos
        if cpos + ln > width:
            ln = width - cpos
        src = self.gr[i.r]
        if i.se:
            dest = sextract64(src, cpos, ln) & M64
        else:
            dest = extract64(src, cpos, ln)
        self.setg(i.t, dest)
        self._nullify = self.sed_cond(i.c, i.d, dest)

    def op_depi_imm(self, i):
        width = 64 if i.d else 32
        ln = i.len
        if i.cpos + ln > width:
            ln = width - i.cpos
        mask0 = deposit64(0, i.cpos, ln, i.i & M64)
        mask1 = deposit64(M64, i.cpos, ln, i.i & M64)
        if i.nz:
            dest = (self.gr[i.t] & mask1) | mask0
        else:
            dest = mask0
        self.setg(i.t, dest)
        self._nullify = self.sed_cond(i.c, i.d, dest)

    def op_dep_imm(self, i):
        width = 64 if i.d else 32
        ln = i.len
        if i.cpos + ln > width:
            ln = width - i.cpos
        val = self.gr[i.r]
        if i.nz:
            dest = deposit64(self.gr[i.t], i.cpos, ln, val)
        else:
            dest = deposit64(0, i.cpos, ln, val)
        self.setg(i.t, dest)
        self._nullify = self.sed_cond(i.c, i.d, dest)

    def _dep_sar(self, i, val):
        widthm1 = 63 if i.d else 31
        shift = (self.sar & widthm1) ^ widthm1
        msb = 1 << (i.len - 1)
        mask = msb + (msb - 1)
        tmp = val & mask
        if i.nz:
            m = (mask << shift) & M64
            dest = (self.gr[i.t] & ~m & M64) | ((tmp << shift) & M64)
        else:
            dest = (tmp << shift) & M64
        self.setg(i.t, dest)
        self._nullify = self.sed_cond(i.c, i.d, dest)

    def op_dep_sar(self, i):
        self._dep_sar(i, self.gr[i.r])

    def op_depi_sar(self, i):
        self._dep_sar(i, i.i & M64)

    # -- floating point ----------------------------------------------------------------
    def op_fid(self, i):
        self.fr[0] = 0x13080000000000 if self.pa20 else 0x0F080000000000

    def _fsrc_d(self, n):
        return 0 if n == 0 else self.fr[n]

    def _fsrc_w(self, n):
        return 0 if n == 0 else self.frw(n)

    def _fres_d(self, t, bits):
        self.fr[t] = bits & M64

    def _fres_w(self, t, bits):
        self.set_frw(t, bits)

    def _fop1(self, i, fs, fd):
        """class 0 unary ops on bit patterns"""
        if i.dbl:
            a = self._fsrc_d(i.r)
            self._fres_d(i.t, fd(a))
        else:
            a = self._fsrc_w(i.r)
            self._fres_w(i.t, fs(a))

    def op_fcpy(self, i):
        self._fop1(i, lambda a: a, lambda a: a)

    def op_fabs(self, i):
        self._fop1(i, lambda a: a & 0x7FFFFFFF, lambda a: a & 0x7FFFFFFFFFFFFFFF)

    def op_fneg(self, i):
        self._fop1(i, lambda a: a ^ 0x80000000, lambda a: a ^ 0x8000000000000000)

    def op_fnegabs(self, i):
        self._fop1(i, lambda a: a | 0x80000000, lambda a: a | 0x8000000000000000)

    def _nan_result_d(self, *ops):
        """the NaN to return when an operand is a NaN (first signalling, else first quiet)"""
        for b in ops:
            if is_nan_bits64(b) and b & 0x0008000000000000:
                return quiet64(b)
        for b in ops:
            if is_nan_bits64(b):
                return b
        return None

    def _nan_result_s(self, *ops):
        for b in ops:
            if is_nan_bits32(b) and b & 0x00400000:
                return quiet32(b)
        for b in ops:
            if is_nan_bits32(b):
                return b
        return None

    def _arith_d(self, i, fn):
        a, b = self._fsrc_d(i.r1), self._fsrc_d(i.r2)
        nan = self._nan_result_d(a, b)
        if nan is not None:
            self._fres_d(i.t, nan)
            return
        try:
            r = fn(f64_from_bits(a), f64_from_bits(b))
        except (ZeroDivisionError, OverflowError, ValueError):
            r = self._special_d(fn, a, b)
        if isinstance(r, float) and math.isnan(r):
            self._fres_d(i.t, PA_DEFAULT_NAN_D)
        else:
            self._fres_d(i.t, f64_to_bits(r))

    def _arith_s(self, i, fn):
        a, b = self._fsrc_w(i.r1), self._fsrc_w(i.r2)
        nan = self._nan_result_s(a, b)
        if nan is not None:
            self._fres_w(i.t, nan)
            return
        try:
            r = fn(f32_from_bits(a), f32_from_bits(b))
        except (ZeroDivisionError, OverflowError, ValueError):
            r = self._special_s(fn, a, b)
        if isinstance(r, float) and math.isnan(r):
            self._fres_w(i.t, PA_DEFAULT_NAN_S)
        else:
            self._fres_w(i.t, f32_to_bits(r))

    @staticmethod
    def _special(fn, fa, fb):
        """IEEE results Python raises on: x/0, inf-inf etc."""
        if fn is _div:
            if fb == 0.0:
                if fa == 0.0 or math.isnan(fa):
                    return float('nan')
                sign = (math.copysign(1.0, fa) * math.copysign(1.0, fb)) < 0
                return float('-inf') if sign else float('inf')
        try:
            return fn(fa, fb)
        except (OverflowError, ValueError):
            return float('nan')

    def _special_d(self, fn, a, b):
        return self._special(fn, f64_from_bits(a), f64_from_bits(b))

    def _special_s(self, fn, a, b):
        return self._special(fn, f32_from_bits(a), f32_from_bits(b))

    def op_fadd(self, i):
        (self._arith_d if i.dbl else self._arith_s)(i, _add)

    def op_fsub(self, i):
        (self._arith_d if i.dbl else self._arith_s)(i, _sub)

    def op_fmpy(self, i):
        (self._arith_d if i.dbl else self._arith_s)(i, _mul)

    def op_fdiv(self, i):
        (self._arith_d if i.dbl else self._arith_s)(i, _div)

    def op_fsqrt(self, i):
        if i.dbl:
            a = self._fsrc_d(i.r)
            nan = self._nan_result_d(a)
            if nan is not None:
                self._fres_d(i.t, nan)
                return
            f = f64_from_bits(a)
            if f < 0:
                self._fres_d(i.t, PA_DEFAULT_NAN_D)
            else:
                self._fres_d(i.t, f64_to_bits(math.sqrt(f)) if f != float('inf') else a)
        else:
            a = self._fsrc_w(i.r)
            nan = self._nan_result_s(a)
            if nan is not None:
                self._fres_w(i.t, nan)
                return
            f = f32_from_bits(a)
            if f < 0:
                self._fres_w(i.t, PA_DEFAULT_NAN_S)
            else:
                self._fres_w(i.t, f32_to_bits(math.sqrt(f)) if f != float('inf') else a)

    def op_frnd(self, i):
        # round to integral value, ties to even, keeping the sign of zero
        if i.dbl:
            a = self._fsrc_d(i.r)
            nan = self._nan_result_d(a)
            if nan is not None:
                self._fres_d(i.t, nan)
                return
            f = f64_from_bits(a)
            if math.isinf(f):
                self._fres_d(i.t, a)
                return
            r = float(round(f))
            self._fres_d(i.t, f64_to_bits(math.copysign(r, f)))
        else:
            a = self._fsrc_w(i.r)
            nan = self._nan_result_s(a)
            if nan is not None:
                self._fres_w(i.t, nan)
                return
            f = f32_from_bits(a)
            if math.isinf(f):
                self._fres_w(i.t, a)
                return
            r = float(round(f))
            self._fres_w(i.t, f32_to_bits(math.copysign(r, f)))

    def op_fcnv(self, i):
        s, d = i.kind
        # source value
        if s == 'f':
            if i.sf:
                src = self._fsrc_d(i.r)
                nan = is_nan_bits64(src)
                f = f64_from_bits(src)
            else:
                src = self._fsrc_w(i.r)
                nan = is_nan_bits32(src)
                f = f32_from_bits(src)
        else:
            src = self._fsrc_d(i.r) if i.sf else self._fsrc_w(i.r)
            if s == 'i':
                f = float(sext64(src) if i.sf else sext32(src))
            else:
                f = float(src if i.sf else src & M32)
            nan = False
        # destination
        if d == 'f':
            if s == 'f' and nan:
                if i.sf and not i.df:
                    r = PA_DEFAULT_NAN_S if (src & 0x0008000000000000) else ((src >> 29) & 0x007FFFFF) | 0x7F800000
                    r = quiet32(r) if (src & 0x0008000000000000) else r
                    self._fres_w(i.t, PA_DEFAULT_NAN_S)
                elif not i.sf and i.df:
                    self._fres_d(i.t, PA_DEFAULT_NAN_D)
                elif i.df:
                    self._fres_d(i.t, self._nan_result_d(src))
                else:
                    self._fres_w(i.t, self._nan_result_s(src))
                return
            if i.df:
                self._fres_d(i.t, f64_to_bits(f))
            else:
                self._fres_w(i.t, f32_to_bits(f))
            return
        # float to integer: d in i, ti (truncate), u, tu
        if i.df:
            width = 64
        else:
            width = 32
        if d in ('i', 'ti'):
            lo, hi = -(1 << (width - 1)), (1 << (width - 1)) - 1
        else:
            lo, hi = 0, (1 << width) - 1
        if nan:
            r = hi
        elif math.isinf(f):
            r = lo if f < 0 else hi
        else:
            if d in ('ti', 'tu'):
                v = math.trunc(f)
            else:
                v = round(f)  # ties to even
            if d in ('u', 'tu') and v < 0:
                # negative values converting to unsigned: QEMU gives 0 (invalid) unless
                # the rounded value is 0
                r = 0 if v == 0 else 0
            elif v < lo:
                r = lo
            elif v > hi:
                r = hi
            else:
                r = v
        r &= (1 << width) - 1
        if i.df:
            self._fres_d(i.t, r)
        else:
            self._fres_w(i.t, r)

    def _fcmp_relation(self, a, b, nan):
        if nan:
            return 'u'
        if a < b:
            return 'l'
        if a > b:
            return 'g'
        return 'e'

    def op_fcmp(self, i):
        if i.dbl:
            a, b = self._fsrc_d(i.r1), self._fsrc_d(i.r2)
            nan = is_nan_bits64(a) or is_nan_bits64(b)
            fa, fb = f64_from_bits(a), f64_from_bits(b)
        else:
            a, b = self._fsrc_w(i.r1), self._fsrc_w(i.r2)
            nan = is_nan_bits32(a) or is_nan_bits32(b)
            fa, fb = f32_from_bits(a), f32_from_bits(b)
        rel = self._fcmp_relation(fa, fb, nan)
        c = i.c
        bit = {'g': (c >> 4) & 1, 'l': (c >> 3) & 1, 'e': (c >> 2) & 1, 'u': (c >> 1) & 1}[rel]
        shadow = self.fr0_shadow()
        if i.y:
            pos = 21 - (i.y - 1)
            shadow = (shadow & ~(1 << pos)) | (bit << pos)
        else:
            cq_mask = 0x7FF << 11
            shadow = (shadow & ~cq_mask) | ((shadow >> 1) & cq_mask)
            shadow = (shadow & ~(1 << 21)) | (((shadow >> 26) & 1) << 21)
            shadow = (shadow & ~(1 << 26)) | (bit << 26)
        self.fr[0] = (shadow & M32) << 32

    def op_ftest(self, i):
        t = self.fr0_shadow()
        eq = False
        if i.y == 1:
            if i.c == 0:
                mask = 1 << 26
            elif i.c in (1, 2):
                mask = (1 << 26) | (0x7FF << 11)
                eq = i.c == 2
            elif i.c in (5, 6):
                mask = (1 << 26) | (0x7F << 15)
                eq = i.c == 6
            elif i.c == 9:
                mask = (1 << 26) | (0x1F << 17)
            elif i.c == 13:
                mask = (1 << 26) | (0x7 << 19)
            elif i.c == 17:
                mask = (1 << 26) | (1 << 21)
            else:
                raise Exit(('illegal', self.pc, i.word))
        else:
            cbit = (i.y ^ 1) - 1
            mask = (1 << 21) >> cbit
        r = (t & mask) != 0
        self._nullify = (not r) if eq else r

    def op_xmpyu(self, i):
        a, b = self._fsrc_w(i.r1), self._fsrc_w(i.r2)
        self.fr[i.t] = (a * b) & M64

    def op_fmpyadd(self, i):
        self._fmpyadd(i, False)

    def op_fmpysub(self, i):
        self._fmpyadd(i, True)

    def _fmpyadd(self, i, sub):
        if i.dbl:
            m = _Pseudo(r1=i.rm1, r2=i.rm2, t=i.tm, dbl=1)
            self._arith_d(m, _mul)
            a = _Pseudo(r1=i.ta, r2=i.ra, t=i.ta, dbl=1)
            self._arith_d(a, _sub if sub else _add)
        else:
            conv = lambda r: (r & 16) * 2 + 16 + (r & 15)
            m = _Pseudo(r1=conv(i.rm1), r2=conv(i.rm2), t=conv(i.tm), dbl=0)
            self._arith_s(m, _mul)
            a = _Pseudo(r1=conv(i.ta), r2=conv(i.ra), t=conv(i.ta), dbl=0)
            self._arith_s(a, _sub if sub else _add)

    def op_fmpyfadd(self, i):
        # fused multiply-add: computed exactly with Python's fractions, then rounded once
        from fractions import Fraction
        if i.dbl:
            a, b, c = self._fsrc_d(i.rm1), self._fsrc_d(i.rm2), self._fsrc_d(i.ra3)
            nan = self._nan_result_d(a, b, c)
            if nan is not None:
                self._fres_d(i.t, nan)
                return
            fa, fb, fc = f64_from_bits(a), f64_from_bits(b), f64_from_bits(c)
        else:
            a, b, c = self._fsrc_w(i.rm1), self._fsrc_w(i.rm2), self._fsrc_w(i.ra3)
            nan = self._nan_result_s(a, b, c)
            if nan is not None:
                self._fres_w(i.t, nan)
                return
            fa, fb, fc = f32_from_bits(a), f32_from_bits(b), f32_from_bits(c)
        if i.neg:
            fa = -fa
        if any(math.isinf(x) for x in (fa, fb, fc)):
            # the product of two finite values never overflows inside a fused operation,
            # so only an infinite operand makes an infinite product
            if math.isinf(fa) or math.isinf(fb):
                if fa == 0 or fb == 0:
                    r = None                        # inf * 0
                else:
                    prod = math.copysign(math.inf, math.copysign(1, fa) * math.copysign(1, fb))
                    r = None if (math.isinf(fc) and math.copysign(1, fc) != math.copysign(1, prod)) else prod
            else:
                r = fc                              # finite product + infinity
        else:
            exact = Fraction(fa) * Fraction(fb) + Fraction(fc)
            if exact != 0:
                r = round_fraction(exact, not i.dbl)
            else:
                r = 0.0 if (math.copysign(1, fa * fb) > 0 or math.copysign(1, fc) > 0) else -0.0
                if fa * fb == 0 and fc == 0:
                    r = fa * fb + fc
        if r is None:
            if i.dbl:
                self._fres_d(i.t, PA_DEFAULT_NAN_D)
            else:
                self._fres_w(i.t, PA_DEFAULT_NAN_S)
        elif i.dbl:
            self._fres_d(i.t, f64_to_bits(r))
        else:
            self._fres_w(i.t, f32_to_bits(r))


class _Pseudo:
    def __init__(self, **f):
        self.f = f

    def __getattr__(self, k):
        try:
            return self.f[k]
        except KeyError:
            raise AttributeError(k)


def _add(a, b):
    return a + b


def _sub(a, b):
    return a - b


def _mul(a, b):
    return a * b


def _div(a, b):
    return a / b
