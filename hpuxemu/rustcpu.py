"""The Rust CPU (rust/hppa32-jit) behind the same interface as cpu.Cpu/cpu.Memory, through
ctypes. Build it with `cargo build --release --features capi,hpux` in rust/hppa32-jit; the shared object is looked
for next to the crate (target/release/libhppa32_jit.so or .dylib) and in $HPPA32_LIB."""

import ctypes
import os
import struct

from .cpu import MemFault, M32

PAGE = 4096

# register numbers of the C API
R_GR = 0
R_FR = 32
R_SAR = 64
R_IAOQ_F = 65
R_IAOQ_B = 66
R_PSW_N = 67
R_PSW_CB = 68
R_PSW_CB_MSB = 69
R_PSW_V = 70
R_CR26 = 71
R_CR27 = 72
R_ICOUNT = 73

EXIT_KINDS = {1: 'syscall', 2: 'break', 3: 'illegal', 4: 'priv', 5: 'fault', 6: 'trap',
              7: 'overflow', 8: 'unaligned', 9: 'hook', 10: 'count'}


class ExitInfo(ctypes.Structure):
    _fields_ = [('kind', ctypes.c_uint32), ('a', ctypes.c_uint32), ('b', ctypes.c_uint32), ('c', ctypes.c_uint32)]


def find_library():
    cands = []
    if os.environ.get('HPPA32_LIB'):
        cands.append(os.environ['HPPA32_LIB'])
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for ext in ('so', 'dylib'):
        cands.append(os.path.join(here, 'rust', 'hppa32-jit', 'target', 'release', 'libhppa32_jit.' + ext))
    for c in cands:
        if os.path.exists(c):
            return c
    raise RuntimeError('libhppa32_jit not found; run `cargo build --release --features capi,hpux` in rust/hppa32-jit (looked at %s)' % ', '.join(cands))


_lib = None


def lib():
    global _lib
    if _lib is None:
        L = ctypes.CDLL(find_library())
        P = ctypes.c_void_p
        u32, u64 = ctypes.c_uint32, ctypes.c_uint64
        L.hppa_new.restype = P
        L.hppa_new.argtypes = [u32]
        L.hppa_free.argtypes = [P]
        L.hppa_map.restype = u32
        L.hppa_map.argtypes = [P, u32, u32, u32]
        L.hppa_unmap.argtypes = [P, u32, u32]
        L.hppa_protect.argtypes = [P, u32, u32, u32]
        L.hppa_host_base.restype = u64
        L.hppa_host_base.argtypes = [P]
        L.hppa_mark.argtypes = [P, u32, u32, u32]
        L.hppa_page_flags.restype = u32
        L.hppa_page_flags.argtypes = [P, u32]
        L.hppa_read.restype = u32
        L.hppa_read.argtypes = [P, u32, ctypes.c_char_p, u32]
        L.hppa_write.restype = u32
        L.hppa_write.argtypes = [P, u32, ctypes.c_char_p, u32]
        L.hppa_get_reg.restype = u64
        L.hppa_get_reg.argtypes = [P, u32]
        L.hppa_set_reg.argtypes = [P, u32, u64]
        L.hppa_set_pc.argtypes = [P, u32]
        L.hppa_set_hooks.argtypes = [P, ctypes.POINTER(u32), u32]
        if hasattr(L, 'hppa_find_free'):
            L.hppa_find_free.restype = u32
            L.hppa_find_free.argtypes = [P, u32, u32, u64, u32]
        if hasattr(L, 'hppa_set_jit'):
            L.hppa_set_jit.restype = u32
            L.hppa_set_jit.argtypes = [P, u32, u32]
            L.hppa_jit_stats.restype = u32
            L.hppa_jit_stats.argtypes = [P, ctypes.POINTER(ctypes.c_uint64), u32]
        if hasattr(L, 'hppa_set_natives'):         # libraries built before it lack it
            L.hppa_set_natives.argtypes = [P, ctypes.POINTER(u32), ctypes.POINTER(ctypes.c_uint8), u32]
        if hasattr(L, 'hppa_reg_ptr'):             # registers and memory in place
            L.hppa_reg_ptr.restype = u64
            L.hppa_reg_ptr.argtypes = [P, u32]
            L.hppa_ptr.restype = u64
            L.hppa_ptr.argtypes = [P, u32, u32, u32]
            L.hppa_ld32.restype = u64
            L.hppa_ld32.argtypes = [P, u32]
        L.hppa_run.argtypes = [P, u64, ctypes.POINTER(ExitInfo)]
        L.hppa_step.restype = u32
        L.hppa_step.argtypes = [P, ctypes.POINTER(ExitInfo)]
        _lib = L
    return _lib


M64 = 0xFFFFFFFFFFFFFFFF


def _reg_view(addr, keep0):
    """gr[] (keep0: r0 stays zero) or fr[] read and written in place in the Rust CPU's
    registers: an index is a memory access, not a call into the library (a system call
    reads and writes a dozen of them)."""
    a = (ctypes.c_uint64 * 32).from_address(addr)

    class RegView:
        __slots__ = ()

        def __getitem__(self, i):
            return a[i]

        def __setitem__(self, i, v):
            if i or not keep0:
                a[i] = v & M64

        def __len__(self):
            return 32

        def __iter__(self):
            return iter(a[:])
    return RegView()


class _Regs:
    """gr[] / fr[] as an indexable view on the Rust registers (libraries without
    hppa_reg_ptr)."""

    def __init__(self, cpu, base, n):
        self.cpu = cpu
        self.base = base
        self.n = n

    def __getitem__(self, i):
        if isinstance(i, slice):
            return [self[k] for k in range(*i.indices(self.n))]
        return lib().hppa_get_reg(self.cpu.h, self.base + i)

    def __setitem__(self, i, v):
        lib().hppa_set_reg(self.cpu.h, self.base + i, v & 0xFFFFFFFFFFFFFFFF)

    def __len__(self):
        return self.n


class RustMemory:
    PAGE = PAGE

    def __init__(self, cpu):
        self.cpu = cpu
        L = lib()
        if hasattr(L, 'hppa_ptr'):
            # the fast paths: one call checks a range and gives its host address
            h = cpu.h
            ptr, ld32, string_at = L.hppa_ptr, L.hppa_ld32, ctypes.string_at

            def read(addr, n):
                addr &= M32
                p = ptr(h, addr, n, 1)
                if p:
                    return string_at(p, n)
                raise MemFault(self._first_bad(addr, n, 1), False)

            def read32(addr):
                addr &= M32
                v = ld32(h, addr)
                if v >> 32:
                    raise MemFault(self._first_bad(addr, 4, 1), False)
                return v
            self.read = read
            self.read32 = read32
            self.fetch = read32

    @property
    def h(self):
        return self.cpu.h

    def map(self, addr, size, prot=7, data=None):
        if not lib().hppa_map(self.h, addr & M32, size, prot):
            raise MemoryError('map %#x+%#x failed' % (addr, size))
        if data is not None:
            self.write(addr, data)

    def unmap(self, addr, size):
        lib().hppa_unmap(self.h, addr & M32, size)

    def protect(self, addr, size, prot):
        lib().hppa_protect(self.h, addr & M32, size, prot)

    def find_free(self, size, lo, hi, upward):
        """a free range of size bytes in [lo, hi) (None: none), or NotImplemented when
        the library cannot search"""
        L = lib()
        if not hasattr(L, 'hppa_find_free'):
            return NotImplemented
        r = L.hppa_find_free(self.h, size, lo, hi, 1 if upward else 0)
        return None if r == 0xFFFFFFFF else r

    def is_mapped(self, addr):
        return bool(lib().hppa_page_flags(self.h, addr & M32) & 8)

    def host_base(self):
        """the host address of guest address 0 (None for a CPU without host-backed memory)"""
        return lib().hppa_host_base(self.h)

    def mark(self, addr, size, prot):
        lib().hppa_mark(self.h, addr & M32, size, prot)

    def prot_of(self, addr):
        return lib().hppa_page_flags(self.h, addr & M32) & 7

    def read(self, addr, n):
        addr &= M32
        buf = ctypes.create_string_buffer(n)
        if not lib().hppa_read(self.h, addr, buf, n):
            raise MemFault(self._first_bad(addr, n, 1), False)
        return buf.raw

    def write(self, addr, data):
        addr &= M32
        data = bytes(data)
        if not lib().hppa_write(self.h, addr, data, len(data)):
            raise MemFault(self._first_bad(addr, len(data), 2), True)

    def _first_bad(self, addr, n, want):
        a = addr & ~(PAGE - 1)
        while a < addr + n:
            if not (lib().hppa_page_flags(self.h, a) & want):
                return a if a > addr else addr
            a += PAGE
        return addr

    def fetch(self, addr):
        return struct.unpack('>I', self.read(addr, 4))[0]

    def read32(self, addr):
        return struct.unpack('>I', self.read(addr, 4))[0]

    def read64(self, addr):
        return struct.unpack('>Q', self.read(addr, 8))[0]

    def write32(self, addr, v):
        self.write(addr, struct.pack('>I', v & M32))

    def write64(self, addr, v):
        self.write(addr, struct.pack('>Q', v & 0xFFFFFFFFFFFFFFFF))

    def read_cstr(self, addr, limit=65536):
        out = bytearray()
        addr &= M32
        while len(out) < limit:
            # read to the end of the page at a time
            n = min(PAGE - (addr & (PAGE - 1)), limit - len(out))
            chunk = self.read(addr, n)
            i = chunk.find(b'\0')
            if i >= 0:
                out += chunk[:i]
                break
            out += chunk
            addr += n
        return bytes(out)


class _CrView:
    def __init__(self, cpu):
        self.cpu = cpu

    def __getitem__(self, i):
        if i == 26:
            return lib().hppa_get_reg(self.cpu.h, R_CR26)
        if i == 27:
            return lib().hppa_get_reg(self.cpu.h, R_CR27)
        return 0

    def __setitem__(self, i, v):
        if i == 26:
            lib().hppa_set_reg(self.cpu.h, R_CR26, v)
        elif i == 27:
            lib().hppa_set_reg(self.cpu.h, R_CR27, v)


def _reg_property(num, mask=None):
    def get(self):
        return lib().hppa_get_reg(self.h, num)

    def set(self, v):
        lib().hppa_set_reg(self.h, num, v & 0xFFFFFFFFFFFFFFFF)
    return property(get, set)


# the JIT: on unless HPUXEMU_JIT says otherwise; a block is compiled after JIT_THRESHOLD
# arrivals, at most JIT_MAXLEN instructions. Compiling a block costs about 0.2 ms and
# saves some 50 ns each time it runs: below a few thousand arrivals the interpreter is
# cheaper (`ls -l /usr/bin`: 0.24 s in the CPU at threshold 50, 0.12 at 2000, 0.10
# without the JIT; bench.c and a large application's start-up gain the same at 50 or 5000)
JIT_DEFAULT = 'on'
JIT_THRESHOLD = 10
JIT_MAXLEN = 64


class RustCpu:
    """Same surface as cpu.Cpu: gr, fr, sar, cr, iaoq_f/b, psw_*, icount, hooks,
    set_pc, pc, run, step, flush_decode (a no-op: the Rust CPU decodes at every fetch)."""

    def __init__(self, pa20=False):
        self.h = lib().hppa_new(1 if pa20 else 0)
        if not self.h:
            raise MemoryError('cannot reserve the guest address space')
        self.pa20 = pa20
        self.mem = RustMemory(self)
        L = lib()
        if hasattr(L, 'hppa_reg_ptr'):
            self.gr = _reg_view(L.hppa_reg_ptr(self.h, 0), True)
            self.fr = _reg_view(L.hppa_reg_ptr(self.h, 1), False)
        else:
            self.gr = _Regs(self, R_GR, 32)
            self.fr = _Regs(self, R_FR, 32)
        self._run = L.hppa_run
        self._set_pc = L.hppa_set_pc
        self._e = ExitInfo()
        self._eref = ctypes.byref(self._e)
        self.cr = _CrView(self)
        self._hooks = set()
        self.priv = 3
        self.set_jit(os.environ.get('HPUXEMU_JIT', JIT_DEFAULT))

    def set_jit(self, cfg):
        """The JIT (rust/hppa32-jit/src/jit.rs): 'off'/'0', 'on'/'1' (the defaults
        JIT_THRESHOLD, JIT_MAXLEN), or 'THRESHOLD,MAXLEN'. False when the library
        has no JIT."""
        L = lib()
        if not hasattr(L, 'hppa_set_jit'):
            return False
        cfg = (cfg or 'off').strip().lower()
        if cfg in ('0', 'off', 'no', 'false'):
            return bool(L.hppa_set_jit(self.h, 0xFFFFFFFF, 0))
        if cfg in ('1', 'on', 'yes', 'true'):
            t, n = JIT_THRESHOLD, JIT_MAXLEN
        else:
            t, n = (int(x) for x in cfg.split(','))
        return bool(L.hppa_set_jit(self.h, t, n))

    def jit_stats(self):
        """{compiled, dropped, refused, flushes, insns, compile_s} or None (JIT off)"""
        L = lib()
        if not hasattr(L, 'hppa_jit_stats'):
            return None
        a = (ctypes.c_uint64 * 10)()
        if not L.hppa_jit_stats(self.h, a, 10):
            return None
        d = dict(zip(('compiled', 'dropped', 'refused', 'flushes', 'insns'), list(a)[:5]))
        d['compile_s'] = round(a[5] / 1e9, 4)
        d.update(zip(('blocks_run', 'block_insns', 'steps', 'handovers'), list(a)[6:10]))
        return d

    def __del__(self):
        h = getattr(self, 'h', None)
        if h and _lib is not None:
            _lib.hppa_free(h)
            self.h = None

    sar = _reg_property(R_SAR)
    iaoq_f = _reg_property(R_IAOQ_F)
    iaoq_b = _reg_property(R_IAOQ_B)
    psw_cb = _reg_property(R_PSW_CB)
    psw_cb_msb = _reg_property(R_PSW_CB_MSB)
    psw_v = _reg_property(R_PSW_V)
    icount = _reg_property(R_ICOUNT)

    @property
    def psw_n(self):
        return bool(lib().hppa_get_reg(self.h, R_PSW_N))

    @psw_n.setter
    def psw_n(self, v):
        lib().hppa_set_reg(self.h, R_PSW_N, 1 if v else 0)

    @property
    def hooks(self):
        return self._hooks

    @hooks.setter
    def hooks(self, s):
        self._hooks = set(s)
        arr = (ctypes.c_uint32 * max(1, len(s)))(*sorted(s))
        lib().hppa_set_hooks(self.h, arr, len(s))

    def set_pc(self, pc):
        self._set_pc(self.h, pc & M32)

    def set_natives(self, entries):
        """[(address, kind)]: routines the CPU runs natively (native.rs; hpuxemu/native.py
        chooses them); replaces the set. False when the library cannot"""
        L = lib()
        if not hasattr(L, 'hppa_set_natives'):
            return False
        n = len(entries)
        addrs = (ctypes.c_uint32 * max(1, n))(*[a & M32 for a, k in entries])
        kinds = (ctypes.c_uint8 * max(1, n))(*[k for a, k in entries])
        L.hppa_set_natives(self.h, addrs, kinds, n)
        return True

    @property
    def pc(self):
        return self.iaoq_f & ~3

    def fr0_shadow(self):
        return self.fr[0] >> 32

    def set_fr0_shadow(self, v):
        self.fr[0] = ((v & M32) << 32) | (self.fr[0] & M32)

    def flush_decode(self, addr=None, size=None):
        pass

    @staticmethod
    def _exit(e):
        k = EXIT_KINDS.get(e.kind, 'unknown')
        if k == 'syscall':
            return ('syscall', e.a)
        if k == 'break':
            return ('break', e.a, e.b, e.c)
        if k in ('illegal', 'priv'):
            return (k, e.a, e.b)
        if k == 'fault':
            return ('fault', e.a, bool(e.b), e.c)
        if k in ('trap', 'overflow', 'hook'):
            return (k, e.a)
        if k == 'unaligned':
            return ('unaligned', e.a, e.b)
        if k == 'count':
            return ('count',)
        return ('unknown', e.kind, e.a, e.b, e.c)

    def run(self, max_insns=None):
        self._run(self.h, max_insns or 0, self._eref)
        return self._exit(self._e)

    def step(self):
        """One instruction, ignoring hooks; raises cpu.Exit-like tuples as in cpu.Cpu."""
        e = ExitInfo()
        if lib().hppa_step(self.h, ctypes.byref(e)):
            from .cpu import Exit
            r = self._exit(e)
            if r[0] == 'fault':
                raise MemFault(r[1], r[2])
            raise Exit(r)
