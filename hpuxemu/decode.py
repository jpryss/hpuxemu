"""decode.py - PA-RISC instruction decoder (PA-RISC 1.1 user level, plus the PA 2.0
non-privileged instructions 32-bit programs may use).

The one place the encodings are written down in this project: `cpu.py` executes what
`decode()` returns, `disasm.py` prints it, and the Rust interpreter (rust/hppa32-jit) is
written to agree with it instruction by instruction. The bit layouts follow the PA-RISC
1.1 Architecture and Instruction Set Reference Manual as transcribed in QEMU's
`target/hppa/insns.decode`; the field conventions are explained inline.

Bit numbering below is LSB = 0 (the manuals number the MSB 0; a field "bits 15..13" here is
bits 16..18 in the manual). Branch displacements and most immediates use PA-RISC's
"low-sign" encoding: the sign bit is the field's least significant bit, the rest of the
field holds the low-order magnitude bits.

decode(word, pa20=False) -> Insn, or an Insn with op 'illegal'.
"""


class Insn:
    """A decoded instruction: `op` names the instruction class (QEMU's trans_* names, so
    cpu.py and the Rust interpreter can share vocabulary); the other attributes are its
    fields. `n` = nullify completer, `cf` = 4-bit condition field (c<<1|f), `d` = PA 2.0
    doubleword form, `m` = base modification (0 none, 1 after/post, -1 before/pre),
    `size` = log2 bytes for loads/stores, `disp` = displacement (bytes), `sp` = space field."""
    __slots__ = ('op', 'word', 'fields')

    def __init__(self, op, word, **f):
        self.op = op
        self.word = word
        self.fields = f

    def __getattr__(self, k):
        try:
            return self.fields[k]
        except KeyError:
            raise AttributeError(k)

    def __repr__(self):
        return 'Insn(%s %s)' % (self.op, ' '.join('%s=%s' % kv for kv in sorted(self.fields.items())))


def bits(w, lsb, n):
    return (w >> lsb) & ((1 << n) - 1)


def sext(v, n):
    """sign-extend an n-bit value"""
    return v - (1 << n) if v & (1 << (n - 1)) else v


def lowsign(v, n):
    """PA 'low sign' immediate: n-bit field whose LSB is the sign"""
    mag = v >> 1
    return mag - (1 << (n - 1)) if v & 1 else mag


# --- field assemblers (names as in insns.decode) --------------------------------------

def assemble_12(w):
    """conditional branch displacement: bits 0 (sign), 2 (bit 10), 12..3 (bits 9..0), *4"""
    v = (bits(w, 3, 10) | (bits(w, 2, 1) << 10)) - (1 << 11 if w & 1 else 0)
    return v << 2


def assemble_17(w):
    """bl/be displacement: sign bit 0, bits 20..16 (w16..w12), bit 2 (w11), bits 12..3 (w10..0)"""
    v = bits(w, 3, 10) | (bits(w, 2, 1) << 10) | (bits(w, 16, 5) << 11)
    if w & 1:
        v -= 1 << 16
    return v << 2


def assemble_22(w):
    """b,l long displacement: sign bit 0, bits 25..16 (10), bit 2, bits 12..3"""
    v = bits(w, 3, 10) | (bits(w, 2, 1) << 10) | (bits(w, 16, 10) << 11)
    if w & 1:
        v -= 1 << 21
    return v << 2


def assemble_21(w):
    """ldil/addil: sign bit 0, bits 11..1 (11), 15..14 (2), 20..16 (5), 13..12 (2); << 11"""
    v = (bits(w, 12, 2)) | (bits(w, 16, 5) << 2) | (bits(w, 14, 2) << 7) | (bits(w, 1, 11) << 9)
    if w & 1:
        v -= 1 << 20
    return (v << 11) & 0xFFFFFFFF


def assemble_16(w):
    """14-bit low-sign displacement in bits 13..0 (narrow mode: bits 15..14 are the space)"""
    return lowsign(bits(w, 0, 14), 14)


def assemble_12a(w):
    """fldw/fstw long form and the PA 2.0 ldw/stw modify form: sign bit 0, bits 13..3 * 4"""
    v = bits(w, 3, 11) << 2
    return v - (1 << 13) if w & 1 else v


def assemble_11a(w):
    """ldd/std/fldd/fstd long form: sign bit 0, bits 13..4 * 8"""
    v = bits(w, 4, 10) << 3
    return v - (1 << 13) if w & 1 else v


def im5_16(w):
    return lowsign(bits(w, 16, 5), 5)


def im5_0(w):
    return lowsign(bits(w, 0, 5), 5)


def lowsign_11(w):
    return lowsign(bits(w, 0, 11), 11)


def assemble_6(v):
    """len field: (v ^ 31) + 1 over 6 bits: 0 -> 32, 1 -> 31 ... (bit 5 set: 64 - low)"""
    return (v ^ 31) + 1


def ma_to_m(v):
    """m/a bits (m = bit1 of v, a = bit0): m=0 none; m=1: a=0 post-modify, a=1 pre-modify"""
    if v & 2:
        return -1 if v & 1 else 1
    return 0


def sr3(w):
    return (bits(w, 13, 1) << 2) | bits(w, 14, 2)


# --- the decoder -----------------------------------------------------------------------

def decode(w, pa20=False):
    op = w >> 26
    w = w & 0xFFFFFFFF
    d5 = bits(w, 5, 1) if pa20 else 0

    if op == 0x00:
        ext = bits(w, 5, 8)
        if ext == 0:
            return Insn('break', w, im5=bits(w, 0, 5), im13=bits(w, 13, 13))
        if ext == 0xC1:
            return Insn('mtsp', w, r=bits(w, 16, 5), sp=sr3(w))
        if ext == 0xC2:
            return Insn('mtctl', w, t=bits(w, 21, 5), r=bits(w, 16, 5))
        if ext == 0xC6 and bits(w, 21, 5) == 11:
            return Insn('mtsarcm', w, r=bits(w, 16, 5))
        if ext == 0xC3:
            return Insn('mtsm', w)
        if ext == 0xA5 and bits(w, 16, 5) == 0:
            return Insn('mfia', w, t=bits(w, 0, 5))
        if ext == 0x25 and bits(w, 16, 5) == 0:
            return Insn('mfsp', w, t=bits(w, 0, 5), sp=sr3(w))
        if ext == 0x45 and bits(w, 16, 5) == 0:
            return Insn('mfctl', w, r=bits(w, 21, 5), t=bits(w, 0, 5), e=bits(w, 14, 1))
        if ext == 0x20 and bits(w, 13, 3) == 0:
            return Insn('sync', w)
        if ext == 0x85 and bits(w, 13, 1) == 0:
            return Insn('ldsid', w, b=bits(w, 21, 5), sp=bits(w, 14, 2), t=bits(w, 0, 5))
        if ext in (0x73, 0x6B, 0x60, 0x65):
            return Insn('priv', w)
        return Insn('illegal', w)

    if op == 0x01:
        # memory management: cache control (nop in user mode), probe; the rest privileged
        ext = bits(w, 6, 8)
        # fdc (0xCA displacement, 0x4A indexed), fdce 0x4B, pdc 0x4E, fic 0x4F; fic and
        # fice in the instruction-space form have a 3-bit space field (16-18) and the
        # 7-bit opcode 0x0A / 0x0B in bits 19-25 (lsb 6..12), as gas assembles them
        if ext == 0xCA or bits(w, 6, 7) in (0x4A, 0x4B, 0x0A, 0x0B) or ext in (0x4F, 0x4E):
            m = bits(w, 5, 1)
            if m and ext != 0xCA:
                return Insn('nop_addrx', w, b=bits(w, 21, 5), x=bits(w, 16, 5), m=1)
            return Insn('nop', w)
        if bits(w, 7, 6) == 0x23:
            return Insn('probe', w, b=bits(w, 21, 5), ri=bits(w, 16, 5), sp=bits(w, 14, 2),
                        imm=bits(w, 13, 1), write=bits(w, 6, 1), t=bits(w, 0, 5))
        if bits(w, 5, 8) == 0x4C and bits(w, 13, 1) == 0:
            return Insn('lci', w, t=bits(w, 0, 5))
        return Insn('priv', w)

    if op == 0x02:
        r2, r1, cf, t = bits(w, 21, 5), bits(w, 16, 5), bits(w, 12, 4), bits(w, 0, 5)
        ext = bits(w, 6, 6)
        sh = bits(w, 6, 2)
        e4 = bits(w, 8, 4)
        if ext == 0x00:
            return Insn('andcm', w, r1=r1, r2=r2, cf=cf, d=d5, t=t)
        if ext == 0x08:
            return Insn('and', w, r1=r1, r2=r2, cf=cf, d=d5, t=t)
        if ext == 0x09:
            return Insn('or', w, r1=r1, r2=r2, cf=cf, d=d5, t=t)
        if ext == 0x0A:
            return Insn('xor', w, r1=r1, r2=r2, cf=cf, d=d5, t=t)
        if ext == 0x0E:
            return Insn('uxor', w, r1=r1, r2=r2, cf=cf, d=d5, t=t)
        if ext == 0x11 and bits(w, 5, 1) == 0:
            return Insn('ds', w, r1=r1, r2=r2, cf=cf, t=t)
        if ext == 0x22:
            return Insn('cmpclr', w, r1=r1, r2=r2, cf=cf, d=d5, t=t)
        if ext == 0x26:
            return Insn('uaddcm', w, r1=r1, r2=r2, cf=cf, d=d5, t=t, tc=0)
        if ext == 0x27:
            return Insn('uaddcm', w, r1=r1, r2=r2, cf=cf, d=d5, t=t, tc=1)
        if ext == 0x2E and r1 == 0:
            return Insn('dcor', w, r=r2, cf=cf, d=d5, t=t, i=0)
        if ext == 0x2F and r1 == 0:
            return Insn('dcor', w, r=r2, cf=cf, d=d5, t=t, i=1)
        if e4 == 0x6:
            return Insn('add', w, r1=r1, r2=r2, cf=cf, d=d5, sh=sh, t=t, l=0, tsv=0, c=0)
        if e4 == 0xA:
            return Insn('add', w, r1=r1, r2=r2, cf=cf, d=d5, sh=sh, t=t, l=1, tsv=0, c=0)
        if e4 == 0xE:
            return Insn('add', w, r1=r1, r2=r2, cf=cf, d=d5, sh=sh, t=t, l=0, tsv=1, c=0)
        if ext == 0x1C:
            return Insn('add', w, r1=r1, r2=r2, cf=cf, d=d5, sh=0, t=t, l=0, tsv=0, c=1)
        if ext == 0x3C:
            return Insn('add', w, r1=r1, r2=r2, cf=cf, d=d5, sh=0, t=t, l=0, tsv=1, c=1)
        if ext == 0x10:
            return Insn('sub', w, r1=r1, r2=r2, cf=cf, d=d5, t=t, tsv=0, b=0, tc=0)
        if ext == 0x30:
            return Insn('sub', w, r1=r1, r2=r2, cf=cf, d=d5, t=t, tsv=1, b=0, tc=0)
        if ext == 0x13:
            return Insn('sub', w, r1=r1, r2=r2, cf=cf, d=d5, t=t, tsv=0, b=0, tc=1)
        if ext == 0x33:
            return Insn('sub', w, r1=r1, r2=r2, cf=cf, d=d5, t=t, tsv=1, b=0, tc=1)
        if ext == 0x14:
            return Insn('sub', w, r1=r1, r2=r2, cf=cf, d=d5, t=t, tsv=0, b=1, tc=0)
        if ext == 0x34:
            return Insn('sub', w, r1=r1, r2=r2, cf=cf, d=d5, t=t, tsv=1, b=1, tc=0)
        if pa20 and bits(w, 5, 9) in (0x1E, 0x1A, 0x18, 0x16, 0x0E, 0x0A, 0x08) and cf == 0:
            return Insn('pa20mm', w)  # hadd/hsub/havg: not implemented
        return Insn('illegal', w)

    if op == 0x08:
        return Insn('ldil', w, t=bits(w, 21, 5), i=assemble_21(w))
    if op == 0x0A:
        return Insn('addil', w, r=bits(w, 21, 5), i=assemble_21(w))
    if op == 0x0D:
        return Insn('ldo', w, b=bits(w, 21, 5), t=bits(w, 16, 5), i=assemble_16(w))

    if op in (0x2D, 0x2C, 0x25, 0x24):
        r, t, cf = bits(w, 21, 5), bits(w, 16, 5), bits(w, 12, 4)
        i = lowsign_11(w)
        e = bits(w, 11, 1)
        if op == 0x2D:
            return Insn('addi', w, r=r, t=t, cf=cf, i=i, tsv=e, tc=0)
        if op == 0x2C:
            return Insn('addi', w, r=r, t=t, cf=cf, i=i, tsv=e, tc=1)
        if op == 0x25:
            return Insn('subi', w, r=r, t=t, cf=cf, i=i, tsv=e)
        return Insn('cmpiclr', w, r=r, t=t, cf=cf, i=i, d=bits(w, 11, 1) if pa20 else 0)

    if op == 0x03:
        # indexed and short-displacement loads/stores
        b, sp = bits(w, 21, 5), bits(w, 14, 2)
        short = bits(w, 12, 1)
        e4 = bits(w, 6, 4)
        if short:
            disp = im5_16(w)
            m = ma_to_m((bits(w, 5, 1) << 1) | bits(w, 13, 1))
            x, scale = 0, 0
        else:
            disp = 0
            x = bits(w, 16, 5)
            m = bits(w, 5, 1)
            scale = bits(w, 13, 1)
        t = bits(w, 0, 5)
        if e4 >> 2 == 0:
            size = e4 & 3
            if size == 3 and not pa20:
                return Insn('illegal', w)
            return Insn('ld', w, b=b, x=x, sp=sp, disp=disp, m=m, scale=scale, size=size, t=t)
        if e4 >> 2 == 2 and short:
            size = e4 & 3
            if size == 3 and not pa20:
                return Insn('illegal', w)
            disp = im5_0(w)
            return Insn('st', w, b=b, sp=sp, disp=disp, m=m, size=size, t=bits(w, 16, 5))
        if e4 == 0x7:
            return Insn('ldc', w, b=b, x=x, sp=sp, disp=disp, m=m, scale=scale, size=2, t=t)
        if e4 == 0x5:
            if not pa20:
                return Insn('illegal', w)
            return Insn('ldc', w, b=b, x=x, sp=sp, disp=disp, m=m, scale=scale, size=3, t=t)
        if e4 in (0x6, 0x4):
            return Insn('priv', w)  # lda
        if e4 in (0xE, 0xF) and short:
            return Insn('priv', w)  # sta
        if e4 == 0xC and short:
            return Insn('stby', w, b=b, r=bits(w, 16, 5), sp=sp, a=bits(w, 13, 1), m=bits(w, 5, 1), disp=im5_0(w))
        if e4 == 0xD and short:
            if not pa20:
                return Insn('illegal', w)
            return Insn('stdby', w, b=b, r=bits(w, 16, 5), sp=sp, a=bits(w, 13, 1), m=bits(w, 5, 1), disp=im5_0(w))
        return Insn('illegal', w)

    if op in (0x09, 0x0B):
        # fldw/fstw (0x09) and fldd/fstd (0x0B), indexed and short forms
        b, sp = bits(w, 21, 5), bits(w, 14, 2)
        short = bits(w, 12, 1)
        if short:
            disp = im5_16(w)
            m = ma_to_m((bits(w, 5, 1) << 1) | bits(w, 13, 1))
            x, scale = 0, 0
        else:
            disp = 0
            x = bits(w, 16, 5)
            m = bits(w, 5, 1)
            scale = bits(w, 13, 1)
        if op == 0x09:
            if bits(w, 7, 3) not in (0, 4):
                return Insn('illegal', w)
            store = bits(w, 9, 1)
            t = bits(w, 0, 5) | (bits(w, 6, 1) << 5)
            return Insn('fstw' if store else 'fldw', w, b=b, x=x, sp=sp, disp=disp, m=m, scale=scale, t=t, size=2)
        if bits(w, 6, 3) != 0:
            return Insn('illegal', w)
        store = bits(w, 9, 1)
        return Insn('fstd' if store else 'fldd', w, b=b, x=x, sp=sp, disp=disp, m=m, scale=scale, t=bits(w, 0, 5), size=3)

    if op in (0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B):
        b, t, sp = bits(w, 21, 5), bits(w, 16, 5), bits(w, 14, 2)
        disp = assemble_16(w)
        size = {0x10: 0, 0x11: 1, 0x12: 2, 0x13: 2, 0x18: 0, 0x19: 1, 0x1A: 2, 0x1B: 2}[op]
        m = 0
        if op in (0x13, 0x1B):
            m = -1 if w & 1 else 1  # ldwm/stwm: d < 0 modifies before, d >= 0 after
        if op < 0x18:
            return Insn('ld', w, b=b, x=0, sp=sp, disp=disp, m=m, scale=0, size=size, t=t)
        return Insn('st', w, b=b, sp=sp, disp=disp, m=m, size=size, t=t)

    if op in (0x17, 0x1F):
        b, t, sp = bits(w, 21, 5), bits(w, 16, 5), bits(w, 14, 2)
        if bits(w, 2, 1) == 1:
            if bits(w, 1, 1) != 0:
                return Insn('illegal', w)
            disp = assemble_12a(w)
            m = 1 if w & 1 else -1  # PA 2.0 ldw,ma/mb with 12-bit displacement: d < 0 is ,ma
            if op == 0x17:
                return Insn('ld', w, b=b, x=0, sp=sp, disp=disp, m=m, scale=0, size=2, t=t)
            return Insn('st', w, b=b, sp=sp, disp=disp, m=m, size=2, t=t)
        disp = assemble_12a(w)
        t = t | (bits(w, 1, 1) << 5)
        return Insn('fldw' if op == 0x17 else 'fstw', w, b=b, x=0, sp=sp, disp=disp, m=0, scale=0, t=t, size=2)

    if op in (0x16, 0x1E):
        b, t, sp = bits(w, 21, 5), bits(w, 16, 5), bits(w, 14, 2)
        disp = assemble_12a(w)
        m = -1 if bits(w, 2, 1) else 1
        t = t | (bits(w, 1, 1) << 5)
        return Insn('fldw' if op == 0x16 else 'fstw', w, b=b, x=0, sp=sp, disp=disp, m=m, scale=0, t=t, size=2)

    if op in (0x14, 0x1C):
        b, t, sp = bits(w, 21, 5), bits(w, 16, 5), bits(w, 14, 2)
        disp = assemble_11a(w)
        m = ma_to_m(bits(w, 2, 2))
        if bits(w, 1, 1) == 0:
            if not pa20:
                return Insn('illegal', w)
            if op == 0x14:
                return Insn('ld', w, b=b, x=0, sp=sp, disp=disp, m=m, scale=0, size=3, t=t)
            return Insn('st', w, b=b, sp=sp, disp=disp, m=m, size=3, t=t)
        return Insn('fldd' if op == 0x14 else 'fstd', w, b=b, x=0, sp=sp, disp=disp, m=m, scale=0, t=t, size=3)

    if op in (0x06, 0x26):
        # fmpyadd / fmpysub; the format bit (bit 5) is 1 for single precision, as HP's
        # assembler encodes ,sgl (binutils' gas test suite, hppa-dis.c) - QEMU's
        # insns.decode has it the other way round
        return Insn('fmpyadd' if op == 0x06 else 'fmpysub', w, rm1=bits(w, 21, 5), rm2=bits(w, 16, 5),
                    ta=bits(w, 11, 5), ra=bits(w, 6, 5), tm=bits(w, 0, 5), dbl=1 - bits(w, 5, 1))

    if op in (0x30, 0x31):
        r = bits(w, 16, 5)
        c = bits(w, 15, 1)
        if bits(w, 14, 1) != 1:
            return Insn('illegal', w)
        d = bits(w, 13, 1) if pa20 else 0
        if op == 0x30:
            if bits(w, 21, 5) != 0:
                return Insn('illegal', w)
            return Insn('bb_sar', w, r=r, c=c, d=d, disp=assemble_12(w), n=bits(w, 1, 1))
        return Insn('bb_imm', w, p=bits(w, 21, 5), r=r, c=c, d=d, disp=assemble_12(w), n=bits(w, 1, 1))

    if op in (0x32, 0x33):
        c, n, disp = bits(w, 13, 3), bits(w, 1, 1), assemble_12(w)
        if op == 0x32:
            return Insn('movb', w, r1=bits(w, 16, 5), r2=bits(w, 21, 5), c=c, n=n, disp=disp)
        return Insn('movbi', w, i=im5_16(w), r=bits(w, 21, 5), c=c, n=n, disp=disp)

    if op in (0x20, 0x22, 0x27, 0x2F):
        c, n, disp = bits(w, 13, 3), bits(w, 1, 1), assemble_12(w)
        d = 1 if op in (0x27, 0x2F) else 0
        if d and not pa20:
            return Insn('illegal', w)
        f = 1 if op in (0x22, 0x2F) else 0
        return Insn('cmpb', w, r1=bits(w, 16, 5), r2=bits(w, 21, 5), c=c, f=f, d=d, n=n, disp=disp)
    if op in (0x21, 0x23):
        c, n, disp = bits(w, 13, 3), bits(w, 1, 1), assemble_12(w)
        return Insn('cmpbi', w, i=im5_16(w), r=bits(w, 21, 5), c=c, f=1 if op == 0x23 else 0, d=0, n=n, disp=disp)
    if op == 0x3B:
        if not pa20:
            return Insn('illegal', w)
        c = bits(w, 13, 2) or 4
        return Insn('cmpbi', w, i=im5_16(w), r=bits(w, 21, 5), c=c, f=bits(w, 15, 1), d=1, n=bits(w, 1, 1), disp=assemble_12(w))
    if op in (0x28, 0x2A):
        return Insn('addb', w, r1=bits(w, 16, 5), r2=bits(w, 21, 5), c=bits(w, 13, 3), f=1 if op == 0x2A else 0, n=bits(w, 1, 1), disp=assemble_12(w))
    if op in (0x29, 0x2B):
        return Insn('addbi', w, i=im5_16(w), r=bits(w, 21, 5), c=bits(w, 13, 3), f=1 if op == 0x2B else 0, n=bits(w, 1, 1), disp=assemble_12(w))

    if op == 0x34:
        r2, r1, c = bits(w, 21, 5), bits(w, 16, 5), bits(w, 13, 3)
        t = bits(w, 0, 5)
        sub = bits(w, 11, 2)
        b10 = bits(w, 10, 1)
        if sub == 0 and b10 == 0 and bits(w, 5, 4) == 0:
            d = bits(w, 9, 1)
            if d and not pa20:
                return Insn('illegal', w)
            return Insn('shrp_sar', w, r1=r1, r2=r2, c=c, d=d, t=t)
        if sub == 1 and b10 == 0:
            return Insn('shrp_imm', w, r1=r1, r2=r2, c=c, d=0, cpos=bits(w, 5, 5), t=t)
        if bits(w, 12, 1) == 0 and b10 == 1:
            if not pa20:
                return Insn('illegal', w)
            return Insn('shrp_imm', w, r1=r1, r2=r2, c=c, d=1, cpos=(bits(w, 11, 1) << 5) | bits(w, 5, 5), t=t)
        if sub == 2 and bits(w, 5, 3) == 0:
            d = bits(w, 9, 1)
            if d and not pa20:
                return Insn('illegal', w)
            ln = assemble_6((bits(w, 8, 1) << 5) | bits(w, 0, 5)) if d else assemble_6(bits(w, 0, 5))
            if not d and bits(w, 8, 1):
                return Insn('illegal', w)
            return Insn('extr_sar', w, r=r2, t=r1, c=c, se=b10, d=d, len=ln)
        if sub == 3:
            return Insn('extr_imm', w, r=r2, t=r1, c=c, se=b10, d=0, pos=bits(w, 5, 5), len=assemble_6(bits(w, 0, 5)))
        return Insn('illegal', w)
    if op == 0x36:
        if not pa20:
            return Insn('illegal', w)
        return Insn('extr_imm', w, r=bits(w, 21, 5), t=bits(w, 16, 5), c=bits(w, 13, 3), se=bits(w, 10, 1), d=1,
                    pos=(bits(w, 11, 1) << 5) | bits(w, 5, 5), len=assemble_6((bits(w, 12, 1) << 5) | bits(w, 0, 5)))

    if op == 0x35:
        t, r, c = bits(w, 21, 5), bits(w, 16, 5), bits(w, 13, 3)
        sub = bits(w, 11, 2)
        nz = bits(w, 10, 1)
        if sub == 0 and bits(w, 5, 3) == 0:
            if bits(w, 9, 1) and not pa20:
                return Insn('illegal', w)
            d = bits(w, 9, 1) if pa20 else 0
            ln = assemble_6((bits(w, 8, 1) << 5) | bits(w, 0, 5)) if d else assemble_6(bits(w, 0, 5))
            return Insn('dep_sar', w, t=t, r=r, c=c, nz=nz, d=d, len=ln)
        if sub == 1:
            return Insn('dep_imm', w, t=t, r=r, c=c, nz=nz, d=0, cpos=bits(w, 5, 5), len=assemble_6(bits(w, 0, 5)))
        if sub == 2 and bits(w, 5, 3) == 0:
            if bits(w, 9, 1) and not pa20:
                return Insn('illegal', w)
            d = bits(w, 9, 1) if pa20 else 0
            return Insn('depi_sar', w, t=t, i=im5_16(w), c=c, nz=nz, d=d, len=assemble_6((bits(w, 8, 1) << 5) | bits(w, 0, 5)))
        if sub == 3:
            return Insn('depi_imm', w, t=t, i=im5_16(w), c=c, nz=nz, d=0, cpos=bits(w, 5, 5), len=assemble_6(bits(w, 0, 5)))
        return Insn('illegal', w)
    if op == 0x3C:
        if not pa20:
            return Insn('illegal', w)
        return Insn('dep_imm', w, t=bits(w, 21, 5), r=bits(w, 16, 5), c=bits(w, 13, 3), nz=bits(w, 10, 1), d=1,
                    cpos=(bits(w, 11, 1) << 5) | bits(w, 5, 5), len=assemble_6((bits(w, 12, 1) << 5) | bits(w, 0, 5)))
    if op == 0x3D:
        if not pa20:
            return Insn('illegal', w)
        return Insn('depi_imm', w, t=bits(w, 21, 5), i=im5_16(w), c=bits(w, 13, 3), nz=bits(w, 10, 1), d=1,
                    cpos=(bits(w, 11, 1) << 5) | bits(w, 5, 5), len=assemble_6((bits(w, 12, 1) << 5) | bits(w, 0, 5)))

    if op in (0x38, 0x39):
        return Insn('be', w, b=bits(w, 21, 5), disp=assemble_17(w), sp=sr3(w), n=bits(w, 1, 1), l=31 if op == 0x39 else 0)

    if op == 0x3A:
        sub = bits(w, 13, 3)
        n = bits(w, 1, 1)
        if sub in (0, 4):
            return Insn('bl', w, l=bits(w, 21, 5), disp=assemble_17(w), n=n)
        if sub == 5:
            return Insn('bl', w, l=2, disp=assemble_22(w), n=n)
        if sub == 1:
            return Insn('b_gate', w, l=bits(w, 21, 5), disp=assemble_17(w), n=n)
        if sub == 2 and bits(w, 2, 11) == 0 and bits(w, 0, 1) == 0:
            return Insn('blr', w, l=bits(w, 21, 5), x=bits(w, 16, 5), n=n)
        if sub == 2 and bits(w, 0, 1) == 1 and bits(w, 21, 5) == 0:
            return Insn('nop', w) if pa20 else Insn('illegal', w)  # branch target stack ops
        if sub == 6 and bits(w, 12, 1) == 0 and bits(w, 2, 10) == 0 and bits(w, 0, 1) == 0:
            return Insn('bv', w, b=bits(w, 21, 5), x=bits(w, 16, 5), n=n)
        if sub in (6, 7) and bits(w, 12, 1) == 1 and bits(w, 16, 5) == 0 and bits(w, 2, 10) == 0:
            return Insn('bve', w, b=bits(w, 21, 5), n=n, l=2 if sub == 7 else 0)
        return Insn('illegal', w)

    if op == 0x2E:
        # fmpyfadd / fmpynfadd
        neg = bits(w, 5, 1)
        if bits(w, 11, 1) == 0:
            rm1 = bits(w, 21, 5) | (bits(w, 7, 1) << 5)
            rm2 = bits(w, 16, 5) | (bits(w, 12, 1) << 5)
            ra3 = (bits(w, 8, 1) << 5) | (bits(w, 13, 3) << 2) | bits(w, 9, 2)
            t = bits(w, 0, 5) | (bits(w, 6, 1) << 5)
            return Insn('fmpyfadd', w, rm1=rm1, rm2=rm2, ra3=ra3, t=t, neg=neg, dbl=0)
        if bits(w, 12, 1) == 0 and bits(w, 6, 3) == 0:
            ra3 = (bits(w, 13, 3) << 2) | bits(w, 9, 2)
            return Insn('fmpyfadd', w, rm1=bits(w, 21, 5), rm2=bits(w, 16, 5), ra3=ra3, t=bits(w, 0, 5), neg=neg, dbl=1)
        return Insn('illegal', w)

    if op == 0x0C:
        return _decode_fp0c(w)
    if op == 0x0E:
        return _decode_fp0e(w)

    if pa20 and op in (0x3E, 0x05):
        return Insn('pa20mm', w)
    if op == 0x05:
        return Insn('illegal', w)
    return Insn('illegal', w)


_FP0_NAMES = {2: 'fcpy', 3: 'fabs', 4: 'fsqrt', 5: 'frnd', 6: 'fneg', 7: 'fnegabs'}
_FP3_NAMES = {0: 'fadd', 1: 'fsub', 2: 'fmpy', 3: 'fdiv'}
_FCNV = {0: ('f', 'f'), 1: ('i', 'f'), 2: ('f', 'i'), 3: ('f', 'ti'), 5: ('u', 'f'), 6: ('f', 'u'), 7: ('f', 'tu')}


def _decode_fp0c(w):
    """Floating-point class 0/1/2/3 (op 0x0C): doubleword-register encodings"""
    r1, r2, t = bits(w, 21, 5), bits(w, 16, 5), bits(w, 0, 5)
    cls = bits(w, 9, 2)
    if cls == 0:
        if w == 0x30000000:
            return Insn('fid', w)
        if bits(w, 6, 3) != 0 or bits(w, 5, 1) != 0 or r2 != 0:
            return Insn('illegal', w)
        sub = bits(w, 13, 3)
        fmt = bits(w, 11, 2)
        if sub in _FP0_NAMES and fmt in (0, 1):
            return Insn(_FP0_NAMES[sub], w, r=r1, t=t, dbl=fmt)
        return Insn('illegal', w)
    if cls == 1:
        if bits(w, 6, 3) != 0 or bits(w, 5, 1) != 0 or bits(w, 18, 3) != 0:
            return Insn('illegal', w)
        sub = bits(w, 15, 3)
        df, sf = bits(w, 13, 2), bits(w, 11, 2)  # destination format, source format
        if sub not in _FCNV or sf > 1 or df > 1:
            return Insn('illegal', w)
        return Insn('fcnv', w, r=r1, t=t, kind=_FCNV[sub], sf=sf, df=df)
    if cls == 2:
        if bits(w, 5, 1) == 1 and r1 == 0 and r2 == 0 and bits(w, 11, 2) == 0 and bits(w, 6, 5) == 0x10:
            return Insn('ftest', w, y=bits(w, 13, 3), c=bits(w, 0, 5))
        if bits(w, 5, 1) != 0:
            return Insn('illegal', w)
        fmt = bits(w, 11, 2)
        if fmt > 1:
            return Insn('illegal', w)
        return Insn('fcmp', w, r1=r1, r2=r2, y=bits(w, 13, 3), c=bits(w, 0, 5), dbl=fmt)
    if bits(w, 5, 1) != 0 or bits(w, 6, 3) != 0:
        return Insn('illegal', w)
    sub = bits(w, 13, 3)
    fmt = bits(w, 11, 2)
    if sub in _FP3_NAMES and fmt in (0, 1):
        return Insn(_FP3_NAMES[sub], w, r1=r1, r2=r2, t=t, dbl=fmt)
    return Insn('illegal', w)


def _decode_fp0e(w):
    """Floating-point class 0/1/2/3 (op 0x0E): singleword-register encodings (the L/R
    halves are registers 0-31 / 32-63), and xmpyu"""
    cls = bits(w, 9, 2)
    ra = bits(w, 21, 5) | (bits(w, 7, 1) << 5)
    rb = bits(w, 16, 5) | (bits(w, 12, 1) << 5)
    rt = bits(w, 0, 5) | (bits(w, 6, 1) << 5)
    if cls == 0:
        sub = bits(w, 13, 3)
        fmt = bits(w, 11, 1)
        if bits(w, 16, 5) != 0 or bits(w, 12, 1) != 0 or bits(w, 8, 1) != 0 or bits(w, 5, 1) != 0:
            return Insn('illegal', w)
        if sub in _FP0_NAMES:
            if fmt == 0:
                return Insn(_FP0_NAMES[sub], w, r=ra, t=rt, dbl=0)
            if bits(w, 7, 1) == 0 and bits(w, 6, 1) == 0:
                return Insn(_FP0_NAMES[sub], w, r=bits(w, 21, 5), t=bits(w, 0, 5), dbl=1)
        return Insn('illegal', w)
    if cls == 1:
        sub = bits(w, 15, 3)
        if sub not in _FCNV or bits(w, 18, 3) != 0 or bits(w, 5, 1) != 0 or bits(w, 8, 1) != 0:
            return Insn('illegal', w)
        df, sf = bits(w, 13, 2), bits(w, 11, 2)
        if df > 1 or sf > 1:
            return Insn('illegal', w)
        r = ra if sf == 0 else bits(w, 21, 5)
        t = rt if df == 0 else bits(w, 0, 5)
        if sf == 1 and bits(w, 7, 1):
            return Insn('illegal', w)
        if df == 1 and bits(w, 6, 1):
            return Insn('illegal', w)
        return Insn('fcnv', w, r=r, t=t, kind=_FCNV[sub], sf=sf, df=df)
    if cls == 2:
        fmt = bits(w, 11, 1)
        # bit 7 is the first operand's half (fr4R), checked below for the double format
        if bits(w, 8, 1) != 0 or bits(w, 6, 1) != 0:
            return Insn('illegal', w)
        if fmt == 0:
            return Insn('fcmp', w, r1=ra, r2=rb, y=bits(w, 13, 3), c=bits(w, 0, 5), dbl=0)
        if bits(w, 7, 1) == 0 and bits(w, 12, 1) == 0:
            return Insn('fcmp', w, r1=bits(w, 21, 5), r2=bits(w, 16, 5), y=bits(w, 13, 3), c=bits(w, 0, 5), dbl=1)
        return Insn('illegal', w)
    sub = bits(w, 13, 3)
    fmt = bits(w, 11, 1)
    if bits(w, 5, 1) != 0:
        return Insn('illegal', w)
    if sub == 2 and fmt == 0 and bits(w, 8, 1) == 1 and bits(w, 6, 1) == 0:
        # xmpyu: 001110 r1 r2 010 .0111 .00 t - 32x32 unsigned multiply into a double register
        return Insn('xmpyu', w, r1=ra, r2=rb, t=bits(w, 0, 5))
    if sub in _FP3_NAMES:
        if fmt == 0 and bits(w, 8, 1) == 0:
            return Insn(_FP3_NAMES[sub], w, r1=ra, r2=rb, t=rt, dbl=0)
        if fmt == 1 and bits(w, 12, 1) == 0 and bits(w, 7, 1) == 0 and bits(w, 6, 1) == 0 and bits(w, 8, 1) == 0:
            return Insn(_FP3_NAMES[sub], w, r1=bits(w, 21, 5), r2=bits(w, 16, 5), t=bits(w, 0, 5), dbl=1)
    return Insn('illegal', w)
