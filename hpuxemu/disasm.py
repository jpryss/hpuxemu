"""disasm.py - PA-RISC disassembler on top of decode.py, in the HP/GNU assembler syntax.

    python3 -m hpuxemu.disasm FILE [START [COUNT]]     a SOM file's code (START: address)
    python3 -m hpuxemu.disasm -w WORD...                hex words

The output is what `as` accepts, so decode.py can be checked against the GNU assembler's
test suite (tools/test_decode.py).
"""
import sys

from .decode import decode

# condition names indexed by the 4-bit field c<<1 | f (f inverts the condition c)
def _conds(names, inv):
    out = []
    for a, b in zip(names, inv):
        out += [(',' + a) if a else '', (',' + b) if b else '']
    return out


ADD_COND = _conds(['', '=', '<', '<=', 'nuv', 'znv', 'sv', 'od'], ['tr', '<>', '>=', '>', 'uv', 'vnz', 'nsv', 'ev'])
SUB_COND = _conds(['', '=', '<', '<=', '<<', '<<=', 'sv', 'od'], ['tr', '<>', '>=', '>', '>>=', '>>', 'nsv', 'ev'])
LOG_COND = _conds(['', '=', '<', '<=', '?4', '?5', '?6', 'od'], ['tr', '<>', '>=', '>', '?12', '?13', '?14', 'ev'])
UNIT_COND = _conds(['', 'swz', 'sbz', 'shz', 'sdc', 'swc', 'sbc', 'shc'], ['tr', 'nwz', 'nbz', 'nhz', 'ndc', 'nwc', 'nbc', 'nhc'])
SED_COND = ['', ',=', ',<', ',od', ',tr', ',<>', ',>=', ',ev']
ADDB_COND = ADD_COND
FCMP_COND = ['false?', 'false', '?', '!<=>', '=', '=t', '?=', '!<>', '!?>=', '<', '?<', '!>=', '!?>', '<=', '?<=', '!>',
             '!?<=', '>', '?>', '!<=', '!?<', '>=', '?>=', '!<', '!?=', '<>', '!=', '!=t', '!?', '<=>', 'true?', 'true']
SIZE_NAME = {0: 'b', 1: 'h', 2: 'w', 3: 'd'}
CR_NAMES = {11: 'sar', 26: 'cr26', 27: 'cr27'}


def r(n):
    return 'r%d' % n


def fr(n):
    """FP register: 0-31 the doubleword (or left half), 32-63 the right half"""
    if n >= 32:
        return 'fr%dR' % (n - 32)
    return 'fr%d' % n


def frl(n):
    """single-precision operand: fr4L / fr4R spelled out"""
    if n >= 32:
        return 'fr%dR' % (n - 32)
    return 'fr%dL' % n


def dcond(table, cf, d):
    """condition completer; PA 2.0 doubleword forms carry a '*' (add,*= ...)"""
    c = table[cf]
    if d:
        return ',*' + c[1:]
    return c


def mod(m):
    return {0: '', 1: ',ma', -1: ',mb'}[m]


def fmt_fp(dbl):
    return ',dbl' if dbl else ',sgl'


def fcnv_name(kind, sf, df):
    s, d = kind
    names = {('f', 'f'): 'fcnvff', ('i', 'f'): 'fcnvxf', ('f', 'i'): 'fcnvfx', ('f', 'ti'): 'fcnvfxt',
             ('u', 'f'): 'fcnvuf', ('f', 'u'): 'fcnvfu', ('f', 'tu'): 'fcnvfut'}
    fmts = ['sgl', 'dbl']
    ifmts = ['sgl', 'dbl']  # integer formats: sgl = 32-bit word, dbl = 64-bit
    return '%s,%s,%s' % (names[kind], fmts[sf] if s == 'f' else ifmts[sf], fmts[df] if d == 'f' else ifmts[df])


def disasm(word, pc=0, pa20=False):
    """One instruction as text; `pc` for branch targets."""
    i = decode(word, pa20)
    o = i.op
    f = i.fields
    n = lambda: ',n' if f.get('n') else ''

    if o == 'illegal':
        return '<illegal %08x>' % word
    if o == 'priv':
        return '<privileged %08x>' % word
    if o == 'pa20mm':
        return '<pa20 multimedia %08x>' % word
    if o == 'break':
        return 'break %d,%d' % (f['im5'], f['im13'])
    if o == 'nop':
        return 'nop' if word == 0x08000240 else 'fdc/fic/pdc (nop)'
    if o == 'nop_addrx':
        # the cache flushes with base modification: which one, from the opcode extension
        e7, e8 = (word >> 6) & 0x7F, (word >> 6) & 0xFF
        name = {0x0A: 'fic', 0x0B: 'fice'}.get(e7) or {0x4A: 'fdc', 0x4B: 'fdce', 0x4E: 'pdc', 0x4F: 'fic'}.get(e8, 'fdc')
        return '%s,m r%d(r%d)' % (name, f['x'], f['b'])
    if o == 'sync':
        return 'sync'
    if o == 'mfia':
        return 'mfia %s' % r(f['t'])
    if o == 'mfsp':
        return 'mfsp sr%d,%s' % (f['sp'], r(f['t']))
    if o == 'mtsp':
        return 'mtsp %s,sr%d' % (r(f['r']), f['sp'])
    if o == 'mfctl':
        return 'mfctl%s %s,%s' % (',w' if f['e'] else '', CR_NAMES.get(f['r'], 'cr%d' % f['r']), r(f['t']))
    if o == 'mtctl':
        if f['t'] == 11:
            return 'mtsar %s' % r(f['r'])
        return 'mtctl %s,%s' % (r(f['r']), CR_NAMES.get(f['t'], 'cr%d' % f['t']))
    if o == 'mtsarcm':
        return 'mtsarcm %s' % r(f['r'])
    if o == 'ldsid':
        return 'ldsid (sr%d,%s),%s' % (f['sp'], r(f['b']), r(f['t'])) if f['sp'] else 'ldsid (%s),%s' % (r(f['b']), r(f['t']))
    if o == 'probe':
        return 'probe%s%s (sr%d,%s),%s,%s' % ('w' if f['write'] else 'r', 'i' if f['imm'] else '', f['sp'], r(f['b']),
                                             ('%d' % f['ri']) if f['imm'] else r(f['ri']), r(f['t']))
    if o == 'lci':
        return 'lci ...,%s' % r(f['t'])

    if o in ('and', 'or', 'xor', 'andcm'):
        if o == 'or' and f['cf'] == 0 and f['r2'] == 0 and f['t'] != 0:
            return 'copy %s,%s' % (r(f['r1']), r(f['t']))
        if o == 'or' and f['cf'] == 0 and f['t'] == 0 and f['r1'] == 0 and f['r2'] == 0:
            return 'nop'
        return '%s%s %s,%s,%s' % (o, dcond(LOG_COND, f['cf'], f['d']), r(f['r1']), r(f['r2']), r(f['t']))
    if o == 'uxor':
        return 'uxor%s %s,%s,%s' % (dcond(UNIT_COND, f['cf'], f['d']), r(f['r1']), r(f['r2']), r(f['t']))
    if o == 'uaddcm':
        return 'uaddcm%s%s %s,%s,%s' % ('t' if f['tc'] else '', dcond(UNIT_COND, f['cf'], f['d']), r(f['r1']), r(f['r2']), r(f['t']))
    if o == 'dcor':
        return '%sdcor%s %s,%s' % ('i' if f['i'] else '', dcond(UNIT_COND, f['cf'], f['d']), r(f['r']), r(f['t']))
    if o == 'ds':
        return 'ds%s %s,%s,%s' % (SUB_COND[f['cf']], r(f['r1']), r(f['r2']), r(f['t']))
    if o == 'cmpclr':
        return 'comclr%s %s,%s,%s' % (dcond(SUB_COND, f['cf'], f['d']), r(f['r1']), r(f['r2']), r(f['t']))
    if o == 'add':
        name = 'add'
        if f['sh']:
            name = 'sh%dadd' % f['sh']
        if f['l']:
            name += 'l'
        elif f['tsv'] and f['c']:
            name += 'co'
        elif f['tsv']:
            name += 'o'
        elif f['c']:
            name += 'c'
        return '%s%s %s,%s,%s' % (name, dcond(ADD_COND, f['cf'], f['d']), r(f['r1']), r(f['r2']), r(f['t']))
    if o == 'sub':
        name = 'sub'
        if f['b']:
            name += 'b'
        if f['tc']:
            name += 't'
        if f['tsv']:
            name += 'o'
        return '%s%s %s,%s,%s' % (name, dcond(SUB_COND, f['cf'], f['d']), r(f['r1']), r(f['r2']), r(f['t']))
    if o == 'addi':
        name = 'addi' + ('t' if f['tc'] else '') + ('o' if f['tsv'] else '')
        return '%s%s %d,%s,%s' % (name, ADD_COND[f['cf']], f['i'], r(f['r']), r(f['t']))
    if o == 'subi':
        return 'subi%s%s %d,%s,%s' % ('o' if f['tsv'] else '', SUB_COND[f['cf']], f['i'], r(f['r']), r(f['t']))
    if o == 'cmpiclr':
        return 'comiclr%s %d,%s,%s' % (dcond(SUB_COND, f['cf'], f['d']), f['i'], r(f['r']), r(f['t']))
    if o == 'ldil':
        return 'ldil L%%0x%x,%s' % (f['i'], r(f['t']))
    if o == 'addil':
        return 'addil L%%0x%x,%s' % (f['i'] & 0xFFFFFFFF, r(f['r']))
    if o == 'ldo':
        if f['b'] == 0:
            return 'ldi %d,%s' % (f['i'], r(f['t']))
        return 'ldo %d(%s),%s' % (f['i'], r(f['b']), r(f['t']))

    if o in ('ld', 'st', 'ldc', 'fldw', 'fstw', 'fldd', 'fstd'):
        sp = ('sr%d,' % f['sp']) if f.get('sp') else ''
        if o == 'ld':
            name = 'ld' + SIZE_NAME[f['size']]
        elif o == 'st':
            name = 'st' + SIZE_NAME[f['size']]
        elif o == 'ldc':
            name = 'ldcw' if f['size'] == 2 else 'ldcd'
        else:
            name = o
        if o in ('fldw', 'fstw'):
            reg = frl(f['t'])
        elif o in ('fldd', 'fstd'):
            reg = fr(f['t'])
        else:
            reg = r(f['t'])
        if f.get('x'):
            addr = '%s(%s%s)' % (r(f['x']), sp, r(f['b']))
            compl = (',s' if f['scale'] else '') + (',m' if f['m'] else '')
            if o in ('ld', 'ldc', 'fldw', 'fldd'):
                return '%s%s %s,%s' % (name + 'x' if o in ('ld', 'ldc') else name, compl, addr, reg)
            return '%s%s %s,%s' % (name, compl, reg, addr)
        addr = '%d(%s%s)' % (f['disp'], sp, r(f['b']))
        compl = mod(f['m'])
        if o in ('st', 'fstw', 'fstd'):
            return '%s%s %s,%s' % (name, compl, reg, addr)
        return '%s%s %s,%s' % (name, compl, addr, reg)
    if o in ('stby', 'stdby'):
        return '%s,%s%s %s,%d(%s)' % (o, 'e' if f['a'] else 'b', ',m' if f['m'] else '', r(f['r']), f['disp'], r(f['b']))

    if o in ('fmpyadd', 'fmpysub'):
        rr = fr if f['dbl'] else frl
        return '%s%s %s,%s,%s,%s,%s' % (o, fmt_fp(f['dbl']), rr(f['rm1']), rr(f['rm2']), rr(f['tm']), rr(f['ra']), rr(f['ta']))
    if o == 'fmpyfadd':
        rr = fr if f['dbl'] else frl
        return '%s%s %s,%s,%s,%s' % ('fmpynfadd' if f['neg'] else 'fmpyfadd', fmt_fp(f['dbl']), rr(f['rm1']), rr(f['rm2']), rr(f['ra3']), rr(f['t']))

    tgt = lambda: '0x%x' % ((pc + 8 + f['disp']) & 0xFFFFFFFF)
    if o == 'bb_sar':
        return 'bvb%s%s %s,%s' % (',>=' if f['c'] else ',<', n(), r(f['r']), tgt())
    if o == 'bb_imm':
        return 'bb%s%s %s,%d,%s' % (',>=' if f['c'] else ',<', n(), r(f['r']), f['p'], tgt())
    if o == 'movb':
        return 'movb%s%s %s,%s,%s' % (SED_COND[f['c']], n(), r(f['r1']), r(f['r2']), tgt())
    if o == 'movbi':
        return 'movib%s%s %d,%s,%s' % (SED_COND[f['c']], n(), f['i'], r(f['r']), tgt())
    if o == 'cmpb':
        return 'comb%s%s %s,%s,%s' % (SUB_COND[f['c'] * 2 + f['f']], n(), r(f['r1']), r(f['r2']), tgt())
    if o == 'cmpbi':
        return 'comib%s%s %d,%s,%s' % (SUB_COND[f['c'] * 2 + f['f']], n(), f['i'], r(f['r']), tgt())
    if o == 'addb':
        return 'addb%s%s %s,%s,%s' % (ADDB_COND[f['c'] * 2 + f['f']], n(), r(f['r1']), r(f['r2']), tgt())
    if o == 'addbi':
        return 'addib%s%s %d,%s,%s' % (ADDB_COND[f['c'] * 2 + f['f']], n(), f['i'], r(f['r']), tgt())
    if o == 'be':
        name = 'ble' if f['l'] else 'be'
        return '%s%s %d(sr%d,%s)' % (name, n(), f['disp'], f['sp'], r(f['b']))
    if o == 'bl':
        if f['l'] == 0:
            return 'b%s %s' % (n(), tgt())
        return 'bl%s %s,%s' % (n(), tgt(), r(f['l']))
    if o == 'b_gate':
        return 'gate%s %s,%s' % (n(), tgt(), r(f['l']))
    if o == 'blr':
        return 'blr%s %s,%s' % (n(), r(f['x']), r(f['l']))
    if o == 'bv':
        return 'bv%s %s(%s)' % (n(), r(f['x']), r(f['b']))
    if o == 'bve':
        return 'bve%s%s (%s)' % (',l' if f['l'] else '', n(), r(f['b']))

    if o == 'shrp_sar':
        return '%s%s %s,%s,%s' % ('shrpd' if f['d'] else 'vshd', dcond(SED_COND, f['c'], f['d']), r(f['r1']), r(f['r2']), r(f['t']))
    if o == 'shrp_imm':
        w_ = 63 if f['d'] else 31
        return '%s%s %s,%s,%d,%s' % ('shrpd' if f['d'] else 'shd', dcond(SED_COND, f['c'], f['d']), r(f['r1']), r(f['r2']), w_ - f['cpos'], r(f['t']))
    if o == 'extr_sar':
        if f['d']:
            return 'extrd,%s%s %s,sar,%d,%s' % ('s' if f['se'] else 'u', dcond(SED_COND, f['c'], 1), r(f['r']), f['len'], r(f['t']))
        return 'vextr%s%s %s,%d,%s' % ('s' if f['se'] else 'u', SED_COND[f['c']], r(f['r']), f['len'], r(f['t']))
    if o == 'extr_imm':
        if f['d']:
            return 'extrd,%s%s %s,%d,%d,%s' % ('s' if f['se'] else 'u', dcond(SED_COND, f['c'], 1), r(f['r']), f['pos'], f['len'], r(f['t']))
        return 'extr%s%s %s,%d,%d,%s' % ('s' if f['se'] else 'u', SED_COND[f['c']], r(f['r']), f['pos'], f['len'], r(f['t']))
    if o == 'dep_sar':
        if f['d']:
            return 'depd%s%s %s,sar,%d,%s' % ('' if f['nz'] else ',z', dcond(SED_COND, f['c'], 1), r(f['r']), f['len'], r(f['t']))
        return '%s%s %s,%d,%s' % ('vdep' if f['nz'] else 'zvdep', SED_COND[f['c']], r(f['r']), f['len'], r(f['t']))
    if o == 'dep_imm':
        if f['d']:
            return 'depd%s%s %s,%d,%d,%s' % ('' if f['nz'] else ',z', dcond(SED_COND, f['c'], 1), r(f['r']), 63 - f['cpos'], f['len'], r(f['t']))
        return '%s%s %s,%d,%d,%s' % ('dep' if f['nz'] else 'zdep', SED_COND[f['c']], r(f['r']), 31 - f['cpos'], f['len'], r(f['t']))
    if o == 'depi_sar':
        if f['d']:
            return 'depdi%s%s %d,sar,%d,%s' % ('' if f['nz'] else ',z', dcond(SED_COND, f['c'], 1), f['i'], f['len'], r(f['t']))
        return '%s%s %d,%d,%s' % ('vdepi' if f['nz'] else 'zvdepi', SED_COND[f['c']], f['i'], f['len'], r(f['t']))
    if o == 'depi_imm':
        if f['d']:
            return 'depdi%s%s %d,%d,%d,%s' % ('' if f['nz'] else ',z', dcond(SED_COND, f['c'], 1), f['i'], 63 - f['cpos'], f['len'], r(f['t']))
        return '%s%s %d,%d,%d,%s' % ('depi' if f['nz'] else 'zdepi', SED_COND[f['c']], f['i'], 31 - f['cpos'], f['len'], r(f['t']))

    if o == 'fid':
        return 'fid'
    if o in ('fcpy', 'fabs', 'fsqrt', 'frnd', 'fneg', 'fnegabs'):
        rr = fr if f['dbl'] else frl
        return '%s%s %s,%s' % (o, fmt_fp(f['dbl']), rr(f['r']), rr(f['t']))
    if o == 'fcnv':
        s, d = f['kind']
        rs = (fr if f['sf'] else frl)(f['r'])
        rt = (fr if f['df'] else frl)(f['t'])
        return '%s %s,%s' % (fcnv_name(f['kind'], f['sf'], f['df']), rs, rt)
    if o == 'ftest':
        return 'ftest' if f['y'] == 1 and f['c'] == 0 else 'ftest y=%d c=%d' % (f['y'], f['c'])
    if o == 'fcmp':
        rr = fr if f['dbl'] else frl
        return 'fcmp%s,%s %s,%s%s' % (fmt_fp(f['dbl']), FCMP_COND[f['c']], rr(f['r1']), rr(f['r2']), (',%d' % f['y']) if f['y'] else '')
    if o in ('fadd', 'fsub', 'fmpy', 'fdiv'):
        rr = fr if f['dbl'] else frl
        return '%s%s %s,%s,%s' % (o, fmt_fp(f['dbl']), rr(f['r1']), rr(f['r2']), rr(f['t']))
    if o == 'xmpyu':
        return 'xmpyu %s,%s,%s' % (frl(f['r1']), frl(f['r2']), fr(f['t']))
    return '<%s %08x>' % (o, word)


def main(argv):
    if len(argv) >= 3 and argv[1] == '-w':
        for w in argv[2:]:
            print('%08x  %s' % (int(w, 16), disasm(int(w, 16))))
        return 0
    if len(argv) < 2:
        print(__doc__)
        return 2
    from . import som
    s = som.load(argv[1])
    start = int(argv[2], 16) if len(argv) > 2 else None
    count = int(argv[3]) if len(argv) > 3 else 64
    for ss in s.subspaces:
        if not ss.loadable or not (ss.name == '$CODE$' or ss.name == '$MILLICODE$'):
            continue
        a = ss.start
        if start is not None and not (ss.start <= start < ss.start + ss.length):
            continue
        off = ss.file_loc
        if start is not None:
            off += start - ss.start
            a = start
        else:
            count = ss.init_length // 4
        for k in range(count):
            if off + 4 > len(s.data):
                break
            w = int.from_bytes(s.data[off:off + 4], 'big')
            print('%08x  %08x  %s' % (a, w, disasm(w, a)))
            a += 4
            off += 4
        if start is not None:
            break
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
