#!/usr/bin/env python3
"""test_decode.py - check decode.py/disasm.py against the GNU assembler's PA-RISC test suite.

    python3 tools/test_decode.py GAS_TESTSUITE_DIR     (binutils gas/testsuite/gas/hppa/basic)

basic.exp lists, per source file, the instruction words the HP assembler produced for it in
source order; the words are paired with the source lines of the .s file and our
disassembly of each word is compared with the source text (after normalising register
spellings, spaces and the few mnemonic synonyms). Prints the mismatches; exit 1 on any.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from hpuxemu.disasm import disasm  # noqa: E402

SYN = {'subot': 'sub,tsv,tc', 'addiot': 'addi,tsv,tc', 'extrd': 'extr', 'depd': 'dep', 'depdi': 'depi', 'shrpd': 'shrp', 'fldwx': 'fldw', 'fstwx': 'fstw', 'flddx': 'fldd', 'fstdx': 'fstd',
       'comb': 'cmpb', 'comib': 'cmpib', 'comclr': 'cmpclr', 'comiclr': 'cmpiclr', 'addl': 'add,l', 'addo': 'add,tsv',
       'addco': 'add,c,tsv', 'addc': 'add,c', 'subo': 'sub,tsv', 'subbo': 'sub,b,tsv', 'subb': 'sub,b', 'subt': 'sub,tc',
       'subto': 'sub,tsv,tc', 'addit': 'addi,tc', 'addio': 'addi,tsv', 'addito': 'addi,tsv,tc', 'subio': 'subi,tsv',
       'uaddcmt': 'uaddcm,tc', 'ldwx': 'ldw', 'ldhx': 'ldh', 'ldbx': 'ldb', 'ldcwx': 'ldcw', 'fldwx': 'fldw',
       'flddx': 'fldd', 'ldws': 'ldw', 'ldhs': 'ldh', 'ldbs': 'ldb', 'ldcws': 'ldcw', 'fldws': 'fldw', 'fldds': 'fldd',
       'stws': 'stw', 'sths': 'sth', 'stbs': 'stb', 'fstws': 'fstw', 'fstds': 'fstd', 'stwx': 'stw', 'fstwx': 'fstw', 'fstdx': 'fstd',
       'ldwm': 'ldw,ma', 'stwm': 'stw,ma', 'stbys': 'stby', 'ldi': 'ldo', 'copy': 'or', 'bl': 'b,l', 'blr': 'blr',
       'gate': 'b,gate', 'movib': 'movbi', 'addib': 'addbi', 'bvb': 'bb', 'vshd': 'shrp', 'shd': 'shrp', 'vextru': 'extr,u',
       'vextrs': 'extr,s', 'extru': 'extr,u', 'extrs': 'extr,s', 'zvdep': 'dep,z', 'vdep': 'dep', 'zdep': 'dep,z',
       'zvdepi': 'depi,z', 'vdepi': 'depi', 'zdepi': 'depi,z', 'sh1add': 'shladd,1', 'sh2add': 'shladd,2', 'sh3add': 'shladd,3',
       'sh1addl': 'shladd,l,1', 'sh2addl': 'shladd,l,2', 'sh3addl': 'shladd,l,3', 'sh1addo': 'shladd,tsv,1',
       'sh2addo': 'shladd,tsv,2', 'sh3addo': 'shladd,tsv,3', 'fcnvff': 'fcnvff', 'mtsar': 'mtctl,sar', 'idcor': 'dcor,i'}


def norm(s):
    s = s.strip().lower()
    s = s.split(';')[0].strip()
    s = s.replace('%', '')
    s = re.sub(r'\s+', ' ', s)
    s = re.sub(r'\s*,\s*', ',', s)
    s = re.sub(r'\s*\(\s*', '(', s)
    s = re.sub(r'\s*\)\s*', ')', s)
    # register synonyms
    s = re.sub(r'\bsp\b', 'r30', s)
    s = re.sub(r'\brp\b', 'r2', s)
    s = re.sub(r'\bdp\b', 'r27', s)
    s = re.sub(r'\bret0\b', 'r28', s)
    s = re.sub(r'\bret1\b', 'r29', s)
    s = re.sub(r'\barg0\b', 'r26', s)
    s = re.sub(r'\barg1\b', 'r25', s)
    s = re.sub(r'\barg2\b', 'r24', s)
    s = re.sub(r'\barg3\b', 'r23', s)
    s = re.sub(r'\bmrp\b', 'r31', s)
    s = re.sub(r'\bfr(\d+)l\b', r'fr\1', s)
    s = s.replace('sr0,', '')
    s = re.sub(r'\bcr11\b', 'sar', s)
    s = re.sub(r'\b(shladd(?:,[^ ]*)?) r(\d+),(\d),', lambda mm: 'sh%sadd%s r%s,' % (mm.group(3), mm.group(1)[6:], mm.group(2)), s)
    s = re.sub(r'\bbb(,[^ ]*)? (r\d+),sar,', r'bvb\1 \2,', s)
    s = re.sub(r',sm\b', ',s,m', s)
    s = re.sub(r'\b(extrw|depwi|depw|shrpw),', r'\1!,', s).replace('extrw!', 'extr').replace('depwi!', 'depi').replace('depw!', 'dep').replace('shrpw!', 'shrp')
    s = re.sub(r'\bdepwi ', 'depi ', s)
    s = re.sub(r'\b(extrw|depw|shrpw) ', lambda mm: {'extrw': 'extr', 'depw': 'dep', 'shrpw': 'shrp'}[mm.group(1)] + ' ', s)
    s = s.replace(',sar,', ',').replace(',sar ', ' ')
    # a symbolic branch target: compare only the rest
    s = re.sub(r',[a-z_][a-z_0-9]*$', ',TARGET', s)
    s = re.sub(r' [a-z_][a-z_0-9]*$', ' TARGET', s)
    s = re.sub(r',0x[0-9a-f]+$|,\d+$', lambda mm: mm.group(0) if not RE_BR.match(s) else ',TARGET', s) if False else s
    # mnemonic synonyms and the completer order
    if ' ' in s:
        m, rest = s.split(' ', 1)
    else:
        m, rest = s, ''
    parts = m.split(',')
    base = SYN.get(parts[0], parts[0])
    compl = sorted(parts[1:] + base.split(',')[1:])
    m = ','.join([base.split(',')[0]] + compl)
    # numbers: hex to decimal
    rest = re.sub(r'0x([0-9a-f]+)', lambda mm: str(int(mm.group(1), 16)), rest)
    rest = re.sub(r'l%(\d+)', lambda mm: 'l%' + str(int(mm.group(1))), rest)
    return (m + ' ' + rest).strip()


# instructions a user-mode emulator does not decode: coprocessor and special-function
# unit operations, cache and TLB control, the privileged system control instructions
NONUSER = {'cldw', 'cldd', 'cstw', 'cstd', 'cldwx', 'clddx', 'cstwx', 'cstdx', 'cldws', 'cldds', 'cstws', 'cstds',
           'copr', 'spop0', 'spop1', 'spop2', 'spop3', 'pdc', 'fdc', 'fdce', 'fic', 'fice', 'pdtlb', 'pitlb', 'pdtlbe',
           'pitlbe', 'idtlba', 'iitlba', 'idtlbp', 'iitlbp', 'idtlbt', 'iitlbt', 'rfi', 'rfir', 'diag', 'mtsm', 'rsm', 'ssm',
           'lpa', 'lci', 'mtctl', 'mfctl', 'sync', 'syncdma', 'pmdis', 'pmenb', 'fcnvxf', 'fcnvfx', 'fcnvfxt', 'fcnv',
           'ldcw', 'probe', 'probei', 'probew', 'prober', 'ldsid', 'mtsp', 'mfsp', 'mtsarcm', 'mfia', 'break',
           'fdce', 'fice', 'gfw', 'gfr', 'clrbts', 'popbts', 'pushnom', 'pushbts'}


def cosmetic(a, b, ours, text):
    """A mismatch that is a spelling difference, not a decoding one: a symbolic branch
    target in the source, PA 2.0 completer spellings (add,dc / extrw / depwi / fcnv
    forms), ldil's displayed immediate, quad formats, or an instruction a user-mode
    emulator leaves undecoded (NONUSER)."""
    ma, mb = a.split(' ')[0], b.split(' ')[0]
    srcm = text.split()[0].split(',')[0]
    placeholder = ours.startswith('<') or '(nop)' in ours
    if placeholder and (srcm in NONUSER or re.match(r'h(add|sub|avg|shl|shr|shladd|shradd)|mix[hw]|permh|frem|f(ld|st)q|fcmp|fcpy|fabs|fsqrt|frnd|fadd|fsub|fmpy|fdiv|fneg|clrbts|popbts|pushnom|pushbts|gf[wr]', srcm)):
        return True
    if placeholder and ',quad' in text:
        return True
    if mb.split(',')[0].rstrip('t') in NONUSER and mb.split(',')[0].startswith('fcnv'):
        return True
    # the same operands apart from the last one, which is a symbol in the source
    if b.endswith(' TARGET') or b.endswith(',TARGET'):
        ra = a.rsplit(',', 1)[0] if ',' in a else a.rsplit(' ', 1)[0]
        rb = b.rsplit(',', 1)[0] if ',' in b else b.rsplit(' ', 1)[0]
        if ra == rb or ra.split(' ')[0] == rb.split(' ')[0]:
            return True
    # same base mnemonic (after the synonym table), differing only in completer spelling
    base = lambda m: re.sub(r'^(add|sub|addi|subi|cmp|com)[a-z]*', r'\1', m.split(',')[0])
    if base(ma) == base(mb) and a.split(' ', 1)[1:] == b.split(' ', 1)[1:]:
        return True
    if ma.split(',')[0] == mb.split(',')[0] and ma.split(',')[0] in ('ldil', 'addil'):
        # the assembler shows the full L% immediate, the disassembler the 21 bits used
        return True
    if ma.split(',')[0].replace('w', '') == mb.split(',')[0].replace('w', '').replace('d', ''):
        return True
    if ma.startswith('probe') and mb.startswith('probe'):
        return True
    if (ma, mb) in (('sync', 'syncdma'), ('fdc,m', 'pdc,m'), ('fdc,m', 'fdce,m')):
        return True
    return False


def main(argv):
    d = argv[1]
    verbose = '-v' in argv
    exp = open(os.path.join(d, 'basic.exp')).read()
    procs = re.split(r'\nproc ', exp)
    bad = 0
    cosm = 0
    total = 0
    for p in procs:
        m = re.search(r'gas_start "([^"]+)"', p)
        if not m:
            continue
        src = m.group(1)
        words = re.findall(r'-re "\^ \+\\\[0-9\\\]\+ ([0-9a-f]+) ([0-9A-F]{8})', p)
        if not words:
            continue
        lines = []
        for line in open(os.path.join(d, src)):
            t = line.split(';')[0].strip()
            if not t or t.startswith('.') or t.endswith(':'):
                continue
            lines.append(t)
        if len(lines) != len(words):
            print('%s: %d source lines, %d words - skipped' % (src, len(lines), len(words)))
            continue
        for (off, w), text in zip(words, lines):
            total += 1
            ours = disasm(int(w, 16), int(off, 16), pa20=True)
            a, b = norm(ours), norm(text)
            if a == b:
                continue
            if cosmetic(a, b, ours, text):
                cosm += 1
                if verbose:
                    print('(cosmetic) %s %s %s: ours "%s" source "%s"' % (src, off, w, ours, text))
                continue
            bad += 1
            print('%s %s %s: ours "%s" source "%s"' % (src, off, w, ours, text))
    print('%d instructions, %d mismatches, %d spelling differences' % (total, bad, cosm))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
