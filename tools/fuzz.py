#!/usr/bin/env python3
"""Differential CPU fuzzer: random instruction sequences on random state, run on the
Python reference CPU (hpuxemu/cpu.py) and the Rust CPU (rust/hppa32-jit), with every
visible difference reported.

    python3 tools/fuzz.py [-n COUNT] [-s SEED] [-j JOBS] [--len MIN-MAX] [--pa20] [--jit N]
                          [--write FILE] [--check FILE] [--only OPS] [-v]

Each sequence is 2-7 random instruction words that decode to user-level instructions
(no system control, no break), placed at CODE_BASE inside a page of nops, with the
general and floating-point registers, sar and the carry bits random and a data page
whose contents are random. Both CPUs run the sequence for at most 12 instructions
(loops stop there); then the exit (count, fault, trap, ...) and the complete state
(registers, psw bits, iaoq, data page) must agree.

`--write FILE` writes the sequences and the Python CPU's results as test vectors (JSON
lines; the format is described in docs/CPU.md) for checking another implementation
(QEMU, a JIT); `--check FILE` runs such a file against the Rust CPU.

The host carry/borrow and nullify state, the PA-RISC default NaN and the rounding of
float-to-integer conversions are where implementations usually disagree; see docs/CPU.md
for the choices made here (QEMU's)."""

import json
import multiprocessing
import os
import random
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from hpuxemu.cpu import Cpu, Memory, M32, M64  # noqa: E402
from hpuxemu.decode import decode  # noqa: E402
from hpuxemu.disasm import disasm  # noqa: E402
from hpuxemu.rustcpu import RustCpu  # noqa: E402

CODE_PAGE = 0x1000
CODE_BASE = 0x1800
DATA_BASE = 0x40000000
DATA_SIZE = 0x10000
NOP = 0x34000000          # ldo 0(r0),r0
MAX_STEPS = 12

# opcodes a user program can contain (top 6 bits); the rest of the word is random
USER_OPS = [0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1e, 0x1f,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e]

# major opcodes grouped by instruction family; a family is picked uniformly, then a major
# in it, then the rest of the word at random (ftest is built from fields: see word())
FAMILIES = [[0x02], [0x03], [0x08], [0x09, 0x0b, 0x14, 0x16, 0x17, 0x1c, 0x1e, 0x1f], [0x0a], [0x0c], [0x0e],
            [0x0d], [0x10, 0x11, 0x12, 0x13], [0x18, 0x19, 0x1a, 0x1b], [0x20, 0x21, 0x22, 0x23], [0x24], [0x25],
            [0x26], [0x28, 0x29, 0x2a, 0x2b], [0x2c, 0x2d], [0x2e], [0x30, 0x31], [0x32, 0x33], [0x34], [0x35],
            [0x3a], ['ftest']]

# instruction classes not fuzzed: system state, undefined encodings, register-indirect
# branches (targets would leave the code page)
SKIP_OPS = {'illegal', 'priv', 'break', 'bv', 'bve', 'be', 'b_gate', 'blr', 'mtctl', 'mtsarcm',
            'mfctl', 'probe', 'fid', 'sync', 'mfia', 'nop_addrx'}


class Gen:
    def __init__(self, rng, pa20=False, only=None):
        self.rng = rng
        self.pa20 = pa20
        self.only = only
        self.counts = {}

    def median(self):
        v = sorted(self.counts.values())
        return v[len(v) // 2]

    def word(self):
        """One random word that decodes to a fuzzable instruction whose branch, if any,
        stays inside the code page."""
        rng = self.rng
        while True:
            op = rng.choice(rng.choice(FAMILIES))
            if op == 'ftest':
                w = (0x0c << 26) | (rng.getrandbits(3) << 13) | (0x10 << 6) | (1 << 5) | rng.getrandbits(5)
            elif op in (0x0c, 0x0e):
                # the FP formats have many must-be-zero bits: build them from fields
                ext = rng.getrandbits(4) if op == 0x0e else 0
                r2 = rng.getrandbits(5) if rng.random() < 0.5 else 0   # r2 = 0 in the unary class
                w = (op << 26) | (rng.getrandbits(5) << 21) | (r2 << 16) | (rng.getrandbits(3) << 13) \
                    | (rng.getrandbits(2) << 11) | (rng.getrandbits(2) << 9) | (ext << 5) | rng.getrandbits(5)
                if rng.random() < 0.1:
                    w = (w & ~0x3FFFFF) | rng.getrandbits(22)   # and sometimes anything
            else:
                w = (op << 26) | rng.getrandbits(26)
            i = decode(w, self.pa20)
            if i.op in SKIP_OPS:
                continue
            if self.only and i.op not in self.only:
                continue
            disp = i.fields.get('disp')
            if i.op in ('bl', 'cmpb', 'cmpbi', 'addb', 'addbi', 'bb_sar', 'bb_imm', 'movb', 'movbi'):
                if disp is None or not (-0x700 <= disp <= 0x700):
                    continue
            if i.op == 'ldc' and not self.pa20 and i.fields.get('size', 2) != 2:
                continue
            # keep the classes balanced: a common class is taken only while it is not
            # far ahead of the rarest one seen (with a retry limit)
            tries = tries + 1 if 'tries' in locals() else 1
            c = self.counts.get(i.op, 0)
            if tries < 100 and self.counts and c > self.median() + 50:
                continue
            self.counts[i.op] = c + 1
            return w

    def state(self, n):
        """Random registers: a mix of data addresses, small values, 32-bit and 64-bit."""
        rng = self.rng
        gr = [0]
        for r in range(1, 32):
            k = rng.random()
            if k < 0.35:
                gr.append((DATA_BASE + 0x2000 + rng.randrange(0, DATA_SIZE - 0x4000)) & ~rng.choice([0, 0, 1, 3, 7]))
            elif k < 0.55:
                gr.append(rng.randrange(0, 64))
            elif k < 0.65:
                gr.append((-rng.randrange(0, 64)) & M32)
            elif k < 0.85:
                gr.append(rng.getrandbits(32))
            elif k < 0.95:
                gr.append(rng.getrandbits(64))
            else:
                gr.append(rng.choice([0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000]))
        fr = []
        for r in range(32):
            k = rng.random()
            if k < 0.3:
                fr.append(struct.unpack('>Q', struct.pack('>d', rng.uniform(-1e6, 1e6)))[0])
            elif k < 0.5:
                hi = struct.unpack('>I', struct.pack('>f', rng.uniform(-1e6, 1e6)))[0]
                lo = struct.unpack('>I', struct.pack('>f', rng.uniform(-1e3, 1e3)))[0]
                fr.append((hi << 32) | lo)
            elif k < 0.6:
                fr.append(rng.choice([0, 0x8000000000000000, 0x7FF0000000000000, 0xFFF0000000000000,
                                      0x7FF8000000000000, 0x7FF4000000000000, 0x7F8000007F800000,
                                      0x7FC000007FA00000, 0x0000000100000001, 0x7FFFFFFFFFFFFFFF,
                                      0x4330000000000000, 0xC330000000000000, 0x41EFFFFFFFE00000]))
            elif k < 0.75:
                fr.append(rng.getrandbits(32) << 32 | rng.getrandbits(32))
            elif k < 0.9:
                fr.append(rng.randrange(0, 1 << 20) << 32 | rng.randrange(0, 1 << 20))
            else:
                fr.append(rng.getrandbits(64))
        fr[0] = (rng.getrandbits(32) & 0x0FFFFFFF) << 32   # status: flags, no exceptions
        return {
            'gr': gr, 'fr': fr,
            'sar': rng.randrange(0, 64 if self.pa20 else 32),
            'psw_cb': rng.choice([0, rng.getrandbits(64), 0x100000000, 0xFFFFFFFFFFFFFFFF]),
            'psw_cb_msb': rng.getrandbits(1),
            'psw_v': rng.choice([0, rng.getrandbits(32), 0x80000000]),
            'words': [self.word() for _ in range(n)],
            'data_seed': rng.getrandbits(32),
        }


def data_bytes(seed):
    """The data page contents from a 32-bit seed: block i (32 bytes) is
    SHA-256 of the 8 bytes seed, i (both 32-bit big-endian). Defined here so that a
    test-vector file can be replayed by another implementation."""
    import hashlib
    return b''.join(hashlib.sha256(struct.pack('>II', seed, i)).digest() for i in range(DATA_SIZE // 32))


def setup(cpu, st, pa20):
    mem = cpu.mem
    mem.map(CODE_PAGE, 0x1000, 7)
    mem.write(CODE_PAGE, struct.pack('>%dI' % (0x1000 // 4), *([NOP] * (0x1000 // 4))))
    mem.write(CODE_BASE, struct.pack('>%dI' % len(st['words']), *st['words']))
    mem.protect(CODE_PAGE, 0x1000, 5)
    mem.map(DATA_BASE, DATA_SIZE, 3)
    if 'data' not in st:
        st['data'] = data_bytes(st['data_seed'])
    mem.write(DATA_BASE, st['data'])
    for r in range(1, 32):
        cpu.gr[r] = st['gr'][r]
    for r in range(32):
        cpu.fr[r] = st['fr'][r]
    cpu.sar = st['sar']
    cpu.psw_cb = st['psw_cb']
    cpu.psw_cb_msb = st['psw_cb_msb']
    cpu.psw_v = st['psw_v']
    cpu.set_pc(CODE_BASE)


def snapshot(cpu, exit_):
    return {
        'exit': list(exit_),
        'gr': [cpu.gr[r] & M64 for r in range(32)],
        'fr': [cpu.fr[r] & M64 for r in range(32)],
        'sar': cpu.sar, 'psw_cb': cpu.psw_cb & M64, 'psw_cb_msb': cpu.psw_cb_msb & 1,
        'psw_v': cpu.psw_v & M64, 'psw_n': bool(cpu.psw_n),
        'iaoq_f': cpu.iaoq_f & M32, 'iaoq_b': cpu.iaoq_b & M32,
        'data': cpu.mem.read(DATA_BASE, DATA_SIZE),
    }


def run_py(st, pa20):
    cpu = Cpu(Memory(), pa20)
    setup(cpu, st, pa20)
    e = cpu.run(MAX_STEPS)
    return snapshot(cpu, e)


_rust = None


def run_rust(st, pa20):
    global _rust
    if _rust is None:
        _rust = RustCpu(pa20)
    cpu = _rust
    cpu.mem.unmap(CODE_PAGE, 0x1000)
    cpu.mem.unmap(DATA_BASE, DATA_SIZE)
    cpu.psw_n = False
    setup(cpu, st, pa20)
    e = cpu.run(MAX_STEPS)
    return snapshot(cpu, e)


def diff(a, b):
    out = []
    for k in ('exit', 'sar', 'psw_cb', 'psw_cb_msb', 'psw_v', 'psw_n', 'iaoq_f', 'iaoq_b'):
        if a[k] != b[k]:
            out.append('%s: %s vs %s' % (k, fmt(a[k]), fmt(b[k])))
    for k in ('gr', 'fr'):
        for r in range(32):
            if a[k][r] != b[k][r]:
                out.append('%s%d: %016x vs %016x' % (k, r, a[k][r], b[k][r]))
    if a['data'] != b['data']:
        for i in range(0, DATA_SIZE, 8):
            if a['data'][i:i + 8] != b['data'][i:i + 8]:
                out.append('mem %08x: %s vs %s' % (DATA_BASE + i, a['data'][i:i + 8].hex(), b['data'][i:i + 8].hex()))
                if len(out) > 40:
                    break
    return out


def fmt(v):
    if isinstance(v, list):
        return '(' + ', '.join(hex(x) if isinstance(x, int) else str(x) for x in v) + ')'
    if isinstance(v, bool):
        return str(v)
    return hex(v)


def describe(st, pa20):
    lines = []
    for k, w in enumerate(st['words']):
        lines.append('  %08x: %08x  %s' % (CODE_BASE + 4 * k, w, disasm(w, CODE_BASE + 4 * k, pa20)))
    lines.append('  sar=%d cb=%x cb_msb=%d v=%x' % (st['sar'], st['psw_cb'], st['psw_cb_msb'], st['psw_v']))
    lines.append('  ' + ' '.join('r%d=%x' % (r, st['gr'][r]) for r in range(1, 32)))
    lines.append('  ' + ' '.join('f%d=%016x' % (r, st['fr'][r]) for r in range(32)))
    return '\n'.join(lines)


def worker(args):
    seed, count, lmin, lmax, pa20, only, write = args
    rng = random.Random(seed)
    gen = Gen(rng, pa20, only)
    fails = []
    vectors = []
    n_ok = 0
    for k in range(count):
        st = gen.state(rng.randint(lmin, lmax))
        a = run_py(st, pa20)
        b = run_rust(st, pa20)
        d = diff(a, b)
        if d:
            fails.append((seed, k, st, d))
            if len(fails) >= 20:
                break
        else:
            n_ok += 1
        if write:
            vectors.append(vector(st, a, pa20))
    return n_ok, fails, vectors


def vector(st, res, pa20):
    return {
        'pa20': pa20, 'code': CODE_BASE, 'words': ['%08x' % w for w in st['words']],
        'max_steps': MAX_STEPS,
        'in': {'gr': ['%x' % v for v in st['gr']], 'fr': ['%016x' % v for v in st['fr']],
               'sar': st['sar'], 'psw_cb': '%x' % st['psw_cb'], 'psw_cb_msb': st['psw_cb_msb'],
               'psw_v': '%x' % st['psw_v'], 'data_seed': st['data_seed']},
        'out': {'exit': [x if not isinstance(x, int) else '%x' % x for x in res['exit']],
                'gr': ['%x' % v for v in res['gr']], 'fr': ['%016x' % v for v in res['fr']],
                'sar': res['sar'], 'psw_cb': '%x' % res['psw_cb'], 'psw_cb_msb': res['psw_cb_msb'],
                'psw_v': '%x' % res['psw_v'], 'psw_n': res['psw_n'],
                'iaoq_f': '%x' % res['iaoq_f'], 'iaoq_b': '%x' % res['iaoq_b'],
                'data_diff': [['%x' % (DATA_BASE + i), res['data'][i:i + 8].hex()] for i in range(0, DATA_SIZE, 8)
                              if res['data'][i:i + 8] != st['data'][i:i + 8]]},
    }


def unvector(v):
    st = {'words': [int(w, 16) for w in v['words']],
          'gr': [int(x, 16) for x in v['in']['gr']], 'fr': [int(x, 16) for x in v['in']['fr']],
          'sar': v['in']['sar'], 'psw_cb': int(v['in']['psw_cb'], 16), 'psw_cb_msb': v['in']['psw_cb_msb'],
          'psw_v': int(v['in']['psw_v'], 16), 'data_seed': v['in']['data_seed']}
    st['data'] = data_bytes(st['data_seed'])
    o = v['out']
    data = bytearray(st['data'])
    for addr, h in o['data_diff']:
        i = int(addr, 16) - DATA_BASE
        data[i:i + 8] = bytes.fromhex(h)
    res = {'exit': [x if not isinstance(x, str) or x in ('count', 'fault', 'trap', 'overflow', 'syscall', 'break', 'illegal', 'priv', 'unaligned', 'hook') else int(x, 16) for x in o['exit']],
           'gr': [int(x, 16) for x in o['gr']], 'fr': [int(x, 16) for x in o['fr']],
           'sar': o['sar'], 'psw_cb': int(o['psw_cb'], 16), 'psw_cb_msb': o['psw_cb_msb'],
           'psw_v': int(o['psw_v'], 16), 'psw_n': o['psw_n'],
           'iaoq_f': int(o['iaoq_f'], 16), 'iaoq_b': int(o['iaoq_b'], 16),
           'data': bytes(data)}
    return st, res, v['pa20']


def check(path):
    bad = n = 0
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            st, exp, pa20 = unvector(json.loads(line))
            got = run_rust(st, pa20)
            d = diff(exp, got)
            n += 1
            if d:
                bad += 1
                if bad <= 20:
                    print('vector %d:\n%s\n  ' % (n, describe(st, pa20)) + '\n  '.join(d))
    print('%d vectors, %d failures' % (n, bad))
    return 1 if bad else 0


def main(argv):
    count, seed, jobs, lmin, lmax, pa20, write, chk, only, verbose = 10000, int(time.time()), os.cpu_count() or 1, 2, 7, False, None, None, None, False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-n':
            i += 1
            count = int(argv[i])
        elif a == '-s':
            i += 1
            seed = int(argv[i])
        elif a == '-j':
            i += 1
            jobs = int(argv[i])
        elif a == '--len':
            i += 1
            lmin, lmax = map(int, argv[i].split('-'))
        elif a == '--jit':
            # the Rust CPU with its JIT: blocks compiled at once, at most N instructions
            # (each sequence's first block then runs compiled, the rest interpreted)
            i += 1
            os.environ['HPUXEMU_JIT'] = '0,%s' % argv[i]
        elif a == '--pa20':
            pa20 = True
        elif a == '--write':
            i += 1
            write = argv[i]
        elif a == '--check':
            i += 1
            chk = argv[i]
        elif a == '--only':
            i += 1
            only = set(argv[i].split(','))
        elif a == '-v':
            verbose = True
        else:
            print(__doc__)
            return 2
        i += 1
    if chk:
        return check(chk)
    t0 = time.time()
    per = max(1, count // jobs)
    tasks = [(seed + j, per, lmin, lmax, pa20, only, write is not None) for j in range(jobs)]
    if jobs > 1:
        with multiprocessing.Pool(jobs) as pool:
            results = pool.map(worker, tasks)
    else:
        results = [worker(t) for t in tasks]
    n_ok = sum(r[0] for r in results)
    fails = [f for r in results for f in r[1]]
    if write:
        with open(write, 'w') as f:
            for r in results:
                for v in r[2]:
                    f.write(json.dumps(v, separators=(',', ':')) + '\n')
    dt = time.time() - t0
    for seed_, k, st, d in fails[:20]:
        print('seed %d sequence %d:\n%s\n  ' % (seed_, k, describe(st, pa20)) + '\n  '.join(d[:40]))
    print('%d sequences agree, %d differ, seed %d, %.1f s (%.0f/s)' % (n_ok, len(fails), seed, dt, (n_ok + len(fails)) / dt))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
