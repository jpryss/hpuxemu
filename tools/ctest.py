#!/usr/bin/env python3
"""Differential compiler test: generate random K&R C programs, compile and run them
with HP's bundled cc inside the emulator and with the host's C compiler, and compare
their output. The programs do unsigned integer arithmetic (wraps, no undefined
behaviour), IEEE double arithmetic with + - * / sqrt (identical everywhere), string
functions, structs, recursion and switch; every function prints a checksum, so any
difference in the CPU, the C library or the emulator's I/O shows up as a diff.

    python3 tools/ctest.py [-r ROOT] [-n PROGRAMS] [-s SEED] [--lines N] [-k]

-k keeps the generated sources in the root's /tmp (ctest_N.c) on failure."""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from emucmd import emulator, default_cpu      # noqa: E402


class Gen:
    def __init__(self, rnd, nfuncs):
        self.r = rnd
        self.nfuncs = nfuncs
        self.out = []

    def expr(self, vars, depth=0):
        r = self.r
        if depth > 3 or r.random() < 0.3:
            k = r.random()
            if k < 0.5:
                return r.choice(vars)
            if k < 0.7:
                return str(r.randint(0, 1000))
            if k < 0.85:
                return 'g[%d]' % r.randint(0, 255)
            return '((unsigned) %d)' % r.randint(0, 0x7FFFFFFF)
        op = r.choice(['+', '-', '*', '/', '%', '<<', '>>', '&', '|', '^', '<', '==', '>'])
        a, b = self.expr(vars, depth + 1), self.expr(vars, depth + 1)
        if op in ('/', '%'):
            return '(%s %s ((%s) | (unsigned) 1))' % (a, op, b)
        if op in ('<<', '>>'):
            # the count is cast to int: HP C A.10.32 (the compiler a 10.20 system has
            # after installation) makes `int >> unsigned` an unsigned shift, the old
            # PCC rule, where ANSI C and gcc keep the left operand's type
            return '(%s %s (int) ((%s) & 31))' % (a, op, b)
        return '(%s %s %s)' % (a, op, b)

    def dexpr(self, vars, depth=0):
        r = self.r
        if depth > 3 or r.random() < 0.3:
            k = r.random()
            if k < 0.6:
                return r.choice(vars)
            if k < 0.8:
                return '%.6f' % r.uniform(-1000, 1000)
            return 'h[%d]' % r.randint(0, 63)
        k = r.random()
        if k < 0.1:
            return 'sqrt(fabs(%s))' % self.dexpr(vars, depth + 1)
        op = r.choice(['+', '-', '*', '/'])
        a, b = self.dexpr(vars, depth + 1), self.dexpr(vars, depth + 1)
        if op == '/':
            return '(%s / (fabs(%s) + 1.0))' % (a, b)
        return '(%s %s %s)' % (a, op, b)

    def func(self, i):
        r = self.r
        o = self.out
        o.append('unsigned f%d(a, b, c)\nunsigned a, b, c;\n{' % i)
        o.append('    unsigned x, y, z, s; int k; double p, q; char buf[64]; struct rec t;')
        o.append('    s = 0; x = a; y = b; z = c; p = (double) a / 7.0; q = (double) b - 3.5;')
        for _ in range(r.randint(6, 16)):
            kind = r.random()
            v = r.choice(['x', 'y', 'z'])
            if kind < 0.35:
                o.append('    %s = %s;' % (v, self.expr(['x', 'y', 'z', 'a', 'b', 'c'])))
            elif kind < 0.5:
                o.append('    for (k = 0; k < %d; k++) { %s = %s; s += %s; }' % (r.randint(1, 20), v, self.expr(['x', 'y', 'z', '(unsigned) k']), v))
            elif kind < 0.62:
                o.append('    if (%s) %s = %s; else %s = %s;' % (self.expr(['x', 'y', 'z']), v, self.expr(['x', 'y']), v, self.expr(['y', 'z'])))
            elif kind < 0.74:
                dv = r.choice(['p', 'q'])
                o.append('    %s = %s;' % (dv, self.dexpr(['p', 'q', '(double) x', '(double) (y & 0xffff)'])))
                o.append('    s += dbits(%s);' % dv)
            elif kind < 0.82:
                o.append('    switch (%s & 7) { case 0: s += 1; break; case 1: s ^= x; break; case 3: s += y << 3; break; case 5: s -= z; break; default: s += 7; }' % v)
            elif kind < 0.9:
                o.append('    sprintf(buf, "%%u-%%x-%%d", %s, %s, (int) (%s & 0x7fff)); s += strlen(buf) + buf[1] + (unsigned) buf[strlen(buf) - 1];' % (v, r.choice(['x', 'y', 'z']), v))
            elif kind < 0.95:
                o.append('    t.a = %s; t.b = (short) %s; t.c = (char) %s; t = copyrec(t); s += t.a + t.b + t.c;' % (v, 'y', 'z'))
            else:
                o.append('    s += fib(%d + (int) (%s & 3));' % (r.randint(3, 12), v))
            o.append('    s = s * (unsigned) 16777619 ^ %s;' % v)
        o.append('    g[%d] = s;' % r.randint(0, 255))
        o.append('    h[%d] = p + q;' % r.randint(0, 63))
        o.append('    return s;\n}\n')

    def program(self):
        o = self.out
        o.append('#include <stdio.h>\n#include <string.h>\n#include <math.h>\n')
        o.append('unsigned g[256]; double h[64];')
        o.append('struct rec { unsigned a; short b; char c; };')
        o.append('struct rec copyrec(r) struct rec r; { struct rec s; s = r; s.a += 1; return s; }')
        o.append('unsigned fib(n) int n; { return n < 2 ? (unsigned) n : fib(n - 1) + fib(n - 2); }')
        o.append('unsigned dbits(d) double d; { union { double d; unsigned w[2]; } u; u.d = d; return u.w[0] + u.w[1] + (u.w[0] ^ u.w[1]) * (unsigned) 3; }')
        for i in range(self.nfuncs):
            self.func(i)
        o.append('int main()\n{\n    unsigned i, s, t;\n    s = 0;')
        o.append('    for (i = 0; i < 256; i++) g[i] = i * (unsigned) 0x9E3779B1;')
        o.append('    for (i = 0; i < 64; i++) h[i] = (double) i * 1.25 - 20.0;')
        for i in range(self.nfuncs):
            o.append('    t = f%d(s + (unsigned) %d, g[%d], (unsigned) %d); s = s * (unsigned) 31 + t; printf("f%d %%u\\n", t);' % (i, self.r.randint(0, 9999), self.r.randint(0, 255), self.r.randint(0, 99999), i))
        o.append('    for (i = 0; i < 256; i++) s = s * (unsigned) 31 + g[i];')
        o.append('    for (i = 0; i < 64; i++) s = s * (unsigned) 31 + dbits(h[i]);')
        o.append('    printf("total %u\\n", s);\n    return 0;\n}')
        return '\n'.join(o) + '\n'


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main(argv):
    root = os.environ.get('HPUX_ROOT')
    n, seed, lines, keep = 3, 1, 3000, False
    i = 1
    while i < len(argv):
        if argv[i] == '-r':
            i += 1
            root = argv[i]
        elif argv[i] == '-n':
            i += 1
            n = int(argv[i])
        elif argv[i] == '-s':
            i += 1
            seed = int(argv[i])
        elif argv[i] == '--lines':
            i += 1
            lines = int(argv[i])
        elif argv[i] == '-k':
            keep = True
        i += 1
    if not root:
        sys.path.insert(0, REPO)
        from hpuxemu import rootdir
        root = rootdir.default_root()
    env = dict(os.environ, HPUX_ROOT=root)
    emu = emulator()
    hostcc = 'cc' if run(['which', 'cc']).returncode == 0 else 'gcc'
    ok = True
    for p in range(n):
        rnd = random.Random(seed + p)
        src = Gen(rnd, max(1, lines // 20)).program()
        name = 'ctest_%d' % p
        gsrc = os.path.join(root, 'tmp', name + '.c')
        with open(gsrc, 'w') as f:
            f.write(src)
        hbin = '/tmp/hpuxemu_%s_host' % name
        r = run([hostcc, '-O0', '-ffp-contract=off', '-fwrapv', '-w', '-o', hbin, gsrc, '-lm'])
        if r.returncode:
            print('%s: host compiler failed: %s' % (name, r.stderr[-400:]))
            ok = False
            continue
        host = run([hbin]).stdout
        r = run(emu + ['/usr/bin/sh', '-c', 'cc -o /tmp/%s /tmp/%s.c -lm && /tmp/%s' % (name, name, name)], cwd=REPO, env=env)
        emuout = r.stdout
        if r.returncode:
            print('%s: FAILED in the emulator (rc %d): %s' % (name, r.returncode, (r.stderr or r.stdout)[-600:]))
            ok = False
            continue
        if host == emuout:
            print('%s: ok (%d lines of C, %d checksums agree)' % (name, src.count('\n'), host.count('\n')))
            if not keep:
                os.unlink(gsrc)
        else:
            diffs = [(a, b) for a, b in zip(host.splitlines(), emuout.splitlines()) if a != b]
            print('%s: DIFFER in %d of %d lines; first: host %r emulator %r (source kept: %s)' % (name, len(diffs), host.count('\n'), diffs[0][0] if diffs else '', diffs[0][1] if diffs else '', gsrc))
            ok = False
        try:
            os.unlink(hbin)
        except OSError:
            pass
    print('ctest: %s' % ('ok' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
