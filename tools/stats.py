#!/usr/bin/env python3
"""stats.py - where the time went, from HPUXEMU_STATS records.

    HPUXEMU_STATS=/tmp/run.jsonl python3 -m hpuxemu.emu ...     (every process appends)
    python3 tools/stats.py /tmp/run.jsonl [--dld ROOT/usr/lib/dld.sl]

Each program image (a start, exec or fork, until it exits or execs) writes one JSON
line: wall and host CPU seconds, seconds inside the guest CPU (cpu.run), seconds loading
the image, each system call's count and wall seconds (blocking included), and a PC
sample every 500,000 guest instructions by mapped file and offset; a long-lived process
rewrites its line every 20 s. The report sums them: the share of host CPU in the guest
CPU, in system calls and loading; the system calls; the programs; the hot code. With
--dld, samples in the low quadrant-2 pages (dld.sl's text at 0x80000000) are named by
dld.sl's symbols.
"""
import bisect
import collections
import json
import sys


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    dld = argv[argv.index('--dld') + 1] if '--dld' in argv else None
    recs = {}
    for line in open(argv[1]):
        r = json.loads(line)
        recs[r['id']] = r                   # a process's latest line
    R = list(recs.values())

    def tot(k):
        return sum(r[k] for r in R)
    user, sysc = tot('user'), tot('sys')
    print('images: %d (%d exec, %d fork, %d start); exited %d, still running %d' % (
        len(R), sum(r['how'] == 'exec' for r in R), sum(r['how'] == 'fork' for r in R),
        sum(r['how'] == 'start' for r in R), sum(r['end'] == 'exit' for r in R),
        sum(r['end'] == 'running' for r in R)))
    print('host CPU: %.0f s (user %.0f, system %.0f); in the guest CPU %.0f s (%.0f%%), loading images %.0f s' % (
        user + sysc, user, sysc, tot('cpu_run'), 100 * tot('cpu_run') / max(user + sysc, 1e-9), tot('load')))
    calls = collections.defaultdict(lambda: [0, 0.0])
    for r in R:
        for k, (n, w) in r['calls'].items():
            calls[k][0] += n
            calls[k][1] += w
    print('system calls: %d; by wall time (blocking included):' % tot('ncalls'))
    for k, (n, w) in sorted(calls.items(), key=lambda kv: -kv[1][1])[:15]:
        print('   %-16s %9d calls %9.1f s %10.1f us/call' % (k, n, w, 1e6 * w / n))
    byprog = collections.defaultdict(lambda: [0, 0.0, 0.0, 0])
    for r in R:
        b = byprog[r['prog'].split('/')[-1]]
        b[0] += 1
        b[1] += r['user'] + r['sys']
        b[2] += r['cpu_run']
        b[3] += r['ncalls']
    print('programs by host CPU:')
    for k, b in sorted(byprog.items(), key=lambda kv: -kv[1][1])[:15]:
        print('   %-24s x%-4d CPU %7.1f s  guest %7.1f s  calls %d' % (k, b[0], b[1], b[2], b[3]))
    names = None
    if dld:
        sys.path.insert(0, __file__.rsplit('/tools/', 1)[0])
        from hpuxemu import som
        b = som.load(dld)
        syms = sorted((s.value & ~3, s.name) for s in b.symbols if s.value and s.value < 0x40000000)
        vals = [v for v, n in syms]

        def names(a):
            i = bisect.bisect_right(vals, a) - 1
            return syms[i][1] if i >= 0 else '?'
    where = collections.Counter()
    for r in R:
        for k, n in r.get('pcs', {}).items():
            f, off = k.rsplit('+', 1)
            a = int(off, 16)
            if f == '?' and names and 0x80000000 <= a < 0x80040000:
                where['dld.sl:' + names(a - 0x80000000)] += n
            elif f == '?':
                where['? %#x' % (a & ~0xffff)] += n
            else:
                where['%s+%#x' % (f.split('/')[-1], a & ~0xff)] += n
    n = sum(where.values())
    if n:
        print('hot code (%d samples, %.1fG guest instructions):' % (n, n * 0.5e-3))
        for k, c in where.most_common(20):
            print('   %5.1f%%  %s' % (100.0 * c / n, k))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
