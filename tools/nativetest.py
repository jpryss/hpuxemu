#!/usr/bin/env python3
"""nativetest.py - the native routines (rust/hppa32-jit/src/hpux.rs) against the real ones.

    python3 tools/nativetest.py ROOT/usr/lib/dld.sl [N]

For each routine native.py knows by name (`$$remU`, `hash_string`, `strcmp`) and each
native kind that could stand in for it, maps the library into a bare CPU, and N times
from one random state runs the real code (natives off) to its return and the native
routine (on): every general register, SAR, the PC it returns to must agree - except the
registers the routine's callers may not rely on (`clobber`, below: the real routine
writes them on some paths only, or only the carry bits differ). Prints the
fingerprint line for native.py's table when a kind matches. Inputs: dividends and
divisors of every size (powers of two, 2^31 and up, 1); strings of every length at
every alignment, equal and different in their first, middle and last byte.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hpuxemu import native, rustcpu, som   # noqa: E402

BASE = 0x80000000
DATA = 0x40000000
RET = 0x00010000         # a page of zeros: "break 0,0" - the routine's return lands there
LENGTHS = {'$$remU': (0x140, 0x12c), 'hash_string': (0x28, 0x30), 'strcmp': (0x2a8, 0x2b8)}
KINDS = {'$$remU': (native.REMU_A, native.REMU_B), 'hash_string': (native.HASH_A, native.HASH_B, native.HASH_C),
         'strcmp': (native.STRCMP, native.LSTRCMP_A, native.LSTRCMP_B, native.LSTRCMP_C)}
NAMES = {1: 'REMU_A', 2: 'HASH_A', 3: 'STRCMP', 4: 'REMU_B', 5: 'HASH_B', 6: 'HASH_C', 10: 'LSTRCMP_A', 11: 'LSTRCMP_B', 12: 'LSTRCMP_C'}


def setup(data):
    c = rustcpu.RustCpu()
    size = (len(data) + 4095) & ~4095
    c.mem.map(BASE, size, 7, data)
    c.mem.protect(BASE, size, 5)
    c.mem.map(DATA, 0x20000, 3)
    c.mem.write(R19, (R19 + 0x3000).to_bytes(4, 'big') * 0x800)
    c.mem.map(RET, 0x1000, 5)
    return c


def run(c, entry, regs, strings, natives):
    for a, b in strings:
        c.mem.write(a, b)
    for i in range(1, 32):
        c.gr[i] = regs[i]
    c.sar = regs[0]
    c.gr[2] = RET + 0x100
    c.gr[31] = RET + 0x200
    c.set_natives(natives)
    c.set_pc(entry)
    r = c.run(100000)
    return r, [c.gr[i] & 0xFFFFFFFF for i in range(32)], c.sar


def cases(name, rnd):
    if name == '$$remU':
        for _ in range(4000):
            k = rnd.random()
            if k < 0.2:
                d = 1 << rnd.randrange(32)
            elif k < 0.3:
                d = rnd.randrange(0x80000000, 0x100000000)
            elif k < 0.35:
                d = 1
            else:
                d = rnd.randrange(1, 1 << rnd.randrange(1, 32))
            n = rnd.randrange(0, 1 << rnd.choice((8, 16, 31, 32)))
            yield {26: n, 25: d}, []
    else:
        alpha = b'abcXYZ_09$@\x7f\x80\xfe'
        for _ in range(3000):
            ln = rnd.choice((0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 64, rnd.randrange(100)))
            s1 = bytes(rnd.choice(alpha) for _ in range(ln))
            a = DATA + 0x100 + rnd.randrange(8)
            if name == 'hash_string':
                yield {26: a}, [(a, s1 + b'\0' + bytes(rnd.randrange(256) for _ in range(8)))]
                continue
            s2 = bytearray(s1)
            how = rnd.randrange(5)
            if how and ln:
                i = (0, ln // 2, ln - 1, rnd.randrange(ln))[how - 1]
                s2[i] = rnd.choice(alpha)
            if rnd.random() < 0.2:
                s2 = s2[:rnd.randrange(len(s2) + 1)]
            b = DATA + 0x8100 + rnd.randrange(8)
            same = rnd.random() < 0.05
            yield {26: a, 25: a if same else b}, [(a, s1 + b'\0' + bytes(rnd.randrange(1, 256) for _ in range(8))),
                                                  (b, bytes(s2) + b'\0' + bytes(rnd.randrange(1, 256) for _ in range(8)))]


# registers the real routine writes on some paths only, or not at all on the paths a
# native one declines: callers do not rely on them (the PA-RISC millicode and procedure
# conventions); everything else must match exactly
CLOBBER = {native.STRCMP: {1, 19, 20, 21, 22, 23, 24, 25, 26, 29, 31, 'sar'},
           native.LSTRCMP_A: {1, 20, 21, 22, 23, 25, 26, 31, 'sar'},
           native.LSTRCMP_B: {1, 20, 21, 22, 23, 25, 26, 31, 'sar'},
           native.LSTRCMP_C: {1, 20, 21, 22, 23, 25, 26, 31, 'sar'}}
# libc's strcmp reads the locale through r19: a data pointer whose every word points at a
# zero word (not a multibyte code set), set up by run()
R19 = DATA + 0x10000


def sign(v):
    return (v > 0) - 0 if v < 0x80000000 else -1


# findlibsym's chain walk: per kind, the offsets in findlibsym of the loop's head, the
# test it resumes at, the places the real loop goes to on an entry whose name is equal
# (which the native walk leaves to it) and the loop's exit; and how to set a case up
WALKS = {
    native.WALK_A: dict(head=0x90, resume=0x134, stops=(0xf8, 0x158, 0x13c), idx=12, table=7, strs=8, typ=6, want=5),
    native.WALK_B: dict(head=0x94, resume=0x18c, stops=(0x110, 0x1ac, 0x194), idx=16, table=7, strs=8, typ=9, want=4),
    native.WALK_C: dict(head=0x90, resume=0x1e0, stops=(0xb4, 0x1e8), idx=13, table=8, strs=9, typ=12, want=None),
}


def walktest(path, data, offs, n):
    """The native chain walk against the real loop (with the native strcmp, which the
    real loop calls): random chains of entries whose names differ from the wanted one in
    their first, second, third or a later character, or not at all, of every type. The
    real loop is run to each arrival at its test of the next index until an entry it
    does not pass over; the native walk must arrive there once, in the same state:
    every register, SAR and the word the loop keeps r19 in."""
    if 'findlibsym' not in offs:
        return
    foff = offs['findlibsym'][0]
    for (name, length, fp), (kind, head) in native.INSIDE.items():
        if native._fp(data[foff:foff + length]) != fp:
            continue
        w = WALKS[kind]
        fn = BASE + foff
        strcmp = [(BASE + offs['strcmp'][0], native.STRCMP)]
        rnd = random.Random(2)
        c = setup(data)
        ok = tried = declined = 0
        diffs = {}
        table, strs, sp = DATA + 0x1000, DATA + 0x4000, DATA + 0x10000
        alpha = b'abX_9'
        for _ in range(n * 3000):
            want = bytes(rnd.choice(alpha) for _ in range(rnd.choice((0, 1, 2, 3, 4, 9))))
            wtype = rnd.choice((2, 3, 7, 16, 1))
            m = rnd.randrange(1, 7)
            order = rnd.sample(range(1, 40), m)
            mem = [(strs, want + b'\0')]
            so = 16
            for k, e in enumerate(order):
                how = rnd.randrange(7)
                if how == 0:
                    nm = want                       # equal: the real loop takes it
                elif how <= 4 and len(want) >= how:
                    nm = bytearray(want + b'q')
                    nm[how - 1] = ord('Z')
                    nm = bytes(nm)
                else:
                    nm = want[:rnd.randrange(len(want) + 1)] + bytes(rnd.choice(alpha) for _ in range(rnd.randrange(1, 5)))
                    if nm == want:
                        nm += b'x'
                mem.append((strs + so, nm + b'\0'))
                nxt = order[k + 1] if k + 1 < m else 0xFFFFFFFF
                ty = rnd.choice((wtype, 2, 3, 7, 16))
                ent = nxt.to_bytes(4, 'big') + so.to_bytes(4, 'big') + bytes(rnd.randrange(256) for _ in range(8)) + bytes((ty, rnd.randrange(256), 0, 0))
                mem.append((table + 20 * e, ent))
                so += len(nm) + 1
            regs = [rnd.randrange(1 << 32) for _ in range(32)]
            regs[0] &= 31
            first = order[0]
            regs[w['idx']] = first
            regs[w['table']] = table
            regs[w['strs']] = strs
            regs[w['typ']] = wtype
            regs[30] = sp
            r19 = rnd.randrange(1 << 32)
            if kind == native.WALK_A:
                regs[21] = first * 4
                regs[5] = strs
                mem.append((sp - 32, r19.to_bytes(4, 'big')))
            elif kind == native.WALK_B:
                regs[15] = first * 4
                regs[4] = strs
                regs[12] = rnd.choice((16, 16, 16, 2, 7))
                mem.append((sp - 32, r19.to_bytes(4, 'big')))
            else:
                regs[29] = first * 5
                mem.append((sp - 72, strs.to_bytes(4, 'big')))
                mem.append((sp - 32, bytes(4)))

            def state():
                return ([c.gr[i] for i in range(32)], c.sar, c.iaoq_f, c.mem.read(sp - 32, 4))

            def start(natives):
                for a, b in mem:
                    c.mem.write(a, b)
                for i in range(1, 32):
                    c.gr[i] = regs[i]
                c.sar = regs[0]
                c.set_natives(natives)
                c.set_pc(fn + w['head'])

            resume = fn + w['resume']
            stops = [fn + x for x in w['stops']]

            def advance(until_resume):
                """step to the next instruction that executes (is not nullified) at a
                stop, or at the resume point too; what stopped it"""
                for _ in range(20000):
                    pc = c.iaoq_f & ~3
                    if not c.psw_n and (pc in stops or (until_resume and pc == resume)):
                        return pc
                    r = c.run(1)
                    if r[0] != 'count':
                        return r
                return 'endless'

            # the real loop: its state at the last arrival at the test before a stop
            start(strcmp)
            expect = None
            while True:
                r = advance(True)
                if r != resume:
                    break
                expect = state()
                c.run(1)
            real_end = (r, state())
            # the native walk: one arrival there, or none
            start(strcmp + [(fn + w['head'], kind)])
            c.run(1)
            first = c.iaoq_f & ~3
            tried += 1
            if expect is None:
                # no entry to pass over: the walk must have declined (one real instruction)
                if first == fn + w['head'] + 4 and (advance(False), state()) == real_end:
                    declined += 1
                    ok += 1
                else:
                    diffs['declines'] = diffs.get('declines', 0) + 1
                continue
            got = state()
            if first != resume:
                diffs['arrival'] = diffs.get('arrival', 0) + 1
                continue
            d = [i for i in range(32) if got[0][i] != expect[0][i]]
            d += [x for x, k in (('sar', 1), ('pc', 2), ('stack', 3)) if got[k] != expect[k]]
            # and from there both go on to the same stop in the same state
            if (advance(False), state()) != real_end:
                d.append('end')
            if d:
                for x in d:
                    diffs[x] = diffs.get(x, 0) + 1
            else:
                ok += 1
        verdict = 'MATCH' if not diffs else 'differs in %s' % diffs
        print('%-12s len %#5x %s  WALK_%s  %d/%d agree (%d left to the real loop) %s' % (
            'findlibsym', length, fp, 'ABC'[kind - 7], ok, tried, declined, verdict))


def main(argv):
    path = argv[1]
    n = int(argv[2]) if len(argv) > 2 else 1
    data = open(path, 'rb').read()
    offs = native.routines(path)
    walktest(path, data, offs, n)
    for name, foff in sorted((nm, f) for nm, fs in offs.items() for f in fs):
        if name not in LENGTHS:
            continue
        for length in LENGTHS[name]:
            fp = native._fp(data[foff:foff + length])
            for kind in KINDS[name]:
                rnd = random.Random(1)
                c = setup(data)
                entry = BASE + foff
                ok = tried = declined = 0
                diffs = {}
                for _ in range(n):
                    for regs_in, strings in cases(name, rnd):
                        regs = [rnd.randrange(1 << 32) for _ in range(32)]
                        regs[0] &= 31
                        for k, v in regs_in.items():
                            regs[k] = v
                        regs[19] = R19
                        if name == 'strcmp':
                            # now and then the locale's flag says multibyte, at the place
                            # one libc or the other looks: the native routine must decline
                            zero, multi = (R19 + 0x3000).to_bytes(4, 'big'), (R19 + 0x3004).to_bytes(4, 'big')
                            k = tried % 16
                            strings = strings + [(R19 + 0x3004, (532).to_bytes(4, 'big')),
                                                 (R19 + 0x1000 - 1960, multi if k == 3 else zero),
                                                 (R19 + 0x1000 - 1972, multi if k == 7 else zero),
                                                 (R19 + 1812, multi if k == 11 else zero)]
                        r1, g1, s1 = run(c, entry, regs, strings, [])
                        r2, g2, s2 = run(c, entry, regs, strings, [(entry, kind)])
                        tried += 1
                        if r1[0] != 'break' or r2[0] != 'break':
                            # the real routine did not return (it trapped, or left for
                            # code this test has no data for): so must the native one
                            if r1 != r2 or g1 != g2:
                                diffs['end'] = diffs.get('end', 0) + 1
                            continue
                        allow = CLOBBER.get(kind, set())
                        d = [i for i in range(1, 32) if g1[i] != g2[i] and i not in allow]
                        if kind == native.STRCMP and 28 in d and sign(g1[28]) == sign(g2[28]):
                            d.remove(28)   # the real one returns a byte difference or +-1
                        if s1 != s2 and 'sar' not in allow:
                            d.append('sar')
                        if r1 != r2:
                            d.append('return %r %r' % (r1, r2))
                        if d:
                            for x in d:
                                diffs[x] = diffs.get(x, 0) + 1
                        else:
                            ok += 1
                verdict = 'MATCH' if not diffs else 'differs in %s' % diffs
                print('%-12s len %#5x %s  %-7s %d/%d agree %s' % (name, length, fp, NAMES[kind], ok, tried, verdict))
                if not diffs and ok:
                    print("    ('%s', %#x, '%s'): native.%s," % (name, length, fp, NAMES[kind]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
