#!/usr/bin/env python3
"""Run a list of guest commands and report which work: exit status, time, and whether
the output matches between the Python and Rust CPUs (or an expected string).

    python3 tools/sweep.py [-r ROOT] [--cpu rust|python|both|bin|all] [-v] [tools/sweep.txt]

The list file has one command per line (run by /usr/bin/sh -c), `#` comments, and an
optional `=> expected substring` after the command. A line starting with `~` has output
that varies from run to run (pids, dates), so the two CPUs' outputs are not compared."""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from emucmd import emulator, default_cpu      # noqa: E402


def run(cmd, cpu, root, timeout=300):
    env = dict(os.environ)
    if root:
        env['HPUX_ROOT'] = root
    t = time.time()
    try:
        p = subprocess.run(emulator(cpu) + ['/usr/bin/sh', '-c', cmd],
                           cwd=REPO, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr, time.time() - t
    except subprocess.TimeoutExpired as e:
        return 'timeout', e.stdout or b'', e.stderr or b'', time.time() - t


def main(argv):
    root = None
    cpus = [default_cpu()]
    verbose = False
    files = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-r':
            i += 1
            root = argv[i]
        elif a == '--cpu':
            i += 1
            cpus = {'both': ['rust', 'python'], 'all': ['bin', 'rust']}.get(argv[i], [argv[i]])
        elif a == '-v':
            verbose = True
        else:
            files.append(a)
        i += 1
    if not files:
        files = [os.path.join(HERE, 'sweep.txt')]
    cmds = []
    for f in files:
        for line in open(f):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            exp = None
            nocompare = line.startswith('~')
            if nocompare:
                line = line[1:].strip()
            if '=>' in line:
                line, exp = line.split('=>', 1)
                line, exp = line.strip(), exp.strip()
            cmds.append((line, exp, nocompare))
    # the C examples the list compiles are staged in the root's /tmp
    import shutil
    if not root:
        sys.path.insert(0, REPO)
        from hpuxemu import rootdir
        root = rootdir.default_root()
    os.makedirs(os.path.join(root, 'tmp'), exist_ok=True)
    for name in os.listdir(os.path.join(REPO, 'examples')):
        if name.endswith('.c'):
            shutil.copy(os.path.join(REPO, 'examples', name), os.path.join(root, 'tmp', name))
    ok = bad = 0
    for cmd, exp, nocompare in cmds:
        results = {c: run(cmd, c, root) for c in cpus}
        rc, out, err, dt = results[cpus[0]]
        status = []
        good = True
        if rc == 'timeout':
            status.append('TIMEOUT')
            good = False
        elif rc != 0:
            status.append('rc=%s' % rc)
        if exp is not None and exp.encode() not in out:
            status.append('EXPECTED %r' % exp)
            good = False
        if b'hpuxemu:' in err:
            status.append(err.decode(errors='replace').strip().splitlines()[0][:100])
            good = False
        if len(cpus) == 2 and not nocompare:
            r2 = results[cpus[1]]
            if (r2[0], r2[1]) != (rc, out):
                status.append('CPUS DIFFER (%s rc=%s)' % (cpus[1], r2[0]))
                good = False
        ok += good
        bad += not good
        print('%s %6.2fs %-50s %s' % ('ok ' if good else 'BAD', dt, cmd[:50], '; '.join(status)))
        if verbose or not good:
            for line in out.decode(errors='replace').splitlines()[:5]:
                print('      | ' + line[:120])
            if not good:
                for line in err.decode(errors='replace').splitlines()[:5]:
                    print('      ! ' + line[:120])
    print('%d ok, %d bad' % (ok, bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
