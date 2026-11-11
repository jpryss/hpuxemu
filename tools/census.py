#!/usr/bin/env python3
"""Start every program of the root once, with no arguments and no input, and classify
what happened: a census of what the emulator can at least begin to run.

    python3 tools/census.py [-r ROOT] [--cpu rust] [-j N] [-t SECONDS] [DIR...] > docs/COMPAT.md

DIR defaults to /usr/bin /usr/sbin /sbin /usr/ccs/bin /usr/contrib/bin /opt/*/bin /etc
(inside the root). Each program runs through the emulator with stdin from /dev/null, a
timeout, and the classes are:

    ok          exited 0
    error N     exited N (usage messages, "no file" - normal for most commands)
    signal      killed by a signal the program itself raised (SIGPIPE, abort ...)
    unimpl      the emulator printed "unimplemented syscall ..." (listed)
    crash       the emulator reported a memory fault, illegal instruction ...
    timeout     still running after the timeout (interactive programs waiting on a tty)

Programs that would change the system (shutdown, reboot, init, mkfs, compressdir...) are
skipped, and the working directory is /tmp; still, run it on a copy of the root: a program
started without arguments can do anything to the files it sees."""

import glob
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from emucmd import emulator, default_cpu      # noqa: E402
sys.path.insert(0, REPO)
from hpuxemu import rootdir  # noqa: E402

SKIP = {'shutdown', 'reboot', 'init', 'halt', 'mkboot', 'rc', 'bcheckrc', 'newfs', 'mkfs', 'fsck', 'mount', 'umount',
        'swapon', 'vgcreate', 'pvcreate', 'lvcreate', 'mediainit', 'kill', 'killall', 'telinit', 'login', 'getty',
        'uugetty', 'cron', 'inetd', 'syslogd', 'sendmail', 'sync', 'update', 'rmsf', 'insf', 'reboot_vsp', 'ioinit',
        'lifinit', 'mksf', 'set_parms', 'rexec', 'sam', 'swinstall', 'swremove', 'swmodify', 'swconfig', 'swverify',
        'swcopy', 'swpackage', 'swreg', 'swlist', 'swacl', 'swagentd', 'swagent', 'rlpdaemon', 'rbootd', 'lpsched',
        'lpshut', 'nettl', 'nettlconf', 'netfmt', 'pwck', 'grpck', 'vipw', 'passwd', 'useradd', 'userdel', 'usermod',
        'groupadd', 'groupdel', 'groupmod', 'rm', 'rmdir', 'mv', 'clri', 'fsdb', 'dd', 'tar', 'cpio', 'pax',
        'frecover', 'fbackup', 'restore', 'dump', 'mkdir', 'compressdir', 'uncompressdir', 'freedisk', 'catman',
        'updist', 'nfsconfcol', 'yes', 'sp_enable', 'sp_disable', 'getx25'}


def classify(rc, err):
    if 'unimplemented syscall' in err:
        names = sorted(set(re.findall(r'unimplemented syscall (\w+)', err)))
        return 'unimpl', ' '.join(names)
    if 'hpuxemu:' in err and ('memory fault' in err or 'illegal instruction' in err or 'privileged' in err or 'unaligned' in err or 'break ' in err):
        line = [l for l in err.splitlines() if 'hpuxemu:' in l][0]
        return 'crash', line.split(':', 2)[-1].strip()[:80]
    if 'hpuxemu:' in err and 'ioctl' in err:
        return 'unimpl', 'ioctl ' + ' '.join(sorted(set(re.findall(r'ioctl (0x[0-9a-f]+)', err))))
    if rc == 'timeout':
        return 'timeout', ''
    if rc == 0:
        return 'ok', ''
    if rc < 0:
        return 'signal', str(-rc)
    return 'error', str(rc)


def run_one(args):
    prog, root, cpu, timeout = args
    env = dict(os.environ, HPUX_ROOT=root)
    t = time.time()
    try:
        p = subprocess.run(emulator(cpu) + ['-C', '/tmp', prog], cwd=REPO, env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = 'timeout', e.stdout or b'', e.stderr or b''
    err = err.decode(errors='replace')
    kind, note = classify(rc, err)
    first = (out or err.encode()).decode(errors='replace').strip().splitlines()
    line = ''.join(ch if ch.isprintable() else ' ' for ch in first[0][:70]) if first else ''
    return prog, kind, note, time.time() - t, line


def main(argv):
    root = None
    cpu = default_cpu()
    jobs = 2
    timeout = 20
    dirs = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-r':
            i += 1
            root = argv[i]
        elif a == '--cpu':
            i += 1
            cpu = argv[i]
        elif a == '-j':
            i += 1
            jobs = int(argv[i])
        elif a == '-t':
            i += 1
            timeout = float(argv[i])
        else:
            dirs.append(a)
        i += 1
    root = root or rootdir.default_root()
    if not dirs:
        dirs = ['/usr/bin', '/usr/sbin', '/sbin', '/usr/ccs/bin', '/usr/contrib/bin'] + \
               sorted(set('/' + os.path.relpath(d, root) for d in glob.glob(os.path.join(root, 'opt/*/bin'))))
    progs = []
    for d in dirs:
        hd = os.path.join(root, d.lstrip('/'))
        if not os.path.isdir(hd):
            continue
        for n in sorted(os.listdir(hd)):
            hp = os.path.join(hd, n)
            if os.path.isfile(hp) and os.access(hp, os.X_OK) and not os.path.islink(hp) and n not in SKIP:
                progs.append(d + '/' + n)
    results = []
    with ThreadPoolExecutor(jobs) as ex:
        for r in ex.map(run_one, [(p, root, cpu, timeout) for p in progs]):
            results.append(r)
            sys.stderr.write('%-8s %-32s %s\n' % (r[1], r[0], r[2]))
    counts = {}
    for r in results:
        counts[r[1]] = counts.get(r[1], 0) + 1
    print('# Program census\n')
    print('*Generated by `tools/census.py`: every program in %s started once with no arguments' % ', '.join(dirs))
    print('and no input, on the %s CPU, %d s timeout.*\n' % (cpu, timeout))
    print('%d programs: ' % len(results) + ', '.join('%d %s' % (counts[k], k) for k in ('ok', 'error', 'signal', 'timeout', 'unimpl', 'crash') if k in counts) + '.')
    print('`error` is the program exiting with a usage message or similar, which is what most')
    print('commands do without arguments; `timeout` is usually a program waiting for a terminal.')
    print('`unimpl` names the system calls that stopped it, `crash` is an emulator-detected fault.\n')
    print('| program | result | note | first line of output |')
    print('|---|---|---|---|')
    for prog, kind, note, dt, first in results:
        print('| `%s` | %s | %s | %s |' % (prog, kind, note.replace('|', '\\|'), first.replace('|', '\\|').replace('`', "'")))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
