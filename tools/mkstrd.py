#!/usr/bin/env python3
"""mkstrd.py - build the STREAMS daemon of a root: kernel/ with a third-party STREAMS
stack's driver libraries, compiled and linked in the emulator by HP's cc, as and ld.

    python3 tools/mkstrd.py ROOT DRIVER ...       a product's STREAMS driver, by name
    python3 tools/mkstrd.py ROOT none             the framework's own drivers only
    python3 tools/mkstrd.py ROOT                  the drivers the master files offer

The framework's own drivers are always in: timod, dlpi, and tcp and udp (kernel/inet.c,
TPI over the host's sockets - HP-UX 11.00's rpcbind and ToolTalk use them through TLI);
ROOT/etc/hpuxemu/streams gets /dev/tcp and /dev/udp if it lacks them.

A kernel driver product installs its libraries in /usr/conf/lib and a master file in
/usr/conf/master.d naming them ($DRIVER_LIBRARY) and the driver's install routine
($DRIVER_INSTALL: DRIVER_install()), which config(1M) links into the kernel. Here the
same libraries are linked with kernel/strd.c's STREAMS framework instead, into
ROOT/stand/hpuxemu/strd. HP's own drivers are the framework's (timod, dlpi) or not
needed; only a product's STREAMS driver is named here.

The result holds the product's code, so it stays in the root (as a kernel built with it
would), never in this repository.
"""
import glob
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from emucmd import emulator      # noqa: E402
SRC = os.path.join(HERE, '..', 'kernel')


def tables(path):
    """{table name: [rows as word lists]} of a master file"""
    out, cur = {}, None
    for line in open(path, encoding='latin1'):
        s = line.strip()
        if not s or s.startswith('*'):
            continue
        if s.startswith('$$$'):
            cur = None
        elif s.startswith('$'):
            cur = out.setdefault(s[1:].split()[0], [])
        elif cur is not None:
            cur.append(s.split())
    return out


def drivers(root):
    """(driver, [libraries], master file) of the master files' install tables"""
    out = []
    for f in sorted(glob.glob(os.path.join(root, 'usr/conf/master.d/*'))):
        if not os.path.isfile(f):
            continue
        t = tables(f)
        libs = {r[0]: r[1:] for r in t.get('DRIVER_LIBRARY', [])}
        for row in t.get('DRIVER_INSTALL', []):
            ls = libs.get(row[0], [])
            if ls and all(os.path.exists(os.path.join(root, 'usr/conf/lib', x)) for x in ls):
                out.append((row[0], ls, os.path.basename(f)))
    return out


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    root = os.path.abspath(argv[1])
    offered = drivers(root)
    if len(argv) == 2:
        for d, ls, f in offered:
            print('%-10s %-16s %s' % (d, f, ' '.join(ls)))
        return 0
    wanted = [d for d in argv[2:] if d != 'none']
    found = [(d, ls) for d, ls, f in offered if d in wanted]
    missing = set(wanted) - {d for d, _ in found}
    if missing:
        print('mkstrd: no master file installs %s with its libraries present' % ', '.join(sorted(missing)))
        return 1
    build = os.path.join(root, 'var/tmp/strd-build')
    shutil.rmtree(build, ignore_errors=True)
    os.makedirs(os.path.join(build, 'o'))
    for f in os.listdir(SRC):
        if f.endswith(('.c', '.h', '.s')):
            shutil.copy(os.path.join(SRC, f), build)
    with open(os.path.join(build, 'drivers.c'), 'w') as f:
        f.write('/* the install routines of the drivers linked in (tools/mkstrd.py) */\n')
        for d, _ in found:
            f.write('extern int %s_install();\n' % d)
        f.write('void\nstrd_drivers()\n{\n')
        for d, _ in found:
            f.write('\t%s_install();\n' % d)
        f.write('}\n')
    libs = [x for _, ls in found for x in ls]
    script = ' && '.join(['cd /var/tmp/strd-build/o'] +
                         ['ar x /usr/conf/lib/%s' % x for x in libs] + [
        'cd ..',
        'cc -c strd.c timod.c dlpi.c inet.c drivers.c',
        'as -o ksubr.o ksubr.s',
        'cc -Wl,-a,archive -o strd strd.o timod.o dlpi.o inet.o drivers.o ksubr.o' + (' o/*.o' if libs else ''),
    ])
    print('mkstrd: drivers %s from %s' % (', '.join(d for d, _ in found) or '(the framework\'s only)', ' '.join(libs) or '-'))
    r = subprocess.run(emulator() + ['-r', root, '/usr/bin/sh', '-c', script],
                       cwd=os.path.join(HERE, '..'))
    if r.returncode != 0 or not os.path.exists(os.path.join(build, 'strd')):
        print('mkstrd: the build failed')
        return 1
    os.makedirs(os.path.join(root, 'stand/hpuxemu'), exist_ok=True)
    shutil.copy(os.path.join(build, 'strd'), os.path.join(root, 'stand/hpuxemu/strd'))
    os.chmod(os.path.join(root, 'stand/hpuxemu/strd'), 0o755)
    shutil.rmtree(build, ignore_errors=True)
    conf = os.path.join(root, 'etc/hpuxemu/streams')
    have = open(conf).read() if os.path.exists(conf) else ''
    names = {line.split()[0] for line in have.splitlines() if line.split() and not line.startswith('#')}
    add = [line for line in ('/dev/tcp\ttcp\t72\t158', '/dev/udp\tudp\t72\t159') if line.split()[0] not in names]
    if add:
        os.makedirs(os.path.dirname(conf), exist_ok=True)
        with open(conf, 'a') as f:
            f.write(''.join(line + '\n' for line in add))
    print('mkstrd: %s/stand/hpuxemu/strd' % root)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
