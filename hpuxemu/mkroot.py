"""mkroot.py - build or extend an HP-UX root from SD-UX depots.

    python3 -m hpuxemu.mkroot ROOT DEPOT PRODUCT/FILESET ...    extract filesets
    python3 -m hpuxemu.mkroot ROOT                              redo the post-processing only

Extraction is depot.extract_fileset: files belong to the host user with their HP-UX modes.
What swinstall's control scripts would then do, as far as a user-mode emulator needs it:

- `/usr/newconfig/<path>` files are copied to `<path>` where that does not exist yet
  (the `newconfig_cp` of the filesets' configure scripts; /sbin/sh among them) or
  where only a control script made it (merged: see merge_config), and the
  directories UX-CORE's configure creates (/tmp, /var/tmp, /var/run, /home ...) are made.
- `ROOT/etc/hpuxemu/owners` records every file's HP-UX owner, group and mode from the
  depot's INFO records: the files are the host user's, and set-id programs (su, passwd,
  login ...) are known from this table (DESIGN.md).
- `ROOT/etc/hpuxemu/release` records the OS release (B.10.20) for uname.
- `ROOT/var/adm/sw/` gets a plain-text list of the installed filesets (not the IPD binary
  database; swlist does not run yet).

Everything is idempotent: run it again after adding filesets.
"""
import os
import time
import shutil
import stat
import sys

from . import depot as depotmod
from .owners import read_owners, write_owners, mnttab  # noqa: F401 (here before owners.py)

HERE = os.path.dirname(os.path.abspath(__file__))

# not copied into place: the trusted-system database (only tsconvert installs it; with
# /tcb present, login runs in trusted mode and wants the kernel's I/O configuration)
NEWCONFIG_SKIP = ('/usr/newconfig/etc/copyright',)
NEWCONFIG_SKIP_DIRS = ('/usr/newconfig/tcb/',)

DIRS = """
0555 /home
0777 /dev/screen
0755 /etc/rc.config.d
0775 /etc/skel
1777 /tmp
0755 /var/adm
0555 /var/adm/syslog
0555 /var/run
0555 /var/spool
0777 /var/spool/sockets
1777 /var/tmp
0555 /etc/local
0555 /etc/default
0755 /var/adm/sw
0755 /var/mail
0755 /var/spool/cron
0755 /dev
0755 /dev/pts
0755 /etc/hpuxemu
0755 /usr/bin/posix
"""

# HP-UX 10's transition links: the 9.x paths that point into the 10.x tree. Scripts still
# write "//lib/..." and "/bin/sh"; 9.x's POSIX shell was /bin/posix/sh (some
# products' scripts still start "#!/bin/posix/sh").
LINKS = """
/bin /usr/bin
/lib /usr/lib
/usr/bin/posix/sh ../sh
"""

# what the control scripts need before any of them runs: `chown root` reads /etc/passwd;
# 11.00 ships the dynamic loader only as /usr/newconfig/usr/lib/dld.sl, which CORE-SHLIBS'
# configure copies into place - with commands that cannot start without it
EARLY_FILES = ('etc/passwd', 'etc/group', 'etc/services', 'etc/protocols', 'usr/lib/dld.sl')


def log(msg):
    print(msg, file=sys.stderr)


def merge_config(root, src, dst, owners):
    """A configuration file that a control script created before its own fileset's
    newconfig copy ran (CDE's configure adds its RPC services to /etc/inetd.conf,
    making the file, when InternetSrvcs has not put HP's version in place yet; the
    copy was then skipped and telnet, ftp ... were missing). swinstall would have run
    InternetSrvcs first. Such a file is not in the owners table (no depot delivered
    it) and has none of HP's lines: it becomes HP's file with the script's lines after
    it. A file that shares lines with HP's (one edited since) is left alone."""
    g = '/' + os.path.relpath(dst, root)
    if g in owners or os.path.islink(src) or os.path.islink(dst) or not g.startswith('/etc/'):
        return False
    try:
        new = open(src, encoding='latin1').read().splitlines()
        cur = open(dst, encoding='latin1').read().splitlines()
    except (OSError, UnicodeError):
        return False
    hp = [l for l in new if l.strip() and not l.startswith('#')]
    if not hp or any(l in cur for l in hp):
        return False
    extra = [l for l in cur if l not in new]
    shutil.copy2(src, dst)
    with open(dst, 'a', encoding='latin1') as f:
        for l in extra:
            f.write(l + '\n')
    return True


def newconfig(root):
    """Copy /usr/newconfig/<path> to /<path> where the target is missing."""
    src = os.path.join(root, 'usr/newconfig')
    n = 0
    if not os.path.isdir(src):
        return 0
    owners = read_owners(root)
    for dirpath, dirnames, filenames in os.walk(src):
        rel = os.path.relpath(dirpath, src)
        for name in filenames:
            s = os.path.join(dirpath, name)
            full = '/usr/newconfig/' + os.path.join(rel, name).replace('./', '')
            if full in NEWCONFIG_SKIP or any(full.startswith(d) for d in NEWCONFIG_SKIP_DIRS):
                continue
            d = os.path.join(root, rel, name) if rel != '.' else os.path.join(root, name)
            if os.path.lexists(d):
                if merge_config(root, s, d, owners):
                    n += 1
                continue
            os.makedirs(os.path.dirname(d), exist_ok=True)
            if os.path.islink(s):
                os.symlink(os.readlink(s), d)
            else:
                shutil.copy2(s, d)
            n += 1
    return n


def make_dirs(root):
    for line in DIRS.strip().split('\n'):
        mode, path = line.split()
        d = os.path.join(root, path.lstrip('/'))
        os.makedirs(d, exist_ok=True)
        os.chmod(d, int(mode, 8) | 0o700)
    for line in LINKS.strip().split('\n'):
        path, target = line.split()
        d = os.path.join(root, path.lstrip('/'))
        if not os.path.lexists(d):
            os.symlink(target, d)
    for rel in EARLY_FILES:
        d = os.path.join(root, rel)
        s = os.path.join(root, 'usr/newconfig', rel)
        if not os.path.lexists(d) and os.path.exists(s):
            shutil.copy2(s, d)


def postprocess(root, release='B.10.20'):
    make_dirs(root)
    n = newconfig(root)
    log('newconfig: %d files put in place' % n)
    with open(os.path.join(root, 'etc/hpuxemu/release'), 'w') as f:
        f.write(release + '\n')
    for name in ('wtmp', 'btmp', 'utmp'):
        p = os.path.join(root, 'var/adm', name)
        if not os.path.exists(p):
            open(p, 'wb').close()
    for p in ('etc/shutdown.allow',):
        p = os.path.join(root, p)
        if not os.path.exists(p):
            open(p, 'wb').close()
    mnttab(root)
    hosts(root)


def hosts(root):
    """/etc/hosts must resolve the node name (uname -n), which is "hpux" unless
    etc/hpuxemu/hostname says otherwise: ToolTalk's ttsession looks its own host up."""
    hn = os.path.join(root, 'etc/hpuxemu/hostname')
    name = (open(hn).read().strip() if os.path.exists(hn) else '') or 'hpux'
    p = os.path.join(root, 'etc/hosts')
    text = open(p).read() if os.path.exists(p) else ''
    if not any(name in line.split() for line in text.splitlines() if not line.startswith('#')):
        with open(p, 'a') as f:
            f.write('127.0.0.1\t%s\n' % name)


def install(root, depot, filesets, owners=None):
    """Extract PRODUCT/FILESET pairs; returns the owners table (also written)."""
    if owners is None:
        owners = read_owners(root)
    installed = set()
    p = os.path.join(root, 'var/adm/sw/hpuxemu.filesets')
    if os.path.exists(p):
        installed = set(open(p).read().split())
    for product, fileset in filesets:
        # a directory that exists already keeps its owner and mode, as with swinstall:
        # a later product listing a directory with its packager's uid must not take
        # it from root (a daemon that checks its directory's owner then refuses to start)
        existing = set()
        try:
            for r in depot.files(product, fileset):
                path = r.get('path')
                if path and os.path.isdir(os.path.join(root, path.lstrip('/'))):
                    existing.add(path)
        except (OSError, KeyError):
            pass
        recs = []
        n = depotmod.extract_fileset(depot, product, fileset, root, log=log, owners=recs)
        for path, mode, uid, gid, typ in recs:
            if typ == 'd' and path in existing:
                continue
            owners[path] = (mode, uid, gid, typ)
        installed.add('%s/%s' % (product, fileset))
        log('%s/%s: %d files' % (product, fileset, n))
    write_owners(root, owners)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as f:
        f.write('\n'.join(sorted(installed)) + '\n')
    return owners


def run_control_scripts(root, depot, filesets, which=('postinstall', 'configure'), cpu='rust', timeout=120,
                        phased=False):
    """Run the filesets' SD-UX control scripts (postinstall, then configure) inside the
    emulator, as swinstall would after copying the files: they make the symbolic links,
    append to configuration files and so on that a plain extraction leaves out. The
    environment is the one swinstall gives them (SW_ROOT_DIRECTORY, SW_SOFTWARE_SPEC,
    SW_LOCATION ...); control_utils' IPD_addfile/IPD_delfile write their lists under
    SW_MODIFY_TMPDIR. Kernel-building scripts fail harmlessly. Results go to
    var/adm/sw/hpuxemu.scripts.

    phased=True is swinstall's own order, for software added to a root that already
    runs: each script name in `which` is a phase over all the filesets (every
    postinstall before any configure), and a product's own script of that name (its
    pfiles: such a preinstall makes the directories its filesets' scripts use)
    runs before the product's fileset scripts. A product instance directory (PRODUCT.3,
    one of several builds of a product in one depot) is named without its suffix in
    SW_SOFTWARE_SPEC. The OS root build keeps the fileset-by-fileset order it was
    developed with."""
    import re
    import subprocess
    import sys
    repo = os.path.dirname(HERE)
    emu = [sys.executable, '-m', 'hpuxemu.emu', '--cpu', cpu, '-r', root]
    # the Rust emulator runs the scripts several times faster: $HPUXEMU, or its release
    # build when there is one (HPUXEMU=python keeps the Python emulator)
    rs = os.environ.get('HPUXEMU') or os.path.join(repo, 'rust', 'hpuxemu', 'target', 'release', 'hpuxemu')
    if rs != 'python' and os.path.exists(rs):
        emu = [rs, '-r', root]
    tmp = '/var/tmp/hpuxemu-sw'
    os.makedirs(os.path.join(root, tmp.lstrip('/')), exist_ok=True)
    results = []
    # swinstall runs the scripts in prerequisite order, and nearly everything requires
    # OS-Core: its UX-CORE scripts first, so that /sbin/sh (which UX-CORE's configure
    # puts in place) exists for the scripts of the products that come before OS-Core
    # in the depot (DCE, Networking, the 100BT drivers ... failed for want of it)
    filesets = sorted(filesets, key=lambda pf: (pf[0], pf[1]) != ('OS-Core', 'UX-CORE'))

    def stage(product, fileset):
        """the control directory: all the fileset's control files, and the product's
        pfiles next to it (scripts use ${SW_CONTROL_DIRECTORY%/*/}/pfiles/...)"""
        try:
            cfs = {c['path']: c for c in depot.control_files(product, fileset)}
        except FileNotFoundError:
            return None, None
        gdir = '%s/%s/%s' % (tmp, product, fileset)
        os.makedirs(os.path.join(root, gdir.lstrip('/')), exist_ok=True)
        for cname in cfs:
            try:
                with open(os.path.join(root, gdir.lstrip('/'), cname), 'wb') as f:
                    f.write(depot.read('catalog/%s/%s/%s' % (product, fileset, cname)))
            except (FileNotFoundError, OSError):
                pass
        pdir = os.path.join(root, tmp.lstrip('/'), product, 'pfiles')
        if not os.path.isdir(pdir):
            os.makedirs(pdir, exist_ok=True)
            for pname in depot.product_control_files(product):
                try:
                    with open(os.path.join(pdir, pname), 'wb') as f:
                        f.write(depot.read('catalog/%s/pfiles/%s' % (product, pname)))
                except (FileNotFoundError, OSError):
                    pass
        return cfs, gdir

    def run_one(product, fileset, name, gdir):
        gpath = '%s/%s' % (gdir, name)
        if not os.path.exists(os.path.join(root, gpath.lstrip('/'))):
            return
        tag = re.sub(r'\.\d+$', '', product)
        spec = '%s.%s' % (tag, fileset) if fileset else tag
        env = {'SW_ROOT_DIRECTORY': '/', 'SW_SOFTWARE_SPEC': spec, 'SW_LOCATION': '/',
               'SW_PATH': '/usr/bin:/usr/sbin:/sbin:/usr/lbin', 'SW_CONTROL_DIRECTORY': gdir + '/', 'SW_MODIFY_TMPDIR': tmp + '/ipd/',
               'SW_SESSION_IS_INSTALL': '1', 'SW_INITIAL_INSTALL': '1', 'SW_CTL_SCRIPT_NAME': name,
               'SW_DEFERRED_KERNBLD': 'true', 'SW_KERNEL_PATH': '/stand/vmunix', 'SW_SYSTEM_FILE_PATH': '/stand/system',
               'SW_TMP': tmp, 'ROOT': '', 'PATH': '/usr/bin:/usr/sbin:/sbin:/usr/lbin'}
        if phased:
            env['LANG'] = 'C'     # swinstall's own locale; scripts use $LANG in paths
        cmd = emu[:]
        for k, v in env.items():
            cmd += ['-e', '%s=%s' % (k, v)]
        # /sbin/sh itself is put in place by UX-CORE's configure script (from
        # /usr/newconfig), so the first scripts run with /usr/bin/sh
        shell = '/sbin/sh' if os.path.exists(os.path.join(root, 'sbin/sh')) else '/usr/bin/sh'
        cmd += [shell, gpath]
        t = time.time()
        try:
            r = subprocess.run(cmd, cwd=repo, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
            rc = r.returncode
            err = (r.stdout + r.stderr).decode(errors='replace').strip().splitlines()
        except subprocess.TimeoutExpired:
            rc = 'timeout'
            err = []
        dt = time.time() - t
        # 11.00 CORE-SHLIBS postinstall moves the new dynamic loader into place with
        # `rm -f /usr/lib/dld.sl; mv /usr/newconfig/usr/lib/dld.sl /usr/lib/dld.sl`,
        # and mv cannot start without the loader it has just removed: finish the move
        dld = os.path.join(root, 'usr/lib/dld.sl')
        if not os.path.lexists(dld):
            for src in ('usr/newconfig/usr/lib/dld.sl', 'usr/lib/#dld.sl.old'):
                if os.path.exists(os.path.join(root, src)):
                    shutil.copy2(os.path.join(root, src), dld)
                    log('%s/%s %s: /usr/lib/dld.sl put back from /%s' % (product, fileset, name, src))
                    break
        last = err[-1][:100] if err else ''
        label = '%s/%s' % (product, fileset) if fileset else '%s (product)' % product
        results.append((label, name, rc, dt, last))
        log('%s %s: %s%s' % (label, name, 'ok' if rc == 0 else 'exit %s' % rc, (' - ' + last) if rc != 0 and last else ''))

    staged = []
    for product, fileset in filesets:
        cfs, gdir = stage(product, fileset)
        if cfs is not None:
            staged.append((product, fileset, cfs, gdir))
    if phased:
        for name in which:
            done = set()
            for product, fileset, cfs, gdir in staged:
                if product not in done:
                    done.add(product)
                    run_one(product, '', name, '%s/%s/pfiles' % (tmp, product))
                if name in cfs:
                    run_one(product, fileset, name, gdir)
    else:
        for product, fileset, cfs, gdir in staged:
            for name in which:
                if name in cfs:
                    run_one(product, fileset, name, gdir)
    with open(os.path.join(root, 'var/adm/sw/hpuxemu.scripts'), 'a') as f:
        for label, name, rc, dt, last in results:
            f.write('%s %s %s %.1f %s\n' % (label, name, rc, dt, last))
    stop_script_daemons(root)
    return results


def stop_script_daemons(root):
    """A control script may start its product's daemon (swagentd, a print spooler), as
    it would on a running system; here nothing is running after the install, so what
    the scripts left behind is stopped: the emulator processes of this root that carry
    a script's environment."""
    import signal
    want = os.path.realpath(root)
    n = 0
    for pid in os.listdir('/proc') if os.path.isdir('/proc') else []:
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            args = open('/proc/%s/cmdline' % pid, 'rb').read().split(b'\0')
        except OSError:
            continue
        if not any(a.startswith(b'SW_CONTROL_DIRECTORY=') for a in args):
            continue
        roots = [args[i + 1].decode(errors='replace') for i, a in enumerate(args[:-1]) if a == b'-r']
        if not any(os.path.realpath(r) == want for r in roots):
            continue
        try:
            os.kill(int(pid), signal.SIGTERM)
            n += 1
        except OSError:
            pass
    if n:
        log('stopped %d daemon%s the control scripts had started' % (n, '' if n == 1 else 's'))


def apply_patches(root, depot, patches):
    """Extract patch filesets [(product, fileset, ancestor)] over the root and record
    them in var/adm/sw/hpuxemu.patches."""
    owners = read_owners(root)
    p = os.path.join(root, 'var/adm/sw/hpuxemu.patches')
    applied = set(open(p).read().split()) if os.path.exists(p) else set()
    for product, fileset, anc in patches:
        recs = []
        n = depotmod.extract_fileset(depot, product, fileset, root, log=log, owners=recs)
        for path, mode, uid, gid, typ in recs:
            owners[path] = (mode, uid, gid, typ)
        applied.add(product)
        log('%s (for %s): %d files' % (product, anc, n))
    write_owners(root, owners)
    with open(p, 'w') as f:
        f.write('\n'.join(sorted(applied)) + '\n')


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    root = argv[1]
    os.makedirs(root, exist_ok=True)
    if len(argv) > 2:
        depot = depotmod.open_depot(argv[2])
        filesets = [tuple(a.split('/')) for a in argv[3:]]
        install(root, depot, filesets)
    postprocess(root)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
