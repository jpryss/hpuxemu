#!/usr/bin/env python3
"""adopt.py - make a copy of a real HP-UX system's files a root for the emulator.

    python3 -m hpuxemu.adopt ROOT [ARCHIVE...] [--release B.11.00] [--hostname NAME]

With ARCHIVEs, ROOT is the directory to unpack them into: tar archives or cpio archives
(HP-UX's binary format, `-c` ASCII, or newc), plain or compressed (.Z, .gz, .bz2, .xz),
made on the HP-UX machine as root, e.g.

    cd / && tar cf /tmp/root.tar etc sbin usr opt var home stand/system
    cd / && find etc sbin usr opt var home -xdev -print | cpio -o > /tmp/root.cpio

(leave out /dev, /tmp, /net and whatever is mounted from elsewhere; several archives -
one per file system, say - are unpacked one after the other). Without ARCHIVEs, ROOT
already holds the machine's files (an archive unpacked by hand, a mounted disk copied
with `cp -a`): their owners and modes are taken as they are on disk, which are HP-UX's
only if they were copied as root with numeric owners. For a dd image of the machine's
disk, `tools/hpdisk.py root IMAGE DIR` does all of this from the image.

What it does - the rest of the machine (users, passwords, installed software, its
configuration) stays as it was:

  the files           written as you, with HP-UX's modes; nothing lands outside ROOT
                      (leading `/` and `..` are not followed, symbolic links are
                      resolved inside ROOT as the emulator resolves them)
  etc/hpuxemu/owners  HP-UX's owner, group and mode of every file, from the archive:
                      the emulator's permission checks and set-user-id programs (su,
                      passwd, login) go by this table
  device files        not created (the emulator has its own /dev); listed in
                      etc/hpuxemu/disk-devices, as are FIFOs and sockets
  etc/hpuxemu/release B.10.20 or B.11.00, from the root's libc (--release overrides):
                      the emulator picks its system call table by it
  etc/hpuxemu/hostname  the machine's node name, from /etc/rc.config.d/netconf
                      (--hostname overrides), so `uname -n` and `hostname` answer as
                      the machine did
  /tmp, /var/tmp ...  the directories every root needs, with their modes

It then says what to look at: the address the node name has in /etc/hosts (programs
that connect to their own host need it to be an address of this machine), and, for
11.00, the STREAMS daemon (tools/mkstrd.py). Running it again, or with more archives,
adds to the root and its tables.
"""
import io
import os
import stat
import subprocess
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from hpuxemu import mkroot      # noqa: E402

BLOCK = 1 << 20


class Stream:
    """a forward-only reader with a look-ahead, over a file or a decompressor's pipe"""

    def __init__(self, f, proc=None):
        self.f = f
        self.proc = proc
        self.buf = b''
        self.pos = 0

    def peek(self, n):
        while len(self.buf) < n:
            more = self.f.read(max(BLOCK, n - len(self.buf)))
            if not more:
                break
            self.buf += more
        return self.buf[:n]

    def read(self, n=-1):
        if n < 0:
            data = self.buf + self.f.read()
            self.buf = b''
        elif n <= len(self.buf):
            data, self.buf = self.buf[:n], self.buf[n:]
        else:
            data = self.buf
            self.buf = b''
            while len(data) < n:
                more = self.f.read(n - len(data))
                if not more:
                    break
                data += more
        self.pos += len(data)
        return data

    def skip(self, n):
        while n > 0:
            got = len(self.read(min(n, BLOCK)))
            if not got:
                break
            n -= got

    def tell(self):
        return self.pos

    def close(self):
        self.f.close()
        if self.proc:
            self.proc.wait()


def open_archive(path):
    """the archive as a Stream of uncompressed bytes"""
    f = open(path, 'rb')
    magic = f.read(6)
    f.seek(0)
    if magic[:2] == b'\x1f\x8b':
        import gzip
        return Stream(gzip.GzipFile(fileobj=f))
    if magic[:3] == b'BZh':
        import bz2
        return Stream(bz2.BZ2File(f))
    if magic[:6] == b'\xfd7zXZ\x00':
        import lzma
        return Stream(lzma.LZMAFile(f))
    if magic[:2] == b'\x1f\x9d':
        # compress(1): gzip reads it
        f.close()
        p = subprocess.Popen(['gzip', '-dc', path], stdout=subprocess.PIPE)
        return Stream(p.stdout, p)
    return Stream(f)


# ---- cpio ---------------------------------------------------------------------------------

def cpio_members(s):
    """(name, mode, uid, gid, mtime, key, nlink, rdev, size) of each member of a cpio
    archive on the Stream; the caller reads or skips the size bytes of data, then calls
    the returned pad function. Formats: old binary (either byte order), -c (odc), newc."""
    while True:
        head = s.peek(6)
        if len(head) < 6:
            return
        if head == b'070707':
            h = s.read(76)
            f = [int(h[a:b], 8) for a, b in ((6, 12), (12, 18), (18, 24), (24, 30), (30, 36), (36, 42), (42, 48),
                                              (48, 59), (59, 65), (65, 76))]
            dev, ino, mode, uid, gid, nlink, rdev, mtime, nsize, size = f
            name = s.read(nsize)
            pad = lambda: None                                  # noqa: E731
        elif head in (b'070701', b'070702'):
            h = s.read(110)
            f = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            ino, mode, uid, gid, nlink, mtime, size, dmaj, dmin, rmaj, rmin, nsize, _ = f
            dev, rdev = (dmaj << 8) | dmin, (rmaj << 24) | rmin
            name = s.read(nsize)
            s.skip((4 - (110 + nsize) % 4) % 4)
            pad = (lambda n=size: s.skip((4 - n % 4) % 4))
        elif head[:2] in (b'\x71\xc7', b'\xc7\x71'):
            order = 'big' if head[:2] == b'\x71\xc7' else 'little'
            h = s.read(26)
            w = [int.from_bytes(h[2 * i:2 * i + 2], order) for i in range(13)]
            _, dev, ino, mode, uid, gid, nlink, rdev, mt1, mt2, nsize, sz1, sz2 = w
            mtime, size = (mt1 << 16) | mt2, (sz1 << 16) | sz2
            name = s.read(nsize)
            s.skip(nsize & 1)
            pad = (lambda n=size: s.skip(n & 1))
        else:
            raise ValueError('not a cpio header at offset %d' % s.tell())
        name = name.split(b'\0')[0].decode('latin-1')
        if name == 'TRAILER!!!':
            return
        yield name, mode, uid, gid, mtime, (dev, ino), nlink, rdev, size, pad


# ---- writing the root ------------------------------------------------------------------------

class Adopter:
    def __init__(self, top):
        self.top = os.path.abspath(top)
        self.owners = {}
        self.devices = []
        self.links = {}
        self.dirmodes = {}
        self.skipped = []
        self.count = 0

    def resolve(self, gpath, last=False, depth=0):
        """the guest path with its directories' symbolic links followed inside the root
        (the last component's too with `last`); None when it would leave the root"""
        if depth > 32:
            return None
        out = []
        parts = [p for p in gpath.split('/') if p not in ('', '.')]
        for k, p in enumerate(parts):
            if p == '..':
                return None
            out.append(p)
            if k == len(parts) - 1 and not last:
                break
            h = os.path.join(self.top, *out)
            if os.path.islink(h):
                target = os.readlink(h)
                base = '' if target.startswith('/') else '/'.join(out[:-1])
                # a link's own .. are the machine's: followed, but never above the root
                merged = []
                for q in (base + '/' + target).split('/'):
                    if q in ('', '.'):
                        continue
                    if q == '..':
                        if merged:
                            merged.pop()
                        continue
                    merged.append(q)
                rest = '/'.join(merged + parts[k + 1:])
                return self.resolve(rest, last, depth + 1)
        return '/' + '/'.join(out)

    def host(self, gpath):
        return os.path.join(self.top, gpath.lstrip('/'))

    def place(self, name):
        """the guest path a member goes to (its parent directory made), or None"""
        g = self.resolve(name)
        if g is None:
            self.skipped.append(name)
            return None
        if g != '/':
            parent = os.path.dirname(self.host(g))
            if not os.path.isdir(parent):
                try:
                    os.makedirs(parent, exist_ok=True)
                except OSError:
                    self.skipped.append(name)
                    return None
        return g

    def clear(self, h):
        if os.path.islink(h) or (os.path.lexists(h) and not os.path.isdir(h)):
            os.unlink(h)

    def add(self, name, mode, uid, gid, mtime, data=None, target=None, linkto=None, rdev=0):
        """one member: data is a function writing the contents to a file object"""
        g = self.place(name)
        if g is None:
            return False
        h = self.host(g)
        fmt = stat.S_IFMT(mode)
        perm = mode & 0o7777
        try:
            if linkto is not None:
                src = self.resolve(linkto, last=False)
                if src is None or not os.path.lexists(self.host(src)):
                    self.skipped.append('%s (link to %s)' % (name, linkto))
                    return False
                self.clear(h)
                os.link(self.host(src), h, follow_symlinks=False)
                self.owners[g] = (perm, uid, gid, 'h')
            elif fmt == stat.S_IFDIR:
                if os.path.islink(h):
                    os.unlink(h)
                os.makedirs(h, exist_ok=True)
                self.dirmodes[h] = perm
                self.owners[g] = (perm, uid, gid, 'd')
            elif fmt == stat.S_IFLNK:
                self.clear(h)
                os.symlink(target, h)
                self.owners[g] = (0o777, uid, gid, 's')
            elif fmt == stat.S_IFREG:
                self.clear(h)
                if os.path.isdir(h):
                    self.skipped.append('%s (a directory is in the way)' % name)
                    return False
                with open(h, 'wb') as f:
                    data(f)
                os.chmod(h, perm | 0o600)
                os.utime(h, (mtime, mtime))
                self.owners[g] = (perm, uid, gid, 'f')
            else:
                kind = {stat.S_IFCHR: 'c', stat.S_IFBLK: 'b', stat.S_IFIFO: 'p', stat.S_IFSOCK: 's'}.get(fmt, '?')
                self.devices.append('%s %o %d %d %d %d' % (g, mode, uid, gid, rdev >> 24, rdev & 0xffffff))
                if kind == '?':
                    self.skipped.append('%s (type %o)' % (name, fmt))
                return False
        except OSError as e:
            self.skipped.append('%s: %s' % (name, e.strerror))
            return False
        self.count += 1
        if self.count % 5000 == 0:
            print('adopt: %d files ...' % self.count, flush=True)
        return True

    # -- the archive formats --

    def tar(self, s):
        with tarfile.open(fileobj=s, mode='r|') as tf:
            for ti in tf:
                mode = ti.mode & 0o7777
                if ti.isdir():
                    self.add(ti.name, stat.S_IFDIR | mode, ti.uid, ti.gid, ti.mtime)
                elif ti.issym():
                    self.add(ti.name, stat.S_IFLNK | 0o777, ti.uid, ti.gid, ti.mtime, target=ti.linkname)
                elif ti.islnk():
                    self.add(ti.name, stat.S_IFREG | mode, ti.uid, ti.gid, ti.mtime, linkto=ti.linkname)
                elif ti.isreg():
                    src = tf.extractfile(ti)

                    def copy(f, src=src):
                        while True:
                            b = src.read(BLOCK)
                            if not b:
                                break
                            f.write(b)
                    self.add(ti.name, stat.S_IFREG | mode, ti.uid, ti.gid, ti.mtime, data=copy)
                else:
                    fmt = (stat.S_IFCHR if ti.ischr() else stat.S_IFBLK if ti.isblk() else
                           stat.S_IFIFO if ti.isfifo() else 0)
                    self.add(ti.name, fmt | mode, ti.uid, ti.gid, ti.mtime,
                             rdev=((ti.devmajor or 0) << 24) | (ti.devminor or 0))

    def cpio(self, s):
        for name, mode, uid, gid, mtime, key, nlink, rdev, size, pad in cpio_members(s):
            fmt = stat.S_IFMT(mode)
            done = False
            if fmt == stat.S_IFLNK:
                target = s.read(size).split(b'\0')[0].decode('latin-1')
                self.add(name, mode, uid, gid, mtime, target=target)
                done = True
            elif fmt == stat.S_IFREG:
                first = self.links.get(key) if nlink > 1 else None
                if first is not None and size == 0:
                    # a later name of a file already written (newc keeps the data for the last)
                    self.add(name, mode, uid, gid, mtime, linkto=first)
                elif first is not None:
                    # the data again (binary, -c), or at last (newc): the file's contents
                    def copy(f, n=size):
                        while n > 0:
                            b = s.read(min(n, BLOCK))
                            if not b:
                                break
                            f.write(b)
                            n -= len(b)
                    g = self.resolve(first)
                    if g is not None and os.path.isfile(self.host(g)) and os.path.getsize(self.host(g)) == 0:
                        with open(self.host(g), 'wb') as f:
                            copy(f)
                    else:
                        s.skip(size)
                    done = True
                    self.add(name, mode, uid, gid, mtime, linkto=first)
                else:
                    def copy(f, n=size):
                        while n > 0:
                            b = s.read(min(n, BLOCK))
                            if not b:
                                break
                            f.write(b)
                            n -= len(b)
                    start = s.tell()
                    if self.add(name, mode, uid, gid, mtime, data=copy) and nlink > 1:
                        self.links[key] = name
                    s.skip(size - (s.tell() - start))
                    done = True
            else:
                self.add(name, mode, uid, gid, mtime, rdev=rdev)
            if not done:
                s.skip(size)
            pad()

    def archive(self, path):
        s = open_archive(path)
        head = s.peek(512)
        try:
            if head[:6] in (b'070707', b'070701', b'070702') or head[:2] in (b'\x71\xc7', b'\xc7\x71'):
                self.cpio(s)
            elif head[257:262] == b'ustar' or tar_checksum_ok(head):
                self.tar(s)
            else:
                raise ValueError('neither a tar nor a cpio archive (fbackup and dump archives are not read: '
                                 'make a tar or cpio on the machine)')
        finally:
            s.close()

    def from_disk(self):
        """the owners and modes of what is in the directory already"""
        for d, dirs, files in os.walk(self.top):
            g = '/' + os.path.relpath(d, self.top).replace(os.sep, '/')
            g = '/' if g == '/.' else g
            if g.startswith('/etc/hpuxemu'):
                continue
            for n in [None] + dirs + files:
                p = d if n is None else os.path.join(d, n)
                gp = g if n is None else g.rstrip('/') + '/' + n
                if n is not None and n in dirs and not os.path.islink(p):
                    continue                                    # comes as its own d
                st = os.lstat(p)
                fmt = stat.S_IFMT(st.st_mode)
                typ = {stat.S_IFDIR: 'd', stat.S_IFREG: 'f', stat.S_IFLNK: 's'}.get(fmt)
                if typ is None:
                    self.devices.append('%s %o %d %d %d %d' % (gp, st.st_mode, st.st_uid, st.st_gid,
                                                              os.major(st.st_rdev), os.minor(st.st_rdev)))
                    continue
                self.owners[gp] = (st.st_mode & 0o7777, st.st_uid, st.st_gid, typ)
                self.count += 1

    def finish(self):
        # directories last: a read-only one must not stop its own files
        for h, perm in self.dirmodes.items():
            try:
                os.chmod(h, perm | 0o700)
            except OSError:
                pass


def tar_checksum_ok(head):
    """an old (V7) tar header: no magic, but the checksum fits"""
    if len(head) < 512 or not head.strip(b'\0'):
        return False
    try:
        want = int(head[148:156].split(b'\0')[0].strip() or b'0', 8)
    except ValueError:
        return False
    return want == sum(head[:148]) + 8 * 32 + sum(head[156:512])


def node_name(root):
    """HOSTNAME of /etc/rc.config.d/netconf"""
    try:
        for line in open(os.path.join(root, 'etc/rc.config.d/netconf'), encoding='latin-1'):
            line = line.strip()
            if line.startswith('HOSTNAME='):
                name = line.split('=', 1)[1].split('#')[0].strip().strip('"\'')
                if name and '$' not in name:
                    return name
    except OSError:
        pass
    return ''


def main(argv):
    release = hostname = None
    args = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '--release':
            i += 1
            release = argv[i]
        elif a == '--hostname':
            i += 1
            hostname = argv[i]
        elif a in ('-h', '--help'):
            sys.stdout.write(__doc__)
            return 0
        else:
            args.append(a)
        i += 1
    if not args:
        sys.stderr.write(__doc__)
        return 2
    root, archives = os.path.abspath(args[0]), args[1:]
    for a in archives:
        if not os.path.isfile(a):
            sys.stderr.write('adopt: %s: no such file\n' % a)
            return 2
    if not archives and not os.path.isdir(root):
        sys.stderr.write('adopt: %s is not a directory (and no archive was given)\n' % root)
        return 2
    os.makedirs(os.path.join(root, 'etc/hpuxemu'), exist_ok=True)
    ad = Adopter(root)
    had_table = bool(mkroot.read_owners(root))
    if archives:
        for a in archives:
            print('adopt: %s' % a, flush=True)
            try:
                ad.archive(a)
            except (ValueError, tarfile.TarError, EOFError) as e:
                sys.stderr.write('adopt: %s: %s\n' % (a, e))
                return 1
        ad.finish()
    elif not had_table:
        ad.from_disk()
        me = os.getuid()
        if me != 0 and all(o[1] == me for o in ad.owners.values()):
            # copied as an ordinary user: the owners are gone, and root's is the best guess
            ad.owners = {g: (m, 0, 0, t) for g, (m, u, gid, t) in ad.owners.items()}
            print('adopt: every file here is yours, so HP-UX\'s owners are lost: all recorded as root\'s.\n'
                  '       (An archive given to adopt, or a copy made as root, keeps them.)')
        else:
            print('adopt: owners and modes taken from the files on disk')
    if not os.path.exists(os.path.join(root, 'usr/lib/dld.sl')):
        sys.stderr.write('adopt: %s has no /usr/lib/dld.sl: not an HP-UX root (was /usr in the archive?)\n' % root)
        return 1

    owners = mkroot.read_owners(root)
    owners.update(ad.owners)
    mkroot.write_owners(root, owners)
    if ad.devices:
        p = os.path.join(root, 'etc/hpuxemu/disk-devices')
        old = [x for x in (open(p).read().split('\n') if os.path.exists(p) else []) if x and not x.startswith('#')]
        with open(p, 'w') as f:
            f.write('# the device files, FIFOs and sockets of the machine: path mode uid gid major minor\n')
            f.write('\n'.join(sorted(set(old + ad.devices))) + '\n')

    if release is None:
        rp = os.path.join(root, 'etc/hpuxemu/release')
        if os.path.exists(rp) and not archives:
            release = open(rp).read().strip()
        else:
            release = 'B.11.00' if os.path.exists(os.path.join(root, 'usr/lib/libc.2')) else 'B.10.20'
    mkroot.make_dirs(root)
    with open(os.path.join(root, 'etc/hpuxemu/release'), 'w') as f:
        f.write(release + '\n')
    for name in ('wtmp', 'btmp', 'utmp'):
        p = os.path.join(root, 'var/adm', name)
        if not os.path.exists(p):
            open(p, 'wb').close()

    hp = os.path.join(root, 'etc/hpuxemu/hostname')
    if hostname is None and not os.path.exists(hp):
        hostname = node_name(root)
    if hostname:
        with open(hp, 'w') as f:
            f.write(hostname + '\n')
    name = (open(hp).read().strip() if os.path.exists(hp) else '') or 'hpux'
    mkroot.hosts(root)

    print('adopt: %s is an hpuxemu root: HP-UX %s, node name %s, %d files in the owners table%s' % (
        root, release, name, len(owners),
        ', %d device files listed in etc/hpuxemu/disk-devices' % len(ad.devices) if ad.devices else ''))
    for e in ad.skipped[:20]:
        print('adopt: left out: ' + e)
    if len(ad.skipped) > 20:
        print('adopt: ... and %d more' % (len(ad.skipped) - 20))
    addr = ''
    try:
        for line in open(os.path.join(root, 'etc/hosts'), encoding='latin-1'):
            f = line.split('#')[0].split()
            if len(f) > 1 and name in f[1:]:
                addr = f[0]
                break
    except OSError:
        pass
    if addr and not addr.startswith('127.'):
        print('adopt: /etc/hosts gives %s the address %s. Programs that connect to their own host\n'
              '       need that to be an address of this machine: change the line (127.0.0.1 will do\n'
              '       for most), or give this machine the address.' % (name, addr))
    if release == 'B.11.00' and not os.path.exists(os.path.join(root, 'stand/hpuxemu/strd')):
        print('adopt: for RPC and CDE on 11.00 (TCP and UDP through TLI), build the STREAMS daemon once:\n'
              '       python3 tools/mkstrd.py %s none' % root)
    print('adopt: try it:  hpuxemu -r %s /usr/bin/sh -c "uname -a; id; ls /"' % root)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
