#!/usr/bin/env python3
"""hpdisk.py - an HP-UX disk image (a dd of a whole disk or of one logical volume) to tar.

    python3 tools/hpdisk.py info IMAGE           what is on it: LIF, LVM, the file systems
    python3 tools/hpdisk.py tar IMAGE OUT.tar    every file system in one tar, each at its
                                                 mount point (from the image's /etc/fstab)
    python3 tools/hpdisk.py tar IMAGE OUT.tar --fs N    file system N of "info" alone
    python3 tools/hpdisk.py ls IMAGE N [PATH]    a directory of file system N
    python3 tools/hpdisk.py root IMAGE DIR       an hpuxemu root straight away: the files
                                                 written as the user, HP-UX's owners in
                                                 DIR/etc/hpuxemu/owners (no sudo needed)

Reads only; nothing is mounted, no root needed, no kernel modules (WSL2's kernel has
neither ufs nor vxfs). Reads HP's HFS (the BSD FFS of HP-UX, long and short file
names) and VxFS (JFS) disk layouts 2 to 4, all big-endian, as on the disk. The tar
keeps HP-UX's numeric owners, modes, symbolic and hard links, device files and times;
extract it with  tar --numeric-owner -xpf OUT.tar -C DIR  (as root, for the owners and
device files). For the emulator, "root" is simpler: it writes the files as the user
and keeps HP-UX's owners in the table the emulator reads, as hpuxemu.mkroot does.

The file systems are found by their superblocks. In an LVM volume group a logical
volume need not be contiguous (lvextend adds extents wherever there is room), so the
physical extent map of the volume group descriptor area is found too and used; when
it is not found, each file system is read as if contiguous, with a warning.
"""
import argparse
import io
import os
import struct
import sys
import tarfile

BE32 = struct.Struct('>I')
LIF_MAGIC = 0x8000
HFS_MAGICS = {0x011954: 'hfs', 0x095014: 'hfs-lfn', 0x195612: 'hfs', 0x05231994: 'hfs-lfn',
              0x612195: 'hfs-sec'}
VX_MAGIC = 0xa501fcf5
VX_OLTMAGIC = 0xa504fcf5
S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0o170000, 0o040000, 0o100000, 0o120000
S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK = 0o020000, 0o060000, 0o010000, 0o140000


def u32(b, o):
    return BE32.unpack_from(b, o)[0]


def u16(b, o):
    return struct.unpack_from('>H', b, o)[0]


def u64(b, o):
    return struct.unpack_from('>Q', b, o)[0]


class Image:
    """the image, and an LVM logical volume's logical-to-physical map over it"""

    def __init__(self, path):
        self.f = open(path, 'rb')
        self.f.seek(0, 2)
        self.size = self.f.tell()

    def pread(self, off, n):
        self.f.seek(off)
        return self.f.read(n)


class Volume:
    """a byte range of the image: contiguous, or a list of (logical offset, physical
    offset, length) pieces from the LVM extent map"""

    def __init__(self, img, start, length, pieces=None):
        self.img = img
        self.start = start
        self.length = length
        self.pieces = pieces

    def read(self, off, n):
        if self.pieces is None:
            return self.img.pread(self.start + off, n).ljust(n, b'\0')
        out = bytearray()
        while n > 0:
            for lo, po, ln in self.pieces:
                if lo <= off < lo + ln:
                    k = min(n, lo + ln - off)
                    out += self.img.pread(po + off - lo, k).ljust(k, b'\0')
                    off += k
                    n -= k
                    break
            else:
                out += b'\0' * n
                break
        return bytes(out)


# ---------------------------------------------------------------- HFS
class HFS:
    """HP-UX HFS: superblock at 8 KB, offsets of struct fs from <sys/fs.h> (10.20)"""
    ROOTINO = 2

    def __init__(self, vol):
        self.vol = vol
        sb = vol.read(8192, 2048)
        self.magic = u32(sb, 1372)
        if self.magic not in HFS_MAGICS:
            raise ValueError('no HFS superblock')
        self.kind = HFS_MAGICS[self.magic]
        (self.sblkno, self.cblkno, self.iblkno, self.dblkno, self.cgoffset,
         self.cgmask) = struct.unpack_from('>6i', sb, 8)
        self.size = u32(sb, 36)
        self.ncg = u32(sb, 44)
        self.bsize, self.fsize, self.frag = struct.unpack_from('>3i', sb, 48)
        self.nindir = u32(sb, 116)
        self.inopb = u32(sb, 120)
        self.ipg, self.fpg = struct.unpack_from('>2i', sb, 184)
        self.fsmnt = sb[212:212 + 512].split(b'\0')[0].decode('latin-1')
        self.ident = ('hfs', self.magic, self.size, self.ncg, sb[128:136])
        self.bytes = self.size * self.fsize
        if not (512 <= self.fsize <= self.bsize <= 65536) or self.ipg <= 0 or self.inopb <= 0:
            raise ValueError('implausible HFS superblock')

    def label(self):
        return self.fsmnt

    def cgimin(self, c):
        return self.fpg * c + self.cgoffset * (c & ~self.cgmask) + self.iblkno

    def inode(self, ino):
        c, i = divmod(ino, self.ipg)
        frag = self.cgimin(c) + (i // self.inopb) * self.frag
        b = self.vol.read(frag * self.fsize + (i % self.inopb) * 128, 128)
        mode = u16(b, 0)
        nlink = struct.unpack_from('>h', b, 2)[0]
        uid = u16(b, 112) << 16 | u16(b, 4)
        gid = u16(b, 114) << 16 | u16(b, 6)
        size = u64(b, 8)
        atime, mtime = u32(b, 16), u32(b, 24)
        db = struct.unpack_from('>12I', b, 40)
        ib = struct.unpack_from('>3I', b, 88)
        flags = u32(b, 100)
        return {'mode': mode, 'nlink': nlink, 'uid': uid, 'gid': gid, 'size': size,
                'mtime': mtime, 'atime': atime, 'db': db, 'ib': ib, 'flags': flags,
                'raw': b, 'rdev': db[0]}

    def blocks(self, ino):
        """the fragment addresses of the file's logical blocks (0: a hole)"""
        out = list(ino['db'])
        need = (ino['size'] + self.bsize - 1) // self.bsize

        def indir(addr, level):
            if len(out) >= need:
                return
            if addr == 0:
                out.extend([0] * min(self.nindir ** (level + 1), need - len(out)))
                return
            data = self.vol.read(addr * self.fsize, self.bsize)
            for k in range(self.nindir):
                if len(out) >= need:
                    return
                a = u32(data, 4 * k)
                if level == 0:
                    out.append(a)
                else:
                    indir(a, level - 1)
        for lvl, a in enumerate(ino['ib']):
            indir(a, lvl)
        return out[:need]

    def read_file(self, ino):
        size = ino['size']
        for k, a in enumerate(self.blocks(ino)):
            n = min(self.bsize, size - k * self.bsize)
            yield self.vol.read(a * self.fsize, n) if a else b'\0' * n

    def readlink(self, ino):
        if ino['flags'] & 1:            # IC_FASTLINK: in the inode itself
            return ino['raw'][40:40 + ino['size']]
        return b''.join(self.read_file(ino))[:ino['size']]

    def dirents(self, ino):
        data = b''.join(self.read_file(ino))
        o = 0
        while o + 8 <= len(data):
            d_ino, reclen, namlen = struct.unpack_from('>IHH', data, o)
            if reclen < 8:
                o = (o // 512 + 1) * 512    # a damaged block: on to the next one
                continue
            if d_ino and namlen:
                name = data[o + 8:o + 8 + namlen]
                if name not in (b'.', b'..'):
                    yield name, d_ino
            o += reclen


# ---------------------------------------------------------------- VxFS
class VxFS:
    """VxFS (JFS) disk layouts 2-4: superblock at 8 KB; the object location table
    names the structural inode list; its fileset headers name the primary fileset's
    inode list (struct vx_fsdisk, vx_olt*, vx_fsethead, vx_icommon of <sys/fs/vx_*.h>)"""
    ROOTINO = 2

    def __init__(self, vol):
        self.vol = vol
        sb = vol.read(8192, 1024)
        if u32(sb, 0) != VX_MAGIC:
            raise ValueError('no VxFS superblock')
        self.version = u32(sb, 4)
        self.bsize = u32(sb, 0x20)
        self.size = u32(sb, 0x24)
        self.bytes = self.size * self.bsize
        self.ident = ('vxfs', sb[8:16], self.size)
        if self.version < 2:
            raise ValueError('VxFS disk layout version %d (only 2 and later)' % self.version)
        olt0 = u32(sb, 0x170)
        self.dinosize = u32(sb, 0x184) or 256
        self.fname = sb[0xc0 + 0x9c:0xc0 + 0x9c + 6]       # fsw_fname (labelit)
        # the object location table
        olt = vol.read(olt0 * self.bsize, u32(sb, 0x178) * self.bsize or self.bsize)
        if u32(olt, 0) != VX_OLTMAGIC:
            raise ValueError('VxFS: no object location table')
        o = u32(olt, 4)
        self.iext = self.fshino = None
        while o + 8 <= len(olt):
            t, n = u32(olt, o), u32(olt, o + 4)
            if t == 4:                       # VX_OLTILIST
                self.iext = u32(olt, o + 8)
            elif t == 2:                     # VX_OLTFSHEAD
                self.fshino = u32(olt, o + 8)
            if n < 8:
                break
            o += n
        if self.iext is None or self.fshino is None:
            raise ValueError('VxFS: object location table without inode list or fileset header')
        # structural inodes: first from the initial extent, then through the structural
        # fileset's own inode list file
        self._st_ilist = None
        fsh = self.st_inode(self.fshino)
        fshdata = b''.join(self.read_file(fsh))
        st = fshdata[0:self.bsize]
        pr = fshdata[self.bsize:2 * self.bsize]
        if len(pr) < 0x40:
            raise ValueError('VxFS: no primary fileset header')
        self._st_ilist = self.st_inode(u32(st, 0x30))
        self.ilist = self.st_inode(u32(pr, 0x30))
        self.ilist_ext = self.extents(self.ilist)

    def label(self):
        return self.fname.split(b'\0')[0].decode('latin-1')

    def parse_inode(self, b):
        orgtype = b[0x31]
        return {'mode': u32(b, 0), 'nlink': u32(b, 4), 'uid': u32(b, 8), 'gid': u32(b, 12),
                'size': u64(b, 0x10), 'atime': u32(b, 0x18), 'mtime': u32(b, 0x20),
                'orgtype': orgtype, 'rdev': u32(b, 0x38), 'raw': b}

    def st_inode(self, ino):
        if self._st_ilist is None:
            return self.parse_inode(self.vol.read(self.iext * self.bsize + ino * self.dinosize,
                                                  self.dinosize))
        return self.parse_inode(self.file_bytes(self._st_ilist, ino * self.dinosize,
                                                self.dinosize))

    def inode(self, ino):
        return self.parse_inode(self.file_bytes(self.ilist, ino * self.dinosize,
                                                self.dinosize, self.ilist_ext))

    def extents(self, ino):
        """(file block, disk block, blocks) for the file's data, in order"""
        b = ino['raw']
        out = []
        if ino['orgtype'] == 1:                         # IORG_EXT4
            fb = 0
            for k in range(10):
                de, des = u32(b, 0x60 + 8 * k), u32(b, 0x64 + 8 * k)
                if des:
                    out.append((fb, de, des))
                fb += des
            ies = u32(b, 0x50)
            nind = self.bsize // 4

            def ind(addr, level):
                nonlocal fb
                if addr == 0:
                    return
                data = self.vol.read(addr * self.bsize, self.bsize)
                for k in range(nind):
                    a = u32(data, 4 * k)
                    if level == 0:
                        if a:
                            out.append((fb, a, ies))
                        fb += ies
                    else:
                        ind(a, level - 1)
            for lvl in range(3):
                ind(u32(b, 0x54 + 4 * lvl), lvl)
        elif ino['orgtype'] == 3:                       # IORG_TYPED
            def typed(data, count):
                for k in range(count):
                    hdr = u64(data, 16 * k)
                    t, off = hdr >> 56, hdr & ((1 << 56) - 1)
                    start, size = u32(data, 16 * k + 8), u32(data, 16 * k + 12)
                    if t == 2 or t == 4:               # data (or data on a device)
                        out.append((off, start, size))
                    elif t == 1 or t == 3:             # indirect address extent
                        typed(self.vol.read(start * self.bsize, size * self.bsize),
                              size * self.bsize // 16)
            typed(b[0x50:0xb0], 6)
        out.sort()
        return out

    def file_bytes(self, ino, off, n, exts=None):
        if ino['orgtype'] == 2:                         # IORG_IMMED
            return ino['raw'][0x50 + off:0x50 + off + n].ljust(n, b'\0')
        out = bytearray()
        for fb, db, cnt in (exts if exts is not None else self.extents(ino)):
            lo, hi = fb * self.bsize, (fb + cnt) * self.bsize
            if hi <= off or lo >= off + n:
                continue
            a, z = max(lo, off), min(hi, off + n)
            if len(out) < a - off:
                out += b'\0' * (a - off - len(out))
            out[a - off:z - off] = self.vol.read(db * self.bsize + a - lo, z - a)
        return bytes(out).ljust(n, b'\0')

    def read_file(self, ino):
        size = ino['size']
        if ino['orgtype'] == 2:
            yield ino['raw'][0x50:0x50 + size]
            return
        exts = self.extents(ino)
        step = 1 << 20
        for off in range(0, size, step):
            yield self.file_bytes(ino, off, min(step, size - off), exts)

    def readlink(self, ino):
        return b''.join(self.read_file(ino))[:ino['size']]

    def dirents(self, ino):
        data = b''.join(self.read_file(ino))
        blk = len(data) if ino['orgtype'] == 2 else self.bsize
        for base in range(0, len(data), blk):
            block = data[base:base + blk]
            if len(block) < 4:
                break
            nhash = u16(block, 2)
            o = 4 + 2 * nhash
            while o + 10 <= len(block):
                d_ino, reclen, namlen = struct.unpack_from('>IHH', block, o)
                if reclen < 10 or o + reclen > len(block):
                    break
                if d_ino and namlen:
                    name = block[o + 10:o + 10 + namlen]
                    if name not in (b'.', b'..'):
                        yield name, d_ino
                o += reclen


# ---------------------------------------------------------------- the disk
def find_filesystems(img):
    """(offset, class) of every superblock found at a 1 KB boundary"""
    found = []
    step = 8 << 20
    off = 0
    hfs_at = {}
    pats = [(struct.pack('>I', VX_MAGIC), 0)] + [(struct.pack('>I', m), 1372) for m in HFS_MAGICS]
    while off < img.size:
        chunk = img.pread(off, step + 2048)
        for pat, at in pats:
            k = chunk.find(pat)
            while 0 <= k < step + at:
                pos = off + k - at                  # where the superblock starts
                if (k - at) % 1024 == 0 and pos >= 8192:
                    if at == 0:
                        found.append((pos - 8192, VxFS))
                    else:
                        hfs_at[pos - 8192] = 1
                k = chunk.find(pat, k + 1)
        off += step
    for s in hfs_at:
        found.append((s, HFS))
    # a file system's backup superblocks are inside it: keep the first of each
    found.sort()
    out = []
    for s, cls in found:
        try:
            fs = cls(Volume(img, s, img.size - s))
        except Exception:
            continue
        # a backup superblock inside a file system found; one elsewhere with the same
        # identity (in an extent of its own, a logical volume not being contiguous)
        # stays a candidate for the LVM map to decide
        if any(o <= s < o + f.bytes for o, f in out):
            continue
        out.append((s, fs))
    return out


def pick(cands, lvm=None):
    """one (offset, fs) per file system: the candidate at an extent with le 0 when
    there is an LVM map, else the first"""
    groups = {}
    for s, fs in cands:
        groups.setdefault(fs.ident, []).append((s, fs))
    out = []
    for g in groups.values():
        best = g[0]
        if lvm and 'maps' in lvm:
            for s, fs in g:
                if s in lvm['fslv']:
                    best = (s, fs)
                    break
        out.append(best)
    return sorted(out, key=lambda x: x[0])


def lif_info(img):
    h = img.pread(0, 256)
    if len(h) < 32 or struct.unpack_from('>H', h, 0)[0] != LIF_MAGIC:
        return None
    dirstart = u32(h, 8) * 256
    names = []
    d = img.pread(dirstart, 8 * 256)
    for k in range(0, len(d), 32):
        name = d[k:k + 10].rstrip(b' \0')
        if struct.unpack_from('>h', d, k + 10)[0] == -1:
            break
        if name:
            names.append(name.decode('latin-1'))
    return h[2:8].decode('latin-1').strip(), names


def lvm_map(img, cands):
    """the logical volumes' extent maps from the volume group descriptor area. Its
    physical extent table has one (lv, le) pair of 16-bit numbers per physical extent
    (0, 0 for a free one); the boot volume /stand is lv 1 le 0 in physical extent 0.
    The table is the longest such run before the first file system; the extent size
    and where extent 0 starts are what puts most superblocks at an extent with le 0."""
    rec = img.pread(8192, 64)
    if rec[:8] != b'LVMREC01':
        return None
    if not cands:
        return {'lvmrec': True}
    end = min(s for s, fs in cands)
    head = img.pread(0, min(end, 16 << 20))
    best = None
    for t in range(8192 + 64, len(head) - 8, 4):
        lv, le = struct.unpack_from('>HH', head, t)
        if not (0 < lv <= 255 and le == 0):
            continue
        seen = {}
        n = 0
        while t + 4 * n + 4 <= len(head):
            lv, le = struct.unpack_from('>HH', head, t + 4 * n)
            if lv > 255 or (lv == 0 and le != 0) or le > 65000:
                break
            if lv:
                if le in seen.setdefault(lv, set()):
                    break
                seen[lv].add(le)
            n += 1
        while n and struct.unpack_from('>HH', head, t + 4 * (n - 1)) == (0, 0):
            n -= 1
        # every lv's extents 0..k-1, and more than one extent in all
        if all(x == set(range(len(x))) for x in seen.values()):
            score = sum(len(x) for x in seen.values())
            if score > 1 and (best is None or score > best[0]):
                best = (score, t, n)
    if best is None:
        return {'lvmrec': True}
    score, t, n = best
    table = [struct.unpack_from('>HH', head, t + 4 * p) for p in range(n)]
    le0 = {p for p, (lv, le) in enumerate(table) if lv and le == 0}
    choice = None
    for pe_mb in (4, 1, 2, 8, 16, 32, 64, 128, 256):
        pe = pe_mb << 20
        firsts = {}
        for s, fs in cands:
            for p in le0:
                f = s - p * pe
                if f >= 0:
                    firsts.setdefault(f, set()).add(s)
        for f, hit in firsts.items():
            if choice is None or len(hit) > len(choice[2]):
                choice = (pe, f, hit)
    if choice is None:
        return {'lvmrec': True}
    pe, first, hit = choice
    maps = {}
    for p, (lv, le) in enumerate(table):
        if lv:
            maps.setdefault(lv, {})[le] = first + p * pe
    fslv = {s: table[(s - first) // pe][0] for s in hit}
    return {'lvmrec': True, 'pe': pe, 'first': first, 'table_at': t, 'maps': maps,
            'fslv': fslv}


def volumes(img):
    """[(n, start, fs, lvnum or None)] with each fs re-opened on its LVM map"""
    cands = find_filesystems(img)
    lvm = lvm_map(img, cands)
    fss = pick(cands, lvm)
    out = []
    for n, (s, fs) in enumerate(fss):
        lv = None
        if lvm and 'maps' in lvm and s in lvm['fslv']:
            lv = lvm['fslv'][s]
            m = lvm['maps'][lv]
            pe = lvm['pe']
            pieces = [(le * pe, m[le], pe) for le in sorted(m)]
            fs = type(fs)(Volume(img, s, len(m) * pe, pieces))
        out.append((n, s, fs, lv))
    return out, lvm


def fstab_of(fs):
    try:
        ino = lookup(fs, b'etc/fstab')
        return b''.join(fs.read_file(fs.inode(ino))).decode('latin-1')
    except Exception:
        return None


def lookup(fs, path):
    ino = fs.ROOTINO
    for part in path.strip(b'/').split(b'/'):
        if not part:
            continue
        for name, i in fs.dirents(fs.inode(ino)):
            if name == part:
                ino = i
                break
        else:
            raise FileNotFoundError(path)
    return ino


def mountpoints(vols, lvm):
    """file system number -> mount point: from the root's /etc/fstab and the LVM map,
    else from HFS's last-mounted name"""
    mp = {}
    root = None
    for n, s, fs, lv in vols:
        tab = fstab_of(fs)
        if tab and '/' in [l.split()[1] for l in tab.splitlines()
                           if l.strip() and not l.startswith('#') and len(l.split()) > 1]:
            root = (n, tab)
            break
    if isinstance(vols, list):
        for n, s, fs, lv in vols:
            if isinstance(fs, HFS) and fs.fsmnt.startswith('/'):
                mp[n] = fs.fsmnt
    if root:
        n0, tab = root
        mp[n0] = '/'
        bylv = {}
        for line in tab.splitlines():
            f = line.split()
            if len(f) > 1 and not line.startswith('#') and 'lvol' in f[0]:
                try:
                    bylv[int(f[0].rsplit('lvol', 1)[1])] = f[1]
                except ValueError:
                    pass
        # the LVM's lv numbers against fstab's lvolN: lvolN is lv N (or N-1), found by
        # the HFS /stand or the root
        if lvm and 'fslv' in lvm:
            lv_of = {n: lv for n, s, fs, lv in vols if lv}
            for shift in (0, 1, -1):
                if all(bylv.get(lv_of[n] + shift, mp.get(n)) == mp.get(n)
                       for n in mp if n in lv_of):
                    for n, lv in lv_of.items():
                        if lv + shift in bylv:
                            mp[n] = bylv[lv + shift]
                    break
        # without the LVM map: what is left by what is in it
        want = [m for m in bylv.values() if m not in mp.values()]
        sig = {'/usr': {b'bin', b'lib', b'include'}, '/var': {b'adm', b'spool'},
               '/stand': {b'vmunix'}, '/tmp': set(), '/home': set(), '/opt': set()}
        left = [v for v in vols if v[0] not in mp]
        for n, s, fs, lv in left:
            try:
                names = {nm for nm, i in fs.dirents(fs.inode(fs.ROOTINO))}
            except Exception:
                continue
            for m in want:
                if sig.get(m) and sig[m] <= names:
                    mp[n] = m
                    want.remove(m)
                    break
        left = [v for v in vols if v[0] not in mp]
        if len(left) == 1 and len(want) == 1:
            mp[left[0][0]] = want[0]
    return mp


def info(path):
    img = Image(path)
    print('%s: %d bytes (%.1f GB)' % (path, img.size, img.size / 1e9))
    lif = lif_info(img)
    if lif:
        print('LIF volume %r: %s' % (lif[0], ' '.join(lif[1])))
    vols, lvm = volumes(img)
    if lvm:
        if 'maps' in lvm:
            print('LVM: physical extents of %d MB from offset %d; extent table at %d; %d logical volumes'
                  % (lvm['pe'] >> 20, lvm['first'], lvm['table_at'], len(lvm['maps'])))
        else:
            print('LVM: LVMREC01 found, extent table not found: file systems read as contiguous')
    mp = mountpoints(vols, lvm)
    for n, s, fs, lv in vols:
        kind = type(fs).__name__ + ('/' + fs.kind if isinstance(fs, HFS) else ' layout %d' % fs.version)
        print('  fs %d at %d: %s, %.0f MB%s%s%s' % (
            n, s, kind, fs.bytes / 1e6,
            ', lv %d' % lv if lv else '',
            ', label %r' % fs.label() if fs.label() else '',
            ', mounted on %s' % mp[n] if n in mp else ''))
    if not vols:
        print('  no HFS or VxFS file system found')


def walk(fs, ino, path, seen, tf, prefix, fsid, errors):
    try:
        entries = list(fs.dirents(fs.inode(ino)))
    except Exception as e:
        errors.append('%s: %s' % (path, e))
        return
    for name, child in entries:
        p = path + '/' + name.decode('latin-1')
        try:
            i = fs.inode(child)
        except Exception as e:
            errors.append('%s: %s' % (p, e))
            continue
        add(fs, child, i, p, seen, tf, prefix, fsid, errors)
        if (i['mode'] & S_IFMT) == S_IFDIR:
            walk(fs, child, p, seen, tf, prefix, fsid, errors)


class _Reader(io.RawIOBase):
    def __init__(self, gen):
        self.gen = gen
        self.buf = b''

    def readable(self):
        return True

    def readinto(self, b):
        while not self.buf:
            try:
                self.buf = next(self.gen)
            except StopIteration:
                return 0
        n = min(len(b), len(self.buf))
        b[:n] = self.buf[:n]
        self.buf = self.buf[n:]
        return n


def add(fs, ino, i, path, seen, tf, prefix, fsid, errors):
    name = (prefix + path).lstrip('/') or '.'
    t = tarfile.TarInfo(name)
    t.mode = i['mode'] & 0o7777
    t.uid, t.gid = i['uid'], i['gid']
    t.uname = t.gname = ''
    t.mtime = i['mtime']
    fmt = i['mode'] & S_IFMT
    key = (fsid, ino)
    if fmt != S_IFDIR and i['nlink'] > 1:
        if key in seen:
            t.type = tarfile.LNKTYPE
            t.linkname = seen[key]
            tf.addfile(t)
            return
        seen[key] = name
    try:
        if fmt == S_IFDIR:
            t.type = tarfile.DIRTYPE
            tf.addfile(t)
        elif fmt == S_IFREG:
            t.size = i['size']
            tf.addfile(t, io.BufferedReader(_Reader(fs.read_file(i)), 1 << 20))
        elif fmt == S_IFLNK:
            t.type = tarfile.SYMTYPE
            t.linkname = fs.readlink(i).split(b'\0')[0].decode('latin-1')
            tf.addfile(t)
        elif fmt in (S_IFCHR, S_IFBLK):
            t.type = tarfile.CHRTYPE if fmt == S_IFCHR else tarfile.BLKTYPE
            t.devmajor, t.devminor = i['rdev'] >> 24, i['rdev'] & 0xffffff
            tf.addfile(t)
        elif fmt == S_IFIFO:
            t.type = tarfile.FIFOTYPE
            tf.addfile(t)
        else:
            errors.append('%s: skipped (mode %o)' % (path, i['mode']))
    except Exception as e:
        errors.append('%s: %s' % (path, e))


def dotar(path, out, only):
    img = Image(path)
    vols, lvm = volumes(img)
    mp = mountpoints(vols, lvm)
    errors = []
    seen = {}
    order = sorted(vols, key=lambda v: (mp.get(v[0], '~'), v[0]))
    with tarfile.open(out, 'w', format=tarfile.GNU_FORMAT) as tf:
        for n, s, fs, lv in order:
            if only is not None and n != only:
                continue
            prefix = '' if only is not None else mp.get(n)
            if prefix is None:
                prefix = '/fs%d' % n
                print('hpdisk: fs %d has no mount point: under %s' % (n, prefix))
            print('hpdisk: fs %d -> %s' % (n, prefix or '/'), flush=True)
            root = fs.inode(fs.ROOTINO)
            add(fs, fs.ROOTINO, root, '', seen, tf, prefix, n, errors)
            walk(fs, fs.ROOTINO, '', seen, tf, prefix, n, errors)
    for e in errors[:50]:
        print('hpdisk: ' + e)
    if len(errors) > 50:
        print('hpdisk: ... %d more' % (len(errors) - 50))
    print('hpdisk: %s written; %d errors' % (out, len(errors)))


class RootWriter:
    """the files into DIR as the host user; HP-UX's owners and modes into the owners
    table; device files only listed (the emulator has its own devices)"""

    def __init__(self, top):
        self.top = top
        self.owners = {}
        self.devices = []
        self.links = {}

    def host(self, gpath):
        return os.path.join(self.top, gpath.lstrip('/'))

    def put(self, fs, ino, i, gpath, fsid, errors):
        h = self.host(gpath)
        fmt = i['mode'] & S_IFMT
        mode = i['mode'] & 0o7777
        key = (fsid, ino)
        try:
            if fmt != S_IFDIR and i['nlink'] > 1 and key in self.links:
                if os.path.lexists(h):
                    os.unlink(h)
                os.link(self.host(self.links[key]), h)
                self.owners[gpath] = (mode, i['uid'], i['gid'], 'h')
                return
            if fmt == S_IFDIR:
                os.makedirs(h, exist_ok=True)
                os.chmod(h, mode | 0o700)
                self.owners[gpath or '/'] = (mode, i['uid'], i['gid'], 'd')
            elif fmt == S_IFREG:
                with open(h, 'wb') as f:
                    for chunk in fs.read_file(i):
                        f.write(chunk)
                os.chmod(h, mode | 0o600)
                os.utime(h, (i['atime'], i['mtime']))
                self.owners[gpath] = (mode, i['uid'], i['gid'], 'f')
            elif fmt == S_IFLNK:
                if os.path.lexists(h):
                    os.unlink(h)
                os.symlink(fs.readlink(i).split(b'\0')[0].decode('latin-1'), h)
                self.owners[gpath] = (mode, i['uid'], i['gid'], 's')
            elif fmt in (S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK):
                self.devices.append('%s %o %d %d %d %d' % (
                    gpath, i['mode'], i['uid'], i['gid'], i['rdev'] >> 24, i['rdev'] & 0xffffff))
                return
            if fmt != S_IFDIR and i['nlink'] > 1:
                self.links[key] = gpath
        except OSError as e:
            errors.append('%s: %s' % (gpath, e))

    def walk(self, fs, ino, gpath, fsid, errors):
        try:
            entries = list(fs.dirents(fs.inode(ino)))
        except Exception as e:
            errors.append('%s: %s' % (gpath, e))
            return
        for name, child in entries:
            p = gpath.rstrip('/') + '/' + name.decode('latin-1')
            try:
                i = fs.inode(child)
            except Exception as e:
                errors.append('%s: %s' % (p, e))
                continue
            self.put(fs, child, i, p, fsid, errors)
            if (i['mode'] & S_IFMT) == S_IFDIR:
                self.walk(fs, child, p, fsid, errors)
        try:
            d = fs.inode(ino)
            os.chmod(self.host(gpath), (d['mode'] & 0o7777) | 0o700)
        except Exception:
            pass


def doroot(path, top):
    img = Image(path)
    vols, lvm = volumes(img)
    mp = mountpoints(vols, lvm)
    if not any(m == '/' for m in mp.values()):
        print('hpdisk: no root file system (one with /etc/fstab naming /) on %s' % path)
        return 1
    os.makedirs(top, exist_ok=True)
    w = RootWriter(top)
    errors = []
    for n, s, fs, lv in sorted(vols, key=lambda v: (mp.get(v[0], '~'), v[0])):
        if n not in mp:
            print('hpdisk: fs %d has no mount point in /etc/fstab: left out' % n)
            continue
        print('hpdisk: fs %d -> %s' % (n, mp[n]), flush=True)
        os.makedirs(w.host(mp[n]), exist_ok=True)
        w.put(fs, fs.ROOTINO, fs.inode(fs.ROOTINO), mp[n] if mp[n] != '/' else '', n, errors)
        w.walk(fs, fs.ROOTINO, mp[n] if mp[n] != '/' else '', n, errors)
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
    from hpuxemu import mkroot
    os.makedirs(os.path.join(top, 'etc/hpuxemu'), exist_ok=True)
    old = mkroot.read_owners(top)
    old.update(w.owners)
    mkroot.write_owners(top, old)
    with open(os.path.join(top, 'etc/hpuxemu/disk-devices'), 'w') as f:
        f.write('# the device files of the disk: path mode uid gid major minor\n')
        f.write('\n'.join(w.devices) + '\n')
    release = 'B.11.00' if os.path.exists(os.path.join(top, 'usr/lib/libc.2')) else 'B.10.20'
    mkroot.make_dirs(top)
    with open(os.path.join(top, 'etc/hpuxemu/release'), 'w') as f:
        f.write(release + '\n')
    for e in errors[:50]:
        print('hpdisk: ' + e)
    if len(errors) > 50:
        print('hpdisk: ... %d more' % (len(errors) - 50))
    print('hpdisk: %s is an hpuxemu root (HP-UX %s, %d files, %d device files listed in '
          'etc/hpuxemu/disk-devices); %d errors' % (top, release, len(w.owners), len(w.devices),
                                                    len(errors)))
    return 0


def dols(path, n, sub):
    img = Image(path)
    vols, lvm = volumes(img)
    fs = [v[2] for v in vols if v[0] == n][0]
    ino = lookup(fs, sub.encode())
    for name, i in sorted(fs.dirents(fs.inode(ino))):
        x = fs.inode(i)
        print('%7o %5d %5d %10d  %s' % (x['mode'], x['uid'], x['gid'], x['size'],
                                        name.decode('latin-1')))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('info')
    p.add_argument('image')
    p = sp.add_parser('tar')
    p.add_argument('image')
    p.add_argument('out')
    p.add_argument('--fs', type=int)
    p = sp.add_parser('root')
    p.add_argument('image')
    p.add_argument('dir')
    p = sp.add_parser('ls')
    p.add_argument('image')
    p.add_argument('fs', type=int)
    p.add_argument('path', nargs='?', default='/')
    a = ap.parse_args()
    if a.cmd == 'info':
        info(a.image)
    elif a.cmd == 'tar':
        dotar(a.image, a.out, a.fs)
    elif a.cmd == 'root':
        sys.exit(doroot(a.image, a.dir))
    else:
        dols(a.image, a.fs, a.path)


if __name__ == '__main__':
    main()
