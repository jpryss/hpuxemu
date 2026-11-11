"""depot.py - read SD-UX depots: the directory depot of an HP-UX CD (on ISO 9660 or copied to a
directory) and serial depots (`.depot` files, tar archives).

    python3 -m hpuxemu.depot SOURCE                  list products and filesets
    python3 -m hpuxemu.depot SOURCE PRODUCT/FILESET  list the fileset's files
    python3 -m hpuxemu.depot -x ROOT SOURCE PRODUCT/FILESET ...   extract into ROOT

Layout (verified on the 10.20 core CD, B3782-10101, and the 10.20 ACE serial depot):

    catalog/INDEX                        the distribution: bundles and products (keyword/value
                                         lines, multi-line quoted strings, `vendor ... end`)
    catalog/PRODUCT/pfiles/INDEX, INFO   the product's INDEX (filesets, control files)
    catalog/PRODUCT/FILESET/INDEX        the fileset's attributes
    catalog/PRODUCT/FILESET/INFO         its control files and files: records starting with
                                         `file` or `control_file`, keys path type (f d s h)
                                         mode uid gid owner group size cksum mtime link_source
                                         compr_type (gzip) compr_cksum compr_size
    PRODUCT/FILESET/<path>               the file, gzip-compressed when compr_type says so
                                         (a directory depot stores it under its full path)

A serial depot is a ustar archive with the same member names. `cksum` is POSIX cksum (CRC-32
with the length appended); extraction verifies it.
"""
import gzip
import io
import os
import stat
import sys
import tarfile
import zlib

from . import iso9660

# POSIX cksum: CRC-32 (polynomial 0x04C11DB7, not reflected) over the data, then over the
# length's bytes little-endian until it is zero, complemented.
_CKSUM_TABLE = []
for _i in range(256):
    _c = _i << 24
    for _ in range(8):
        _c = ((_c << 1) ^ 0x04C11DB7) if _c & 0x80000000 else (_c << 1)
    _CKSUM_TABLE.append(_c & 0xFFFFFFFF)


def cksum(data):
    c = 0
    t = _CKSUM_TABLE
    for b in data:
        c = ((c << 8) & 0xFFFFFFFF) ^ t[(c >> 24) ^ b]
    n = len(data)
    while n:
        c = ((c << 8) & 0xFFFFFFFF) ^ t[(c >> 24) ^ (n & 0xFF)]
        n >>= 8
    return (~c) & 0xFFFFFFFF


def parse_attrs(text):
    """Parse an SD keyword/value file into a list of (keyword, value) pairs, in order.
    Values may be quoted strings spanning lines (with backslash escapes)."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        j = text.find('\n', i)
        if j < 0:
            j = n
        line = text[i:j]
        i = j + 1
        if not line.strip():
            continue
        k, _, v = line.partition(' ')
        v = v.lstrip()
        if v.startswith('"'):
            # quoted, possibly multi-line
            buf = []
            p = i - len(line) - 1 + len(k) + 1 + (len(line) - len(k) - 1 - len(v)) + 1  # after the quote
            p = text.find('"', i - len(line) - 1) + 1
            while True:
                q = text.find('"', p)
                if q < 0:
                    buf.append(text[p:])
                    p = n
                    break
                if text[q - 1] == '\\':
                    buf.append(text[p:q - 1] + '"')
                    p = q + 1
                    continue
                buf.append(text[p:q])
                p = q + 1
                break
            v = ''.join(buf)
            i = text.find('\n', p)
            i = n if i < 0 else i + 1
        out.append((k, v))
    return out


def parse_records(text, starters=('file', 'control_file')):
    """Split an INFO file into records: a list of dicts, each starting at a `file` or
    `control_file` line (the keyword is stored as 'kind')."""
    recs = []
    cur = None
    for k, v in parse_attrs(text):
        if k in starters:
            cur = {'kind': k}
            recs.append(cur)
        elif cur is not None:
            cur[k] = v
    return recs


def parse_index(text):
    """Split an INDEX file into objects: a list of dicts with 'kind' = distribution, bundle,
    product, subproduct, fileset, vendor ... (nested `vendor ... end` blocks are flattened)."""
    objs = []
    cur = None
    for k, v in parse_attrs(text):
        if k in ('distribution', 'bundle', 'product', 'subproduct', 'fileset', 'vendor', 'category', 'media'):
            cur = {'kind': k}
            objs.append(cur)
        elif k == 'end':
            cur = None
        elif cur is not None:
            cur[k] = v
    return objs


class Depot:
    """Common interface: products(), filesets(product), files(product, fileset), read(...)."""

    def read_text(self, member):
        return self.read(member).decode('latin1')

    def products(self):
        idx = parse_index(self.read_text('catalog/INDEX'))
        return [o for o in idx if o['kind'] == 'product']

    def bundles(self):
        idx = parse_index(self.read_text('catalog/INDEX'))
        return [o for o in idx if o['kind'] == 'bundle']

    def product_index(self, product):
        return parse_index(self.read_text('catalog/%s/pfiles/INDEX' % product))

    def filesets(self, product):
        """The product's filesets: `all_filesets` of its INDEX, each with the attributes of
        catalog/PRODUCT/FILESET/INDEX (tag, title, revision, size ...)."""
        out = []
        for o in self.product_index(product):
            if o['kind'] == 'product':
                for tag in o.get('all_filesets', '').split():
                    try:
                        objs = parse_index(self.read_text('catalog/%s/%s/INDEX' % (product, tag)))
                        fs = next((x for x in objs if x['kind'] == 'fileset'), {'kind': 'fileset'})
                    except FileNotFoundError:
                        fs = {'kind': 'fileset'}
                    fs['tag'] = tag
                    out.append(fs)
        return out

    def files(self, product, fileset):
        """The fileset's file records (kind == 'file'), as dicts."""
        recs = parse_records(self.read_text('catalog/%s/%s/INFO' % (product, fileset)))
        return [r for r in recs if r['kind'] == 'file']

    def product_control_files(self, product):
        """the names in catalog/PRODUCT/pfiles (INDEX, INFO, README, control_func ...)"""
        try:
            recs = parse_records(self.read_text('catalog/%s/pfiles/INFO' % product))
        except FileNotFoundError:
            recs = []
        names = [r['path'] for r in recs if r['kind'] == 'control_file']
        return sorted(set(names) | {'INDEX', 'INFO'})

    def control_files(self, product, fileset):
        recs = parse_records(self.read_text('catalog/%s/%s/INFO' % (product, fileset)))
        return [r for r in recs if r['kind'] == 'control_file']

    def file_data(self, product, fileset, rec):
        """The decompressed, checksum-verified contents of a `file` record of type f."""
        member = '%s/%s%s' % (product, fileset, rec['path'])
        data = self.read(member)
        # 10.20 depots say compr_type/compr_cksum; 11.00 depots spell them out
        # (compression_type, compression_cksum, compression_state)
        ctype = rec.get('compr_type', rec.get('compression_type'))
        ccks = rec.get('compr_cksum', rec.get('compression_cksum'))
        if rec.get('compression_state') == 'uncompressed':
            ctype = None
        if ctype == 'gzip':
            if ccks is not None and cksum(data) != int(ccks):
                raise IOError('%s: compressed checksum mismatch' % member)
            data = gzip.decompress(data)
        elif ctype not in (None, 'none'):
            raise IOError('%s: unknown compression %s' % (member, ctype))
        if 'cksum' in rec and cksum(data) != int(rec['cksum']):
            raise IOError('%s: checksum mismatch' % member)
        if 'size' in rec and len(data) != int(rec['size']):
            raise IOError('%s: size %d, expected %s' % (member, len(data), rec['size']))
        return data


class DirDepot(Depot):
    """A directory depot in a directory on disk."""

    def __init__(self, path):
        self.path = path

    def read(self, member):
        with open(os.path.join(self.path, member), 'rb') as f:
            return f.read()


class IsoDepot(Depot):
    """A directory depot on an ISO 9660 image."""

    def __init__(self, path):
        self.iso = iso9660.Iso(path)

    def read(self, member):
        e = self.iso.lookup(member)
        if e is None:
            raise FileNotFoundError(member)
        return self.iso.read(e)


class _Slice(io.RawIOBase):
    """A read-only file object over a byte range of another file (a tar inside an ISO)."""

    def __init__(self, f, start, size):
        self.f, self.start, self.size, self.pos = f, start, size, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, off, whence=0):
        if whence == 0:
            self.pos = off
        elif whence == 1:
            self.pos += off
        else:
            self.pos = self.size + off
        return self.pos

    def tell(self):
        return self.pos

    def readinto(self, b):
        n = min(len(b), max(0, self.size - self.pos))
        self.f.seek(self.start + self.pos)
        data = self.f.read(n)
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


class TarDepot(Depot):
    """A serial depot: a tar archive (the `.depot` files of HP's software site, the ACE CD -
    whose ISO 9660 file system holds the single file `Ace5_pb.00D`)."""

    def __init__(self, path, fileobj=None):
        self.tar = tarfile.open(path, 'r:', fileobj=fileobj)
        self.members = {m.name: m for m in self.tar.getmembers()}

    def read(self, member):
        m = self.members.get(member) or self.members.get('./' + member)
        if m is None:
            raise FileNotFoundError(member)
        return self.tar.extractfile(m).read()


def open_depot(source):
    """A Depot for an ISO image, a directory (depot or a directory holding `*.depot` files is
    not handled here), or a serial depot file."""
    if os.path.isdir(source):
        return DirDepot(source)
    with open(source, 'rb') as f:
        head = f.read(32768 + 8)
    if head[32768 + 1:32768 + 6] == b'CD001' or head[:2] == b'\x80\x00':
        iso = iso9660.Iso(source)
        if iso.lookup('catalog') is not None:
            return IsoDepot(source)
        # an ISO holding one serial depot file
        for p, e in iso.walk():
            if not e.isdir:
                return TarDepot(p, fileobj=io.BufferedReader(_Slice(iso.f, (e.extent + e.ear) * iso9660.BLOCK, e.size)))
        raise IOError('%s: neither a directory depot nor a serial depot' % source)
    return TarDepot(source)


def root_path(root, gpath):
    """The host path of guest path `gpath` under `root`, following symbolic links the way
    the guest would (an absolute link target is inside the root)."""
    parts = [x for x in gpath.split('/') if x not in ('', '.')]
    resolved = []
    hops = 0
    while parts:
        seg = parts.pop(0)
        if seg == '..':
            if resolved:
                resolved.pop()
            continue
        cand = os.path.join(root, *(resolved + [seg]))
        if parts and os.path.islink(cand):
            hops += 1
            if hops > 40:
                break
            target = os.readlink(cand)
            if target.startswith('/'):
                resolved = []
            parts = [x for x in target.split('/') if x not in ('', '.')] + parts
            continue
        resolved.append(seg)
    return os.path.join(root, *resolved) if resolved else root


def extract_fileset(depot, product, fileset, root, log=None, owners=None):
    """Extract one fileset into ROOT. Files belong to the host user; their HP-UX mode is
    applied (set-id bits included: the host ignores them for the host user, and the emulator
    reads them from `owners`). `owners` collects (path, mode, uid, gid) for every file."""
    files = depot.files(product, fileset)
    hardlinks = []
    for rec in files:
        path = rec['path']
        dest = root_path(root, path)
        t = rec.get('type', 'f')
        mode = int(rec.get('mode', '0644'), 8)
        if owners is not None:
            owners.append((path, mode, int(rec.get('uid', 0)), int(rec.get('gid', 0)), t))
        if t == 'd':
            os.makedirs(dest, exist_ok=True)
            os.chmod(dest, (mode | 0o700) & 0o7777)
        elif t == 'f':
            data = depot.file_data(product, fileset, rec)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if os.path.lexists(dest):
                os.unlink(dest)
            with open(dest, 'wb') as o:
                o.write(data)
            os.chmod(dest, (mode | 0o600) & 0o7777)
            if rec.get('mtime', '').isdigit():
                os.utime(dest, (int(rec['mtime']), int(rec['mtime'])))
        elif t == 's':
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if os.path.lexists(dest):
                os.unlink(dest)
            os.symlink(rec['link_source'], dest)
        elif t == 'h':
            hardlinks.append((dest, rec['link_source']))
        else:
            if log:
                log('%s/%s: %s: unknown type %s' % (product, fileset, path, t))
    for dest, src in hardlinks:
        srcp = root_path(root, src)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.lexists(dest):
            os.unlink(dest)
        try:
            os.link(srcp, dest)
        except OSError:
            if os.path.exists(srcp):
                with open(srcp, 'rb') as i, open(dest, 'wb') as o:
                    o.write(i.read())
                os.chmod(dest, os.stat(srcp).st_mode & 0o7777)
            elif log:
                log('%s/%s: hard link %s -> %s: source missing' % (product, fileset, dest, src))
    return len(files)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    if argv[1] == '-x':
        root = argv[2]
        depot = open_depot(argv[3])
        for pf in argv[4:]:
            product, fileset = pf.split('/')
            n = extract_fileset(depot, product, fileset, root, log=lambda s: print(s, file=sys.stderr))
            print('%s/%s: %d files' % (product, fileset, n))
        return 0
    depot = open_depot(argv[1])
    if len(argv) == 2:
        for p in depot.products():
            print('%s %s %s' % (p['tag'], p.get('revision', ''), p.get('title', '')))
            for fs in depot.filesets(p['tag']):
                print('    %-20s %s' % (fs['tag'], fs.get('title', '')))
    else:
        product, fileset = argv[2].split('/')
        for r in depot.files(product, fileset):
            print('%s %6s %8s %s%s' % (r['type'], r.get('mode', ''), r.get('size', ''), r['path'],
                                       (' -> ' + r['link_source']) if 'link_source' in r else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
