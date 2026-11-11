"""iso9660.py - a small ISO 9660 reader for HP-UX media (no Rock Ridge, no Joliet: HP's CDs
use plain level-2 names in mixed case and need neither).

    python3 -m hpuxemu.iso9660 IMAGE            list
    python3 -m hpuxemu.iso9660 IMAGE OUTDIR     extract everything

HP's mastering tool records directory sizes that can be short by whole sectors: the root of
the 10.20 core CD says 3 sectors and the `catalog` entry sits in a 4th. `readdir` therefore
keeps reading sectors after the recorded size while they hold well-formed records and do
not begin with the `.` entry of the next directory.

The 10.20 core CD is a hybrid: a LIF volume (boot loader, kernel, install file system) in
the last part of the image, and this ISO 9660 file system holding the SD-UX depot.
"""
import os
import struct
import sys

BLOCK = 2048


class Entry:
    __slots__ = ('name', 'extent', 'size', 'isdir', 'ear')

    def __init__(self, name, extent, size, isdir, ear):
        self.name, self.extent, self.size, self.isdir, self.ear = name, extent, size, isdir, ear


class Iso:
    def __init__(self, path):
        self.path = path
        self.f = open(path, 'rb')
        self.f.seek(16 * BLOCK)
        pvd = self.f.read(BLOCK)
        if pvd[1:6] != b'CD001':
            raise ValueError('%s: no ISO 9660 volume descriptor' % path)
        self.volume_id = pvd[40:72].decode('latin1').rstrip()
        self.root = self._rec(pvd[156:190])
        self._dircache = {}

    @staticmethod
    def _rec(r):
        ln = r[0]
        if ln == 0:
            return None
        ear = r[1]
        extent = struct.unpack('<I', r[2:6])[0]
        size = struct.unpack('<I', r[10:14])[0]
        flags = r[25]
        nl = r[32]
        name = r[33:33 + nl]
        if name == b'\x00':
            name = '.'
        elif name == b'\x01':
            name = '..'
        else:
            name = name.decode('latin1')
            if ';' in name:
                name = name.split(';')[0]
            if name.endswith('.'):
                name = name[:-1]
        return Entry(name, extent, size, bool(flags & 2), ear)

    @staticmethod
    def _sector_ok(sec):
        """Every record in the sector is well-formed (a directory continuation)."""
        off = 0
        seen = 0
        while off < len(sec):
            ln = sec[off]
            if ln == 0:
                return seen > 0 and not any(sec[off:])
            if ln < 34 or off + ln > len(sec) or sec[off + 1] != 0:
                return False
            nl = sec[off + 32]
            if nl == 0 or 33 + nl > ln or sec[off + 25] & ~3 or sec[off + 28:off + 32] != b'\x01\x00\x00\x01':
                return False
            nm = sec[off + 33:off + 33 + nl]
            if nm not in (b'\x00', b'\x01') and any(c < 32 or c > 126 for c in nm):
                return False
            off += ln
            seen += 1
        return seen > 0

    def readdir(self, rec):
        if rec.extent in self._dircache:
            return self._dircache[rec.extent]
        self.f.seek(rec.extent * BLOCK)
        data = self.f.read(rec.size)
        for _ in range(64):
            more = self.f.read(BLOCK)
            if len(more) < BLOCK or not self._sector_ok(more) or (more[32] == 1 and more[33] in (0, 1)):
                break
            data += more
        out = []
        off = 0
        while off < len(data):
            ln = data[off]
            if ln == 0:
                off = (off // BLOCK + 1) * BLOCK
                continue
            e = self._rec(data[off:off + ln])
            off += ln
            if e.name in ('.', '..'):
                continue
            out.append(e)
        self._dircache[rec.extent] = out
        return out

    def walk(self, rec=None, path=''):
        """Yield (path, Entry) for everything below `rec` (default: the root)."""
        rec = rec or self.root
        for e in self.readdir(rec):
            p = path + '/' + e.name
            yield p, e
            if e.isdir:
                yield from self.walk(e, p)

    def lookup(self, path):
        rec = self.root
        for part in path.strip('/').split('/'):
            if not part:
                continue
            if not rec.isdir:
                return None
            for e in self.readdir(rec):
                if e.name == part:
                    rec = e
                    break
            else:
                return None
        return rec

    def read(self, rec):
        self.f.seek((rec.extent + rec.ear) * BLOCK)
        return self.f.read(rec.size)

    def extract(self, rec, dest):
        os.makedirs(os.path.dirname(dest) or '.', exist_ok=True)
        self.f.seek((rec.extent + rec.ear) * BLOCK)
        left = rec.size
        with open(dest, 'wb') as o:
            while left:
                b = self.f.read(min(left, 1 << 20))
                if not b:
                    break
                o.write(b)
                left -= len(b)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    iso = Iso(argv[1])
    if len(argv) > 2:
        for p, e in iso.walk():
            if not e.isdir:
                iso.extract(e, argv[2] + p)
    else:
        for p, e in iso.walk():
            print(('d ' if e.isdir else '  ') + '%10d %s' % (e.size, p))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
