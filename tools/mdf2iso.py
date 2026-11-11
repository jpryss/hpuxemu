#!/usr/bin/env python3
"""mdf2iso.py - an ISO 9660 image from a raw CD image (Alcohol 120%'s .mdf, a .bin).

    python3 tools/mdf2iso.py IMAGE.mdf IMAGE.iso

A raw image holds whole sectors: 2352 bytes (sync, header, 2048 bytes of data, error
correction), or 2448 with the 96 bytes of subchannel after each. The sector size is
taken from the file's length and checked against the sync pattern; mode 1 sectors give
their 2048 data bytes. An image already of 2048-byte sectors is copied as it is.
"""
import sys

SYNC = b'\x00' + b'\xff' * 10 + b'\x00'


def main(argv):
    if len(argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    src, dst = argv[1], argv[2]
    with open(src, 'rb') as f:
        head = f.read(2448 * 2)
        f.seek(0, 2)
        size = f.tell()
        sector = None
        for n in (2448, 2352):
            if size % n == 0 and head[:12] == SYNC and head[n:n + 12] == SYNC:
                sector = n
                break
        if sector is None:
            if head[:12] == SYNC:
                sys.stderr.write('mdf2iso: raw sectors of an unknown size\n')
                return 1
            sector = 2048
        f.seek(0)
        with open(dst, 'wb') as o:
            count = 0
            while True:
                s = f.read(sector)
                if len(s) < sector:
                    break
                if sector == 2048:
                    o.write(s)
                elif s[15] == 1:
                    o.write(s[16:16 + 2048])
                elif s[15] == 2:
                    o.write(s[24:24 + 2048])     # mode 2 form 1: after the subheader
                else:
                    o.write(b'\0' * 2048)
                count += 1
    sys.stderr.write('mdf2iso: %d sectors of %d bytes -> %s\n' % (count, sector, dst))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
