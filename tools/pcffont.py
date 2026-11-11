#!/usr/bin/env python3
"""pcffont.py - X11 PCF bitmap fonts from an HP-UX root for the stub X server: reads
.pcf and .pcf.Z files (the Unix compress format, an LZW decoder included), font
directories (fonts.dir, fonts.alias) and matches XLFD patterns.

    python3 tools/pcffont.py FONTDIR... PATTERN      # list the matching names
    python3 tools/pcffont.py -show FILE.pcf[.Z] TEXT # print TEXT with the font

A Font has: name, ascent, descent, min_char, max_char, default_char, glyphs
{code: (left, right, width, ascent, descent, bits)} with `bits` a list of rows of ints
(bit 1 << (w-1-x) for pixel x), and metrics for QueryFont."""

import os
import re
import struct
import sys


# ---- compress(1) .Z: LZW with variable code width, block mode -------------------------

def uncompress(data):
    if data[:2] != b'\x1f\x9d':
        return data
    maxbits = data[2] & 0x1F
    block = bool(data[2] & 0x80)
    pos = 3
    out = bytearray()
    width = 9
    clear = 256
    nxt = 257 if block else 256
    prev = None
    dic = {}
    bitbuf = 0
    nbits = 0
    # codes are read in groups aligned to width*8 bits (compress resets the bit buffer
    # after a CLEAR, aligned to the group)
    codes_in_group = 0
    i = pos
    n = len(data)
    while True:
        while nbits < width and i < n:
            bitbuf |= data[i] << nbits
            nbits += 8
            i += 1
        if nbits < width:
            break
        code = bitbuf & ((1 << width) - 1)
        bitbuf >>= width
        nbits -= width
        codes_in_group += 1
        if block and code == clear:
            # skip to the end of the current group of codes
            rest = (codes_in_group % 8)
            if rest:
                skip = (8 - rest) * width
                while skip > 0:
                    if nbits >= skip:
                        bitbuf >>= skip
                        nbits -= skip
                        skip = 0
                    else:
                        skip -= nbits
                        bitbuf = 0
                        nbits = 0
                        i += (skip + 7) // 8 if False else 0
                        # skip whole bytes
                        whole = skip // 8
                        i += whole
                        skip -= whole * 8
                        if skip:
                            if i < n:
                                bitbuf = data[i] >> skip
                                nbits = 8 - skip
                                i += 1
                            skip = 0
            dic = {}
            nxt = 257
            width = 9
            prev = None
            codes_in_group = 0
            continue
        if code < 256:
            entry = bytes([code])
        elif code in dic:
            entry = dic[code]
        elif prev is not None and code == nxt:
            entry = prev + prev[:1]
        else:
            break
        out += entry
        if prev is not None and nxt < (1 << maxbits):
            dic[nxt] = prev + entry[:1]
            nxt += 1
            if nxt >= (1 << width) and width < maxbits:
                width += 1
                codes_in_group = 0
        prev = entry
    return bytes(out)


# ---- PCF ---------------------------------------------------------------------------------

PCF_PROPERTIES = 1
PCF_ACCELERATORS = 2
PCF_METRICS = 4
PCF_BITMAPS = 8
PCF_INK_METRICS = 16
PCF_BDF_ENCODINGS = 32
PCF_SWIDTHS = 64
PCF_GLYPH_NAMES = 128
PCF_BDF_ACCELERATORS = 256
PCF_COMPRESSED_METRICS = 0x100
PCF_BYTE_MASK = 4
PCF_BIT_MASK = 8


class Font:
    def __init__(self, data, name=''):
        self.name = name
        if data[:4] != b'\x01fcp':
            raise ValueError('not a PCF file')
        n = struct.unpack('<I', data[4:8])[0]
        tables = {}
        for i in range(n):
            typ, fmt, size, off = struct.unpack('<IIII', data[8 + 16 * i:24 + 16 * i])
            tables[typ] = (fmt, size, off)
        self.props = {}
        if PCF_PROPERTIES in tables:
            self.props = self._properties(data, *tables[PCF_PROPERTIES])
        self.metrics = self._metrics(data, *tables[PCF_METRICS])
        enc_fmt, enc_size, enc_off = tables[PCF_BDF_ENCODINGS]
        self.encoding = self._encodings(data, enc_fmt, enc_off)
        self.bitmaps = self._bitmaps(data, *tables[PCF_BITMAPS])
        acc = tables.get(PCF_BDF_ACCELERATORS) or tables.get(PCF_ACCELERATORS)
        self.ascent, self.descent = self._accelerators(data, *acc) if acc else (max(m[3] for m in self.metrics), max(m[4] for m in self.metrics))
        self.glyphs = {}
        for code, idx in self.encoding.items():
            if idx < len(self.metrics):
                l, r, w, a, d, attr = self.metrics[idx]
                self.glyphs[code] = (l, r, w, a, d, self.bitmaps[idx] if idx < len(self.bitmaps) else [])
        codes = sorted(self.glyphs)
        self.min_char = codes[0] if codes else 0
        self.max_char = codes[-1] if codes else 0
        self.default_char = self.props.get('DEFAULT_CHAR', self.min_char)
        ws = [g[2] for g in self.glyphs.values()]
        self.max_width = max(ws) if ws else 0
        self.min_width = min(ws) if ws else 0

    @staticmethod
    def _order(fmt):
        return '>' if fmt & PCF_BYTE_MASK else '<'

    def _properties(self, data, fmt, size, off):
        o = self._order(struct.unpack('<I', data[off:off + 4])[0])
        n = struct.unpack(o + 'I', data[off + 4:off + 8])[0]
        p = off + 8
        props = []
        for i in range(n):
            name_off, is_str, value = struct.unpack(o + 'IBI', data[p:p + 9])
            props.append((name_off, is_str, value))
            p += 9
        p += (4 - (n * 9) % 4) % 4 if (n * 9) % 4 else 0
        strsize = struct.unpack(o + 'I', data[p:p + 4])[0]
        p += 4
        strs = data[p:p + strsize]
        out = {}
        for name_off, is_str, value in props:
            name = strs[name_off:].split(b'\0', 1)[0].decode('latin1')
            out[name] = strs[value:].split(b'\0', 1)[0].decode('latin1') if is_str else value
        return out

    def _metrics(self, data, fmt, size, off):
        f = struct.unpack('<I', data[off:off + 4])[0]
        o = self._order(f)
        out = []
        if f & PCF_COMPRESSED_METRICS:
            n = struct.unpack(o + 'H', data[off + 4:off + 6])[0]
            p = off + 6
            for i in range(n):
                l, r, w, a, d = struct.unpack('BBBBB', data[p:p + 5])
                out.append((l - 128, r - 128, w - 128, a - 128, d - 128, 0))
                p += 5
        else:
            n = struct.unpack(o + 'I', data[off + 4:off + 8])[0]
            p = off + 8
            for i in range(n):
                out.append(struct.unpack(o + 'hhhhhH', data[p:p + 12]))
                p += 12
        return out

    def _encodings(self, data, fmt, off):
        f = struct.unpack('<I', data[off:off + 4])[0]
        o = self._order(f)
        minb2, maxb2, minb1, maxb1, default = struct.unpack(o + 'HHHHH', data[off + 4:off + 14])
        p = off + 14
        out = {}
        for b1 in range(minb1, maxb1 + 1):
            for b2 in range(minb2, maxb2 + 1):
                idx = struct.unpack(o + 'H', data[p:p + 2])[0]
                p += 2
                if idx != 0xFFFF:
                    out[(b1 << 8) | b2] = idx
        return out

    def _bitmaps(self, data, fmt, size, off):
        f = struct.unpack('<I', data[off:off + 4])[0]
        o = self._order(f)
        n = struct.unpack(o + 'I', data[off + 4:off + 8])[0]
        p = off + 8
        offsets = struct.unpack(o + '%dI' % n, data[p:p + 4 * n])
        p += 4 * n
        sizes = struct.unpack(o + '4I', data[p:p + 16])
        p += 16
        glyph_pad = 1 << (f & 3)
        bitmap_size = sizes[f & 3]
        bits = data[p:p + bitmap_size]
        msb_bits = bool(f & PCF_BIT_MASK)
        unit = 1 << ((f >> 4) & 3)
        out = []
        for i in range(n):
            l, r, w, a, d, attr = self.metrics[i]
            width = r - l
            height = a + d
            stride = ((width + 7) // 8 + glyph_pad - 1) // glyph_pad * glyph_pad
            rows = []
            base = offsets[i]
            for y in range(height):
                row = bits[base + y * stride:base + (y + 1) * stride]
                # byte order within units
                if unit > 1 and not (f & PCF_BYTE_MASK):
                    row = b''.join(row[k:k + unit][::-1] for k in range(0, len(row), unit))
                v = 0
                for x in range(width):
                    byte = row[x // 8] if x // 8 < len(row) else 0
                    bit = (byte >> (7 - x % 8)) & 1 if msb_bits else (byte >> (x % 8)) & 1
                    v = (v << 1) | bit
                rows.append(v)
            out.append(rows)
        return out

    def _accelerators(self, data, fmt, size, off):
        f = struct.unpack('<I', data[off:off + 4])[0]
        o = self._order(f)
        # 8 flag bytes, then fontAscent, fontDescent (int32)
        ascent, descent = struct.unpack(o + 'ii', data[off + 12:off + 20])
        return ascent, descent

    def text_width(self, text):
        w = 0
        for ch in text:
            g = self.glyphs.get(ch) or self.glyphs.get(self.default_char)
            if g:
                w += g[2]
        return w


def load(path, name=''):
    with open(path, 'rb') as f:
        data = f.read()
    if path.endswith('.Z') or data[:2] == b'\x1f\x9d':
        data = uncompress(data)
    return Font(data, name)


# ---- directories and XLFD matching -------------------------------------------------------

class FontDir:
    """fonts.dir and fonts.alias of several directories: name -> file, alias -> name"""

    def __init__(self, dirs):
        self.names = {}       # lower-cased XLFD -> path
        self.aliases = {}
        for d in dirs:
            p = os.path.join(d, 'fonts.dir')
            if os.path.exists(p):
                with open(p, encoding='latin1') as f:
                    for line in f.read().splitlines()[1:]:
                        if ' ' in line:
                            fn, _, name = line.partition(' ')
                            self.names[name.strip().lower()] = os.path.join(d, fn)
            p = os.path.join(d, 'fonts.alias')
            if os.path.exists(p):
                with open(p, encoding='latin1') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('!') or line == '"FILE_NAMES_ALIASES"':
                            continue
                        import shlex
                        try:
                            parts = shlex.split(line)
                        except ValueError:
                            parts = line.split(None, 1)
                        if len(parts) >= 2:
                            self.aliases[parts[0].lower()] = parts[1].lower()
        self.cache = {}

    def match(self, pattern, limit=1000):
        pat = pattern.lower()
        rx = re.compile('^' + re.escape(pat).replace('\\*', '.*').replace('\\?', '.') + '$')
        out = [n for n in self.aliases if rx.match(n)]
        out += [n for n in self.names if rx.match(n)]
        return out[:limit]

    def open(self, name):
        """the Font for an XLFD name, alias or pattern (first match), or None"""
        key = name.lower()
        target = self.aliases.get(key, key)
        for _ in range(4):
            if target in self.names:
                break
            # a pattern: the first match, which may be an alias (CDE's
            # "-dt-interface user-medium-r-normal-s*-..." names its fonts.alias entries);
            # an alias can itself be a pattern (variable -> -*-helvetica-bold...)
            m = self.match(target)
            if not m:
                return None
            target = self.aliases.get(m[0], m[0])
        else:
            return None
        if target not in self.cache:
            try:
                self.cache[target] = load(self.names[target], target)
            except (OSError, ValueError, struct.error, IndexError):
                self.cache[target] = None
        return self.cache[target]


def main(argv):
    if len(argv) >= 3 and argv[1] == '-show':
        f = load(argv[2])
        text = argv[3] if len(argv) > 3 else 'Hello'
        print('%s: %dx(%d+%d), %d glyphs' % (f.name or argv[2], f.max_width, f.ascent, f.descent, len(f.glyphs)))
        for y in range(f.ascent + f.descent):
            line = ''
            for ch in text.encode('latin1'):
                g = f.glyphs.get(ch)
                if not g:
                    continue
                l, r, w, a, d, rows = g
                ry = y - (f.ascent - a)
                width = r - l
                v = rows[ry] if 0 <= ry < len(rows) else 0
                line += ' ' * max(0, l) + ''.join('#' if v & (1 << (width - 1 - x)) else '.' for x in range(width)) + ' ' * max(0, w - r)
            print(line)
        return 0
    if len(argv) < 3:
        print(__doc__)
        return 2
    fd = FontDir(argv[1:-1])
    for n in fd.match(argv[-1]):
        print(n)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
