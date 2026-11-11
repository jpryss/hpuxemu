"""som.py - SOM object files (HP-UX PA-RISC a.out, shared libraries and relocatables).

The layouts are those of the root's `/usr/include/filehdr.h`, `aouthdr.h`, `spacehdr.h`,
`scnhdr.h`, `syms.h` and `shl.h` (the dynamic-loader structures); all fields big-endian.

    python3 -m hpuxemu.som FILE          header, aux header, spaces, subspaces, dl header
    python3 -m hpuxemu.som -s FILE       the symbol dictionary too
    python3 -m hpuxemu.som -d FILE       the dynamic loader tables (imports, exports, shlibs)
"""
import struct
import sys

MAGIC = {0x104: 'EXECLIBMAGIC', 0x106: 'RELOC_MAGIC', 0x107: 'EXEC_MAGIC', 0x108: 'SHARE_MAGIC',
         0x109: 'SHMEM_MAGIC', 0x10b: 'DEMAND_MAGIC', 0x10d: 'DL_MAGIC', 0x10e: 'SHL_MAGIC'}
SYSTEM_ID = {0x20b: 'PA-RISC 1.1', 0x210: 'PA-RISC 1.0', 0x214: 'PA-RISC 2.0'}

HPUX_AUX_ID = 4

# symbol types (syms.h)
ST_NAMES = ['NULL', 'ABSOLUTE', 'DATA', 'CODE', 'PRI_PROG', 'SEC_PROG', 'ENTRY', 'STORAGE', 'STUB',
            'MODULE', 'SYM_EXT', 'ARG_EXT', 'MILLICODE', 'PLABEL', 'OCT_DIS', 'MILLI_EXT', 'TSTORAGE']
SS_NAMES = ['UNSAT', 'EXTERNAL', 'LOCAL', 'UNIVERSAL']


def be32(b, o):
    return struct.unpack_from('>I', b, o)[0]


def be32s(b, o):
    return struct.unpack_from('>i', b, o)[0]


def be16(b, o):
    return struct.unpack_from('>H', b, o)[0]


def cstr(b, o):
    e = b.find(b'\0', o)
    return b[o:e if e >= 0 else len(b)].decode('latin1')


class Space:
    __slots__ = ('name', 'flags', 'number', 'subspace_index', 'subspace_quantity', 'loadable', 'private')


class Subspace:
    __slots__ = ('name', 'space_index', 'flags', 'file_loc', 'init_length', 'start', 'length',
                 'alignment', 'loadable', 'quadrant', 'access', 'code_only', 'fixup_index', 'fixup_quantity')

    def __repr__(self):
        return '<Subspace %s start %#x len %#x init %#x file %#x q%d%s>' % (
            self.name, self.start, self.length, self.init_length, self.file_loc, self.quadrant,
            '' if self.loadable else ' not loadable')


class Symbol:
    __slots__ = ('name', 'qualifier', 'type', 'scope', 'value', 'arg_reloc', 'hidden', 'info')

    def __repr__(self):
        return '<Symbol %s %s %s %#x>' % (self.name, ST_NAMES[self.type] if self.type < len(ST_NAMES) else self.type,
                                          SS_NAMES[self.scope] if self.scope < 4 else self.scope, self.value)


class Som:
    def __init__(self, data, name='?'):
        self.data = data
        self.name = name
        b = data
        self.system_id = be16(b, 0)
        self.magic = be16(b, 2)
        self.version_id = be32(b, 4)
        if self.magic not in MAGIC:
            raise ValueError('%s: not a SOM file (magic %#x)' % (name, self.magic))
        (self.entry_space, self.entry_subspace, self.entry_offset, self.aux_header_location,
         self.aux_header_size, self.som_length, self.presumed_dp, self.space_location,
         self.space_total, self.subspace_location, self.subspace_total, self.loader_fixup_location,
         self.loader_fixup_total, self.space_strings_location, self.space_strings_size,
         self.init_array_location, self.init_array_total, self.compiler_location, self.compiler_total,
         self.symbol_location, self.symbol_total, self.fixup_request_location, self.fixup_request_total,
         self.symbol_strings_location, self.symbol_strings_size, self.unloadable_sp_location,
         self.unloadable_sp_size, self.checksum) = struct.unpack_from('>28I', b, 16)
        self.exec = None  # the HP-UX exec aux header, as a dict
        self.aux = []
        self._parse_aux()
        self.spaces = []
        self.subspaces = []
        self._parse_spaces()
        self._symbols = None
        self._dl = None

    # -- aux headers --------------------------------------------------------------------
    def _parse_aux(self):
        b = self.data
        off = self.aux_header_location
        end = off + self.aux_header_size
        while off + 8 <= end:
            flags = be32(b, off)
            length = be32(b, off + 4)
            typ = flags & 0xFFFF
            self.aux.append((typ, off, length))
            if typ == HPUX_AUX_ID:
                keys = ('tsize', 'tmem', 'tfile', 'dsize', 'dmem', 'dfile', 'bsize', 'entry', 'flags', 'bfill')
                vals = struct.unpack_from('>10I', b, off + 8)
                self.exec = dict(zip(keys, vals))
            off += 8 + length

    # -- spaces and subspaces ------------------------------------------------------------
    def _parse_spaces(self):
        b = self.data
        strs = self.space_strings_location
        for i in range(self.space_total):
            o = self.space_location + i * 36
            s = Space()
            s.name = cstr(b, strs + be32(b, o))
            s.flags = be32(b, o + 4)
            s.loadable = bool(s.flags & (1 << 31))
            s.private = bool(s.flags & (1 << 29))
            s.number = be32s(b, o + 8)
            s.subspace_index = be32s(b, o + 12)
            s.subspace_quantity = be32(b, o + 16)
            self.spaces.append(s)
        for i in range(self.subspace_total):
            o = self.subspace_location + i * 40
            s = Subspace()
            s.space_index = be32s(b, o)
            s.flags = be32(b, o + 4)
            s.access = s.flags >> 25
            s.loadable = bool(s.flags & (1 << 21))
            s.quadrant = (s.flags >> 19) & 3
            s.code_only = bool(s.flags & (1 << 16))
            s.file_loc = be32s(b, o + 8)
            s.init_length = be32(b, o + 12)
            s.start = be32(b, o + 16)
            s.length = be32(b, o + 20)
            s.alignment = be32(b, o + 24) & 0x7FFFFFF
            s.name = cstr(b, strs + be32(b, o + 28))
            s.fixup_index = be32s(b, o + 32)
            s.fixup_quantity = be32(b, o + 36)
            self.subspaces.append(s)

    def subspace(self, name):
        for s in self.subspaces:
            if s.name == name:
                return s
        return None

    # -- symbols -----------------------------------------------------------------------
    @property
    def symbols(self):
        if self._symbols is None:
            b = self.data
            strs = self.symbol_strings_location
            out = []
            for i in range(self.symbol_total):
                o = self.symbol_location + i * 20
                flags = be32(b, o)
                s = Symbol()
                s.hidden = bool(flags >> 31)
                s.type = (flags >> 24) & 0x3F
                s.scope = (flags >> 20) & 0xF
                s.arg_reloc = flags & 0x3FF
                s.name = cstr(b, strs + be32(b, o + 4))
                q = be32(b, o + 8)
                s.qualifier = cstr(b, strs + q) if q else ''
                s.info = be32(b, o + 12)
                s.value = be32(b, o + 16)
                out.append(s)
            self._symbols = out
        return self._symbols

    def symbol(self, name):
        for s in self.symbols:
            if s.name == name:
                return s
        return None

    # -- the dynamic loader header ($SHLIB_INFO$ for libraries, $DLT$/$PLT$ in programs) ----
    @property
    def dl(self):
        """The dl_header of a shared library or a dynamically linked program, as a dict,
        plus its tables: shlibs, imports, exports (dicts), string table. None if absent."""
        if self._dl is not None:
            return self._dl or None
        info = self.subspace('$SHLIB_INFO$')
        if info is None or info.init_length < 112:
            self._dl = {}
            return None
        b = self.data
        o = info.file_loc
        keys = ('hdr_version', 'ltptr_value', 'shlib_list_loc', 'shlib_list_count', 'import_list_loc',
                'import_list_count', 'hash_table_loc', 'hash_table_size', 'export_list_loc',
                'export_list_count', 'string_table_loc', 'string_table_size', 'dreloc_loc', 'dreloc_count',
                'dlt_loc', 'plt_loc', 'dlt_count', 'plt_count')
        d = dict(zip(keys, struct.unpack_from('>18i', b, o)))
        d['highwater_mark'], d['flags'] = struct.unpack_from('>hh', b, o + 72)
        keys2 = ('export_ext_loc', 'module_loc', 'module_count', 'elaborator', 'initializer',
                 'embedded_path', 'initializer_count', 'tdsize', 'fastbind_list_loc')
        d.update(zip(keys2, struct.unpack_from('>9i', b, o + 76)))
        d['_file_loc'] = o
        # "text relative" offsets: relative to the start of the $TEXT$ space in the file
        # (the dl header itself lives in $SHLIB_INFO$, the first subspace of $TEXT$)
        text = self.space_text_file_base()
        st = text + d['string_table_loc']
        d['strings'] = b[st:st + d['string_table_size']]

        def s(off):
            return cstr(d['strings'], off)

        shl = []
        for i in range(d['shlib_list_count']):
            p = text + d['shlib_list_loc'] + i * 8
            name = be32(b, p)
            fl = b[p + 4]
            shl.append({'name': s(name), 'internal_name': bool(fl & 2), 'dash_l': bool(fl & 1),
                        'bind': b[p + 5], 'highwater': be16(b, p + 6)})
        d['shlibs'] = shl
        imps = []
        for i in range(d['import_list_count']):
            p = text + d['import_list_loc'] + i * 8
            imps.append({'name': s(be32(b, p)), 'type': b[p + 6], 'bypassable': bool(b[p + 7] & 0x80)})
        d['imports'] = imps
        exps = []
        for i in range(d['export_list_count']):
            p = text + d['export_list_loc'] + i * 20
            nxt, name, value, info_ = struct.unpack_from('>iiii', b, p)
            exps.append({'next': nxt, 'name': s(name), 'value': value, 'type': b[p + 16],
                         'module': struct.unpack_from('>h', b, p + 18)[0],
                         'version': (info_ >> 16) & 0xFFFF, 'arg_reloc': info_ & 0x3FF, 'size': info_})
        d['exports'] = exps
        self._dl = d
        return d

    def space_text_file_base(self):
        """File offset of the $TEXT$ space's first byte (what "text relative" means)."""
        for s in self.subspaces:
            if s.space_index < len(self.spaces) and self.spaces[s.space_index].name == '$TEXT$' and s.loadable:
                return s.file_loc - (s.start - self.exec['tmem']) if self.exec else s.file_loc
        return self.exec['tfile'] if self.exec else 0

    # -- description -------------------------------------------------------------------
    def describe(self, symbols=False, dltables=False):
        out = []
        out.append('%s: %s %s version %d' % (self.name, SYSTEM_ID.get(self.system_id, hex(self.system_id)),
                                             MAGIC[self.magic], self.version_id))
        out.append('  entry space %d subspace %d offset %#x  presumed dp %#x  som length %d' % (
            self.entry_space, self.entry_subspace, self.entry_offset, self.presumed_dp, self.som_length))
        if self.exec:
            e = self.exec
            out.append('  text %#x+%#x (file %#x)  data %#x+%#x (file %#x)  bss %#x  entry %#x  flags %#x' % (
                e['tmem'], e['tsize'], e['tfile'], e['dmem'], e['dsize'], e['dfile'], e['bsize'], e['entry'], e['flags']))
        for t, o, ln in self.aux:
            if t != HPUX_AUX_ID:
                out.append('  aux header type %d length %d' % (t, ln))
        for sp in self.spaces:
            out.append('  space %-12s %s%s subspaces %d..%d' % (sp.name, 'loadable ' if sp.loadable else '',
                                                               'private' if sp.private else 'shared',
                                                               sp.subspace_index, sp.subspace_index + sp.subspace_quantity - 1))
        for ss in self.subspaces:
            out.append('    %-16s start %08x len %8x init %8x file %8x q%d acc %#x%s%s' % (
                ss.name, ss.start, ss.length, ss.init_length, ss.file_loc, ss.quadrant, ss.access,
                ' code' if ss.code_only else '', '' if ss.loadable else ' (unloadable)'))
        if symbols:
            for s in self.symbols:
                out.append('    %08x %-10s %-9s %s%s' % (s.value, ST_NAMES[s.type] if s.type < len(ST_NAMES) else s.type,
                                                       SS_NAMES[s.scope] if s.scope < 4 else s.scope,
                                                       s.name, (' (' + s.qualifier + ')') if s.qualifier else ''))
        d = self.dl
        if d:
            out.append('  dl header version %d flags %#x ltptr %#x dlt %#x+%d plt %#x+%d imports %d exports %d shlibs %d modules %d%s' % (
                d['hdr_version'], d['flags'], d['ltptr_value'], d['dlt_loc'], d['dlt_count'], d['plt_loc'], d['plt_count'],
                d['import_list_count'], d['export_list_count'], d['shlib_list_count'], d['module_count'],
                (' path ' + cstr(d['strings'], d['embedded_path'])) if d['embedded_path'] > 0 else ''))
            if dltables:
                for sh in d['shlibs']:
                    out.append('    shlib %s bind %d%s' % (sh['name'], sh['bind'], ' (-l)' if sh['dash_l'] else ''))
                for i, im in enumerate(d['imports']):
                    out.append('    import %4d %-10s %s' % (i, ST_NAMES[im['type']] if im['type'] < len(ST_NAMES) else im['type'], im['name']))
                for ex in d['exports']:
                    out.append('    export %08x %-10s %s' % (ex['value'], ST_NAMES[ex['type']] if ex['type'] < len(ST_NAMES) else ex['type'], ex['name']))
        return '\n'.join(out)


def load(path):
    with open(path, 'rb') as f:
        return Som(f.read(), path)


def main(argv):
    symbols = '-s' in argv
    dltables = '-d' in argv
    files = [a for a in argv[1:] if not a.startswith('-')]
    if not files:
        print(__doc__)
        return 2
    for f in files:
        print(load(f).describe(symbols, dltables))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
