"""native.py - which routines of a mapped library the Rust CPU may run natively.

dld.sl resolves a large program's symbols with three small routines it calls millions of
times, and a loop over each library's export hash chain (findlibsym): `$$remU` (millicode remainder: PA-RISC 1.1 divides a bit per step), `hash_string`
and `strcmp`. When a process maps dld.sl's text executable, `natives_for` finds them by
the library's symbol table, checks each routine's code against the versions whose native
equivalent (rust/hppa32-jit/src/hpux.rs) was compared with the real code instruction for
instruction (tools/nativetest.py), and gives their run-time addresses. Unknown code - another dld.sl, a patch
that changed one - is left to run as it is.

HPUXEMU_NATIVE=0 turns it off; HPUXEMU_NATIVE=calls leaves findlibsym's loop to the real
code (the three called routines stay native).
"""
import hashlib
import os

from . import som

# native.rs kinds
REMU_A, HASH_A, STRCMP, REMU_B, HASH_B, HASH_C = 1, 2, 3, 4, 5, 6
WALK_A, WALK_B, WALK_C = 7, 8, 9
LSTRCMP_A, LSTRCMP_B, LSTRCMP_C = 10, 11, 12

# (symbol, length of its code, sha256 of it, first 24 hex digits) -> kind: each the routine
# from its symbol to its last return, compared register for register with native.rs by
# tools/nativetest.py (filled in from that tool's runs)
FINGERPRINTS = {
    # dld.sl of 10.20 with patches and of 11.00
    ('$$remU', 0x140, 'dc785fc0ebe228b42c343dcb'): REMU_A,
    ('hash_string', 0x28, '9160ee50e9b95ee657fb33fb'): HASH_A,
    ('strcmp', 0x2a8, 'fd185bf6b6b68566ea51621c'): STRCMP,
    ('hash_string', 0x28, 'c804963defb33f9c5c35b0c8'): HASH_B,
    ('strcmp', 0x2a8, 'fe31f76e0efae02e735695fc'): STRCMP,
    # 10.20's original dld.sl
    ('$$remU', 0x12c, 'ea578e76a942f8d8c57789e6'): REMU_B,
    ('hash_string', 0x30, '706375441247db5a5ab08f9f'): HASH_C,
    # libc.1's strcmp (the routine itself, after its export stub), up to its multibyte path
    ('strcmp', 0x2b8, 'ddadeccaa731866040d5e199'): LSTRCMP_A,          # 10.20
    ('strcmp', 0x2b8, 'a47ae4a2794ddfa72355b2ca'): LSTRCMP_B,          # 11.00's libc.1
    ('strcmp', 0x2b8, '705e0b7a002dda303f33885e'): LSTRCMP_C,          # 11.00's libc.2
}
# findlibsym's loop over an export hash chain is entered at its head, inside the routine:
# (symbol, length, fingerprint) -> (kind, the head's offset). The whole routine is
# fingerprinted, since the native walk resumes in it and relies on its register use
# (tools/nativetest.py runs both and compares the state where the walk resumes).
INSIDE = {
    ('findlibsym', 0x298, '939b8cba4a24876b29b750c2'): (WALK_A, 0x90),     # 10.20 with patches
    ('findlibsym', 0x308, '5c1500d9665472b05c67f12a'): (WALK_B, 0x94),     # 11.00
    ('findlibsym', 0x2b0, '3cd9b29dcd98154bcd368b18'): (WALK_C, 0x90),     # 10.20
}
NAMES = ('$$remU', 'hash_string', 'strcmp', 'findlibsym')
# the libraries looked at, by the start of their file name
LIBRARIES = ('dld', 'libc.')
_cache = {}
_tables = {}


def _fp(code):
    return hashlib.sha256(code).hexdigest()[:24]


def routines(path):
    """{symbol: [file offsets]} of the routines native.py knows by name, from the
    library's symbol table (a name can be there twice: an export stub and the code)"""
    st = os.stat(path)
    key = (path, st.st_ino, st.st_mtime)
    if key in _cache:
        return _cache[key]
    out = {}
    try:
        b = som.load(path)
    except Exception:
        _cache[key] = out
        return out
    for s in b.symbols:
        if s.name in NAMES and s.value:
            v = s.value & ~3
            for ss in b.subspaces:
                if ss.length and ss.start <= v < ss.start + ss.length:
                    f = v - ss.start + ss.file_loc
                    if f not in out.setdefault(s.name, []):
                        out[s.name].append(f)
                    break
    _cache[key] = out
    return out


def table(path):
    """[(file offset, kind, file offset and length of the code it relies on)] for the
    known routines of the library at host `path`. Reading a library's symbols and
    fingerprinting takes milliseconds, which every process start would pay for libc: the
    table is kept in the user's cache directory, for the file's mtime and size and this
    module's tables."""
    import marshal
    try:
        st = os.stat(path)
    except OSError:
        return []
    key = (os.path.realpath(path), st.st_mtime_ns, st.st_size)
    if key in _tables:
        return _tables[key]
    tag = _fp(repr((sorted(FINGERPRINTS.items()), sorted(INSIDE.items()), key)).encode())
    base = os.environ.get('XDG_CACHE_HOME') or os.path.join(os.path.expanduser('~'), '.cache')
    cache = os.path.join(base, 'hpuxemu', 'natives-%s.marshal' % tag)
    try:
        with open(cache, 'rb') as f:
            out = marshal.loads(f.read())
        _tables[key] = out
        return out
    except (OSError, EOFError, ValueError, TypeError):
        pass
    out = []
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return out
    for name, foff in ((nm, f) for nm, fs in routines(path).items() for f in fs):
        for (n, length, fp), kind in FINGERPRINTS.items():
            if n == name and _fp(data[foff:foff + length]) == fp:
                out.append((foff, kind, foff, length))
                break
        for (n, length, fp), (kind, head) in INSIDE.items():
            if n == name and _fp(data[foff:foff + length]) == fp:
                out.append((foff + head, kind, foff, length))
                break
    _tables[key] = out
    try:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        tmp = '%s.%d' % (cache, os.getpid())
        with open(tmp, 'wb') as f:
            marshal.dump(out, f)
        os.replace(tmp, cache)
    except OSError:
        pass
    return out


def natives_for(path, base, off, size):
    """[(run-time address, kind)] for the known routines of the library at host `path`,
    whose file bytes from `off` are mapped at `base` for `size` bytes"""
    mode = os.environ.get('HPUXEMU_NATIVE', '1')
    if mode == '0':
        return []
    found = []
    for entry, kind, foff, length in table(path):
        if mode == 'calls' and kind in (WALK_A, WALK_B, WALK_C):
            continue
        if off <= foff and foff + length <= off + size:
            found.append((base + entry - off, kind))
    return found
