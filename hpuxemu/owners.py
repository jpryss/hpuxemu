"""owners.py - the root's owners table (etc/hpuxemu/owners: the HP-UX mode, owner, group
and type of every file the depots delivered, by guest path) and /etc/mnttab.

Every emulated process reads the table at its first stat, so this module imports nothing
the emulator does not already have (mkroot, which builds roots, pulls in shutil and the
depot reader: a short program's start-up time again)."""
import os
import time


def _owners_cache(p):
    """where the parsed owners table of the file p is kept between processes: the
    user's cache directory (the root stays as it was built)"""
    import hashlib
    base = os.environ.get('XDG_CACHE_HOME') or os.path.join(os.path.expanduser('~'), '.cache')
    key = hashlib.sha256(os.path.realpath(p).encode()).hexdigest()[:16]
    return os.path.join(base, 'hpuxemu', 'owners-%s.marshal' % key)


def read_owners(root):
    """{guest path: (mode, uid, gid, type)} from the root's etc/hpuxemu/owners. Parsing
    its 20,000 lines takes longer than many a program's run, so the parsed table is
    cached (marshal, for the table's mtime and size) and read from there while the
    table is unchanged."""
    import marshal
    owners = {}
    p = os.path.join(root, 'etc/hpuxemu/owners')
    try:
        st = os.stat(p)
    except OSError:
        return owners
    stamp = (st.st_mtime_ns, st.st_size)
    cache = _owners_cache(p)
    import gc
    try:
        with open(cache, 'rb') as f:
            data = f.read()       # marshal.load on the file reads it piecemeal: 5x slower
        # the collector would walk the table's tuples while they are made
        was = gc.isenabled()
        gc.disable()
        try:
            cstamp, owners = marshal.loads(data)
        finally:
            if was:
                gc.enable()
        if tuple(cstamp) == stamp and isinstance(owners, dict):
            return owners
    except (OSError, EOFError, ValueError, TypeError):
        pass
    owners = {}
    for line in open(p):
        parts = line.rstrip('\n').split(' ', 4)
        if len(parts) == 5:
            mode, uid, gid, typ, path = parts
            owners[path] = (int(mode, 8), int(uid), int(gid), typ)
    try:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        tmp = '%s.%d' % (cache, os.getpid())
        with open(tmp, 'wb') as f:
            marshal.dump((stamp, owners), f)
        os.replace(tmp, cache)
    except OSError:
        pass
    return owners


def write_owners(root, owners):
    os.makedirs(os.path.join(root, 'etc/hpuxemu'), exist_ok=True)
    with open(os.path.join(root, 'etc/hpuxemu/owners'), 'w') as f:
        for path in sorted(owners):
            mode, uid, gid, typ = owners[path]
            f.write('%04o %d %d %s %s\n' % (mode, uid, gid, typ, path))


def mnttab(root):
    """/etc/mnttab (the text form getmntent reads): the root is one hfs file system"""
    p = os.path.join(root, 'etc/mnttab')
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        with open(p, 'w') as f:
            f.write('/dev/root / hfs defaults 0 1 %d 0\n' % int(time.time()))
