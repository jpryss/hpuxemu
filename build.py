#!/usr/bin/env python3
"""build.py - build the emulator's HP-UX root from your HP-UX 10.20 media.

    python3 build.py [-o ROOTDIR] [--force] [--list] [--patches] [--scripts] SOURCE...

SOURCE is the core CD as an .iso image, a mounted CD, a copy of its files, or a serial
depot (.depot file, or the ACE CD's image). The filesets named in data/filesets.txt are
taken from each source (--list shows what would be taken). data/media.sha256 holds the
checksums of the images this was developed with: a different image is reported, not
refused. Without all "required" filesets nothing is built (--force builds anyway). Nothing
from the media is in this repository.

--scripts runs the filesets' postinstall and configure control scripts inside the
emulator afterwards (needs the Rust CPU built), as swinstall would: symbolic links,
configuration file entries. --patches applies the patches (PHCO_nnnn, PHNE_, PHSS_; kernel patches PHKL_ are of no
use to an emulator) found on the sources whose ancestor fileset is installed, after
the filesets, as one series in patch number order across all the sources (a later
patch wins whichever disc it is on); var/adm/sw/hpuxemu.patches lists what was applied.

The default ROOTDIR is `hpuxroot` next to this repository (hpuxemu/rootdir.py).
"""
import fnmatch
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from hpuxemu import depot as depotmod, mkroot, rootdir  # noqa: E402


def wanted():
    """[(pattern, required)], [exclusion patterns]"""
    pats, excl = [], []
    for line in open(os.path.join(HERE, 'data/filesets.txt')):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if parts[0] == 'required':
            pats.append((parts[1], True))
        elif parts[0].startswith('-'):
            excl.append(parts[0][1:])
        else:
            pats.append((parts[0], False))
    return pats, excl


def select(depot, pats, excl):
    """The depot's PRODUCT/FILESET pairs matching the patterns, and the required patterns
    nothing matched."""
    avail = []
    for p in depot.products():
        for fs in depot.filesets(p['tag']):
            # a product INDEX can list filesets the depot does not hold (the ACE CD's
            # copies of core products do): those have no INDEX of their own
            if len(fs) > 2:
                avail.append('%s/%s' % (p['tag'], fs['tag']))
    chosen = []
    missing = []
    for pat, req in pats:
        hits = [a for a in avail if fnmatch.fnmatchcase(a, pat)]
        if req and not hits:
            missing.append(pat)
        for h in hits:
            if h not in chosen and not any(fnmatch.fnmatchcase(h, e) for e in excl):
                chosen.append(h)
    return chosen, missing


def patches(depot, root):
    """The depot's (product, fileset, ancestor) of user-level patches whose ancestor
    fileset is installed in the root, in patch number order."""
    p = os.path.join(root, 'var/adm/sw/hpuxemu.filesets')
    installed = set(open(p).read().split()) if os.path.exists(p) else set()
    out = []
    for prod in depot.products():
        m = re.match(r'(PH(CO|NE|SS))_(\d+)$', prod['tag'])
        if not m:
            continue
        for fs in depot.filesets(prod['tag']):
            # 11.00 qualifies the ancestor: OS-Core.UX-CORE,fr=B.11.00,v=HP
            for anc in fs.get('ancestor', '').split():
                anc = anc.split(',')[0].replace('.', '/', 1)
                if anc in installed and fs.get('is_kernel', 'false') != 'true':
                    out.append((int(m.group(3)), prod['tag'], fs['tag'], anc))
                    break
    out.sort()
    return [(a, b, c) for _, a, b, c in out]


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def known_sums():
    sums = {}
    p = os.path.join(HERE, 'data/media.sha256')
    if os.path.exists(p):
        for line in open(p):
            parts = line.split()
            if len(parts) >= 2:
                sums[parts[1]] = parts[0]
    return sums


def main(argv):
    out = None
    force = False
    listonly = False
    want_patches = False
    want_scripts = False
    sources = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-o':
            i += 1
            out = argv[i]
        elif a == '--force':
            force = True
        elif a == '--list':
            listonly = True
        elif a == '--patches':
            want_patches = True
        elif a == '--scripts':
            want_scripts = True
        elif a.startswith('-'):
            print(__doc__)
            return 2
        else:
            sources.append(a)
        i += 1
    if not sources:
        print(__doc__)
        return 2
    out = out or rootdir.default_root()
    pats, excl = wanted()
    release = 'B.10.20'
    sums = known_sums()
    for src in sources:
        if os.path.isfile(src):
            s = sha256(src)
            name = os.path.basename(src)
            if name in sums and sums[name] != s:
                print('note: %s differs from the image this was developed with (sha256 %s)' % (src, s))
            elif name not in sums:
                print('note: %s: not a known image (sha256 %s)' % (src, s))
        depot = depotmod.open_depot(src)
        # the release the root is: OS-Core's revision (B.10.20, B.11.00)
        for p in depot.products():
            if p['tag'] == 'OS-Core' and re.match(r'^B\.1\d\.\d\d$', p.get('revision', '')):
                release = p['revision']
        chosen, missing = select(depot, pats, excl)
        print('%s: %d filesets' % (src, len(chosen)))
        inst = os.path.join(out, 'var/adm/sw/hpuxemu.filesets')
        if os.path.exists(inst):
            # a root already there: only what neither it nor the sources have is missing
            installed = open(inst).read().split()
            missing = [m for m in missing if not any(fnmatch.fnmatchcase(x, m) for x in installed)]
        if missing and not force:
            print('required filesets missing from %s: %s' % (src, ' '.join(missing)))
            if len(sources) == 1:
                print('nothing built (--force overrides)')
                return 1
        if listonly:
            for c in chosen:
                print('   ', c)
            continue
        os.makedirs(out, exist_ok=True)
        # the release marker first: the control scripts run in the emulator, which
        # picks the system call numbers by it
        os.makedirs(os.path.join(out, 'etc/hpuxemu'), exist_ok=True)
        with open(os.path.join(out, 'etc/hpuxemu/release'), 'w') as f:
            f.write(release + '\n')
        mkroot.install(out, depot, [tuple(c.split('/')) for c in chosen])
        if want_scripts:
            mkroot.make_dirs(out)
            mkroot.run_control_scripts(out, depot, [tuple(c.split('/')) for c in chosen])
    if want_patches:
        # one series over all the sources, in patch number order: a core disc with an
        # ACE merged into its depot and a later enhancements CD each carry patches, and
        # a later (higher) number must be applied after an earlier one whichever disc
        # it is on, so that its files win
        series = []
        depots = {}
        for src in sources:
            depots[src] = depotmod.open_depot(src)
            pl = patches(depots[src], out)
            print('%s: %d patches apply' % (src, len(pl)))
            for prod, fs, anc in pl:
                series.append((int(prod.split('_')[1]), prod, fs, anc, src))
        series.sort()
        if listonly:
            for _, prod, fs, anc, src in series:
                print('    %s (for %s) from %s' % (prod, anc, os.path.basename(src)))
        else:
            i = 0
            while i < len(series):
                j = i
                while j < len(series) and series[j][4] == series[i][4]:
                    j += 1
                mkroot.apply_patches(out, depots[series[i][4]], [(p, f, a) for _, p, f, a, _ in series[i:j]])
                i = j
    if not listonly:
        mkroot.postprocess(out, release)
        print('root built in %s' % out)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
