#!/usr/bin/env python3
"""swinstall.py - add products from an SD-UX depot to an existing root, the way swinstall
would: checkinstall and preinstall scripts, the files, postinstall, then configure - each
phase over all the filesets, a product's own scripts before its filesets'.

    python3 tools/swinstall.py [-r ROOT] [--arch PREFIX] [--list] DEPOT SPEC...

DEPOT is a directory depot (a product CD's depot directory copied out, say), an .iso with the depot at
its top, or a serial depot. SPEC is PRODUCT or PRODUCT.FILESET, in the order to install
(prerequisites first). A depot that holds several builds of a product (for
HP-UX 9, 10 and another system, say) has one control directory per build: the one whose architecture
starts with --arch is taken (default: HP-UX_B.10, or HP-UX_B.11 for an 11.00 root).
--list shows the products and filesets that SPEC selects without installing.

The root runs the scripts, so it must be a working root already (build.py made). Files
are owned as the depot says (var/adm/sw/hpuxemu.owners); results of the scripts go to
var/adm/sw/hpuxemu.scripts. Example:

    python3 tools/swinstall.py --list /cd/DEPOT                      # what is on it
    python3 tools/swinstall.py -r ../hpuxroot-app /cd/DEPOT Product Other.RUNTIME
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
from hpuxemu import depot as depotmod, mkroot, rootdir  # noqa: E402


def main(argv):
    root = None
    arch = None
    listonly = False
    args = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-r':
            root = argv[i + 1]
            i += 2
            continue
        if a == '--arch':
            arch = argv[i + 1]
            i += 2
            continue
        if a == '--list':
            listonly = True
        elif a.startswith('-'):
            print(__doc__)
            return 2
        else:
            args.append(a)
        i += 1
    if len(args) < 2:
        print(__doc__)
        return 2
    root = root or rootdir.default_root()
    if arch is None:
        rel = os.path.join(root, 'etc/hpuxemu/release')
        arch = 'HP-UX_B.11' if os.path.exists(rel) and open(rel).read().startswith('B.11') else 'HP-UX_B.10'
    d = depotmod.open_depot(args[0])
    # product tag -> the control directory of the build for this architecture
    cdirs = {}
    for p in d.products():
        cd = p.get('control_directory', p['tag'])
        a = p.get('architecture', '')
        if p['tag'] not in cdirs or a.startswith(arch):
            if p['tag'] not in cdirs or not cdirs[p['tag']][1].startswith(arch):
                cdirs[p['tag']] = (cd, a)
    order = []
    for spec in args[1:]:
        prod, _, fs = spec.partition('.')
        if prod not in cdirs:
            print('%s: no product %s in the depot' % (spec, prod))
            return 1
        cd, a = cdirs[prod]
        if a and not a.startswith(arch):
            print('%s: no build for %s (only %s)' % (spec, arch, a))
            return 1
        tags = [f['tag'] for f in d.filesets(cd)]
        if fs and fs not in tags:
            print('%s: no fileset %s in %s (%s)' % (spec, fs, cd, ' '.join(tags)))
            return 1
        for t in ([fs] if fs else tags):
            if (cd, t) not in order:
                order.append((cd, t))
    if listonly:
        for cd, t in order:
            print('%s/%s' % (cd, t))
        return 0
    mkroot.run_control_scripts(root, d, order, which=('checkinstall', 'preinstall'), timeout=600, phased=True)
    mkroot.install(root, d, order)
    mkroot.run_control_scripts(root, d, order, which=('postinstall',), timeout=600, phased=True)
    mkroot.run_control_scripts(root, d, order, which=('configure',), timeout=600, phased=True)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
