#!/bin/sh
# Build the HP-UX 10.20 root hpuxemu runs programs in, from your own media, and check it.
#
#     sh tools/mkroot.sh CORE.iso [ENHANCE.iso] [OUTDIR]
#
# CORE.iso    the HP-UX 10.20 core CD image (B3782-10101: boot volume + SD-UX depot)
# ENHANCE.iso the OS enhancements CD (the ACE patch bundle); optional but the X and
#             CDE work was verified with it applied
# OUTDIR      where the root goes (default ../hpuxroot next to the checkout)
#
# Steps: the Rust CPU is built if it is not; build.py extracts the filesets listed in
# data/filesets.txt, applies the ACE patches whose ancestor fileset is installed, runs
# each fileset's postinstall/configure control scripts inside the emulator (they make
# the links, the font directories, /sbin/sh ...), copies /usr/newconfig; then the
# acceptance tests run against the new root. About 10 minutes.
#
# The root contains HP's licensed software: keep it on your machine.

set -e
here=$(cd "$(dirname "$0")/.." && pwd)
core=$1
enh=$2
out=${3:-$here/../hpuxroot}
[ -n "$core" ] || { sed -n '2,20p' "$0"; exit 2; }
[ -f "$core" ] || { echo "$core: not found"; exit 2; }
case "$enh" in /*|./*|../*) ;; "") ;; *) [ -f "$enh" ] || { out=$enh; enh=""; } ;; esac

cd "$here"
if [ ! -x rust/hpuxemu/target/release/hpuxemu ]; then
    echo "== building the emulator"
    (cd rust/hpuxemu && cargo build --release)
fi
if [ -e "$out" ]; then
    echo "$out exists; move it away first (the build does not merge into an old root)"
    exit 2
fi
echo "== building the root in $out"
python3 build.py --patches --scripts -o "$out" "$core" $enh

echo "== checking"
export HPUX_ROOT=$out
for d in usr/lib/X11/fonts/misc usr/lib/X11/fonts/iso_8859.1/75dpi usr/lib/X11/fonts/iso_8859.1/100dpi usr/lib/X11/fonts/hp_roman8/75dpi; do
    if [ -d "$out/$d" ] && [ ! -f "$out/$d/fonts.dir" ]; then
        echo "   fonts.dir missing in /$d - running HP's mkfontdir"
        $(python3 tools/emucmd.py) /usr/bin/X11/mkfontdir "/$d"
    fi
done
$(python3 tools/emucmd.py) /usr/bin/uname -a
python3 tools/sweep.py | tail -1
python3 tools/ptytest.py | tail -1
python3 tools/xtest.py | tail -1
python3 tools/cdetest.py | tail -1
echo "== root ready: export HPUX_ROOT=$out"
