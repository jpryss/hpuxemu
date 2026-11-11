#!/bin/sh
# Start an HP-UX CDE session in a Xephyr window, for WSL2 with WSLg (or any Linux
# desktop): Xephyr gives CDE a screen of its own (dtwm cannot share WSLg's) and serves
# the root's own fonts. Safe to run twice: what already runs is left alone.
#
#     sh tools/cde-wsl.sh [WIDTHxHEIGHT]        default 1152x864
#
# Needs: sudo apt install xserver-xephyr xfonts-base
# Xephyr listens on TCP (WSLg keeps /tmp/.X11-unix read-only) and the programs use
# DISPLAY=localhost:1. HP-UX's portmap needs port 111, which a user may open only after
# net.ipv4.ip_unprivileged_port_start=0, and HP-UX's process ids end at 30000:
# kernel.pid_max=30000 (both asked for with sudo, until the next restart).
# Logging out (EXIT on the front panel) ends the session as dtlogin would: the
# session's programs are stopped and, if this script started it, Xephyr closes.
SIZE=${1:-1152x864}
HERE=$(cd "$(dirname "$0")/.." && pwd)
ROOT=${HPUX_ROOT:-$(dirname "$HERE")/hpuxroot}
cd "$HERE" || exit 1
EMU="$(python3 tools/emucmd.py) -r $ROOT"
FP=$(find "$ROOT/usr/lib/X11/fonts" -name fonts.dir -printf '%h,')/usr/share/fonts/X11/misc
if [ "$(sysctl -n net.ipv4.ip_unprivileged_port_start)" != 0 ]; then
    sudo sysctl -q -w net.ipv4.ip_unprivileged_port_start=0
fi
# HP-UX's process ids end at 30000 (the host's are the guest's; csh hangs on larger)
if [ "$(sysctl -n kernel.pid_max)" -gt 30000 ]; then
    sudo sysctl -q -w kernel.pid_max=30000
fi
if ! (ss -lnu 2>/dev/null || netstat -lnu 2>/dev/null) | grep -q ':111 '; then
    $EMU /usr/sbin/portmap
fi
XPID=
if ! pgrep -x Xephyr >/dev/null; then
    rm -f /tmp/.X1-lock
    Xephyr :1 -screen "$SIZE" -ac -listen tcp -fp "$FP" 2>/dev/null &
    XPID=$!
    sleep 2
fi
mkdir -p "$ROOT/home/me"
# the emulator's process table: what runs now (portmap) outlives the session
TABLE="$ROOT/var/run/hpuxemu"
BEFORE=$(ls "$TABLE" 2>/dev/null)
(
    # HP's own Xsession, as dtlogin would run it: it sets the search paths (icons, help,
    # action types: without them the File Manager shows names but no icons), starts
    # ttsession and dthello, gathers the Application Manager, then execs dtsession
    $EMU -e DISPLAY=localhost:1 -e HOME=/home/me -e LANG=C -e USER=root -e LOGNAME=root \
         -e SHELL=/usr/bin/sh -e PATH=/usr/bin:/usr/bin/X11 /usr/dt/bin/Xsession
    # dtsession has ended (logout). dtlogin would now reset the X server, which ends
    # every client still connected; here the session's programs are stopped instead
    for p in $(ls "$TABLE" 2>/dev/null); do
        echo "$BEFORE" | grep -qx "$p" || kill "$p" 2>/dev/null
    done
    [ -n "$XPID" ] && kill "$XPID" 2>/dev/null
    echo "CDE session ended"
) &
echo "CDE is starting in the Xephyr window; errors go to $ROOT/home/me/.dt/errorlog"
