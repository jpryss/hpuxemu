# Getting started

From nothing to an HP-UX shell on Linux. You need:

- a Linux machine (Ubuntu 24.04 LTS on x86-64 is what it is tested on, WSL2 on Windows
  included; Python 3.11 or newer and any recent Rust; on other CPUs than x86-64 the
  interpreter runs instead of the JIT);
- **your own HP-UX system**: installation media - the *HP-UX 10.20 CORE 9000/700* CD
  (B3782-10101) as an `.iso` image, optionally the *OS enhancements* CD with the ACE
  patch bundle, or the HP-UX 11.00 *Install & Update* disc - or a tar or cpio archive
  of a real HP-UX machine's files, or an image of its disk. This project contains no HP
  software; the HP-UX system you run is built from what you are licensed to use.

Lines starting with `$` are typed in a terminal on the Linux machine; the ones starting
with `#` as root on the HP-UX machine.

## 1. Get the emulator

On Ubuntu 24.04 (Debian and the others: the same packages under their names):

    $ sudo apt install git python3 python3-pil cargo   # Pillow only for the stub X server's PNGs
    $ git clone --recursive https://github.com/jpryss/hpuxemu && cd hpuxemu
    $ (cd rust/hpuxemu && cargo build --release)       # about a minute: the emulator
    $ alias hpuxemu=$PWD/rust/hpuxemu/target/release/hpuxemu

One setting of the Linux machine matters: **process ids**. HP-UX's end at 30000, the
emulated processes have the host's, and some HP-UX programs (`csh` for one) hang when
they get a larger one. Most Linux systems hand out ids up to 32768 or 4194304, so:

    $ sudo sysctl -w kernel.pid_max=30000                                  # until the next boot
    $ echo kernel.pid_max=30000 | sudo tee /etc/sysctl.d/90-hpuxemu.conf   # for good

The emulator prints a warning at every start while the limit is higher. (On WSL2 the
first line goes into `/etc/wsl.conf` as a boot command, or is run after each start.)

Nothing else is needed: the emulator is one Rust program, `hpuxemu` (the alias is for the
commands below; a link in a directory of your PATH does as well). Python runs the tools
around it - `build.py`, which makes the root, and the tests - and the tools find the
program at the place cargo built it, or where `$HPUXEMU` says. Ubuntu's `cargo` package
builds the crates; so does a `rustup` toolchain. The CPU is a submodule
(`rust/hppa32-jit`): `git submodule update --init` fetches it if the clone was not
`--recursive`.

There is a second implementation of the emulator, in Python, kept as the readable
reference (`python3 -m hpuxemu.emu --cpu rust PROGRAM`, with the same options;
`HPUXEMU=python` makes the tools use it). It loads the CPU as a library - `(cd
rust/hppa32-jit && cargo build --release --features capi,hpux)` builds
`libhppa32_jit.so` - or runs on its own Python CPU (`--cpu python`), a thousand times
slower. It answers the same system calls the same way, several times slower: starting
a short command takes it 40 ms, the Rust program 5.

## 2. Make an HP-UX root

The *root* is a directory holding an HP-UX system's files; the emulator runs programs
from it and lets them see nothing else. Make one from media (below), or from a machine
you have ([A root from a real machine](#a-root-from-a-real-machine)).

The short way, with your two CD images (core, and the OS enhancements CD with the
ACE patches), is one script that builds the root and runs the acceptance tests on it
(about 10 minutes):

    $ sh tools/mkroot.sh ~/hpux/core.iso ~/hpux/enhance.iso      # -> ../hpuxroot

A core disc that has HP's December 1999 ACE merged into its depot (as the core disc
some vendors shipped with their systems does: HP's own CD, unchanged, plus 107
patches and the ACE bundles) works the same way, and a third argument puts the root
elsewhere:

    $ sh tools/mkroot.sh ~/hpux/core-ace.iso ~/hpux/enhance.iso ../hpuxroot-ace

The patches of both discs are applied as one series in patch number order, so a
later patch wins whichever disc it is on. Such a root has a newer C compiler (HP C
A.10.32 instead of A.10.07) and a newer `dld.sl`.

The long way, which it wraps:

The root is built from the CD images; it goes to `hpuxroot` next to the repository
(`-o DIR` puts it elsewhere; the emulator finds it there, or where `$HPUX_ROOT` points):

    $ python3 build.py --patches --scripts ~/hpux/core.iso ~/hpux/enhance.iso
    ...
    OS-Core/UX-CORE: 1083 files
    ...
    PHCO_20829 (for OS-Core/UX-CORE): 2 files
    newconfig: 479 files put in place
    root built in /home/you/hpuxroot

This takes a few minutes and makes a 475 MB root with 304 filesets and 88 patches
(the core CD alone, without the scripts: 400 MB, 274 filesets, 71 s). `--scripts` runs
each fileset's postinstall and configure scripts inside the emulator, as `swinstall`
would, for the symbolic links and configuration entries they make; it needs the
emulator built first. `build.py` reads the ISO 9660 image
and HP's SD-UX depot on it itself; a mounted CD or a copy of its files works the same.
The checksums of the images this was tested with are in `data/media.sha256`: a
different image is reported, not refused. What is taken from the CD is listed in
`data/filesets.txt` (all of it but the localized manuals and messages and the install
and diskless servers); `--list` shows the selection without building.

The files in the root belong to you, with HP-UX's modes; their HP-UX owners are in
`etc/hpuxemu/owners`, and owners and ACLs set later in extended attributes of the files
(`user.hpux.owner`, `user.hpux.acl`) - copy a root with `cp -a`, `rsync -aX` or
`tar --xattrs` to keep them. On a file system without user extended attributes (a
Windows drive under WSL) the owners go to the table and `chacl` is refused. The CDs' `/usr/newconfig` configuration files are put in place,
`/etc/mnttab` describes the root as one file system, and `etc/hpuxemu/release` says
which HP-UX this is (`B.10.20`).

### A root from a real machine

If the HP-UX machine still runs, archive its files there, as root, and adopt the archive
here. Take the file systems that hold the system and its software; leave out `/dev`,
`/tmp` and what is mounted from elsewhere:

    # cd / && tar cf /tmp/root.tar etc sbin usr opt var home stand/system
    $ python3 -m hpuxemu.adopt ../hpuxroot-mybox root.tar
    adopt: ../hpuxroot-mybox is an hpuxemu root: HP-UX B.10.20, node name mybox, ...
    $ hpuxemu -r ../hpuxroot-mybox /usr/bin/sh -i

`cpio` archives work the same - HP-UX's binary format (`find etc sbin usr opt var home
| cpio -o > root.cpio`) or `-c` - and so do compressed ones (`.Z`, `.gz`) and several
archives in one command, a tape's worth each. Users, passwords and installed software
stay the machine's; `adopt` writes the files as you, records HP-UX's owners and modes in
`etc/hpuxemu/owners` as `build.py` does, lists the device files it leaves out, and takes
the release from the root's libc and the node name from `/etc/rc.config.d/netconf`. It
tells you when the machine's own address in `/etc/hosts` needs a look (programs that
connect to their own host need the name to resolve to an address of *this* machine).
`python3 -m hpuxemu.adopt DIR` alone does the same for a directory that already holds
the files, taking the owners as they are on disk.

If all you have is the disk - a `dd` image of it, or of one logical volume - nothing
needs to be mounted: `tools/hpdisk.py` reads the LIF header, the LVM layout and the HFS
and VxFS file systems itself.

    $ python3 tools/hpdisk.py info disk.img            # the volumes and file systems on it
    $ python3 tools/hpdisk.py ls disk.img 1 /etc       # look into file system 1
    $ python3 tools/hpdisk.py root disk.img ../hpuxroot-mybox
    $ python3 tools/hpdisk.py tar disk.img all.tar     # or a tar, each file system at its mount point

For an 11.00 machine, build the STREAMS daemon afterwards as below (`tools/mkstrd.py`;
it needs the machine's C compiler, the bundled one will do).

### HP-UX 11.00

The same `build.py` makes an 11.00 root from the 11.00 *Install & Update* disc
(5012-7970) or the *Extension Pack 9808* core disc, as an `.iso`:

    $ python3 build.py --patches --scripts -o ../hpuxroot11 ~/hpux/11.00-install.iso
    $ export HPUX_ROOT=$PWD/../hpuxroot11

It records `B.11.00` in `etc/hpuxemu/release`, and the emulator then uses 11.00's system
call numbers. The 32-bit programs run (shells, the commands, `cc`, `ps`, X clients, CDE);
the 64-bit programs under `/usr/lib/pa20_64` cannot run (ELF-64 for a PA-RISC 2.0 CPU the
emulator does not have).

11.00's RPC (rpcbind, and with it ToolTalk and so CDE's messaging) uses TCP and UDP
through TLI, on `/dev/tcp` and `/dev/udp`: build the root's STREAMS daemon once, with
HP's compiler in the root, and they exist:

    $ python3 tools/mkstrd.py ../hpuxroot11 none
    $ hpuxemu /usr/sbin/rpcbind      # tools/cdetest.py starts it

Threaded programs (`cc ... -lpthread`) run: the emulator schedules their kernel threads
itself (DESIGN.md section 9). The SNMP agent answers MIB-2 from the host's network tables
(as root, for port 161):

    $ hpuxemu /usr/sbin/snmpdm &
    $ hpuxemu /usr/sbin/mib2agt &

The 11.00-only checks are a sweep list of their own:

    $ python3 tools/sweep.py -r ../hpuxroot11 tools/sweep11.txt

### Where the time goes

Set `HPUXEMU_STATS` to a file and every emulated process appends where its time went
(host CPU, time inside the guest CPU, each system call, PC samples); `tools/stats.py`
sums it up:

    $ HPUXEMU_STATS=/tmp/run.jsonl hpuxemu /usr/bin/sh -c 'cc -o /tmp/hello /tmp/hello.c'
    $ python3 tools/stats.py /tmp/run.jsonl --dld ../hpuxroot/usr/lib/dld.sl

dld.sl's hottest routines run natively on the Rust CPU (`HPUXEMU_NATIVE=0` to compare
without); `tools/nativetest.py ROOT/usr/lib/dld.sl` checks them against the real code.
The Rust CPU compiles hot code with its JIT: `HPUXEMU_JIT=off` runs the interpreter
alone, `HPUXEMU_JIT=0,64` compiles everything at once (the setting to test the
JIT with), `HPUXEMU_FASTMEM=0` makes compiled loads check the page flags instead of
relying on the host's page protection; the stats file has each process's JIT counters (blocks compiled and run,
instructions interpreted, seconds spent compiling).

## Adding software

`tools/swinstall.py` adds products from an SD-UX depot to a root that already works, in
swinstall's order (checkinstall and preinstall scripts, the files, postinstall, then
configure, each over all filesets). A depot with builds for several systems is fine: the
build for the root's release is taken (`--arch` to choose). Install into a copy (`cp -a`,
which keeps the owners in extended attributes) if the root should stay as it was:

    $ cp -a ../hpuxroot ../hpuxroot-app
    $ python3 tools/swinstall.py --list /cd/DEPOT                 # products and filesets
    $ python3 tools/swinstall.py -r ../hpuxroot-app /cd/DEPOT Product Other.RUNTIME

Name the products in the order their prerequisites need. What each control script said
is in the root's `var/adm/sw/hpuxemu.scripts`. A product whose own installer is a shell
script on its CD runs the same way as on HP-UX: copy or link the CD's files into the
root and start the script with the emulator.

### The guest's clock and name

A root can run at another date: `etc/hpuxemu/clock` holds one (`1999-06-01` or
`1999-06-01 10:00`, local time) and the guest's clock is at that date when the file is
written, running on from there. Files changed since then show guest times; older ones
keep theirs. Software of the 1990s that mishandles dates after 1999 runs as it did:

    $ echo 1999-06-01 > ../hpuxroot/etc/hpuxemu/clock

The node name `uname -n` and `hostname` report is `hpux`, or what `etc/hpuxemu/hostname`
holds; `/etc/hosts` in the root must give that name an address of the machine
(`127.0.0.1` does for most programs).

## 3. Run a program

    $ hpuxemu /usr/bin/uname -a
    HP-UX myhost B.10.20 A 9000/715 2000000000 two-user license
    $ hpuxemu /usr/bin/sh -c 'ls -l /usr/bin | head -3'
    total 90544
    drwxr-xr-x   2 bin        bin           4096 Nov  5 00:41 X11
    -rwxr-xr-x   1 bin        bin         339968 Jun 10  1996 adb

Paths are inside the root. `-e VAR=VALUE` adds to the environment (`PATH`, `HOME=/`,
`TERM`, `LOGNAME=root`, `SHELL`, `TZ` are set by default), `-r DIR` names another root,
`-t` traces every system call like HP-UX's `tusc`. The exit status is the program's.

An interactive shell, with job control (`sleep 100 &`, `jobs`, Ctrl-Z, `fg`, Ctrl-C):

    $ hpuxemu -e HISTFILE=/.sh_history /usr/bin/sh -i
    # ps -ef
         UID   PID  PPID  C    STIME TTY       TIME COMMAND
        root  3130  3126  0 00:22:03 ?         0:00 /usr/bin/sh -i
        root  3132  3130  0 00:22:03 ?         0:00 ps -ef
    # exit

(`HISTFILE` is set because HP's POSIX shell opens its history file only when it is,
and names jobs from it.) Your terminal is the shell's: `tty` says `/dev/pts/N`, `vi`
works, `stty` works.

### Users

Programs run as root unless told otherwise; `-u NAME` (or a uid) starts one as a user
of the root's `/etc/passwd`, with its groups from `/etc/group`, and the HP-UX
permission rules then apply as on the real system - a user cannot write `/etc/passwd`,
`su` and `passwd` work through their set-user-id bits, `/tmp` is sticky:

    $ hpuxemu -u testuser /usr/bin/sh
    $ id
    uid=501(testuser) gid=20(users)

Users are added as on HP-UX (`useradd`, `vipw`, or SAM); the files they create are
theirs (the `user.hpux.owner` attribute). Directories they cannot search, and ACLs
(`chacl`, `lsacl`, `getaccess`), work as on HP-UX. If `inetd` refuses to start with no
message after a crash, its lock semaphore is still in the host's System V IPC table:
`ipcs -s` and `ipcrm -s ID` for key `0x01090522`.

## 4. Compile something

HP's bundled C compiler (K&R C, no `-O`) is on the core CD, with `as`, `ld` and `make`:

    $ cat > ../hpuxroot/tmp/hello.c <<'EOF'
    #include <stdio.h>
    main() { printf("hello from HP-UX %d\n", 10); return 0; }
    EOF
    $ hpuxemu /usr/bin/sh -c 'cc -o /tmp/hello /tmp/hello.c && /tmp/hello'
    hello from HP-UX 10

The program is a real HP-UX SOM executable, dynamically linked against the root's
`libc.1` through HP's `dld.sl`, exactly as it would be on a 9000/700.

## 5. X programs

X clients in the root (`xterm`, `xclock`, `hpterm`, `dtterm`, `xlsfonts` ... in
`/usr/bin/X11`) talk to an X server through a Unix-domain socket, and the emulator
passes `/tmp/.X11-unix/*` through to the host, so an X server running on the Linux
machine is reached with its usual `DISPLAY`:

    $ xhost +local:                                   # or copy ~/.Xauthority into the root as /.Xauthority
    $ hpuxemu -e DISPLAY=:0 /usr/bin/X11/xterm

(`-e DISPLAY=host:0` for a TCP connection works too.) The X server must serve the
fonts the clients ask for; HP's are in the root under `/usr/lib/X11/fonts` and can be
added to a modern server's font path with `xset +fp` after `mkfontdir` has run on them
(HP's own `mkfontdir`, inside the emulator, works for that). Motif and CDE programs
want HP's fonts and the `XKeysymDB` of the root, which the control scripts put in
place when the root is built with `--scripts`.

Without an X server, `tools/xstub.py` is a small one in Python: one 24-bit screen
composed from the clients' windows in stacking order, the root's own fonts, written to
a PNG every second. It takes pointer and keyboard input over a control socket, so a
program can be driven, not just started:

    $ python3 tools/xstub.py -d 21 -c /tmp/xs.ctl -o /tmp/screen.png -t 120 &
    $ hpuxemu -e DISPLAY=:21 /usr/dt/bin/dtterm &
    $ python3 tools/xdrive.py /tmp/xs.ctl windows            # what is on the screen
    $ python3 tools/xdrive.py /tmp/xs.ctl "type ls /\n" "click 240 108" "snap /tmp/menu.png"

`click X Y [button]`, `move`, `press`, `release`, `key Return`, `type TEXT`, `snap FILE`,
`windows` (the top-level windows with their class), `tree`. `mwm` runs against it and
frames the other clients; `tools/xtest.py` runs xclock and xterm, `tools/cdetest.py` a
CDE session, against it. It is a test server: no extensions, no authorization, no
clipping finer than windows, and Motif under a window manager still has cosmetic
gaps. The real X server on the host is the target.

### CDE

The desktop runs too. ToolTalk's `ttsession` registers with an RPC portmapper on
port 111, so one must be listening: HP-UX's own works (`hpuxemu /usr/sbin/portmap`
once; it stays in the background), and so does the host's
`rpcbind`. Then:

    $ hpuxemu -e DISPLAY=:0 -e HOME=/home/me -e LANG=C \
          -e USER=root -e LOGNAME=root -e SHELL=/usr/bin/sh /usr/dt/bin/Xsession

starts the session the way a CDE login does: HP's `Xsession` sets the desktop's search
paths (icons, help, actions - `dtsession` started directly runs, but the File Manager
then shows names without icons), starts `ttsession` and the Application Manager, and
runs `dtsession`: `dtwm` with the front panel, and the default session's `dtfile` and
`dthelpview`. `HOME` is a directory inside the root (make it
first); the session writes `.dt/` there, and `.dt/errorlog` is where to look when
something does not come up. `tools/cdetest.py` does all of this against the stub
server, clicks the front panel's Text Editor control and checks that `dtpad` appears
(through `dtaction` and ToolTalk). Known gap: that `dtpad`, started by the session,
shows no text field and ignores keys on the stub server, while `dtpad` started by hand
works.

### Windows: WSL2

WSL2 on Windows 11 (and recent Windows 10) has an X server built in, WSLg: `$DISPLAY`
is `:0`, and `xterm`, `xclock` and `dtterm` started with `-e DISPLAY=:0` open as ordinary
Windows windows. Two things need more: WSLg is itself the window manager, so `mwm` and
CDE's `dtwm` cannot run on it, and its X server cannot read the root's fonts. A nested
X server in a window, Xephyr, solves both:

    $ sudo apt install xserver-xephyr xfonts-base
    $ sh tools/cde-wsl.sh                  # or: sh tools/cde-wsl.sh 1280x960

starts Xephyr with the root's fonts on its font path, HP-UX's `portmap`, and a CDE
session in it (home directory `/home/me` in the root). With Windows display scaling at
125% or 150%, keep the size well under the screen's: 1152x864 fits a 2560x1440 screen
at 150%. If the Xephyr window does not appear after it has been closed and restarted,
`wsl --shutdown` from PowerShell resets WSLg. Logging out (EXIT on the front panel,
then *Continue logout*) ends the session the way `dtlogin` would: the session's
programs stop and the Xephyr window closes; `sh tools/cde-wsl.sh` starts a new one.

### Logging in over the network

`inetd` and `telnetd` run, so the machine can be logged into the way its users did
from a Windows X terminal: telnet in, and the login scripts point `DISPLAY` back at
the X server. `telnet` must be enabled in the root's `/etc/inetd.conf` (the line from
`/usr/newconfig/etc/inetd.conf`), then:

    $ hpuxemu /usr/sbin/portmap     # once, for RPC
    $ hpuxemu /usr/sbin/inetd       # listens on port 23
    $ telnet localhost                                       # from anywhere that reaches the host

`tools/telnettest.py` logs in and checks `who -mR` names the remote host. Port 23
needs root on the host (or a redirect from a high port); accounts and passwords are
the root's own `/etc/passwd`.

## What to try next

- `tools/sweep.py` runs the 66 commands of `tools/sweep.txt` and reports which work
  (`--cpu all` runs each on the Python emulator too and compares); `tools/ptytest.py` drives an
  interactive shell on a pseudo-terminal; `tools/ctest.py` compiles random C programs
  with HP's `cc` and checks them against the host's compiler.
- `python3 -m hpuxemu.som -d /usr/lib/libc.1` (give the host path) shows a SOM file's
  headers and shared-library dictionary; `python3 -m hpuxemu.disasm FILE [ADDR]`
  disassembles.
- [DESIGN.md](DESIGN.md) explains how it all works, [DEVELOPMENT.md](DEVELOPMENT.md) how
  to work on it, [COMPAT.md](COMPAT.md) what has been tried.

## If something goes wrong

- `hpuxemu: unimplemented syscall NAME(N)`: the program asked for something not done yet;
  [SYSCALLS.md](SYSCALLS.md) lists what is. Open an issue with the program's name.
- `memory fault at ADDR (read) pc PC` with a register dump: the program crashed in the
  emulator; run it again with `-t` to see the system calls before it, with
  `HPUXEMU_JIT=off` to see whether the JIT has a part in it, and on the Python emulator
  (`python3 -m hpuxemu.emu --cpu rust`, `--cpu python`) to see whether the two agree.
- `required filesets missing`: the image is not the core CD, or a different release;
  `--list` shows what `build.py` found.
- `kernel.pid_max` warning: HP-UX process ids end at 30000 and `csh` hangs when it gets
  a larger one; `sudo sysctl -w kernel.pid_max=30000` (the emulator says so itself).
- A program that connects to its own host name and waits for ever: the name's address
  in the root's `/etc/hosts` is not one of this machine's.
