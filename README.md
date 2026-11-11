# hpuxemu — run HP-UX programs on Linux

**hpuxemu runs unmodified 32-bit programs for HP-UX 10.20 and 11.00 (PA-RISC) on an
ordinary PC running Linux.** It emulates the PA-RISC CPU and translates HP-UX's system
calls to the host's, the way `qemu-user` does for Linux programs: no HP-UX kernel and no
virtual machine are needed. The programs run inside an *HP-UX root* - a directory
holding an HP-UX system's files - and see nothing outside it.

You bring the HP-UX system yourself: the root is built from **your own HP-UX
installation media**, or copied from a real HP-UX machine. This repository contains no
HP software.

**New here? Read [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)** - from nothing to
an HP-UX shell.

## Quick start

    git clone --recursive https://github.com/jpryss/hpuxemu && cd hpuxemu
    (cd rust/hpuxemu && cargo build --release)       # the emulator; needs Rust
    alias hpuxemu=$PWD/rust/hpuxemu/target/release/hpuxemu
    python3 build.py --patches --scripts core.iso    # your HP-UX CD image -> ../hpuxroot
    hpuxemu /usr/bin/sh -i                           # an HP-UX shell

## What works

Tested with roots built from the HP-UX 10.20 core CD (9000/700) with the ACE patch
bundle, and from the HP-UX 11.00 Install & Update disc; one emulator runs both and
takes the release from the root.

- **The command line**: `sh` (the POSIX shell), `ksh`, `csh` with job control and
  terminal signals, `vi`, `ed`, the usual commands - `ls`, `grep`, `awk`, `sed`, `sort`,
  `find`, `tar`, `cpio`, `compress`, `bc`, `nroff`, `man`, `ps`, `bdf`.
- **Users and permissions**: real, effective and saved ids, groups, set-user-id programs
  (`su`, `passwd`, `login`), the permission bits, the sticky bit and HFS access control
  lists, enforced by the emulator (`-u USER` starts a program as a user); `useradd`,
  `cron`; SAM comes up, in its terminal and Motif forms.
- **Development**: HP's bundled `cc`, `as`, `ld`, `make`, `nm`, `size`: a C program is
  compiled, linked against the real shared libc through HP's `dld.sl` and run, inside
  the emulator.
- **Processes and IPC**: signals with HP-UX's own signal frame; fork, exec and wait
  with host processes; pipes, pseudo-terminals, sockets, System V shared memory,
  semaphores and message queues, memory-mapped files shared between processes;
  **kernel threads** on 11.00 (`cc ... -lpthread`).
- **The network**: `inetd` and `telnetd` accept logins; `ping`, `ifconfig`;
  RPC with HP-UX's own `portmap`/`rpcbind`; TLI and STREAMS on 11.00; the SNMP agent of
  11.00 answering MIB-2 from the host's network tables.
- **X clients**: `xterm`, `dtterm`, `xclock`, `mwm`, and the **CDE desktop**
  of both releases - `dtsession`, ToolTalk's `ttsession`, `dtwm` with the front panel,
  `dtfile`, `dthelpview`, `dtpad` - on the host's X server, on Xephyr (WSL2 included), or
  on `tools/xstub.py`, a small X server for tests that renders to a PNG.
- **Software added from its own media**: `tools/swinstall.py` installs products from an
  SD-UX depot into a root the way `swinstall` does, control scripts included.
- **A root from a real machine**: a tar or cpio archive of its files
  (`hpuxemu/adopt.py`), or a dd image of its disk - LVM, HFS and VxFS are read directly
  (`tools/hpdisk.py`).

Every program of the 10.20 test root has been started once; the result is in
[docs/COMPAT.md](docs/COMPAT.md). `tools/sweep.py` runs a list of 66 commands and
compares the emulator with its Python reference implementation; `tools/ctest.py`
compiles random C programs with HP's `cc` and compares their output with the host
compiler's.

**Speed**: on x86-64 the emulator translates PA-RISC to x86-64 as it runs
([hppa32-jit](https://github.com/jpryss/hppa32-jit)): compiled C code runs at about 1.5
billion PA-RISC instructions per second on a 2.1 GHz Xeon, more than ten times the
workstations these programs were written for. `uname` takes 5 ms, compiling and running
a C program a tenth of a second ([docs/BENCHMARK.md](docs/BENCHMARK.md)). On other
hosts an interpreter runs at about 100 million instructions per second.

## What does not

- 64-bit programs (PA 2.0 wide mode; `/usr/lib/pa20_64` of 11.00).
- Anything that needs the HP-UX kernel itself: device drivers and the device tree
  (`ioscan`, `lssf`), `mount`, logical volumes, `swapinfo`, `/dev/kmem` readers. SAM
  starts, but its disk and device screens have nothing to show.
- More than one CPU: a process's threads take turns.
- `dtlogin`, the graphical login, has not been tried; sessions are started with
  `Xsession`.
- Hosts other than Linux. The JIT is for x86-64; elsewhere the interpreter runs.

## Getting the emulator

    sudo apt install git python3 python3-pil cargo   # or your system's equivalents
    git clone --recursive https://github.com/jpryss/hpuxemu && cd hpuxemu
    (cd rust/hpuxemu && cargo build --release)       # -> rust/hpuxemu/target/release/hpuxemu

The CPU is a crate of its own, [hppa32-jit](https://github.com/jpryss/hppa32-jit), a
submodule at `rust/hppa32-jit` (`git submodule update --init` if the clone was not
`--recursive`). The emulator is one program and needs nothing else at run time; Python
runs the tools around it: building roots, the tests.

There is also a Python implementation of the same emulator in `hpuxemu/` - slower,
easier to read, the reference the Rust one is compared with
(`python3 -m hpuxemu.emu PROGRAM`; it loads the CPU as a library:
`(cd rust/hppa32-jit && cargo build --release --features capi,hpux)`). The tools use the
Rust program when it is built, the Python one with `HPUXEMU=python`.

## Making an HP-UX root

**From installation media** - the CD images as `.iso` files, mounted, or copied into a
directory:

    python3 build.py --patches --scripts core.iso enhance.iso          # 10.20 -> ../hpuxroot
    python3 build.py --patches --scripts -o ../hpuxroot11 11.00.iso    # 11.00
    sh tools/mkroot.sh core.iso enhance.iso                            # 10.20: build, then test

`build.py` reads the ISO 9660 image and HP's SD-UX depot on it itself, takes the filesets
listed in [data/filesets.txt](data/filesets.txt), applies the patches found on the
media whose ancestor fileset is installed, and runs the filesets' control scripts
inside the emulator as `swinstall` would. It says so when a required fileset is
missing. A raw CD image (`.mdf`, `.bin`) becomes an `.iso` with `tools/mdf2iso.py`.

**From a real HP-UX machine** - archive its files there, then adopt the archive here;
users, passwords and installed software stay the machine's:

    cd / && tar cf /tmp/root.tar etc sbin usr opt var home             # on HP-UX, as root
    python3 -m hpuxemu.adopt ../hpuxroot-mybox root.tar                # here

`cpio` archives (HP-UX's binary format or `-c`) work the same, compressed or not, and so
do several archives in one command. From a dd image of the machine's disk:

    python3 tools/hpdisk.py info disk.img                              # what is on it
    python3 tools/hpdisk.py root disk.img ../hpuxroot-mybox

**More software** from an SD-UX depot (a product CD, a `.depot` file):

    python3 tools/swinstall.py --list /cd/DEPOT
    python3 tools/swinstall.py -r ../hpuxroot /cd/DEPOT Product

## Using it

With the alias from the quick start; paths are paths inside the root.

| what | command |
|---|---|
| an HP-UX shell (as root) | `hpuxemu /usr/bin/sh -i` |
| one command | `hpuxemu /usr/bin/sh -c 'uname -a; bdf'` |
| as an HP-UX user | `hpuxemu -u NAME /usr/bin/sh -i` |
| another root | `hpuxemu -r ../hpuxroot11 /usr/bin/uname -a` (or `HPUX_ROOT=`) |
| trace system calls (like `tusc`) | `hpuxemu -t /usr/bin/ls /etc` |
| an X client | `hpuxemu -e DISPLAY=:0 /usr/bin/X11/xterm` |
| the CDE desktop | [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md#cde); `sh tools/cde-wsl.sh` on WSL2 |
| telnet logins | `hpuxemu /usr/sbin/inetd`, then `telnet localhost` |
| copy files in or out | through the root directory: `ROOT/tmp/x` is `/tmp/x` inside |

**Options**

| | |
|---|---|
| `-r ROOT` | the HP-UX root (default: `$HPUX_ROOT`, else `./hpuxroot`, else `../hpuxroot`) |
| `-u USER` | the HP-UX user to start as (a name or uid of the root's `/etc/passwd`; default root) |
| `-e VAR=VALUE` | set an environment variable inside |
| `-C DIR`, `-0 ARGV0` | the working directory; the program's `argv[0]` (`-sh` for a login shell) |
| `-t` | trace system calls |
| `HPUXEMU_JIT=off` | run the interpreter alone (`0,64`: compile everything at once) |
| `HPUXEMU_STATS=FILE` | where each process's time went, for `tools/stats.py` |
| `HPUXEMU=python` | make the tools use the Python emulator |

A root can run at another date (`ROOT/etc/hpuxemu/clock`) and under another node name
(`ROOT/etc/hpuxemu/hostname`); see the getting-started guide.

## Documentation

| | |
|---|---|
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | first steps: a root, a shell, the compiler, X and CDE, logins |
| [docs/COMPAT.md](docs/COMPAT.md) | what has been tested, program by program |
| [docs/DESIGN.md](docs/DESIGN.md) | how it works |
| [docs/ABI.md](docs/ABI.md), [docs/SYSCALLS.md](docs/SYSCALLS.md) | the HP-UX interface it implements: SOM, the stack, signals; every system call |
| [docs/CPU.md](docs/CPU.md) | the CPU model, the fuzzer, where the architecture leaves things open |
| [docs/BENCHMARK.md](docs/BENCHMARK.md) | speed |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | for developers: layout, the tests, debugging |

## Tools

| | |
|---|---|
| `build.py`, `tools/mkroot.sh` | build a root from HP-UX installation media; the same, then the tests |
| `hpuxemu/adopt.py` | makes a root from a real machine's tar/cpio archive |
| `tools/hpdisk.py` | reads an HP-UX disk image (LIF, LVM, HFS, VxFS): list it, make a tar or a root of it |
| `tools/swinstall.py` | installs products from an SD-UX depot into a root |
| `hpuxemu/mkroot.py`, `hpuxemu/depot.py`, `hpuxemu/iso9660.py` | the steps `build.py` runs; list or extract a depot; read a CD image |
| `tools/mdf2iso.py` | a raw CD image to `.iso` |
| `tools/mkstrd.py` | builds a root's STREAMS daemon (TLI on 11.00; a product's STREAMS driver) |
| `tools/cde-wsl.sh` | a CDE session in Xephyr |
| `tools/xstub.py`, `tools/xdrive.py` | an X server for tests, and its remote control |
| `tools/sweep.py`, `ptytest.py`, `xtest.py`, `cdetest.py`, `telnettest.py`, `ctest.py`, `census.py` | the tests |
| `tools/stats.py` | sums up `HPUXEMU_STATS` files |
| `python3 -m hpuxemu.som`, `python3 -m hpuxemu.disasm` | a SOM file's headers and symbols; a disassembler |
| `tools/` (the rest) | for developers ([docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)) |

## Contributing

Bug reports are welcome as GitHub issues. Most useful: the program, the HP-UX release,
and the last lines of `hpuxemu -t ...`. A program that stops with `unimplemented
syscall NAME` shows exactly what is missing.

## Licence, trademarks and provenance

MIT, see [LICENSE](LICENSE).

HP-UX, PA-RISC and HP 9000 are trademarks of Hewlett-Packard (today HP Inc. and Hewlett
Packard Enterprise); CDE and Motif are trademarks of The Open Group. This project is
not affiliated with, endorsed by or supported by any of them. It contains no HP code or
data: the HP-UX root, and any application installed in it, are built from installation
media, or copied from a system, that you are licensed to use. What the emulator knows
about the HP-UX interface comes from HP's published header files and manuals, the
PA-RISC architecture documentation, and from studying how HP-UX programs and libraries
behave, for the purpose of interoperability; it does not circumvent any licence check.
