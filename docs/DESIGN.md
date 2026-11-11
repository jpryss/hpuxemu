# How hpuxemu works

hpuxemu is a user-mode emulator: one HP-UX process is one host process, the PA-RISC
instructions are interpreted, and each system call the program makes is carried out by
the emulator with the host's facilities. There is no kernel, no device, no scheduler of
its own: the host's process model does that part. This is the design `qemu-user` uses
for Linux programs on foreign CPUs, and [aixemu](https://github.com/jpryss/aixemu) for
AIX programs; the differences are all in what HP-UX programs expect, which
[ABI.md](ABI.md) specifies.

The code is in two layers:

- **The CPU**: a PA-RISC 1.1 interpreter (with the PA 2.0 user-level instructions a
  32-bit program may use) with a 4 GB guest address space, and a JIT for x86-64:
  `rust/hppa32-jit` (the [hppa32-jit](https://github.com/jpryss/hppa32-jit) crate, a
  submodule). `hpuxemu/cpu.py` is the same CPU in Python, written to be read and to
  serve as the reference. [CPU.md](CPU.md) has the model and how the two are checked
  against each other.
- **The OS layer**: the loader, the process state, the 220 system call handlers, signal
  delivery, kernel threads, the process table. It exists twice. `rust/hpuxemu` is the
  emulator: a Rust program on the CPU crate. `hpuxemu/emu.py` is the same emulator in
  Python, the readable reference the Rust one is compared with; it drives either CPU
  (`--cpu python` or `--cpu rust`, the latter through ctypes, `hpuxemu/rustcpu.py`).
  Sections 1-9 describe the design by the Python names (`sys_open`, `hostpath`,
  `deliver_signals`); the Rust emulator has the same functions under the same names, and
  section 10 says where they are and what differs.

Around them: readers for the media (`iso9660.py`, `depot.py`) and the root builders
(`build.py` and `mkroot.py` from media, `adopt.py` from a machine's archive,
`tools/hpdisk.py` from a disk image), the SOM object-format parser (`som.py`), a decoder and
disassembler (`decode.py`, `disasm.py`) that the CPU and the tools share, and
`consts.py`, generated from the root's own `/usr/include` (`tools/genconsts.py`) so that
every constant, errno, signal number and structure offset is HP's, not typed in.

## 1. The root

An HP-UX program needs HP-UX's files: `libc.1`, `dld.sl`, the message catalogs, the
terminal database, `/etc/passwd`. hpuxemu runs programs inside a *root*, a directory
with those files, and never shows them anything outside it: every path a program passes
to a system call is resolved inside the root, symbolic links included (an absolute link
target is a root path), the way a chroot would. `/dev/null`, `/dev/tty`, `/dev/zero`,
`/dev/{u,}random` and the pseudo-terminals `/dev/pts/N` are the host's.

The root is built from the user's own HP-UX CDs by `build.py`. HP's core CD is a
hybrid: a LIF boot volume at the end (the installer kernel) and an ISO 9660 file system
holding an SD-UX *directory depot* - `catalog/INDEX` names the products, each product's
`catalog/PRODUCT/pfiles/INDEX` its filesets, each fileset's `INFO` lists the files with
path, type, mode, owner, size, mtime and checksum, and the files themselves are under
`PRODUCT/FILESET/` compressed with gzip. `depot.py` reads that (and the tar-format
*serial depots* of patch bundles), checks every file's CRC, and extracts the filesets
`data/filesets.txt` names. HP's CD mastering records directory sizes short by whole
sectors, which `iso9660.py` has to work around.

The files are written with their HP-UX modes (set-id bits included) but belong to the
host user; their HP-UX owners go to `etc/hpuxemu/owners`, which `stat` answers from
(so `ls -l` shows `bin bin`); later changes go to the files' attributes (§6). `build.py --patches` applies the
patches of the ACE bundle whose ancestor fileset is installed, in patch number order,
which is what `swinstall` would do without the kernel ones. `--scripts` then runs each
fileset's `postinstall` and `configure` control scripts *inside the emulator* with the
environment `swinstall` gives them (`SW_ROOT_DIRECTORY`, `SW_SOFTWARE_SPEC` ...): they
make the symbolic links and configuration-file entries a plain extraction lacks, and
they are the first real workload the emulator runs on a new root.

A root can also come from a machine that exists. `hpuxemu/adopt.py` unpacks tar and cpio
archives made on it (HP-UX's binary cpio headers, `-c`, compressed with `compress`) and
`tools/hpdisk.py` reads a dd image of its disk - LIF, LVM with its extent maps, HFS and
VxFS - without mounting anything. Both write the files as the host user and HP-UX's
owners and modes into the same table, leave device files out (they are listed in
`etc/hpuxemu/disk-devices`), and record the release and the machine's node name; the
machine's users, passwords and installed software are simply there.

## 2. Loading a program

HP-UX 10.20 executables are SOM files (`som.py`): a file header, auxiliary headers (the
`HPUX_AUX_ID` one gives text/data/bss sizes, file offsets and the entry point), spaces
and subspaces, symbols. The loader maps text at its address (`0x1000` and up, quadrant
1), data and bss in quadrant 2 (`0x40001000` and up), sets the break after bss, builds
the stack at `0x7B03A000` - **the PA-RISC stack grows upwards**, so the lowest address
is the bottom - with the argument and environment strings and vectors, then a 16-byte
*process-info block* crt0 reads through r23 (word 0, the CPU version, becomes
`_CPU_REVISION`: 0x210, PA-RISC 1.1), then the initial sp, 64-byte aligned, with
argc/argv/envp/info also in the argument slots below it (`-36(sp)` ...). Registers at
entry: r26 = argc, r25 = argv, r24 = envp, r23 = info, r27 = the data pointer (the SOM's
presumed dp), r30 = sp, pc = the entry point. Data, bss, heap and stack are executable,
as on PA-RISC HP-UX (a JIT runs code from malloc'd memory).

That is the whole kernel part of program startup. A dynamically linked program's crt0
reads the SOM's shared-library dictionary itself, opens `/usr/lib/dld.sl` with ordinary
`open`/`read`/`lseek`/`mmap` calls, maps it, and jumps into it; `dld.sl` then maps the
libraries (`mmap` of the text, `MAP_PRIVATE|MAP_ANONYMOUS` for the bss and `MAP_FIXED`
file mappings right below it for the data), resolves the imports through the linkage
tables and calls `main`. Where things go follows HP-UX's quadrants: shared executable
mappings - library text, dld.sl's own - from `0xC0001000` up (quadrant 4, above the
gateway page), other shared mappings from `0x80000000` up (quadrant 3), private ones
downwards from `0x7A000000` (quadrant 2; a private `MAP_SHLIB` bss too, so that the
data dld maps below it has room). Programs notice: HP's Java VM treats code below
`0xC0000000` as the program's and calls it without setting r19, the linkage pointer a
library's code needs. The emulator does none of this: it only has to get `mmap`,
`brk` and a handful of early calls (`sigsetreturn`, `sysconf`, `fss`, `getpid`...)
right. `#!` scripts are handled by the emulator: the interpreter is loaded with the
script's path appended to its arguments.

## 3. Running: the CPU and the gateway

The CPU interprets until something needs the "kernel": a system call, a fault, a
breakpoint, an illegal instruction, or the instruction budget of one run (4 million
instructions, so that signals are looked at regularly). A system call on PA-RISC HP-UX
is a `ble` through the *gateway page* at `0xC0000000`: `ldil L%0xc0000000,r1;
ble 4(sr7,r1); ldi N,r22`. The CPU stops when the pc reaches that page; the emulator
reads the call number from r22, the arguments from r26-r23 and the stack, runs
`Process.sys_<name>`, stores the result in r28 (r29 for a second value), the error
flag in r22, and resumes at r31, the link register `ble` set.

Memory is a flat 4 GB guest address space with a protection byte per 4 KB page. The
Rust CPU reserves 4 GB of host address space with `mmap(PROT_NONE)` and makes pages
accessible as the guest maps them, so a guest address is a host address plus a base;
the Python CPU keeps a dictionary of pages. Loads and stores check the page's
protection before touching it, so a fault is reported synchronously with the exact
address - no host signal handling. Guest page 0 is readable unless the program was
linked with `ld -z` (the SOM's exec flags say), because HP-UX let programs read null
pointers and some do; the break always has one extra page mapped beyond it because
HP's libc string functions read past it by words.

## 4. System calls

Each handler is a method `sys_<name>` taking up to eight integer arguments; it returns
an integer (or a pair for r28/r29) or raises `HpuxError(errno)`. Paths are translated
into the root; descriptors are the host's own (an HP-UX fd *is* the host fd, which makes
`fork`, `dup2` and inheritance across `exec` free); structures are packed with the
offsets `consts.py` holds. [SYSCALLS.md](SYSCALLS.md) lists them all with their
docstrings, which are the specification.

The way into a handler is short because it is taken millions of times: the Rust CPU's
registers are a ctypes array over the `Cpu` structure itself (`cpu.gr[22]` is a memory
read, not a call into the library), the four stack arguments are one read, a guest read
is one call that checks the range and gives its host address, and the handler for each
call number is looked up once. A process also starts and ends cheaply, which a shell
script's hundreds of commands notice: the parsed owners table is cached in the user's
cache directory (`~/.cache/hpuxemu`, for the table's mtime and size), modules only rare
paths use are imported there, and once the guest has exited the host process ends with
`os._exit` instead of Python's own shutdown (under a profiler, normally).

Where HP-UX differs from the host in a way a program can see, the handler does the
translation: `getdents` returns HP-UX's `struct __dirent` with 64-bit cookies;
`stat`'s device numbers have the major in the top byte; `ioctl` maps the `termio` and
`termios` requests and the window size; `select`'s fd_sets are big-endian words;
`uname` says `HP-UX`, `B.10.20`, `9000/715`; errno and signal numbers are mapped both
ways (HP-UX's `SIGUSR1` is 16, `SIGCHLD` 18).

**Processes** are host processes. `fork` is a host fork (the child continues the same
emulator with the same CPU state; HP-UX's convention of returning the parent's pid
with r29 = 1 in the child is kept), `exec` loads the new image into the same host
process, `wait` is the host's with the status translated, pids are the host's. `ps`
needs a process table: every emulator process publishes a line about itself in
`<root>/var/run/hpuxemu/<pid>` and `pstat` reads those (stale ones belong to dead
pids). Pipes, process groups and sessions, the controlling terminal, `tcsetpgrp` -
all the host's, which is why job control in the HP-UX shells just works.

Because an HP-UX descriptor *is* the host descriptor, the emulator keeps its own
stderr (traces, faults, "unimplemented" messages) on a private copy at a high
descriptor, out of a daemon's reach when it closes 0-2. `uname -n` is `hpux` (or
`etc/hpuxemu/hostname`), a name the root's `/etc/hosts` resolves, never the host's.

**Signals** are where the emulator has to do the kernel's work in detail. A host
signal (from `alarm`, `kill`, the terminal, a child's death) is recorded by a Python
handler; between CPU runs and after every system call the emulator delivers what is
pending and not blocked by building the frame the HP-UX kernel builds - a `struct
sigcontext` above sp with the registers, the handler's argument spill area and a frame
marker - and entering the handler with r2 and the frame marker's RP' slot pointing at
the return routine libc registered with `sigsetreturn`; that routine makes the
`sigcleanup` call, which restores the context the frame marker points to. Blocking
calls (`read`, `write`, `wait`, `pause`, `poll`, `select`) go through the C library
directly rather than Python's wrappers so that a signal interrupts them; a handler
with `SA_RESTART` sends the call back to the gateway, otherwise it fails with EINTR.
[ABI.md](ABI.md) §5 has the frame.

**Sockets** are host sockets: `socket`, `bind`, `connect`, `accept`, `send`/`recv` and
the rest go straight to the host with the HP-UX `sockaddr` (a 16-bit big-endian
family) translated to the host's. Unix-domain socket paths are inside the root except
`/tmp/.X11-unix/*`, which is the host's, so an X server on the host is reached the
normal way. **System V IPC** is the host's too: a shared memory segment is attached
inside the guest address space with `shmat(SHM_REMAP)` at the host address of the
guest page (the Rust CPU's memory is one 4 GB host reservation, so that works; the
Python CPU gets a private copy), semaphores and message queues map the HP-UX flag and
command values. **Pseudo-terminals**: `/dev/ptym/clone` gives a host pty master whose
`ISPTM`/`ISPTS` ioctls name the slave `/dev/pts/N` with the host's number, which is
what libc's `ptsname` derives and the child opens. **The telnet driver**: HP's
`telnetd` asks the kernel (`SIOCJNVS`) to join the connection to the pty and move the
bytes itself until a telnet command arrives; the emulator runs that join as a thread
that peeks at the socket, forwards up to the first IAC and ends there, so `telnetd`
gets the command exactly as it would from the kernel (ABI.md §7).

## 5. Two CPUs

The Python CPU is the reference: 1,400 lines that follow QEMU's hppa
target in structure and naming (the condition evaluation, `do_add`/`do_sub`, the
carry/borrow bits in `psw_cb`, the nullification rules), easy to read next to the
architecture manual. The Rust CPU reproduces it and runs about a hundred times faster.
Neither is trusted alone: `tools/fuzz.py` generates random instruction sequences on
random register and memory state, runs both and compares every register, flag and the
data page; a million sequences without a difference is the bar for a change
([CPU.md](CPU.md)). The decoder was checked against the GNU assembler's test suite
(`tools/test_decode.py`).

The JIT (`rust/hppa32-jit/src/jit.rs`, with its assembler in `x86.rs`) is the third
implementation, inside the Rust CPU and checked against the Python one by the same
fuzzer (`tools/fuzz.py --jit N` compiles every block at once, at most N instructions).
It translates PA-RISC straight to x86-64: no compiler library, nothing but `libc`.

A *block* runs from a place control arrives at to the next branch and its delay slot,
on one page, at most 64 instructions; it is compiled when the place has been arrived at
ten times (`HPUXEMU_JIT=off|on|THRESHOLD,MAXLEN`) - compiling takes microseconds. Each
instruction becomes a fixed x86 sequence that works on the `Cpu` structure in memory,
so compiled code and interpreter share one state at every boundary. In compiled code
r15 is the Cpu, r14 the guest memory's base, r13 the page flags, rbp the instruction
count, r12b whether the next instruction is nullified, and rbx a branch's outcome while
its delay slot runs. Sequences exist for the integer arithmetic and logic (conditions
and carries as the interpreter computes them, in 64 bits, the flags taken from a 32-bit
operation where the condition is a 32-bit one), immediate extracts and deposits, byte,
halfword and word loads and stores, every branch, floating-point loads, stores, copies,
arithmetic and conversions (SSE2); everything else runs through the interpreter's own
`exec` from inside the block, as does a floating-point operation whose result is a NaN
or out of range. An instruction after one that may nullify it is jumped over. Anything
unusual hands over *before* the instruction with the state exactly as the interpreter
would have it - an access the page flags refuse or that is not aligned (it might cross a
page), a store to a page holding compiled code - and the interpreter executes it, so
faults and traps happen in one place only.

In the Rust emulator a load does not look at the page flags at all (`Cpu::set_fast_mem`):
it is one host load from base + address, and a load the guest may not make faults on
the host - nothing is mapped there, or the page has no access (the host's protection
mirrors that; `Mem::protect` keeps it so). The CPU's SIGSEGV/SIGBUS handler finds the
load by the faulting instruction's address and continues at that instruction's
hand-over, which is the path the flag check took: the stack still grows on demand, a
nil pointer still becomes the guest's SIGSEGV. This is how aixemu's PowerPC JIT
(ppc32-jit) and user-mode QEMU read memory. Stores keep their check - it is also what
notices a store into compiled code - and so do loads once a page is mapped write- or
execute-only, which a host page cannot express. The handler owns the two signals: the
emulator never sets them on the host; one that another process sends is passed on to
it (`host::fault_fallback`) and handled as the guest's disposition says. The Python
emulator, which sets host handlers of its own, leaves this off; `HPUXEMU_FASTMEM=0`
turns it off, `HPPA_FASTMEM=1` on for the fuzzer. The carries an add stores are left out when
a later add of the block stores them again and nothing in between could show them (no
memory access, no branch, no nullification, no call).

Two shapes of HP's compiled code shaped the blocks: a forward conditional branch with
`,n`, which nullifies its delay slot exactly when it is taken, is a side exit and the
block runs on (HP's compilers chain such branches); and a `bl` to a routine run
natively (below) calls it from the block and goes on after it. The multiply millicode
(`$$mulI`) dispatches through a jump table whose entries put a branch in the delay slot
of another: an unconditional branch with `,n` compiles with its slot as a nop whatever
it holds, and a branch in the delay slot of one always taken compiles with the first
target's instruction as its own delay slot - each compiled instruction carries its
address and the iaoq_b it runs with, so a block need not be contiguous. Both apply only
to a block's first instruction, the one sure not to be nullified.

Blocks have no prologue: one trampoline enters them and they leave through common
exits. A block's end *jumps straight to the next block* when the address is known: the
jump first goes to a stub that returns to the dispatcher, is patched when the target is
compiled, and patched back when the target is dropped. A branch through a register
looks its target up in a direct-mapped table. Every block begins by checking that no
page with compiled code changed and that the instruction budget covers it - so
`run(max)` is exact, which the thread scheduler and the PC sampling rely on. Compiling
a block sets its page's CODE flag; every write to such a page and every map, unmap and
protect clears it and records the page, and its blocks are dropped before anything
runs again (HP's Java VM writes its compiled code into the heap and rewrites it). The code
cache is one 64 MB mapping, flushed when full. `HPPA_JIT_MAP=FILE` writes each block's
host address range and guest PC (to attribute a profiler's samples, e.g. py-spy's
`--native`), `HPPA_JIT_TRACE=1` prints the addresses interpreted most and the
instructions compiled code ran through the interpreter. The interpreter keeps the
instructions it decoded by address, each checked against the word it was decoded from.

Beside it, a narrower shortcut: a few routines the Rust CPU runs natively. dld.sl
resolving symbols spends a third of its instructions in `$$remU` (a remainder: PA-RISC
1.1 has no divide), `hash_string` and `strcmp`. When a process maps dld.sl's text
executable, `hpuxemu/native.py` finds them by the library's symbol table, checks each
routine's code against a fingerprint (symbol, length, SHA-256), and hands their
addresses to the CPU, which marks the pages (`NATIVE`, like the hooks' `HOOKED`) and on
reaching such an address - not in a delay slot, not nullified - runs
`rust/hppa32-jit/src/hpux.rs` instead: the result, every register the real routine writes
on all its paths with the value it leaves, the return as the real one returns. Callers
may rely on what the convention promises and on what a millicode routine never touches,
nothing else; `tools/nativetest.py` runs real and native on random inputs from random
register state and compares all of it, apart from the caller-saved registers a
procedure may leave anything in, and strcmp's result beyond its sign (the real one
returns a byte difference on some paths, +-1 on others; dld's callers test zero). A
native routine declines - the real code runs - on anything unusual: a zero divisor, a
null pointer, an unreadable byte, a string over 1 MB. Unknown code, another dld.sl or
a patched routine, is not touched. Counted as one instruction each, so `icount` shrinks.

Two more of the same kind. libc's own `strcmp` (a fifth of a large application's
start, most of it one library searching a table) is native for 10.20's libc.1 and 11.00's
libc.1 and libc.2, with the real routine's result exactly: 0, +1 or -1, and the byte
difference when both strings start at the same odd address and differ at once; it
declines when the locale's flag (read through r19, as the routine does) says multibyte.
And the loop inside dld.sl's `findlibsym` that walks an export hash chain is entered
natively at its head: every entry whose name differs from the wanted one is passed over
in one go, and the real loop resumes at its own test of the next index - before the
first entry whose name is equal (versions, types and messages stay the real code's),
or at the chain's end. This one is not a routine with a convention to lean on, so it
leaves every register as the real loop's last round does, and `nativetest.py` compares
all of them, SAR and the loop's stack word with the real loop (run with the native
strcmp it calls), per dld.sl version: the three have three different loops. A compiled
block may start at a native routine's address: it tries the routine first and goes on
with the real code when it declines. `native.py` keeps what it found in each library in
`~/.cache/hpuxemu`, since every process maps libc. `HPUXEMU_NATIVE=0` turns all of it
off, `=calls` the walk alone.

## 6. Users and permissions

Every emulated process is one host user, so the host never refuses anything; the
emulator does the kernel's own checks instead. A process has real, effective and saved
user and group ids and supplementary groups (`setuid`, `seteuid`, `setresuid`,
`setgroups` with the kernel's rules); the program given on the command line starts as
root, or as the user named with `-u`; `login` and `su` change identity the way they do
on HP-UX, because the set-user-id and set-group-id bits are honoured on `exec`. File
ownership is the host file's `user.hpux.owner` extended attribute ("uid gid", written
by `chown` and when a process creates a file), else the owners table the root was built
with (`etc/hpuxemu/owners`, every file of the depot with its uid and gid, by path), else
root's. The attribute goes with the file through `rename` and `link`; `rename` gives a
file whose owner is only in the table the attribute first, and a new file at a path
the table names gets one, so the table's entry for an old file never applies to a new
one. Modes are the host file's. HFS access control lists are the same: the optional
entries in `user.hpux.acl` ("uid.gid=mode,...", -36 for %), the three base entries the
owner and the mode bits, `getacl`/`setacl`/`fgetacl`/`fsetacl` as on HP-UX, `chmod`
deleting the optional entries (POSIX.1), `st_acl` in `stat` (the + of `ls -l`). On a
host file system without user extended attributes ownership falls back to the table and
`setacl` says EOPNOTSUPP, which is what HP-UX says off HFS.

Every path lookup needs search permission on each directory it looks a name up in, as
the kernel's does - with the effective ids, the real ones for `access` - starting from
the working directory for a relative path. Then `open`, `access`, `getaccess`, `exec`,
`chdir`, `unlink`, `mkdir`, `mknod`, `rmdir`, `rename`, `link`, `symlink`, `chmod`,
`chown`, `utime`, `truncate` and `kill` apply acl(5)'s check (the most specific level of
matching entries decides: u.g, u.%, %.g, %.%; with only the base entries that is the
owner/group/other bits), the superuser exemption (except execute on a file no entry
lets anyone execute), the sticky bit on `/tmp`, and ownership for `chmod`/`chown`/
`utime`/`setacl`. The superuser's lookups skip the search checks, so a root process
costs nothing extra.

## 7. What is deliberately not emulated

- Device files other than the few listed: HP-UX device numbers mean nothing on the host.
- The host's own permission checks: every emulated process is the same host user. The
  HP-UX users are real inside the emulator, though - see §6.
- The kernel's view of itself: `pstat` answers what `ps` needs and little more;
  `mount`, `ioscan`, `swapinfo` fail.

## 8. STREAMS drivers: the STREAMS daemon

HP-UX 11.00's RPC and ToolTalk reach TCP and UDP only through TLI on the STREAMS devices
`/dev/tcp` and `/dev/udp`, and some products bring a STREAMS driver of their own: a
protocol stack as libraries of relocatable PA-RISC objects that `config` links into the
kernel, which their applications talk to through TLI and STREAMS ioctls. A user-mode
emulator has no kernel to link a driver into, and reimplementing a protocol stack would
replace the product's code with a guess. Instead STREAMS runs in an ordinary emulated
process, the **STREAMS daemon** (`/stand/hpuxemu/strd` of the root), a product's driver
code with it:

- `kernel/strd.c` is a STREAMS framework written to the SVR4 rules with HP-UX's
  structures (`sys/stream.h`): `allocb`, `putq`, `getq`, `putnext`, `qenable` and the
  service-procedure scheduler, `timeout`, `str_install`, multiplexing (`I_LINK`), stream
  heads. Kernel-only services are trivial in one single-threaded process (`spl*` do
  nothing). `kernel/ksubr.s` is the kernel's `setjmp`, whose `label_t` is smaller than
  libc's `jmp_buf`. Beside the product's driver it has drivers of its own: `timod`,
  `dlpi` (the LAN, 802.3 with LLC1, whose frames go to a host program, "the wire", or
  nowhere), and `tcp` and `udp` (`kernel/inet.c`: TPI providers, T_COTS_ORD and
  T_CLTS, each stream one host socket - HP-UX 11.00's rpcbind, RPC library and ToolTalk
  reach TCP and UDP only through TLI on `/dev/tcp` and `/dev/udp`).
- `tools/mkstrd.py ROOT DRIVER` links that with the libraries the product's master file
  (`/usr/conf/master.d`) names, in the emulator with HP's `cc`, `as` and `ld`, and calls
  `DRIVER_install()` at start-up as the kernel would. The result contains the product's
  code: it stays in the root.
- `hpuxemu/streams.py`: opening a device of `ROOT/etc/hpuxemu/streams` connects to the
  daemon's socket (starting the daemon if needed); the connection is the stream.
  `putmsg`, `getmsg`, `putpmsg`, `getpmsg`, `read`, `write`, the `I_*` ioctls, `poll`
  and `select` work on it as on HP-UX; other ioctls go down as transparent ioctls, their
  copies made by the emulator. Messages reaching the stream head come back over the
  connection and wait in the emulator until read. HP's libnsl does without `timod` for
  its own requests: two ioctls (`I_ASYNC_ACK` and an unnamed `_IO('S', 99)`) send a TPI
  request and wait for its acknowledgement; the emulator does that. 11.00's libnsl adds
  `I_ASYNC_ACK_NEW` (the same), `I_GET_QLEN`, and `I_XTI_USND`/`I_XTI_URCV` for
  datagrams ({?, ?, flags, ctl length, data length, ctl, data}: a T_UNITDATA_REQ sent,
  a T_UNITDATA_IND received, the lengths written back).
- Streams the emulator answers itself (`netman.MibStream`): on 11.00, `/dev/ip`,
  `/dev/nuls`, `/dev/dlpi` and `/dev/lanN` when the root's daemon does not register
  them. They exist for network management only - libnm's MIB-2 requests (a
  T_OPTMGMT_REQ for MIB2_IP, answered with one T_OPTMGMT_ACK per table; DLPI's
  `DL_HP_PPA_REQ`, `DL_ATTACH_REQ` and HP's request 526 for an interface entry) - with
  the tables `/dev/netman` serves on 10.20 (`hpuxemu/netman.py`). The same Stream
  interface (`msgs`, `call`, `ready`), so getmsg's MORECTL/MOREDATA, `poll` and the
  `I_*` ioctls (modules can be pushed and popped) work as on a daemon's stream; the host
  descriptor is an eventfd that never becomes readable.


## 9. Kernel threads (HP-UX 11.00)

11.00's libpthread runs each POSIX thread on a kernel thread (an LWP). The emulator
gives a process several LWPs on its one CPU (`hpuxemu/lwp.py`, mixed into Process):

- **Contexts.** An LWP is its saved registers - general, floating point, SAR, the PC
  queue, the PSW bits, cr26 and cr27 (the thread pointer libpthread's TLS hangs off) -
  and its own signal mask. Switching saves the running one's and loads another's.
  `_lwp_create` takes the context from the `ucontext_t` `_lwp_makecontext` filled: the
  thread starts the way a system call returns, at r31 (a plabel: the start routine and
  its gp), with r30 its stack, r26 its argument, the narrow state's word at +236 its
  cr27 and the creator's r27.
- **When threads switch.** A thread that waits in the kernel gives the CPU away
  (`ksleep` until a `kwakeup` on the same address, `_lwp_wait`, `sched_yield`,
  `_lwp_suspend`); and every RUN_CHUNK instructions the next runnable one runs, so a
  thread spinning on a lock cannot starve its holder. One thread runs at a time, so
  `ksleep`'s "release the lock and sleep" is atomic without more ado. The lock it
  releases is libpthread's four-word ldcw lock ({1,1,1,1} free: ldcw needs a 16-byte
  aligned word, which is whichever of the four the address rounds up to). A timeout is
  ksleep's value (ETIMEDOUT), not an error.
- **Host calls that would block.** With several threads, a `read`, `recv`, `accept`,
  `getmsg`, `select`, `poll`, `waitpid`, `nanosleep` or `sigtimedwait` that cannot go
  ahead does not stop the process: its thread parks with the conditions it waits for
  (descriptors and events, a child, a signal, a deadline) and its context back at the
  gateway, the call number and arguments intact; when a condition holds the thread runs
  and makes the call again, now without waiting. A deadline returns what the call
  returns on a timeout (select and poll clear their sets). When no thread can run, the
  process waits in one poll over every parked descriptor.
- `fork` leaves the child only the calling thread; `exec` one thread; the process ends
  with its last thread (`_lwp_exit`). Signals go to the process: the running thread, or
  a sleeping one that does not block them (its wait ends with EINTR), or a thread
  waiting for them in `sigwait`/`sigtimedwait` (its wait is made again and takes the
  signal). `_lwp_kill` (`pthread_kill`) aims at one thread: the signal waits on that
  thread (its `tpending`) and becomes pending when it runs, so its handler runs there;
  a wait of that thread's ends with EINTR (a parked host call returns EINTR instead of
  being made again), unless the thread blocks the signal or waits for it in sigwait.
  From the second thread on the host
  catches the signals whose action is the default as well, so that the emulator, not
  the host, decides - a SIGTERM every thread blocks waits for the sigwait thread instead
  of ending the process.

## 10. The Rust emulator

`rust/hpuxemu` is the OS layer in Rust: `main.rs` (the command
line), `process.rs` (the process: its state, paths inside the root, guest memory access,
the permission check with owners and ACLs, the stat buffers), `loader.rs` and `som.rs`
(a SOM program into memory, the first stack, the natively run routines of dld.sl and
libc), `kernel.rs` (the run loop: what the CPU stops for, the system call's way in and
out, the trace), `signals.rs`, `threads.rs` (section 9), `streams.rs` and `netman.rs`
(section 8 and the MIB devices), and `syscalls/` by subject - `files.rs`, `proc.rs`,
`mmap.rs`, `ioctl.rs` (with select and poll), `net.rs`, `ipc.rs`, `misc.rs`. It needs
`libc` and the CPU crate and nothing else.

A handler is `fn sys_open(&mut self, a: &[u32; 8]) -> SysResult`; each module lists its
handlers by name in a `TABLE`, and `syscalls/mod.rs` builds the two tables by number
(10.20's and 11.00's) once. What the Python emulator raises is the error side of the result: `Stop`
is an errno, `Interrupted` (a host call returned EINTR), `InterruptedWithMask`
(sigsuspend), `NoReturn` (sigcleanup set the registers), `Switched` (another thread
runs) or `Exec`. `consts.rs` - every constant, structure layout and system call number
- is generated from the Python tables by `tools/genrust.py`, so the two emulators cannot
disagree on a number; structures are filled through `Pk` with the generated (offset,
size) of each member.

Where it differs from the Python emulator:

- **Signals**: the host handler sets a bit in an atomic word, and `poll_signals()`
  moves the bits into `pending` wherever the Python emulator looks at `self.pending`
  (Python's own handlers run between bytecodes). SIGPIPE has its default action from the
  start, as a process on HP-UX has it (Python starts with it ignored).
- **Memory**: `read`, `write` and a file's `mmap` go straight between the host
  descriptor and guest memory (a read into pages the JIT has compiled code from still
  goes through `Mem::write`, which drops that code).
- **The owners table** is not parsed: the file is in path order, and a lookup bisects
  its bytes (`owners.rs`; that it is in order is checked once per version of the file).
  The table of natively run routines is cached as text (`~/.cache/hpuxemu/natives-*.txt`).
- **The telnet join** (SIOCJNVS) is a thread, as in Python, and a guest read waiting
  for it gives way to a signal.
- **The STREAMS daemon** is started as the emulator itself running `/stand/hpuxemu/strd`.
- getsockopt(SO_ERROR) gives HP-UX's errno.

The two are kept equal by running them side by side: `tools/sweep.py --cpu all` runs
each command of the list on both and compares status and output, and the tools
(`cdetest.py`, `ptytest.py`, `telnettest.py`, `ctest.py`, `census.py`) take
either (`tools/emucmd.py`: the Rust program when it is built, `HPUXEMU=python` for the
Python one). A change to a system call goes into both, the Python one first where the
question is what HP-UX does: it is the quicker place to find out.
