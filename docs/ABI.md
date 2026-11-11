# The HP-UX 10.20 / PA-RISC program interface

What a 32-bit HP-UX 10.20 program expects from the kernel, as the emulator implements
it. Everything here was taken from the root's own headers (`/usr/include`, read by
`tools/genconsts.py` into `hpuxemu/consts.py`) and from disassembling the root's
`crt0.o`, `libc.1` and `dld.sl`; where a fact comes from an observation of a program
rather than a document, it says so. The system calls themselves are in
[SYSCALLS.md](SYSCALLS.md), the CPU in [CPU.md](CPU.md).

Numbers are hexadecimal when written with `0x`, structure offsets decimal. "Word" is 32
bits, big-endian.

## 1. Executables: SOM

HP-UX 10.20 object files are SOM (System Object Model; `som.py`, the fields from
`/usr/include/filehdr.h`, `aouthdr.h`, `spacehdr.h`, `scnhdr.h`, `syms.h`, `shl.h`).
The file header starts with `system_id` (0x20b = PA-RISC 1.1, 0x214 = PA-RISC 2.0) and
`a_magic`:

| magic | kind |
|---|---|
| 0x106 | relocatable object |
| 0x107 | EXEC_MAGIC: text and data loaded as one piece (old-style, writable text) |
| 0x108 | SHARE_MAGIC: shared text (the common case) |
| 0x10b | DEMAND_MAGIC: shared text, demand-paged |
| 0x10e | SHL_MAGIC: a shared library (`.sl`) |

The header gives the location of the auxiliary headers, the space and subspace
dictionaries, the symbol and string tables. The **`HPUX_AUX_ID` (type 4) auxiliary
header** is the one a loader needs: `tsize tmem tfile dsize dmem dfile bsize entry
flags bfill` - sizes, memory addresses and file offsets of text and data, the bss
size, the entry address, and `exec_flags`, whose bit 0 is set by `ld -z` ("nil pointer
dereference is an error"). The loader maps `tsize` bytes from `tfile` at `tmem`
(0x1000 for programs), `dsize` from `dfile` at `dmem` (0x40001000 and up), zero-fills
`bsize` after it, and sets the break there. For SHARE_MAGIC files `tfile` is 0, so the
SOM header and dictionaries are mapped too, at 0x1000: crt0 and `dld.sl` read them
from memory.

A dynamically linked program or a library has a `$SHLIB_INFO$` subspace holding the
**dl_header** (`shl.h`): version, the linkage-table pointer, and the locations and
counts of the shared-library list, import list, export list, hash table, string table
and the data relocations, all relative to the text. `python3 -m hpuxemu.som -d FILE`
prints it. The emulator does not interpret it (section 3).

## 2. The address space

PA-RISC addresses are 32-bit offsets in one of four quadrants of 1 GB, each with a
space register; a 32-bit HP-UX process sees:

| range | quadrant | contents |
|---|---|---|
| 0x00000000-0x3FFFFFFF | 1, sr4 | text, from 0x1000; page 0 readable unless `ld -z` |
| 0x40000000-0x7FFFFFFF | 2, sr5 | data from 0x40001000, bss, the heap (brk) growing up; private mappings placed downwards from 0x7A000000; the stack at 0x7B03A000 growing up |
| 0x80000000-0xBFFFFFFF | 3, sr6 | shared mappings and shared-library text, upwards from 0x80000000 |
| 0xC0000000-0xFFFFFFFF | 4, sr7 | the kernel; the gateway page at 0xC0000000 |

The stack base 0x7B03A000 and the quadrant use are what the 10.20 kernel does (the
addresses a program sees in a core file or `ps -l`); the mmap placement rule is the
emulator's. The page size is 4 KB. `mmap` of a file is a copy (`MAP_SHARED` writes are
written back at `munmap`/exit); `MAP_FIXED` is honoured anywhere, which `dld.sl` relies
on when it places a library's data right below the anonymous region it got for the bss.
HP-UX's own `MAP_SHLIB` (0x40) and `MAP_VARIABLE` (0x8) flags are accepted.

**Space registers** are not emulated: every space is the same flat 4 GB, `mfsp`
reads 0, `mtsp` is a no-op, and `ldsid` returns 0. Programs use them only to build
inter-space branches (`ldsid; mtsp sr0; be (sr0,...)`), which thus go where the offset
says.

## 3. Program entry

The kernel enters the program at the SOM's entry address (crt0) with:

| register | value |
|---|---|
| r26 | argc |
| r25 | argv |
| r24 | envp |
| r23 | the process-info block: 4 words the kernel fills; crt0 copies word 0 to `_CPU_REVISION`, bits of word 1 to `_FPU_MODEL` and `_FPU_REVISION`, word 3 to `_CPU_KEYBITS_1`. crt0 requires envp < r23 <= sp. All zeros here |
| r27 | dp, the data pointer: the SOM's presumed dp |
| r30 | sp, 64-byte aligned |
| iaoq | the entry address, privilege 3 |

Below sp, the four argument slots of the standard calling convention hold the same
values: argc at -36(sp), argv at -40, envp at -44, the info block at -48. The strings
and vectors are at the bottom of the stack, which **grows upwards**: the lowest
address is the base, a called function's frame is above the caller's, and the frame
marker (32 bytes: `fm_edp fm_esr4 fm_erp fm_crp fm_sl fm_clup fm_ep fm_psp`) sits
right below sp, so that the previous sp is at -4(sp) and RP' (the return address of a
call through a stub) at -24(sp). This matters for signal frames (section 5).

crt0 looks at `uname`'s release to decide between old- and new-style startup
(`_is_89_0` checks release[3] in `8`,`9` and release[4] == `.`): with `B.10.20` the
new-style code runs. It then reads the dl header's version word from the mapped SOM
to see whether the program is dynamically linked, and if so **maps `/usr/lib/dld.sl`
itself** with `open`, `read`, `lseek` and `mmap` and jumps into it; `dld.sl` maps the
libraries named in the shared-library list the same way (text with `MAP_PRIVATE`,
bss as `MAP_PRIVATE|MAP_ANONYMOUS`, then the data `MAP_FIXED` below the bss), binds
the imports lazily through the linkage tables, and calls `main`. Nothing of this needs
the kernel beyond ordinary system calls; the emulator's loader only handles the main
SOM, the stack, and `#!` scripts.

## 4. System calls

A system call is a `ble` into the **gateway page**; the sequence libc emits is

    ldil   L%0xc0000000,r1
    ble    4(sr7,r1)          ; branch external, link in r31
    ldi    N,r22              ; the delay slot: the call number

with the number from `sys/syscall.h` in r22 (`SYSCALL_NAMES` in `consts.py`; 139 is
`sigcleanup`, which the header names only in a comment), the first four arguments in
r26, r25, r24, r23 and the rest in the caller's argument slots at -52(sp), -56(sp),
-60(sp), -64(sp). The kernel returns to r31 (the address after the delay slot) with:

| register | value |
|---|---|
| r28 | the result, or the errno on failure |
| r29 | a second result where there is one: `pipe` (the second descriptor), `fork` (see below), `getpid` (the parent's pid), `getuid`/`getgid` (the effective id), `lseek64` (the high word) |
| r22 | 0 on success, 1 on failure (libc's stub then copies r28 to `errno` and returns -1) |

`fork` returns the *parent's* pid with r29 = 1 in the child and the child's pid with
r29 = 0 in the parent; libc's `fork` turns that into the usual 0/pid.

Observed demands of this libc that a kernel must meet: `read`/`write` of length 0 with
any buffer address must succeed (`ld` writes 0 bytes from a null pointer); the page
beyond the break must be readable (`strlen` and friends work by words); null pointers
are read by some programs (`head` dereferences one when built without `-z`).

### Structures

All layouts come from the headers (`consts.OFFSET`/`SIZEOF`), compiled with `gcc -m32
-malign-double` to get HP's alignment (8-byte doubles and `long long`). The ones that
matter most:

- `struct stat` (104 bytes): `st_dev` 0, `st_ino` 4, `st_mode` 8 (short), `st_nlink`
  10 (short), `st_rdev` 16, `st_size` 20, `st_atime` 24, `st_mtime` 32, `st_ctime` 40,
  `st_blksize` 48, `st_blocks` 52, `st_fstype` 74, `st_realdev` 76, `st_basemode` 80,
  `st_uid` 84, `st_gid` 88. `struct stat64` (120 bytes) has 64-bit `st_ino` and
  `st_size`. Device numbers: major in bits 24-31, minor below.
- `getdents` returns `struct __dirent` of `sys/dirent.h`: `{u64 cookie; u32 ino; i16
  reclen; i16 namlen; char name[]}` 8-byte aligned, and libc's `readdir` converts it to
  the 264-byte `struct dirent` (`d_ino d_reclen d_namlen d_name[256]`). The cookie is
  what a later `lseek` on the directory gets.
- `struct utsname`: five 9-byte fields (`sysname nodename release version machine`)
  and a 15-byte `__idnumber`; `uname` gives `HP-UX`, the host name, `B.10.20`, `A`,
  `9000/715`, `2000000000`.
- `sigset_t` is 8 words, 32 bytes; signal n is bit (n-1)%32 of word (n-1)/32 (the
  first word holds signals 1-32, so the old one-word `sigblock`/`sigsetmask` masks are
  that word). `struct sigaction` is `{sa_handler; sigset_t sa_mask; sa_flags}` = 40
  bytes; `struct sigvec` `{sv_handler; sv_mask; sv_flags}` = 12.
- `termios` is 36 bytes (`c_iflag c_oflag c_cflag c_lflag c_reserved c_cc[16]`),
  reached with `TCGETATTR` 0x4024_5410, `TCSETATTR` 0x8024_5411 and the `W`/`F`
  variants; the old `termio` is 18 bytes (`c_cc[8]`), `TCGETA` 0x4012_5401 ...
  `TCSETAF` 0x8012_5404. `TIOCGWINSZ` 0x4008_546B is `struct winsize`.
- `fd_set` for `select` is an array of words, bit i%32 of word i/32.

Signal numbers: HUP 1, INT 2, QUIT 3, ILL 4, TRAP 5, ABRT 6, EMT 7, FPE 8, KILL 9,
BUS 10, SEGV 11, SYS 12, PIPE 13, ALRM 14, TERM 15, **USR1 16, USR2 17, CHLD 18**, PWR
19, VTALRM 20, PROF 21, IO 22, WINCH 23, **STOP 24, TSTP 25, CONT 26, TTIN 27, TTOU
28**, URG 29, LOST 30, XCPU 33, XFSZ 34. Errno values are the SVR3 ones with HP's
additions (`EWOULDBLOCK` 246, `ENOSYS` 251).

## 5. Signals

How the 10.20 kernel delivers a signal was reconstructed from libc's `_sigreturn`,
`sigsetreturn` and `sigaction` and the `sigcontext` of `sys/signal.h`; the emulator
does exactly this and the shells' job control, `sleep`, `trap` and `alarm` behave as
on the real system.

**Registration.** At startup libc calls `sigsetreturn(addr, 0x6211988, 0x570)`: `addr`
is the address of its `_sigreturn` routine (in a dynamically linked program a *plabel*,
see below), 0x570 = 1392 = `sizeof(struct sigcontext)`, and the middle argument looks
like a version date. The kernel remembers where handlers return to.

**The frame.** To deliver a signal with a handler the kernel writes a `struct
sigcontext` on the stack above sp (its own frame, the stack growing up):

| offset | field | contents |
|---|---|---|
| 0 | `sc_syscall` | the interrupted system call's number, or 0 |
| 12 | `sc_syscall_action` | `SIG_RESTART` (0) or `SIG_RETURN` (1) |
| 8 | `sm_omask` | the first word of the previous mask |
| 16, 20 | `sm_rval1`, `sm_rval2` | r28, r29 at the interruption |
| 40 | `sc_sl.sl_ss` (`save_state`, 1152 bytes) | `ss_flags` (`SS_INSYSCALL` when restarting), then the narrow registers: gr1, rp, gr3-gr22, arg3-arg0 (r23-r26), dp, ret0, ret1, sp, gr31, cr11 (sar), `ss_pcoq_head`/`ss_pcoq_tail` (the instruction queue), the space registers and control registers (zero here), then at +256 the 32 floating-point registers as doubles, at +512 128 reserved bytes |
| 1232 | `sc_mask` (`sl_uc.uc_sigmask`, 32 bytes) | the previous mask |
| 1344 | `sc_args[4]` | the handler's argument spill: `sc_args[3]` = sig, `[2]` = code, `[1]` = scp (the slots at -36, -40, -44 of the handler's sp) |
| 1360 | `sc_sfm` (frame marker) | `fm_psp` (+28) = the sigcontext's address; `fm_erp` (+8) and `fm_crp` (+12) = the return routine |

The emulator keeps the CPU state the architected words do not hold (the carry/borrow
bits, `psw_v`, the nullify bit) in the reserved area with a magic string, which
`sigcleanup` checks. The sigcontext is placed so that the handler's sp, right after it,
is 64-byte aligned.

**Entering the handler.** sp = the end of the sigcontext; r26 = sig, r25 = code, r24 =
the sigcontext's address; r2 = the return routine; r19 = the handler's gp when the
handler is a plabel. A **plabel** is how a dynamically linked program refers to a
function: a pointer with bit 1 set to a two-word entry `{address, gp}` in the data
segment; `$$dyncall` and the kernel dereference it. Handlers reached through an *export
stub* (`bl` to the body, then `ldw -24(r30),r2; ldsid; mtsp; be,n 0(sr0,r2)`) return
through the frame marker's RP' slot, not r2 - hence both are set.

**Returning.** libc's `_sigreturn` makes the `sigcleanup` system call (139). The
kernel finds the sigcontext through the frame marker: `*(sp - 4)` (`_TOS_TO_SIGCONTEXTP`
in the header), not through the argument, which is the handler's r28. It restores the
registers, the instruction queue and the mask, and if `sc_syscall_action` is
`SIG_RESTART` the queue points at the gateway again with r22 and the arguments intact,
so the call is remade; otherwise the call returns EINTR (`sm_rval1`). `SA_RESTART`
chooses between the two for `read`, `write`, `wait`, `ioctl`, `fcntl` and the
network calls; `pause`, `sigsuspend` and `sigpause` always return EINTR after the
handler.

**Masks.** While a handler runs its signal (unless `SA_NODEFER`) and `sa_mask` are
blocked; the previous mask is in the frame and restored by `sigcleanup`.
`sigsuspend`/`sigpause` install their mask, wait, let the handler run with it, and
return EINTR with the original mask. `sigsetstatemask(mask)` (used by `siglongjmp`)
sets the first mask word and returns the old. `sigvector` is the BSD form: a one-word
mask, `SV_RESETHAND` and `SV_ONSTACK` in the flags; calls interrupted under it are
not restarted.

**Default actions** follow `signal(5)`: terminate for most, ignore for CHLD, WINCH,
URG, CONT, PWR, IO, stop for STOP, TSTP, TTIN, TTOU.

## 6. Processes and descriptors

Pids are the host's; `getpid` also returns the parent's in r29. `fork` and `vfork`
are both a real fork. `exec` keeps descriptors unless `FD_CLOEXEC` is set
(descriptors the kernel creates are inheritable). `wait` statuses are encoded as on
every Unix (exit<<8, signal in the low 7 bits, 0x7F for stopped) with HP-UX signal
numbers. `pstat(PSTAT_PROC, buf, size, count, index)` returns `count` entries from
index `index` on, each with its `pst_idx`, or one entry for pid `index` when `count` is
0; `pst_term` holds the controlling terminal's major and minor numbers, which `ps`
matches against the devices in `/dev`.

## 7. Sockets, IPC and pseudo-terminals

- `struct sockaddr` is `{u16 sa_family; char sa_data[14]}` (no length byte);
  `sockaddr_in` `{family, port, addr, zero[8]}`, `sockaddr_un` `{family, path[92]}`.
  `AF_UNIX` 1, `AF_INET` 2; `SOCK_STREAM` 1, `SOCK_DGRAM` 2, `SOCK_RAW` 3; `SOL_SOCKET`
  0xFFFF with the BSD option numbers (`SO_REUSEADDR` 4, `SO_KEEPALIVE` 8, `SO_SNDBUF`
  0x1001 ...); `MSG_OOB` 1, `MSG_PEEK` 2. libc 10.20 makes the direct calls (`socket`
  290, `connect` 277, `accept` 275, `send` 285 ... in `syscall.h`); the `*2` forms
  (386, 384, 385, 387) take the same arguments.
- `struct ifreq` is 32 bytes (`ifr_name[16]` + a 16-byte union), `struct ifconf`
  `{len, buf}`; `SIOCGIFCONF` 0xC0086914, `SIOCGIFFLAGS` 0xC0206911, `SIOCGIFADDR`
  0xC020690D. Interfaces are `lo0`, `lan0`, `lan1` ...
- System V IPC: `IPC_CREAT` 01000, `IPC_EXCL` 02000, `IPC_NOWAIT` 04000, `IPC_RMID` 0,
  `IPC_SET` 1, `IPC_STAT` 2; `semctl` commands are the BSD numbers (`GETNCNT` 3,
  `GETPID` 4, `GETVAL` 5, `GETALL` 6, `GETZCNT` 7, `SETVAL` 8, `SETALL` 9);
  `struct ipc_perm` is 48 bytes (`uid gid cuid cgid mode seq key` then padding),
  `shmid_ds` 104, `semid_ds` 84, `msqid_ds` 104 with 16-bit `msg_qnum`/`msg_qbytes`.
  A message's type is a 32-bit `long`.
- Pseudo-terminals (STREAMS style): a master comes from `/dev/ptym/clone` (or
  `/dev/ptmx`); `ioctl(ISPTM = _IO('t',71))` returns its device number and `ptsname`
  names the slave `/dev/pts/<minor>`; `ISPTS` (`_IO('t',73)`) returns the slave's
  device number for the check; `UNLKPT` unlocks. `setsid()` is `setpgrp3(2)`,
  `setpgrp3()` is `setpgrp3(1)`. hpterm's trap mechanism (`TIOCTRAP`, `TIOCMONITOR`
  ...) is accepted and never triggers.
- The telnet driver: HP's `telnetd` does not copy bytes itself. It hands the connection
  and the pty master to the kernel's *NVS* driver with `ioctl(sock, SIOCJNVS, &ptyfd)`
  (`_IOW('s', 255, int)` = 0x800473FF; the pty's descriptor is in the low halfword of
  the int, e.g. 0x08010003 for fd 3), which moves data between the two until a telnet
  command (IAC) arrives from the client, then unjoins and lets `telnetd` read the
  command and join again. CR NUL and CR LF from the client become CR and LF; 0xFF going
  out is doubled. The emulator does this with a thread per join (`join_nvs`); while a
  socket is joined the program's own reads and selects on it wait for the join to end.
- Set-id: `execve` of a file with S_ISUID/S_ISGID (the mode in the root, the owner in
  its `user.hpux.owner` attribute or `etc/hpuxemu/owners`) sets the effective and saved id; `setuid` from a non-root
  effective id can set the real/effective id only to the real or saved one, and
  `setresuid`, `setregid` and the group calls follow the 10.20 rules. `getaccess(path,
  uid, ngroups, gidset, label, privs)` asks about any identity: `uid` -34 (UID_EUID),
  -33 (UID_RUID), -32 (UID_SUID); `ngroups` -1 … -5 (NGROUPS_EGID … NGROUPS_EGID_SUPP)
  name the process's own group sets, otherwise `gidset` lists them. `login` and
  `cron` use it.

## 8. Quirks worth knowing

- A CPU fault delivered to a handler carries HP-UX's trap number as `code` (15 data
  page fault, 18 data memory protection), and the saved state's `iir`/`isr`/`ior`
  (cr19-21) hold the faulting instruction, space and address; an SA_SIGINFO handler
  gets `si_code` SEGV_MAPERR (108) or SEGV_ACCERR (109) and `si_addr`.
- A MAP_SHARED file mapping is the host file mapped shared (Rust CPU): writes are seen
  by every process mapping the file at once. On the Python CPU it is still a copy,
  written back at munmap and exit.

- `sigstack`/`sigaltstack` (`portmap`, the `rpc.*` daemons) are recorded and reported
  back but never used: handlers always run on the normal stack.
- `time(tloc)` stores the result at `tloc` as well as returning it; `login` writes
  utmp's time from the stored value and showed 1970 before this was done.
- A root with `/tcb` present makes `login` run in trusted-system mode (and then fail
  for want of `/tcb/files/auth`); `/usr/newconfig/tcb` is therefore not copied into
  the root.
- `signal()` in libc 10.20 is the System V kind (`SV_RESETHAND`): the handler is reset
  to default when it fires. `expr` is 32-bit. HP's `cc` converts an 18-digit floating
  literal one ulp low, and `printf` prints exact digits only up to the 17th. These are
  the real system's behaviours, reproduced, not emulator bugs.

- `getnumfds()` returns one more than the highest open descriptor: libc's `closeall`
  loops up to it.
- `sysfs(GETFSIND, name)` / `(GETFSTYP, index, buf)` / `(GETNFSTYP)`: the file system
  types (`hfs`, `nfs`, `cdfs`, `vxfs`, `autofs`, `lofs`); `df` uses them.
- `fss()` is called by `dld.sl` and libc at startup (a fair-share scheduler query); 0.
- `lseek` on a terminal fails with ESPIPE on the host; the HP-UX shell takes that as
  "not seekable" and reads a character at a time, which is fine.
- The C locale is built into libc: there is no `/usr/lib/nls/loc/locales/POSIX` file
  and the `ENOENT` on it is normal.
- HP's POSIX shell opens its history file only when `HISTFILE` is set, and names jobs
  from it (`<job name not known>` otherwise).
