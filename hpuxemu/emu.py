"""emu.py - the Python HP-UX emulator: loader, process, system calls (the reference
implementation; docs/DESIGN.md explains the design, docs/ABI.md the interface).

    python3 -m hpuxemu.emu [-r ROOT] [-t] [-e VAR=VAL] [-0 ARGV0] [-C DIR] [-u USER] [--cpu python|rust] PROGRAM [ARGS...]

PROGRAM is a path inside the root (or a name looked up on the guest's PATH). -0 sets its
argv[0] (a login shell is started as "-sh"), -C the working directory (/), -u the user
it runs as (a name or uid from the root's /etc/passwd; root by default). -t traces
system calls like HP-UX's `tusc`. Each `sys_<name>` docstring is the description used by
tools/syscalls_doc.py for SYSCALLS.md.
"""
import ctypes
import errno as herrno
import fcntl as hfcntl
import os
import select
import signal as hsignal
import stat as hstat
import struct
import sys
import time

from . import consts, native, rootdir, som, streams
from .lwp import LwpMixin, _Switched
from .consts import C, OFFSET, SIZEOF, SYSCALL_NAMES, ERRNO_NAMES, SIGNAL_NAMES
from .scall11 import SYSCALL_NAMES_11
from .consts11 import OFFSET as OFFSET_PSTAT64
from .cpu import Cpu, Memory, MemFault, M32


def make_cpu(kind):
    """'python': the reference interpreter in cpu.py; 'rust': rust/hppa32-jit through ctypes."""
    if kind == 'rust':
        from .rustcpu import RustCpu
        return RustCpu()
    if kind == 'python':
        return Cpu(Memory())
    raise ValueError('unknown cpu %r' % kind)

GATEWAY = 0xC0000000
# where mcas_util() lives on the gateway page (sysconf(_SC_MCAS_OFFSET) tells libc):
# msem_lock's compare-and-swap, done by the emulator under a host file lock
MCAS_OFFSET = 0x800
TEXT_BASE = 0x1000
STACK_BASE = 0x7B03A000     # where HP-UX 10.20 puts a 32-bit process's stack (it grows up)
STACK_LIMIT = 0x7B03A000 + 8 * 1024 * 1024
# instructions per CPU run between checks for pending signals
RUN_CHUNK = 4000000
PRIVATE_MMAP_TOP = 0x7A000000   # private mappings are placed downwards from here (Q2)
SHARED_MMAP_BASE = 0x80000000   # shared mappings upwards from here (Q3)
SHARED_MMAP_END = 0xC0000000
SHLIB_TEXT_BASE = 0xC0001000    # shared executable mappings: Q4, above the gateway page
SHLIB_TEXT_END = 0xF0000000     # (0xF0000000 up is I/O space on the real machines)
PAGE = 4096

TCGETA, TCSETA, TCSETAW, TCSETAF = 0x40125401, 0x80125402, 0x80125403, 0x80125404  # sys/termio.h: _IOR/_IOW('T', 1-4, struct termio)
ENOENT = C['ENOENT']
EINVAL = C['EINVAL']
EBADF = C['EBADF']
ENOSYS = C['ENOSYS']
EFAULT = C['EFAULT']
ENOMEM = C['ENOMEM']
EINTR = C['EINTR']
ECHILD = C['ECHILD']
EACCES = C['EACCES']
ELOOP = C['ELOOP']
ESRCH = C['ESRCH']

# host errno -> HP-UX errno, by name
HOST2GUEST_ERRNO = {}
for _num, _name in herrno.errorcode.items():
    if _name == 'EWOULDBLOCK':
        continue
    if _name in C:
        HOST2GUEST_ERRNO[_num] = C[_name]
HOST2GUEST_ERRNO[herrno.EAGAIN] = C['EAGAIN']
HOST2GUEST_ERRNO[herrno.ENOTSUP] = C.get('ENOTSUP', C['EOPNOTSUPP'])

# HP-UX signal <-> host signal, by name
GUEST2HOST_SIG = {}
HOST2GUEST_SIG = {}
for _num, _name in SIGNAL_NAMES.items():
    h = getattr(hsignal, _name, None)
    if h is not None:
        GUEST2HOST_SIG[_num] = int(h)
        HOST2GUEST_SIG[int(h)] = _num
# HP-UX 11.00's signals past 10.20's 32 (sys/signal.h; NSIG 45): SIGXCPU 33, SIGXFSZ 34,
# SIGCANCEL 35, SIGGFAULT 36 and the realtime signals 37..44 - the host's own XCPU
# and XFSZ, and its realtime signals for the rest
SIGNALS_11 = {33: 'SIGXCPU', 34: 'SIGXFSZ', 35: 'SIGCANCEL', 36: 'SIGGFAULT'}
SIGNALS_11.update({37 + i: 'SIGRTMIN+%d' % i for i in range(8)})
for _num, _h in [(33, int(hsignal.SIGXCPU)), (34, int(hsignal.SIGXFSZ))] + \
        [(37 + i, int(hsignal.SIGRTMIN) + i) for i in range(8)] + \
        [(35, int(hsignal.SIGRTMIN) + 8), (36, int(hsignal.SIGRTMIN) + 9)]:
    if _h not in HOST2GUEST_SIG and _num not in GUEST2HOST_SIG:
        GUEST2HOST_SIG[_num] = _h
        HOST2GUEST_SIG[_h] = _num



# the STREAMS pseudo-terminal ioctls of sys/strtio.h (_IO('t', n))
UNLKPT, ISPTM, ISPTS, TIOCSIGNAL = 0x20007446, 0x20007447, 0x20007449, 0x20007478
# sys/ptyio.h: TIOCTRAP _IOW('t',103,int), TIOCTRAPSTATUS _IOR('t',102,int), TIOCREQCHECK/TIOCREQSET (struct request_info)
TIOCTRAP, TIOCTRAPSTATUS = 0x80047467, 0x40047466
TIOCREQCHECK, TIOCREQSET = C.get('TIOCREQCHECK', -1), C.get('TIOCREQSET', -1)

# syscall.h names 139 only in a comment: it is sigcleanup, the return from a handler
SYSCALL_NAMES.setdefault(139, 'sigcleanup')
SYSCALL_NAMES_11.setdefault(139, 'sigcleanup')


# the host's struct flock (Linux, 64-bit): l_type, l_whence, l_start, l_len, l_pid and the
# padding to 32 bytes. F_GETLK used to slice 24 bytes of a 28-byte answer and crash.
HOST_FLOCK = 'hhqqi4x'

# HPUXEMU_TRACE_PC=1 with -t: each traced system call also shows its stub and caller
TRACE_PC = bool(os.environ.get('HPUXEMU_TRACE_PC'))


def hp_dev(dev):
    """A host device number as an HP-UX dev_t: major in bits 24..31, minor below."""
    return ((os.major(dev) & 0xFF) << 24) | (os.minor(dev) & 0xFFFFFF)


def sigbit(sig):
    """The bit of signal `sig` in a 256-bit sigset_t seen as one big-endian integer: word
    (sig-1)/32 of the 8 words, bit (sig-1)%32 in that word."""
    word, bit = (sig - 1) // 32, (sig - 1) % 32
    return (1 << bit) << (256 - 32 * (word + 1))


# signals whose default action is to ignore them, and those that stop the process
SIG_DEFAULT_IGNORE = {C[n] for n in ('SIGCHLD', 'SIGWINCH', 'SIGURG', 'SIGCONT', 'SIGPWR', 'SIGIO') if n in C}
SIG_STOPS = {C[n] for n in ('SIGSTOP', 'SIGTSTP', 'SIGTTIN', 'SIGTTOU') if n in C}

# system calls that are restarted after a handler with SA_RESTART returns; the ones that
# wait for a signal (pause, sigsuspend, sigpause) always return EINTR
# calls that may wait: a signal that came while the program ran is handled before one
# of them starts (as a kernel delivers it on the way back to user mode), the call made
# again when the handler returns
BLOCKING = {'read', 'readv', 'write', 'writev', 'wait', 'waitpid', 'wait3', 'recv', 'recvfrom',
            'recvmsg', 'send', 'sendto', 'sendmsg', 'accept', 'connect', 'msgsnd', 'msgrcv',
            'semop', 'select', 'poll', 'pause', 'getmsg', 'putmsg', 'getpmsg', 'putpmsg',
            'nanosleep', 'sigtimedwait', 'sigwait'}
# the calls a thread waits in by itself when the process has several (lwp.py)
THREAD_WAITS = {'read', 'readv', 'recv', 'recvfrom', 'recvmsg', 'accept', 'getmsg', 'getpmsg', 'poll', 'select',
                'waitpid', 'wait', 'wait3', 'nanosleep', 'sigtimedwait', 'sigwait'}
STATS_FILE = os.environ.get('HPUXEMU_STATS')
STATS_CHUNK = 500000            # instructions between PC samples with HPUXEMU_STATS
RESTARTABLE = {'read', 'readv', 'write', 'writev', 'wait', 'waitpid', 'wait3', 'open', 'ioctl', 'fcntl', 'lockf',
               'recv', 'recvfrom', 'recvmsg', 'send', 'sendto', 'sendmsg', 'accept', 'connect', 'msgsnd', 'msgrcv',
               'semop'}

_libc = ctypes.CDLL(None, use_errno=True)
_libc.read.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
_libc.read.restype = ctypes.c_ssize_t
_libc.write.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
_libc.write.restype = ctypes.c_ssize_t
_libc.waitpid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_int]
_libc.waitpid.restype = ctypes.c_int
_libc.pause.restype = ctypes.c_int
_libc.poll.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int]
_libc.poll.restype = ctypes.c_int
_libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
_libc.mmap.restype = ctypes.c_void_p
for _n in ('bind', 'connect'):
    getattr(_libc, _n).argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    getattr(_libc, _n).restype = ctypes.c_int
_libc.accept.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
_libc.accept.restype = ctypes.c_int
_libc.send.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
_libc.send.restype = ctypes.c_ssize_t
_libc.recv.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
_libc.recv.restype = ctypes.c_ssize_t
_libc.sendto.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
_libc.sendto.restype = ctypes.c_ssize_t
_libc.recvfrom.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
_libc.recvfrom.restype = ctypes.c_ssize_t


_libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
_libc.shmget.restype = ctypes.c_int
_libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
_libc.shmat.restype = ctypes.c_void_p
_libc.shmdt.argtypes = [ctypes.c_void_p]
_libc.shmdt.restype = ctypes.c_int
_libc.shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_libc.shmctl.restype = ctypes.c_int
_libc.semget.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
_libc.semget.restype = ctypes.c_int
_libc.semop.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
_libc.semop.restype = ctypes.c_int
_libc.semctl.restype = ctypes.c_int
_libc.msgget.argtypes = [ctypes.c_int, ctypes.c_int]
_libc.msgget.restype = ctypes.c_int
_libc.msgsnd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
_libc.msgsnd.restype = ctypes.c_int
_libc.msgrcv.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_long, ctypes.c_int]
_libc.msgrcv.restype = ctypes.c_ssize_t
_libc.msgctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_libc.msgctl.restype = ctypes.c_int

# the host's System V IPC structures (glibc, 64-bit Linux): what IPC_STAT returns
HOST_IPC = {
    'perm': ('=iIIIIHHH', ('key', 'uid', 'gid', 'cuid', 'cgid', 'mode', 'pad', 'seq')),     # 48 bytes with padding
    'shm': {'segsz': ('=Q', 48), 'atime': ('=q', 56), 'dtime': ('=q', 64), 'ctime': ('=q', 72), 'cpid': ('=i', 80), 'lpid': ('=i', 84), 'nattch': ('=Q', 88), 'size': 112},
    'sem': {'otime': ('=q', 48), 'ctime': ('=q', 64), 'nsems': ('=Q', 80), 'size': 104},
    'msg': {'stime': ('=q', 48), 'rtime': ('=q', 56), 'ctime': ('=q', 64), 'cbytes': ('=Q', 72), 'qnum': ('=Q', 80), 'qbytes': ('=Q', 88), 'lspid': ('=i', 96), 'lrpid': ('=i', 100), 'size': 120},
}
# HP-UX semctl commands are the BSD numbers; Linux's differ
HOST_SEMCMD = {0: 0, 1: 1, 2: 2, 3: 14, 4: 11, 5: 12, 6: 13, 7: 15, 8: 16, 9: 17}


def host_errno_call(fn, *args):
    """Call a libc function that returns -1/errno; EINTR raises _Interrupted."""
    r = fn(*args)
    if r < 0:
        e = ctypes.get_errno()
        if e == herrno.EINTR:
            raise _Interrupted()
        raise OSError(e, os.strerror(e))
    return r


class _Interrupted(Exception):
    """A blocking host call returned EINTR: a signal is pending for the guest."""


def host_read(fd, n):
    """read(2) through libc so that a signal interrupts it (Python's os.read restarts
    after running the handler, and a handler that raises would lose data)."""
    buf = ctypes.create_string_buffer(max(n, 1))
    r = _libc.read(fd, buf, n)
    if r < 0:
        e = ctypes.get_errno()
        if e == herrno.EINTR:
            raise _Interrupted()
        raise OSError(e, os.strerror(e))
    return buf.raw[:r]


def host_write(fd, data):
    r = _libc.write(fd, data, len(data))
    if r < 0:
        e = ctypes.get_errno()
        if e == herrno.EINTR:
            raise _Interrupted()
        raise OSError(e, os.strerror(e))
    return r


def host_waitpid(pid, options):
    st = ctypes.c_int(0)
    r = _libc.waitpid(pid, ctypes.byref(st), options)
    if r < 0:
        e = ctypes.get_errno()
        if e == herrno.EINTR:
            raise _Interrupted()
        raise OSError(e, os.strerror(e))
    return r, st.value


# Waiting for a signal or a descriptor without losing a wake-up: the host handler only
# records a signal (the guest's handler runs at the next system call return), so one that
# arrives between "is anything pending?" and the blocking call would be slept through -
# until a timeout, or for ever (csh in sigpause, its child's SIGCHLD already taken). The
# host's signals are blocked over the check, and sigsuspend/ppoll unblock them atomically.
_CATCHABLE = set(hsignal.valid_signals()) - {hsignal.SIGKILL, hsignal.SIGSTOP}
_libc.sigemptyset.argtypes = [ctypes.c_void_p]
_libc.sigaddset.argtypes = [ctypes.c_void_p, ctypes.c_int]
_libc.sigsuspend.argtypes = [ctypes.c_void_p]
_libc.ppoll.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
_libc.ppoll.restype = ctypes.c_int
signal_pending_check = None     # set by the emulator: is a deliverable guest signal pending?


def chld_is_news():
    """Whether a host SIGCHLD is one HP-UX would send: a child exited or stopped. Linux
    also sends one when a child is continued (SIGCONT), which HP-UX does not - and a
    SIGCHLD handler without SA_RESTART then makes the parent's waitpid fail with EINTR
    (a stop, SIGCONT and SIGTERM, then waitpid: the stop's status read again). Looked at
    without reaping (WNOWAIT); a continue alone is taken off the host's record and the
    signal dropped. An exit merged into the same SIGCHLD is seen; one after it raises
    another SIGCHLD."""
    try:
        if os.waitid(os.P_ALL, 0, os.WEXITED | os.WSTOPPED | os.WNOHANG | os.WNOWAIT) is not None:
            return True
        if os.waitid(os.P_ALL, 0, os.WCONTINUED | os.WNOHANG) is not None:
            return False
    except (ChildProcessError, OSError, AttributeError):
        pass
    return True


def set_signal_pending_check(fn):
    global signal_pending_check
    signal_pending_check = fn


try:
    # signal.pthread_sigmask turns the old mask it returns into a set of Signals enum
    # members, 30 of them: most of a select()'s cost. _signal's gives the numbers.
    from _signal import pthread_sigmask as _sigmask
except ImportError:
    _sigmask = hsignal.pthread_sigmask

_sigsets = {}


def _c_sigset(sigs):
    """a C sigset_t of the signals: the same few masks over and over, so kept"""
    key = frozenset(int(s) for s in sigs)
    buf = _sigsets.get(key)
    if buf is None:
        buf = ctypes.create_string_buffer(256)
        _libc.sigemptyset(buf)
        for s in key:
            _libc.sigaddset(buf, s)
        if len(_sigsets) < 64:
            _sigsets[key] = buf
    return buf


def host_pause():
    old = _sigmask(hsignal.SIG_BLOCK, _CATCHABLE)
    try:
        if signal_pending_check is None or not signal_pending_check():
            _libc.sigsuspend(_c_sigset(old))
    finally:
        _sigmask(hsignal.SIG_SETMASK, old)
    raise _Interrupted()


def host_poll(entries, timeout_ms):
    """poll(2) over [(fd, events)]; returns [revents] (EINTR raises _Interrupted)."""
    n = len(entries)
    buf = (ctypes.c_int * (2 * max(n, 1)))()
    little = sys.byteorder == 'little'
    for i, (fd, ev) in enumerate(entries):
        buf[2 * i] = fd
        buf[2 * i + 1] = (ev & 0xFFFF) if little else (ev & 0xFFFF) << 16   # events, revents: two shorts
    old = _sigmask(hsignal.SIG_BLOCK, _CATCHABLE)
    try:
        if signal_pending_check is not None and signal_pending_check():
            raise _Interrupted()
        if timeout_ms is None or timeout_ms < 0:
            ts = None
        else:
            ts = (ctypes.c_long * 2)(timeout_ms // 1000, (timeout_ms % 1000) * 1000000)
        r = _libc.ppoll(buf, n, ts, _c_sigset(old))
    finally:
        _sigmask(hsignal.SIG_SETMASK, old)
    if r < 0:
        e = ctypes.get_errno()
        if e == herrno.EINTR:
            raise _Interrupted()
        raise OSError(e, os.strerror(e))
    out = []
    for i in range(n):
        v = buf[2 * i + 1] & 0xFFFFFFFF
        out.append((v >> 16) if little else (v & 0xFFFF))
    return out


# the arguments the trace shows as strings
PATH_SYSCALLS = {'open': [0], 'creat': [0], 'stat': [0], 'lstat': [0], 'stat64': [0], 'lstat64': [0], 'access': [0], 'chdir': [0],
                 'unlink': [0], 'execve': [0], 'execv': [0], 'readlink': [0], 'chmod': [0], 'chown': [0], 'mkdir': [0], 'rmdir': [0],
                 'link': [0, 1], 'symlink': [0, 1], 'rename': [0, 1], 'utime': [0], 'truncate': [0], 'statfs': [0], 'statvfs': [0],
                 'pathconf': [0], 'mknod': [0], 'lchown': [0], 'write': [1]}


def _re():
    """the re module, imported when first needed (it costs a short program's start-up
    4 ms, and two rare paths use it)"""
    import re
    return re


class HpuxError(Exception):
    def __init__(self, e):
        Exception.__init__(self, ERRNO_NAMES.get(e, str(e)))
        self.errno = e


def host_err(e):
    return HpuxError(HOST2GUEST_ERRNO.get(e.errno, C['EIO']))


_PACKERS = {}
_INT_CODES = {1: '>B', 2: '>H', 4: '>I', 8: '>Q'}


def _packer(sname):
    """member -> (offset, size, struct packer or None, mask) for a structure"""
    layout = OFFSET[sname]
    out = {}
    for k, (off, size) in layout.items():
        code = _INT_CODES.get(size)
        out[k] = (off, size, struct.Struct(code).pack_into if code else None, (1 << (8 * size)) - 1)
    _PACKERS[sname] = out
    return out


def pack(sname, fields):
    """Pack a dict of member -> int (or bytes) into a guest structure by consts.OFFSET."""
    buf = bytearray(SIZEOF[sname])
    layout = _PACKERS.get(sname) or _packer(sname)
    for k, v in fields.items():
        off, size, pk, mask = layout[k]
        if isinstance(v, (bytes, bytearray)):
            buf[off:off + min(size, len(v))] = v[:size]
        elif pk is not None:
            pk(buf, off, v & mask)
        else:
            buf[off:off + size] = (v & mask).to_bytes(size, 'big')
    return bytes(buf)


def unpack(sname, data):
    out = {}
    for k, (off, size) in OFFSET[sname].items():
        if size <= 8 and k not in ('c_cc', 'd_name', 'sa_data', 'sun_path', 'sin_zero', 'f_basetype'):
            out[k] = int.from_bytes(data[off:off + size], 'big')
        else:
            out[k] = bytes(data[off:off + size])
    return out


class Process(LwpMixin):
    def __init__(self, root, trace=False, env=None, cpu='python'):
        self.root = root.rstrip('/')
        self.rootreal = os.path.realpath(self.root)
        self.trace = trace
        self.cpu_kind = cpu
        self.cpu = make_cpu(cpu)
        self.mem = self.cpu.mem
        self.cwd = '/'
        self.brk = 0
        self.brk_base = 0
        self.priv_mmap = PRIVATE_MMAP_TOP
        self.shared_mmap = SHARED_MMAP_BASE
        self.mappings = []     # (addr, size, host mmap object or None, fd or None, flags)
        self.fds = {}          # guest fd -> dict(flags, path, dir cursor)
        # non-blocking descriptors, by the way they were made so (HP-UX's three
        # kinds, recv(2), socket(7)): 'nonblock' (O_NONBLOCK: EAGAIN), 'ndelay'
        # (O_NDELAY: a read or write that would block returns 0, accept says
        # EWOULDBLOCK), 'fio' (ioctl FIOSNBIO/FIONBIO: EWOULDBLOCK on sockets).
        # O_NONBLOCK and O_NDELAY win over FIOSNBIO.
        self.nbmode = {}
        self.umask = 0o022
        self.uid = 0            # real; euid/suid are the effective and saved ids
        self.euid = 0
        self.suid = 0
        self.egid = 0
        self.sgid = 0
        self.groups = []        # supplementary groups (setgroups/initgroups)
        self.gid = 0
        self.host_uid = os.getuid()
        self.host_gid = os.getgid()
        self.owners = None     # etc/hpuxemu/owners, loaded at the first stat
        self.hpcache = {}      # (dev, ino) -> host path or fd it was just reached by (one system call)
        self.xcache = {}       # (dev, ino, ctime, name) -> extended attribute value
        self.shm_attached = {}  # guest address -> (shmid, size, host address for a private copy)
        self.ptys = {}          # guest slave name -> host slave path (from /dev/ptym/clone)
        # a pty master is marked in its fd record ('pty': number) so that dup, dup2
        # and fcntl(F_DUPFD) carry the mark (grantpt's helper gets the master on fd 0)
        self.pid = os.getpid()
        self.env = env or {}
        self.sigactions = {}   # signo -> (handler, mask, flags)
        self.sigmask = 0
        self.pending = set()
        set_signal_pending_check(lambda: any(self.deliverable(g) for g in self.pending))
        self.fault_info = {}      # signal -> details of the CPU fault that raised it
        self.sigreturn_addr = 0
        self.exited = None
        self.have_tty = os.isatty(0)
        self.my_ttys = set()
        for fd in (0, 1, 2):
            try:
                if os.isatty(fd):
                    self.my_ttys.add(os.ttyname(fd))
            except OSError:
                pass
        self.argv0 = ''
        self.release = open(os.path.join(self.root, 'etc/hpuxemu/release')).read().strip() if os.path.exists(os.path.join(self.root, 'etc/hpuxemu/release')) else 'B.10.20'
        # the guest clock: etc/hpuxemu/clock holds a date ("1999-06-01" or "1999-06-01
        # 12:00[:00]", local time), the guest's time when the file was written; from then on
        # it runs with the host's. No file: the host's time.
        self.clock_offset, self.clock_anchor = 0, None
        cf = os.path.join(self.root, 'etc/hpuxemu/clock')
        if os.path.exists(cf):
            try:
                txt = open(cf).read().split('#')[0].strip()
                for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
                    try:
                        t = time.mktime(time.strptime(txt, fmt))
                        break
                    except ValueError:
                        t = None
                if t is not None:
                    self.clock_anchor = os.stat(cf).st_mtime
                    self.clock_offset = int(t - self.clock_anchor)
            except OSError:
                pass
        # an 11.00 root: its programs use the 11.00 system call numbers (same handlers)
        self.scall_names = SYSCALL_NAMES_11 if self.release.startswith('B.11') else SYSCALL_NAMES
        self.scall_cache = {}         # number -> (name, handler)
        self.inhibit = []             # siginhibit/sigenable: the masks to restore
        # the node name: etc/hpuxemu/hostname, else "hpux" - never the host's own, which
        # the root's /etc/hosts could not resolve (ttsession looks itself up by it)
        hn = os.path.join(self.root, 'etc/hpuxemu/hostname')
        self.nodename = (open(hn).read().strip() if os.path.exists(hn) else '') or 'hpux'
        try:
            from .owners import mnttab
            mnttab(self.root)
        except OSError:
            pass

    # -- paths (chroot-style, as aixemu's hostpath) -------------------------------------
    HOST_DEVICES = frozenset(('/dev/null', '/dev/tty', '/dev/zero', '/dev/urandom', '/dev/random'))

    def hostpath(self, gpath, follow_last=True, search=True, cred=None):
        """The host path of a guest path, resolved inside the root (symbolic links
        included). Like the kernel's lookup it needs search permission on every
        directory it looks a name up in - with the effective ids, or `cred` (uid,
        groups) for access(); a relative path starts in the working directory, whose
        own path is not searched again. search=False is for the emulator's own use."""
        if gpath == '':
            raise HpuxError(ENOENT)
        if search:
            if cred is None:
                cred = (self.euid, [self.egid] + self.groups)
            if cred[0] == 0:
                cred = None
        else:
            cred = None
        if gpath.startswith('/'):
            parts = []
        else:
            parts = [(x, False) for x in self.cwd.split('/') if x not in ('', '.')]
        parts += [(x, True) for x in gpath.split('/') if x not in ('', '.')]
        resolved = []
        cur = None              # lstat of the directory `resolved` names, when known
        hops = 0
        while parts:
            seg, chk = parts.pop(0)
            if chk and cred is not None:
                self.search_ok('/' + '/'.join(resolved), cred, cur)
            if seg == '..':
                if resolved:
                    resolved.pop()
                cur = None
                continue
            cand = self.root + '/' + '/'.join(resolved + [seg])
            lst = None
            if parts or follow_last:
                try:
                    lst = os.lstat(cand)
                except OSError:
                    pass
            if lst is not None and hstat.S_ISLNK(lst.st_mode):
                hops += 1
                if hops > 40:
                    raise HpuxError(ELOOP)
                target = os.readlink(cand)
                tparts = [(x, chk) for x in target.split('/') if x not in ('', '.')]
                if target.startswith('/'):
                    resolved = []
                parts = tparts + parts
                cur = None
                continue
            resolved.append(seg)
            cur = lst
        norm = '/' + '/'.join(resolved)
        if norm.startswith('/dev/'):
            if norm in self.HOST_DEVICES:
                return norm
            if norm == '/dev/console':
                return '/dev/tty' if self.have_tty else os.path.join(self.root, 'var/adm/console.log')
            if norm in self.my_ttys or (norm.startswith('/dev/pts/') and norm[9:].isdigit()):
                # the host's pseudo-terminals are the guest's
                return norm
        # no host realpath() check after this: the walk above looked every component
        # up inside the root and followed each link itself (an absolute target from
        # the root, '..' never above it), so root + norm names nothing outside it - and
        # a second resolution cost as much as the walk (a stat()'s lookup)
        return self.root + norm

    def search_ok(self, gdir, cred, st=None):
        """EACCES unless `cred` may search the directory gdir (a resolved guest path:
        no links in it; st its lstat if the lookup has it); ENOTDIR if it is not a
        directory"""
        if st is None:
            try:
                st = os.stat(self.root + gdir)
            except OSError:
                return          # the lookup itself reports it
        if not hstat.S_ISDIR(st.st_mode):
            raise HpuxError(C['ENOTDIR'])
        if not self.allowed(gdir, st, 1, cred[0], cred[1], src=self.root + gdir):
            raise HpuxError(EACCES)

    def guest_abspath(self, gpath):
        if not gpath.startswith('/'):
            gpath = self.cwd.rstrip('/') + '/' + gpath
        parts = []
        for x in gpath.split('/'):
            if x in ('', '.'):
                continue
            if x == '..':
                if parts:
                    parts.pop()
            else:
                parts.append(x)
        return '/' + '/'.join(parts)

    # -- memory helpers ----------------------------------------------------------------
    def rd(self, addr, n):
        if n == 0:
            return b''
        try:
            return self.mem.read(addr, n)
        except MemFault:
            raise HpuxError(EFAULT)

    def wr(self, addr, data):
        if not data:
            return
        try:
            self.mem.write(addr, data)
        except MemFault:
            raise HpuxError(EFAULT)

    def rd32(self, addr):
        return struct.unpack('>I', self.rd(addr, 4))[0]

    def wr32(self, addr, v):
        self.wr(addr, struct.pack('>I', v & M32))

    def rdstr(self, addr, limit=4096):
        try:
            return self.mem.read_cstr(addr, limit).decode('latin1')
        except MemFault:
            raise HpuxError(EFAULT)

    def rdvec(self, addr):
        out = []
        while True:
            p = self.rd32(addr)
            if p == 0:
                break
            out.append(self.rdstr(p))
            addr += 4
        return out

    def map_anon(self, addr, size, prot=7):
        self.mem.map(addr, size, prot)

    # -- loading -----------------------------------------------------------------------
    def find_program(self, name):
        if '/' in name:
            return name
        path = self.env.get('PATH', '/usr/bin:/bin:/usr/ccs/bin:/sbin')
        for d in path.split(':'):
            cand = (d or '.') + '/' + name
            try:
                hp = self.hostpath(cand)
            except HpuxError:
                continue
            if os.path.isfile(hp) and os.access(hp, os.X_OK):
                return cand
        return name

    # -- HPUXEMU_STATS=FILE: where each program image's time goes ---------------------
    stats = None

    def stats_begin(self, how, path):
        """a new program image (exec, the first load) or a forked copy starts its account"""
        if not STATS_FILE:
            return
        t = os.times()
        self.stats = {'how': how, 'prog': path, 'pid': os.getpid(), 't0': time.perf_counter(),
                      'u0': t.user, 's0': t.system, 'run': 0.0, 'nrun': 0, 'load': 0.0,
                      'calls': {}, 'pcs': {}}

    def stats_where(self, pc, prog, maps=()):
        """'file+0xoffset' for a PC in a mapped file (the program's text: its own path)"""
        for base, size, path, off in maps:
            if base <= pc < base + size:
                root = self.root.rstrip('/') if isinstance(getattr(self, 'root', None), str) else ''
                if root and path.startswith(root + '/'):
                    path = path[len(root):]
                return '%s+%#x' % (path, pc - base + off)
        for m in self.mappings:
            base, size, path = m[0], m[1], m[2]
            if path and base <= pc < base + size:
                return '%s+%#x' % (path, pc - base + m[3])
        tb = getattr(self, 'text_base', None)
        if tb is not None and tb <= pc < tb + getattr(self, 'text_size', 0):
            return '%s+%#x' % (prog, pc)
        return '?+%#x' % pc

    def stats_end(self, why, keep=False):
        """the image ends (exit, exec): one JSON line - wall and host CPU seconds, the
        seconds in the CPU (cpu.run), the image's load, and each system call's count and
        wall seconds"""
        st = self.stats
        if st is None:
            return
        if not keep:
            self.stats = None
        st['last'] = time.perf_counter()
        t = os.times()
        calls = st['calls']
        rec = {'id': '%d-%.6f' % (st['pid'], st['t0']), 'pid': st['pid'], 'how': st['how'], 'prog': st['prog'], 'end': why,
               'wall': round(time.perf_counter() - st['t0'], 4),
               'user': round(t.user - st['u0'], 3), 'sys': round(t.system - st['s0'], 3),
               'cpu_run': round(st['run'], 4), 'nrun': st['nrun'], 'load': round(st['load'], 4),
               'ncalls': sum(c[0] for c in calls.values()),
               'call_wall': round(sum(c[1] for c in calls.values()), 4),
               'calls': {k: [v[0], round(v[1], 4)] for k, v in sorted(calls.items(), key=lambda kv: -kv[1][1])[:25]}}
        js = self.cpu.jit_stats() if hasattr(self.cpu, 'jit_stats') else None
        if js:
            rec['jit'] = js
        if st['pcs']:
            # the samples by mapped file and offset (the program's own text by its path)
            where = {}
            for pc, n in st['pcs'].items():
                k = self.stats_where(pc, st['prog'], st.get('maps', ()))
                where[k] = where.get(k, 0) + n
            rec['pcs'] = where
        try:
            fd = os.open(STATS_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            import json
            os.write(fd, (json.dumps(rec) + '\n').encode())
            os.close(fd)
        except OSError:
            pass

    def load(self, path, argv, envp):
        """Load a SOM executable the way the HP-UX 10.20 kernel does (binfmt-som style:
        text and data mapped from the file at their link addresses, bss zeroed, the stack at
        STACK_BASE with argc/argv/envp in r26/r25/r24 and the kernel's process-info block
        in r23), then start at the entry point."""
        hp = self.hostpath(path)
        try:
            with open(hp, 'rb') as f:
                data = f.read()
        except OSError as e:
            # a missing program or #! interpreter: exec fails with ENOENT and the old
            # image goes on, as on HP-UX (a configure script whose #!/sbin/sh did not
            # exist yet killed the emulator with a host traceback)
            raise host_err(e)
        if data[:2] == b'#!':
            # an interpreter script
            line = data.split(b'\n', 1)[0][2:].decode('latin1').strip().split()
            if not line:
                raise HpuxError(C['ENOEXEC'])
            return self.load(line[0], line[:1] + line[1:] + [path] + argv[1:], envp)
        try:
            s = som.Som(data, path)
        except ValueError:
            raise HpuxError(C['ENOEXEC'])
        if s.exec is None or s.magic not in (0x107, 0x108, 0x10b):
            raise HpuxError(C['ENOEXEC'])
        e = s.exec
        self.som = s
        self.cpu = make_cpu(self.cpu_kind)
        self.mem = self.cpu.mem
        self.argv0 = path
        self.argv = argv
        self.start_time = int(self.now())
        self.publish()
        # text: the file from tfile at tmem (for SHARE_MAGIC programs tfile is 0, so the
        # SOM header and the dictionaries are mapped too, at 0x1000: dld and crt0 read them)
        tstart = e['tmem'] & ~(PAGE - 1)
        tlen = (e['tmem'] + e['tsize'] + PAGE - 1) & ~(PAGE - 1)
        self.text_base, self.text_size = e['tmem'], e['tsize']
        self.mem.map(tstart, tlen - tstart, 7)
        self.mem.write(e['tmem'], data[e['tfile']:e['tfile'] + e['tsize']])
        self.mem.protect(tstart, tlen - tstart, 5)
        dstart = e['dmem'] & ~(PAGE - 1)
        dend = (e['dmem'] + e['dsize'] + e['bsize'] + PAGE - 1) & ~(PAGE - 1)
        # data, bss, the heap and the stack are executable, as on PA-RISC HP-UX: HP's Java VM
        # runs the code its JIT writes into malloc'd memory
        self.mem.map(dstart, dend - dstart, 7)
        self.mem.write(e['dmem'], data[e['dfile']:e['dfile'] + e['dsize']])
        self.brk_base = self.brk = (e['dmem'] + e['dsize'] + e['bsize'] + PAGE - 1) & ~(PAGE - 1)
        self.mem.map(self.brk, PAGE, 7)   # the page beyond the break (sys_brk)
        if not (e['flags'] & 1):
            # exec_flags bit 0 (ld -z) makes nil-pointer dereferences an error; without it
            # HP-UX lets a program read page 0 as zeros (head -3 reads argv past its end)
            self.mem.map(0, PAGE, 1)
        # the stack
        self.mem.map(STACK_BASE, 256 * 1024, 7)
        self.stack_mapped_end = STACK_BASE + 256 * 1024
        sp = self.build_stack(argv, envp)
        cpu = self.cpu
        cpu.gr[30] = sp
        cpu.gr[27] = s.presumed_dp
        cpu.cr[27] = 0
        cpu.set_pc(e['entry'])
        cpu.gr[31] = cpu.iaoq_f
        return s

    def build_stack(self, argv, envp):
        """argv/envp strings and vectors at the bottom of the stack, then the kernel's
        process-info block (what crt0 reads through r23), then sp (64-byte aligned, with the
        argument slots -36..-48(sp) filled as the calling convention has them)."""
        p = STACK_BASE + 16
        strs = []
        for a in argv + envp:
            strs.append(p)
            b = a.encode('latin1') + b'\0'
            self.mem.write(p, b)
            p += len(b)
        p = (p + 7) & ~7
        argvp = p
        for i, a in enumerate(argv):
            self.mem.write32(p, strs[i])
            p += 4
        self.mem.write32(p, 0)
        p += 4
        envpp = p
        for i in range(len(envp)):
            self.mem.write32(p, strs[len(argv) + i])
            p += 4
        self.mem.write32(p, 0)
        p += 4
        p = (p + 7) & ~7
        # the process-info block: crt0 copies word 0 to _CPU_REVISION, word 1's bits to
        # _FPU_MODEL/_FPU_REVISION, word 3 to _CPU_KEYBITS_1. Word 0 is the CPU version
        # sysconf(_SC_CPU_VERSION) gives: HP's Java VM checks
        # _CPU_REVISION for PA-RISC 1.0/1.1/2.0 and its JIT gives up - with a longjmp to a
        # buffer nothing has set - when it is none of them
        info = p
        self.mem.write(p, struct.pack('>IIII', C.get('CPU_PA_RISC1_1', 0x210), 0, 0, 0))
        p += 16
        sp = (p + 64 + 63) & ~63
        self.mem.write32(sp - 36, len(argv))
        self.mem.write32(sp - 40, argvp)
        self.mem.write32(sp - 44, envpp)
        self.mem.write32(sp - 48, info)
        cpu = self.cpu
        cpu.gr[26] = len(argv)
        cpu.gr[25] = argvp
        cpu.gr[24] = envpp
        cpu.gr[23] = info
        return sp

    # -- running -----------------------------------------------------------------------
    def run(self):
        cpu = self.cpu
        hooks = os.environ.get('HPUXEMU_HOOKS')
        if hooks:
            cpu.hooks = set(int(h, 16) for h in hooks.split(','))
        while self.exited is None:
            if self.pending:
                self.deliver_signals()
                if self.exited is not None:
                    break
            if self.stats is not None:
                t0 = time.perf_counter()
                r = cpu.run(STATS_CHUNK)
                self.stats['run'] += time.perf_counter() - t0
                self.stats['nrun'] += 1
                if r[0] == 'count':
                    # a PC sample every STATS_CHUNK instructions: where the guest's time goes
                    pc = cpu.iaoq_f & ~3
                    pcs = self.stats['pcs']
                    pcs[pc] = pcs.get(pc, 0) + 1
            else:
                r = cpu.run(RUN_CHUNK)
            kind = r[0]
            if kind == 'count':
                if self.lwps:
                    self.lwp_preempt()
                continue
            if kind == 'syscall':
                if r[1] == GATEWAY + MCAS_OFFSET:
                    self.mcas_util()
                elif self.stats is not None:
                    name = self.scall_names.get(cpu.gr[22] & M32, 'sys%d' % (cpu.gr[22] & M32))
                    t0 = time.perf_counter()
                    try:
                        self.syscall()
                    finally:
                        if self.stats is not None:
                            c = self.stats['calls'].setdefault(name, [0, 0.0])
                            c[0] += 1
                            t1 = time.perf_counter()
                            c[1] += t1 - t0
                            if t1 - self.stats.get('last', self.stats['t0']) > 20:
                                # a snapshot for a process that may never exit
                                self.stats_end('running', keep=True)
                else:
                    self.syscall()
            elif kind == 'hook':
                # HPUXEMU_HOOKS=addr,...: log the registers when execution reaches an address
                sys.stderr.write('hook %08x: %s\n' % (r[1], ' '.join('r%d=%x' % (i, cpu.gr[i] & M32) for i in range(1, 32))))
                for i in (26, 25, 24, 23):
                    a = cpu.gr[i] & M32
                    if self.mem.is_mapped(a):
                        try:
                            sys.stderr.write('    r%d -> %r\n' % (i, self.mem.read(a, 32)))
                        except MemFault:
                            pass
                saved = cpu.hooks
                cpu.hooks = set()
                cpu.step()
                cpu.hooks = saved
            elif kind == 'fault' and STACK_BASE <= r[1] < STACK_LIMIT and not self.mem.is_mapped(r[1]):
                # the stack grows up on demand, to its 8 MB limit
                page = r[1] & ~(PAGE - 1)
                self.mem.map(page, 16 * PAGE if page + 16 * PAGE <= STACK_LIMIT else STACK_LIMIT - page, 7)
            elif kind == 'fault':
                # HP-UX's trap numbers (machine/trap.h, PA-RISC 1.1): 15 data page fault
                # (nothing mapped), 18 data memory protection (mapped, access denied)
                mapped = self.mem.is_mapped(r[1])
                fault = {'addr': r[1] & M32, 'write': bool(r[2]), 'pc': r[3] & M32,
                         'trap': 18 if mapped else 15, 'mapped': mapped}
                self.fatal('memory fault at %#x (%s) pc %#x' % (r[1], 'write' if r[2] else 'read', r[3]),
                           C['SIGSEGV'] if r[1] < 0xC0000000 else C['SIGBUS'], fault)
            elif kind == 'illegal':
                self.fatal('illegal instruction %08x at %#x' % (r[2], r[1]), C['SIGILL'])
            elif kind == 'break':
                self.fatal('break %d,%d at %#x' % (r[1], r[2], r[3]), C['SIGTRAP'])
            elif kind == 'priv':
                self.fatal('privileged instruction %08x at %#x' % (r[2], r[1]), C['SIGILL'])
            elif kind in ('trap', 'overflow'):
                self.fatal('conditional trap at %#x' % r[1], C['SIGFPE'])
            elif kind == 'unaligned':
                self.fatal('unaligned ldcw at %#x pc %#x' % (r[1], r[2]), C['SIGBUS'])
            else:
                self.fatal('unexpected CPU exit %r' % (r,), C['SIGILL'])
        self.stats_end('exit')
        return self.exited

    def fatal(self, msg, sig, fault=None):
        """A fault the CPU reported: the signal goes to the program's handler if it has
        one (the Bourne shell grows its memory from a SIGSEGV handler), with the context's
        pc at the faulting instruction; otherwise the process dies with the signal and a
        register dump."""
        cpu = self.cpu
        handler = self.sigactions.get(sig, (0,))[0]
        if handler not in (0, 1) and not (self.sigmask & sigbit(sig)):
            if self.trace:
                sys.stderr.write('[%d] -- %s: %s\n' % (self.pid, SIGNAL_NAMES.get(sig, sig), msg))
            self.pending.add(sig)
            if fault:
                self.fault_info[sig] = fault
            self.deliver_signals()
            return
        sys.stderr.write('hpuxemu: %s: %s\n' % (self.argv0, msg))
        sys.stderr.write('  ' + ' '.join('r%d=%08x' % (i, cpu.gr[i] & M32) for i in range(1, 32)) + '\n')
        sys.stderr.write('  pc=%08x npc=%08x sar=%x icount=%d\n' % (cpu.iaoq_f, cpu.iaoq_b, cpu.sar, cpu.icount))
        self.exited = ('signal', sig)

    # -- system calls ------------------------------------------------------------------
    def syscall(self):
        cpu = self.cpu
        num = cpu.gr[22] & M32
        ent = self.scall_cache.get(num)
        if ent is None:
            name = self.scall_names.get(num, 'sys%d' % num)
            ent = self.scall_cache[num] = (name, getattr(self, 'sys_' + name, None))
        name, fn = ent
        where = (cpu.gr[31] & M32, cpu.gr[2] & M32) if self.trace else None
        gr = cpu.gr
        sp = gr[30] & M32
        args = [gr[26] & M32, gr[25] & M32, gr[24] & M32, gr[23] & M32]
        try:
            # the stack arguments at sp-52, -56, -60, -64: one read
            a8, a7, a6, a5 = struct.unpack('>4I', self.mem.read(sp - 64, 16))
            args += (a5, a6, a7, a8)
        except MemFault:
            try:
                for i in range(4):
                    args.append(self.mem.read32(sp - 52 - 4 * i))
            except MemFault:
                args += [0, 0, 0, 0]
        if self.hpcache:
            self.hpcache = {}
        self.owners_fresh = False
        ret2 = None
        interrupted = False
        t0 = time.time() if self.trace else 0
        if self.pending and name in BLOCKING and self.deliver_before_call():
            return
        if self.lwps and len(self.lwps) > 1 and name in THREAD_WAITS:
            # several threads: a call that would block the host waits in this thread only
            try:
                self.lwp_would_block(name, args)
            except _Switched:
                if self.trace:
                    sys.stderr.write('[%d] %s(%s) waits\n' % (self.pid, name, ', '.join('%#x' % x for x in args[:4])))
                if self.pending and self.exited is None:
                    self.deliver_signals()
                return
        try:
            if fn is None:
                sys.stderr.write('hpuxemu: unimplemented syscall %s(%d) args %s\n' % (name, num, ' '.join('%x' % a for a in args[:4])))
                raise HpuxError(ENOSYS)
            r = fn(*args)
            if isinstance(r, tuple):
                r, ret2 = r
            if r is None:
                r = 0
            err = 0
        except HpuxError as e:
            r = e.errno
            err = 1
            if r == C['EAGAIN'] and args and args[0] in self.nbmode:
                r, err = self.nb_result(name, args[0], r)
        except _Interrupted:
            # a signal arrived during a blocking call: EINTR now; deliver_signals decides
            # whether the handler's SA_RESTART turns that into a restart of the call
            self.poll_signals()
            r = EINTR
            err = 1
            interrupted = name in RESTARTABLE
        except _InterruptedWithMask as e:
            # sigsuspend: return EINTR with the mask restored, after the handler runs
            # with the temporary mask (the frame carries the one to restore)
            r = EINTR
            err = 1
            cpu.gr[28] = r
            cpu.gr[22] = 1
            cpu.set_pc(cpu.gr[31])
            self.deliver_signals()
            # the frame's saved mask is the sigsuspend one; the mask after the handler
            # must be the original
            self.fix_frame_mask(e.mask)
            return
        except _NoReturn:
            if self.trace:
                sys.stderr.write('[%d] %s(...)\n' % (self.pid, name))
            return
        except _Switched:
            # the thread blocked (or ended) and another runs: its registers are loaded
            if self.trace:
                sys.stderr.write('[%d] %s(%s) blocks\n' % (self.pid, name, ', '.join('%#x' % x for x in args[:4])))
            if self.pending and self.exited is None:
                self.deliver_signals()
            return
        if self.trace:
            shown = ['%#x' % a for a in args[:4]]
            if name in PATH_SYSCALLS:
                for k in PATH_SYSCALLS[name]:
                    try:
                        shown[k] = repr(self.rdstr(args[k], 200))
                    except HpuxError:
                        pass
            if name in ('connect', 'bind', 'sendto') and len(args) > 2:
                shown[1] = self.sockaddr_str(args[1] if name != 'sendto' else args[4], args[2] if name != 'sendto' else args[5])
            t1 = time.time()
            sys.stderr.write('%s.%03d [%d] %s(%s) = %s%s%s\n' % (
                time.strftime('%H:%M:%S', time.localtime(t1)), int(t1 * 1000) % 1000,
                self.pid, name, ', '.join(shown),
                ('error %s' % ERRNO_NAMES.get(r, r)) if err else ('%#x' % (r & M32)),
                (' r29=%#x' % ret2) if ret2 is not None else '',
                (' <%.3fs>' % (t1 - t0)) if t1 - t0 >= 0.05 else ''))
            if TRACE_PC and where:
                # HPUXEMU_TRACE_PC: where the call came from - the system call stub (r31,
                # the gateway's return) and the stub's caller (r2)
                sys.stderr.write('    from %08x, called from %08x\n' % where)
        if self.exited is not None:
            return
        cpu.gr[28] = r & M32
        cpu.gr[22] = err
        if ret2 is not None:
            cpu.gr[29] = ret2 & M32
        cpu.set_pc(cpu.gr[31])
        if self.pending or interrupted:
            self.deliver_signals(restartable=interrupted)

    # ---- identity, limits and time ----
    def sys_exit(self, status, *a):
        """exit(status): end the process (shared file mappings are written back)"""
        self.writeback_all()
        self.exited = ('exit', status & 0xFF)

    def sys_getpid(self, *a):
        """getpid(): the host pid; r29 = the parent's"""
        return (self.pid, os.getppid())

    def sys_getuid(self, *a):
        """getuid(): r28 = real uid, r29 = effective uid"""
        return (self.uid, self.euid)

    def sys_getgid(self, *a):
        """getgid(): r28 = real gid, r29 = effective gid"""
        return (self.gid, self.egid)

    def sys_setuid(self, uid, *a):
        """setuid(uid): the superuser sets all three ids; anyone else only to the real or saved id (EPERM otherwise). The host user never changes: the emulator's own access checks are what the ids govern"""
        if self.euid == 0:
            self.uid = self.euid = self.suid = uid
        elif uid in (self.uid, self.suid):
            self.euid = uid
        else:
            raise HpuxError(C['EPERM'])
        return 0

    def sys_setgid(self, gid, *a):
        """setgid(gid): as setuid, for the group ids"""
        if self.euid == 0:
            self.gid = self.egid = self.sgid = gid
        elif gid in (self.gid, self.sgid):
            self.egid = gid
        else:
            raise HpuxError(C['EPERM'])
        return 0

    def sys_seteuid(self, uid, *a):
        """seteuid(uid): the effective uid, to the real or saved one unless superuser"""
        if self.euid == 0 or uid in (self.uid, self.suid):
            self.euid = uid
            return 0
        raise HpuxError(C['EPERM'])

    def sys_setegid(self, gid, *a):
        """setegid(gid)"""
        if self.euid == 0 or gid in (self.gid, self.sgid):
            self.egid = gid
            return 0
        raise HpuxError(C['EPERM'])

    def sys_geteuid(self, *a):
        """geteuid()"""
        return self.euid

    def sys_getegid(self, *a):
        """getegid()"""
        return self.egid

    def sys_getpgrp2(self, pid, *a):
        """getpgrp2(pid): the process group of pid (0 = this process)"""
        return os.getpgid(pid or 0)

    def sys_getsid(self, pid, *a):
        """getsid(pid): the session of pid (0 = this process)"""
        return os.getsid(pid or 0)

    def sys_umask(self, m, *a):
        """umask(mask): the file creation mask, applied to the host's too"""
        old = self.umask
        self.umask = m & 0o777
        os.umask(self.umask)
        return old

    def sys_brk(self, addr, *a):
        """brk(addr): set the break; the heap grows up from the end of bss. One page beyond
        the break is always mapped: HP-UX's libc reads past the break (its string functions
        work by words), which the HP-UX kernel tolerates - Linux's HP-UX emulation did the
        same (`sys_brk(addr + PAGE_SIZE)`, "libc relies on kernel bugs")"""
        addr = (addr + PAGE - 1) & ~(PAGE - 1)
        if addr < self.brk_base or addr > self.brk_base + 256 * 1024 * 1024:
            raise HpuxError(ENOMEM)
        if addr > self.brk:
            self.mem.map(self.brk, addr + PAGE - self.brk, 7)
        elif addr < self.brk:
            self.mem.unmap(addr + PAGE, self.brk - addr)
        self.brk = addr
        return 0

    def sys_sbrk(self, *a):
        """sbrk: not a system call on HP-UX (libc uses brk); ENOSYS"""
        raise HpuxError(ENOSYS)

    def sys_sysconf(self, which, *a):
        """sysconf(name): the values of a 10.20 system"""
        table = {C.get('_SC_ARG_MAX', 0): 20478, C.get('_SC_CHILD_MAX', 1): 1024, C.get('_SC_CLK_TCK', 2): 100,
                 C.get('_SC_NGROUPS_MAX', 3): 20, C.get('_SC_OPEN_MAX', 4): 1024, C.get('_SC_JOB_CONTROL', 5): 1,
                 C.get('_SC_SAVED_IDS', 6): 1, C.get('_SC_VERSION', 7): 199309, C.get('_SC_PAGE_SIZE', 24): 4096,
                 C.get('_SC_CPU_VERSION', 10001): C.get('CPU_PA_RISC1_1', 0x210),
                 10004: MCAS_OFFSET}                      # _SC_MCAS_OFFSET
        # POSIX.1b and POSIX threads (11.00's sys/unistd.h numbers and limits.h values;
        # libpthread asks for _SC_THREAD_THREADS_MAX at start-up)
        table.update({400: 32, 401: 1, 402: 1, 403: 1, 404: 1, 405: 32, 406: 1, 407: 1, 408: 1, 409: 1, 410: 1,
                      411: 1, 412: 1, 413: 1, 414: 1, 415: 1, 416: 2, 417: 2048, 418: 20, 419: 8, 420: 32, 421: 8,
                      422: 256, 423: 32767, 424: 32,
                      430: 4, 431: 128, 432: 4096, 433: 64, 434: 199506, 435: 1, 436: 1, 437: 1, 438: -1, 439: -1,
                      440: 1, 441: 1, 442: 1024, 443: 1024, 444: 64,
                      10010: 37, 10011: 44})                 # _SC_SIGRTMIN, _SC_SIGRTMAX
        if which == 10003:
            # _SC_MSEM_LOCKID: the id msem_lock writes into a semaphore it holds; the
            # pid, so a forked child has its own
            self.msem_lockid = True
            return self.pid
        if which in table:
            return table[which]
        if self.trace:
            sys.stderr.write('hpuxemu: sysconf(%d) unknown\n' % which)
        raise HpuxError(EINVAL)

    def sys_utssys(self, buf, n, typ, *a):
        """utssys(buf, n, type): uname (0), ustat (2), gethostname (5)"""
        if typ == 0:
            node = self.nodename[:8]
            self.wr(buf, pack('utsname', {'sysname': b'HP-UX', 'nodename': node.encode(), 'release': self.release.encode(),
                                          'version': b'A', 'machine': b'9000/715', '__idnumber': b'2000000000'}))
            return 0
        if typ == 5:
            self.wr(buf, self.nodename.encode()[:n - 1] + b'\0')
            return 0
        if typ == 2:
            st = os.statvfs(self.root)
            self.wr(buf, pack('ustat', {'f_tfree': st.f_bfree, 'f_tinode': st.f_ffree, 'f_blksize': st.f_bsize}))
            return 0
        raise HpuxError(EFAULT)

    def sys_getdomainname(self, buf, n, *a):
        """getdomainname(buf, len): an empty NIS domain"""
        self.wr(buf, b'\0' * min(n, 1))
        return 0

    def now(self):
        """the guest's time (etc/hpuxemu/clock)"""
        return time.time() + self.clock_offset

    def sys_clock_gettime(self, clock, tp, *a):
        """clock_gettime(clock_id, &timespec): CLOCK_REALTIME (1) is the guest's time;
        the CPU-time clocks (CLOCK_VIRTUAL 2, CLOCK_PROFILE 4) the process's"""
        if clock == 1:
            t = self.now()
        elif clock in (2, 4):
            t = time.process_time()
        else:
            raise HpuxError(EINVAL)
        sec = int(t)
        self.wr(tp, struct.pack('>ii', sec, int((t - sec) * 1e9)))
        return 0

    def sys_clock_getres(self, clock, tp, *a):
        """clock_getres(clock_id, &timespec): 10 ms, the HP-UX clock tick"""
        if clock not in (1, 2, 4):
            raise HpuxError(EINVAL)
        if tp:
            self.wr(tp, struct.pack('>ii', 0, 10000000))
        return 0

    def gtime(self, t):
        """a host file time as the guest sees it: shifted like the clock when the file
        changed after the clock was set (made "now" in the guest's time), as it is before"""
        t = int(t)
        if self.clock_anchor is not None and t >= int(self.clock_anchor):
            return t + self.clock_offset
        return t

    def sys_time(self, tloc=0, *a):
        """time(tloc): seconds since the epoch, also stored at tloc when it is not null - the kernel does that store, not libc (telnetd's utmp records had stack garbage for their logout time)"""
        t = int(self.now())
        if tloc:
            try:
                self.wr32(tloc, t)
            except (HpuxError, MemFault):
                pass
        return t

    def sys_gettimeofday(self, tv, tz, *a):
        """gettimeofday(tv, tz): the guest clock (the host's, or etc/hpuxemu/clock); tz is all zeros"""
        t = self.now()
        if tv:
            self.wr(tv, struct.pack('>II', int(t), int((t % 1) * 1000000)))
        if tz:
            self.wr(tz, struct.pack('>ii', 0, 0))
        return 0

    def sys_times(self, buf, *a):
        """times(buf): the host process times in ticks of 1/100 s, elapsed ticks returned"""
        t = os.times()
        hz = 100
        self.wr(buf, struct.pack('>IIII', int(t.user * hz), int(t.system * hz), int(t.children_user * hz), int(t.children_system * hz)))
        return int((time.monotonic()) * hz) & 0x7FFFFFFF

    def sys_alarm(self, secs, *a):
        """alarm(secs): the host's alarm; SIGALRM comes back through the host handler"""
        self.install_host_handler(C['SIGALRM'], self.sigactions.get(C['SIGALRM'], (0,))[0])
        return hsignal.alarm(secs)

    def sys_pause(self, *a):
        """pause(): wait for a signal (always EINTR)"""
        host_pause()

    def sys_nice(self, inc, *a):
        """nice(inc): accepted; the priority stays 20"""
        return 20

    def sys_mount(self, *a):
        """mount(): refused with EPERM - there is nothing to mount; the root is the host's file system (dtfile and mountall ask)"""
        raise HpuxError(C['EPERM'])

    sys_vfsmount = sys_mount

    def sys_umount(self, *a):
        """umount(): EPERM, as mount"""
        raise HpuxError(C['EPERM'])

    def sys_chroot(self, path, *a):
        """chroot(path): EPERM - the root is fixed when the emulator starts"""
        raise HpuxError(C['EPERM'])

    def sys_ulimit(self, cmd, arg, *a):
        """ulimit(cmd, arg): UL_GETFSIZE a 2 GB file size limit, UL_GETMAXBRK the top of the heap; setting is ignored"""
        if cmd == 1:
            return 0x7FFFFFFF >> 9
        if cmd == 2:
            return 0
        if cmd == 4:
            return 1024
        if cmd == 3:
            return 0x7FFFFFFF
        raise HpuxError(EINVAL)

    def sys_getrlimit(self, res, buf, *a):
        """getrlimit(resource, rlp): the limits of rlimit()"""
        self.wr(buf, struct.pack('>II', *self.rlimit(res)))
        return 0

    def sys_getrlimit64(self, res, buf, *a):
        """getrlimit64(resource, rlp): the same, 64-bit values"""
        cur, mx = self.rlimit(res)
        self.wr(buf, struct.pack('>QQ', cur, mx))
        return 0

    def rlimit(self, res):
        inf = 0x7FFFFFFF
        table = {0: (inf, inf), 1: (inf, inf), 2: (0x04000000, 0x04000000), 3: (0x00800000, 0x00800000), 4: (inf, inf),
                 5: (inf, inf), 6: (1024, 1024), 7: (inf, inf)}
        if res not in table:
            raise HpuxError(EINVAL)
        return table[res]

    def sys_setrlimit(self, res, buf, *a):
        """setrlimit(resource, rlp): accepted and ignored"""
        return 0

    def sys_setrlimit64(self, res, buf, *a):
        """setrlimit64(resource, rlp): accepted and ignored"""
        return 0

    def sys_getrusage(self, who, buf, *a):
        """getrusage(who, buf): user and system time of the process (RUSAGE_SELF) or its children; the other fields are zero"""
        t = os.times()
        u = t.user if who == 0 else t.children_user
        s = t.system if who == 0 else t.children_system
        self.wr(buf, pack('rusage', {'ru_utime': struct.pack('>II', int(u), int((u % 1) * 1e6)),
                                     'ru_stime': struct.pack('>II', int(s), int((s % 1) * 1e6))}))
        return 0

    def sys_getpriority(self, which, who, *a):
        """getpriority(which, who): always 20"""
        return 20

    def sys_setpriority(self, which, who, prio, *a):
        """setpriority(which, who, prio): accepted and ignored"""
        return 0

    # ---- files ----
    def fd_check(self, fd):
        if fd not in self.fds:
            raise HpuxError(EBADF)
        return fd

    def newfd(self, hostfd, path='', flags=0):
        # Python makes new descriptors close-on-exec; the guest's are inherited unless
        # it asks otherwise (fcntl F_SETFD)
        os.set_inheritable(hostfd, True)
        self.fds[hostfd] = {'path': path, 'flags': flags, 'dirpos': 0, 'dirents': None}
        return hostfd

    def sys_open(self, path, flags, mode, *a):
        """open(path, flags, mode): HP-UX O_ flags are mapped to the host's"""
        gp = self.rdstr(path)
        return self.do_open(gp, flags, mode)

    def do_open(self, gp, flags, mode):
        hflags = flags & 3
        for g, h in (('O_APPEND', os.O_APPEND), ('O_CREAT', os.O_CREAT), ('O_TRUNC', os.O_TRUNC), ('O_EXCL', os.O_EXCL),
                     ('O_NONBLOCK', os.O_NONBLOCK), ('O_NDELAY', os.O_NONBLOCK), ('O_NOCTTY', os.O_NOCTTY), ('O_SYNC', os.O_SYNC)):
            if flags & C[g]:
                hflags |= h
        gabs = self.guest_abspath(gp)
        if gabs in ('/dev/ptym/clone', '/dev/ptmx'):
            return self.open_pty_master(flags)
        if gabs == '/dev/netman':
            # HP-UX's network management driver: its ioctls are answered here (netman.py)
            try:
                fd = os.open('/dev/null', os.O_RDWR)
            except OSError as e:
                raise host_err(e)
            self.newfd(fd, gabs, flags)
            self.fds[fd]['netman'] = True
            return fd
        if (self.release.startswith('B.11') and gabs not in self.stream_devices() and
                _re().fullmatch(r'/dev/(ip|nuls|dlpi|lan\d+)', gabs)):
            return self.open_mib_stream(gabs, flags)
        if gabs in self.stream_devices() and self.stream_devices()[gabs][0] != '-':
            fd = self.open_stream(gabs, flags)
            if fd is not None:
                return fd
        if gabs in self.ptys:
            # a pseudo-terminal slave the guest got from the clone device
            try:
                fd = os.open(self.ptys[gabs], hflags)
            except OSError as e:
                raise host_err(e)
            self.my_ttys.add(self.ptys[gabs])
            return self.newfd(fd, gabs, flags)
        hp = self.hostpath(gp)
        want = (1 if hflags & 3 in (os.O_RDONLY, os.O_RDWR) else 0) * 4 + (2 if hflags & 3 in (os.O_WRONLY, os.O_RDWR) or flags & C['O_TRUNC'] else 0)
        existed = os.path.lexists(hp)
        if existed:
            self.check(gp, want)
        elif hflags & os.O_CREAT:
            self.check_dir_write(gp)
        else:
            raise HpuxError(ENOENT)
        try:
            fd = os.open(hp, hflags, mode & 0o7777)
        except OSError as e:
            raise host_err(e)
        if not existed:
            try:
                self.new_file_owner(self.guest_abspath(gp), fd)
            except (OSError, HpuxError):
                pass
        if os.path.isdir(hp):
            self.fds[fd] = {'path': self.guest_abspath(gp), 'flags': flags, 'dirpos': 0, 'dirents': None}
        else:
            self.newfd(fd, self.guest_abspath(gp), flags)
        return fd

    PTY_MAJOR = 16      # HP-UX's pty master driver; slaves are /dev/pty/tty[p-z][0-9a-f]

    def join_nvs(self, sock, pty):
        """SIOCJNVS(socket, &ptyfd): HP-UX's telnet driver joins a connection to a
        pseudo-terminal in the kernel: data goes between the two without telnetd, and
        when a telnet command (IAC) arrives from the client the driver unjoins, leaving
        it for telnetd, which handles the option and joins again. A helper process does
        that here: it peeks at the socket, forwards up to the first IAC (CR NUL and
        CR LF become CR and LF), and exits when it sees one, when either side closes,
        or when the pty's reader is gone; 0xFF going out is doubled. It is a thread of
        this process, not a child: telnetd would take a child's exit for login's."""
        self.fd_check(sock)
        self.fd_check(pty)
        import threading
        s = os.dup(sock)
        p = os.dup(pty)
        t = threading.Thread(target=self.nvs_pump, args=(s, p, self.trace), daemon=True)
        t.start()
        self.fds[sock]['joined'] = t
        return 0

    def joined_wait(self, fd, timeout=None):
        """While a telnet join owns a socket, the guest sees nothing on it: a read or recv
        waits for the join to end (an IAC arrived or a side closed), a select/poll with a
        timeout gives up after it. True if the fd is (still) joined."""
        t = self.fds.get(fd, {}).get('joined')
        if t is None:
            return False
        if not t.is_alive():
            del self.fds[fd]['joined']
            return False
        t.join(timeout)
        if t.is_alive():
            return True
        del self.fds[fd]['joined']
        return False

    def nvs_pump(self, s, p, trace):
        try:
            import select as hselect
            import socket as hs
            sk = hs.socket(fileno=s)
            sk.setblocking(True)
            why = ''
            while True:
                r, _, _ = hselect.select([s, p], [], [])
                if s in r:
                    try:
                        data = sk.recv(4096, hs.MSG_PEEK)
                    except OSError:
                        data = b''
                    if not data:
                        why = 'client closed'
                        break
                    i = data.find(b'\xff')
                    if i == 0:
                        why = 'telnet command for telnetd'
                        break
                    chunk = data[:i] if i > 0 else data
                    if chunk.endswith(b'\r') and len(chunk) == len(data):
                        chunk = chunk[:-1]      # wait for what follows the CR
                        if not chunk:
                            hselect.select([s], [], [], 0.2)
                            continue
                    sk.recv(len(chunk))
                    out = chunk.replace(b'\r\n', b'\n').replace(b'\r\0', b'\r')
                    try:
                        os.write(p, out)
                    except OSError:
                        why = 'pty gone'
                        break
                if p in r:
                    try:
                        data = os.read(p, 4096)
                    except OSError:
                        data = b''
                    if not data:
                        why = 'pty closed'
                        break
                    try:
                        sk.sendall(data.replace(b'\xff', b'\xff\xff'))
                    except OSError:
                        why = 'client gone'
                        break
            if trace:
                sys.stderr.write('hpuxemu: telnet join ends: %s\n' % why)
            sk.close()
        except Exception as e:
            sys.stderr.write('hpuxemu: telnet pump: %r\n' % (e,))
        try:
            os.close(p)
        except OSError:
            pass

    def open_pty_master(self, flags):
        """/dev/ptym/clone: a host pseudo-terminal pair; the master's device number names
        the slave (/dev/pty/ttyp0 for minor 0 ...), which libc's ptsname derives from fstat
        and the guest opens by name"""
        try:
            master, slave = os.openpty()
        except OSError as e:
            raise host_err(e)
        host_slave = os.ttyname(slave)
        os.close(slave)
        # the slave is /dev/pts/N with the host's number: ptsname() asks the master for its
        # device number (ISPTM) and names the slave after the minor
        n = int(host_slave.rsplit('/', 1)[1]) if host_slave.rsplit('/', 1)[1].isdigit() else len(self.ptys)
        self.ptys['/dev/pts/%d' % n] = host_slave
        self.newfd(master, '/dev/ptym/clone', flags)
        self.fds[master]['pty'] = n
        return master

    # ---- STREAMS devices: descriptors served by the root's STREAMS daemon (streams.py) ----
    def stream_devices(self):
        if getattr(self, '_stream_devs', None) is None:
            self._stream_devs = streams.devices(self.root)
        return self._stream_devs

    def open_stream(self, gabs, flags):
        """a STREAMS device: a connection to the daemon, which opens the driver; None
        when the root has no daemon (then the path is an ordinary one)"""
        sock = streams.connect(self.root, self.cpu_kind)
        if sock is None:
            return None
        st = streams.Stream(sock, self.stream_devices()[gabs][0])
        try:
            st.open(flags, self.euid, self.egid, self.pid)
        except streams.StreamError as e:
            sock.close()
            raise HpuxError(e.errno or C['ENXIO'])
        fd = sock.detach()
        st.sock = None
        self.newfd(fd, gabs, flags)
        self.fds[fd]['stream'] = st
        if self.trace:
            sys.stderr.write('[%d] open %s: stream %d of the STREAMS daemon\n' % (self.pid, gabs, st.sid))
        return fd

    def open_mib_stream(self, gabs, flags):
        """11.00's /dev/ip (and /dev/nuls, where libnm pushes tcpm and udpm): a stream the
        emulator answers itself, MIB-2 for libnm's mibget (netman.MibStream). The host
        descriptor is an eventfd, never readable, so a poll waits on the messages."""
        from . import netman
        r = os.eventfd(0)
        st = netman.MibStream(os.path.basename(gabs), lambda: self.mib_netman(True))
        self.newfd(r, gabs, flags)
        self.fds[r]['stream'] = st
        return r

    def mib_netman(self, lan_first=False):
        """the host's MIB-2 tables (netman.Netman): /dev/netman's, or 11.00's /dev/ip's
        (lan_first: numbered as 11.00 numbers the interfaces)"""
        from . import netman
        cache = getattr(self, 'netmans', None)
        if cache is None:
            cache = self.netmans = {}
        if lan_first not in cache:
            cache[lan_first] = netman.Netman(self.interfaces(), self.now() - 3600 - self.clock_offset, self.release,
                                             lan_first)
        return cache[lan_first]

    def stream_of(self, fd):
        """the Stream of a descriptor (None for any other), set to use this descriptor"""
        st = self.fds.get(fd, {}).get('stream')
        if st is not None:
            st.fd = fd
        return st

    def stream_nonblock(self, fd):
        return bool(self.fds[fd]['flags'] & (C['O_NONBLOCK'] | C['O_NDELAY']))

    def stream_wait(self, fd):
        """wait for the daemon (a signal interrupts: EINTR)"""
        rev = host_poll([(fd, select.POLLIN)], -1)
        if rev[0] & select.POLLNVAL:
            raise HpuxError(EBADF)

    def stream_call(self, st, op, payload):
        try:
            rval, err, data = st.call(op, payload, copyin=lambda a, n: bytes(self.rd(a, n)), copyout=self.wr)
        except streams.StreamError as e:
            raise HpuxError(e.errno or C['ENXIO'])
        if rval < 0:
            raise HpuxError(err or C['EINVAL'])
        return rval, data

    def stream_put(self, fd, st, ctl, data, band, hipri):
        if st.hangup:
            raise HpuxError(C['ENXIO'])
        if st.werror:
            raise HpuxError(st.werror)
        if hipri and ctl is None:
            raise HpuxError(EINVAL)
        if ctl is None and data is None:
            return 0
        payload = struct.pack('>iiii', 1 if hipri else 0, band, -1 if ctl is None else len(ctl),
                              -1 if data is None else len(data)) + (ctl or b'') + (data or b'')
        self.stream_call(st, streams.RQ_PUTMSG, payload)
        return 0

    def strbuf_in(self, ptr):
        """a struct strbuf to send: its bytes, None for no part"""
        if not ptr:
            return None
        maxlen, ln, buf = struct.unpack('>iiI', self.rd(ptr, 12))
        if ln < 0:
            return None
        return bytes(self.rd(buf, ln)) if ln else b''

    def sys_putmsg(self, fd, ctlp, datap, flags, *a):
        """putmsg(fd, ctlptr, dataptr, flags): a message down a stream (RS_HIPRI: M_PCPROTO)"""
        self.fd_check(fd)
        st = self.stream_of(fd)
        if st is None:
            raise HpuxError(C['ENOSTR'])
        if flags & ~C['RS_HIPRI']:
            raise HpuxError(EINVAL)
        return self.stream_put(fd, st, self.strbuf_in(ctlp), self.strbuf_in(datap), 0, flags & C['RS_HIPRI'])

    def sys_putpmsg(self, fd, ctlp, datap, band, flags, *a):
        """putpmsg(fd, ctlptr, dataptr, band, flags): putmsg with a priority band (MSG_BAND) or MSG_HIPRI"""
        self.fd_check(fd)
        st = self.stream_of(fd)
        if st is None:
            raise HpuxError(C['ENOSTR'])
        hipri = flags == C['MSG_HIPRI']
        if flags not in (C['MSG_HIPRI'], C['MSG_BAND']) or (hipri and band):
            raise HpuxError(EINVAL)
        return self.stream_put(fd, st, self.strbuf_in(ctlp), self.strbuf_in(datap), band, hipri)

    def stream_get(self, fd, ctlp, datap, pred):
        """the common part of getmsg/getpmsg: the message, the return value (MORECTL,
        MOREDATA)"""
        st = self.stream_of(fd)
        if st is None:
            raise HpuxError(C['ENOSTR'])
        try:
            m = st.wait_msg(self.stream_nonblock(fd), self.stream_wait, pred)
        except streams.StreamError as e:
            raise HpuxError(e.errno or C['ENXIO'])
        ret = 0

        def part(ptr, val, more):
            nonlocal ret
            if not ptr:
                if val is not None:
                    ret |= more
                return val
            maxlen, ln, buf = struct.unpack('>iiI', self.rd(ptr, 12))
            if val is None:
                self.wr(ptr + 4, struct.pack('>i', -1))
                return None
            if maxlen < 0:
                ret |= more
                return val
            n = min(maxlen, len(val))
            if n:
                self.wr(buf, val[:n])
            self.wr(ptr + 4, struct.pack('>i', n))
            if n < len(val):
                ret |= more
                return val[n:]
            return None

        if m is None:           # hung up: an empty message, end of file
            for ptr in (ctlp, datap):
                if ptr:
                    self.wr(ptr + 4, struct.pack('>i', 0))
            return None, 0
        typ = m.type
        m.ctl = part(ctlp, m.ctl, C['MORECTL'])
        m.data = part(datap, m.data, C['MOREDATA'])
        if m.ctl is None and m.data is None:
            st.msgs.remove(m)
        m.type = typ
        return m, ret

    def sys_getmsg(self, fd, ctlp, datap, flagsp, *a):
        """getmsg(fd, ctlptr, dataptr, flagsp): the next message of a stream (*flagsp
        RS_HIPRI: a priority one); MORECTL/MOREDATA when parts are left"""
        self.fd_check(fd)
        want = struct.unpack('>i', self.rd(flagsp, 4))[0]
        if want & ~C['RS_HIPRI']:
            raise HpuxError(EINVAL)
        pred = (lambda m: m.type == streams.M_PCPROTO) if want else (lambda m: True)
        m, ret = self.stream_get(fd, ctlp, datap, pred)
        self.wr(flagsp, struct.pack('>i', C['RS_HIPRI'] if m is not None and m.type == streams.M_PCPROTO else 0))
        return ret

    def sys_getpmsg(self, fd, ctlp, datap, bandp, flagsp, *a):
        """getpmsg(fd, ctlptr, dataptr, bandp, flagsp): getmsg by band (MSG_ANY, MSG_BAND, MSG_HIPRI)"""
        self.fd_check(fd)
        want = struct.unpack('>i', self.rd(flagsp, 4))[0]
        band = struct.unpack('>i', self.rd(bandp, 4))[0]
        if want == C['MSG_HIPRI']:
            pred = lambda m: m.type == streams.M_PCPROTO
        elif want == C['MSG_BAND']:
            pred = lambda m: m.type == streams.M_PCPROTO or m.band >= band
        elif want == C['MSG_ANY']:
            pred = lambda m: True
        else:
            raise HpuxError(EINVAL)
        m, ret = self.stream_get(fd, ctlp, datap, pred)
        if m is not None:
            self.wr(bandp, struct.pack('>i', m.band))
            self.wr(flagsp, struct.pack('>i', C['MSG_HIPRI'] if m.type == streams.M_PCPROTO else C['MSG_BAND']))
        return ret

    def stream_read(self, fd, st, buf, n):
        """read(2) on a stream, by the read mode (I_SRDOPT)"""
        out = b''
        while True:
            try:
                m = st.wait_msg(self.stream_nonblock(fd) or out != b'', self.stream_wait)
            except streams.StreamError as e:
                if out:
                    break
                raise HpuxError(e.errno or C['ENXIO'])
            if m is None:
                break
            if m.ctl is not None:
                if st.rdopt & C['RPROTDAT']:
                    m.data, m.ctl = m.ctl + (m.data or b''), None
                elif st.rdopt & C['RPROTDIS']:
                    m.ctl = None
                elif out:
                    break
                else:
                    raise HpuxError(C['EBADMSG'])
            data = m.data or b''
            take = data[:n - len(out)]
            out += take
            m.data = data[len(take):]
            if not m.data or st.rdopt & C['RMSGD']:
                st.msgs.remove(m)
            if not (st.rdopt & C['RNORM']) or len(out) >= n or not data:
                break
            if not st.msgs:
                break
        if out:
            self.wr(buf, out)
        return len(out)

    def stream_ioctl(self, fd, st, req, arg):
        """the STREAMS ioctls; others go down the stream as transparent ioctls"""
        call = self.stream_call
        if req == C['I_STR']:
            cmd, tmo, ln, dp = struct.unpack('>iiiI', self.rd(arg, 16))
            data = bytes(self.rd(dp, ln)) if ln > 0 else b''
            rval, out = call(st, streams.RQ_IOCTL, struct.pack('>iiI', req, 0, 12 + len(data)) +
                             struct.pack('>iii', cmd, tmo, ln) + data)
            if out:
                self.wr(dp, out)
            self.wr(arg + 8, struct.pack('>i', len(out)))
            return rval
        if req in (self.I_TPI_ACK, self.I_ASYNC_ACK, self.I_ASYNC_ACK_NEW):
            return self.stream_tpi_ack(fd, st, arg)
        # HP-UX's stream head queries (sys/stropts.h): the answer in *arg
        if req in (self.I_GET_STH_WROFF, self.I_GET_STRMSGSZ, self.I_GET_STRCTLSZ, self.I_GET_PUSHCNT,
                   self.I_GET_HIWAT, self.I_GET_LOWAT):
            if req == self.I_GET_PUSHCNT:
                v = call(st, streams.RQ_IOCTL, struct.pack('>iiI', C['I_LIST'], 0, 0))[0] - 1
            else:
                v = {self.I_GET_STH_WROFF: 0, self.I_GET_STRMSGSZ: self.STRMSGSZ, self.I_GET_STRCTLSZ: self.STRCTLSZ,
                     self.I_GET_HIWAT: 65536, self.I_GET_LOWAT: 8192}[req]
            self.wr(arg, struct.pack('>i', v))
            return 0
        if req in (self.I_SET_XTI, self.I_SET_HIWAT, self.I_SET_LOWAT):
            return 0
        if req == self.I_XTI_USND:
            # 11.00's t_sndudata: {?, ?, flags, ctl length, data length, ctl, data} - a
            # T_UNITDATA_REQ and the datagram, as putmsg would send them
            flags, clen, dlen, cbuf, dbuf = struct.unpack('>iiiII', self.rd(arg + 8, 20))
            ctl = bytes(self.rd(cbuf, clen)) if clen > 0 else b''
            data = bytes(self.rd(dbuf, dlen)) if dbuf and dlen >= 0 else b''
            self.stream_put(fd, st, ctl, data, 0, False)
            return 0
        if req == self.I_XTI_URCV:
            return self.stream_xti_urcv(fd, st, arg)
        if req == self.I_GET_QLEN:
            # 11.00: the messages waiting at the stream head
            st.ready()
            self.wr(arg, struct.pack('>i', len(st.msgs)))
            return 0
        if req in (C['I_PUSH'], C['I_FIND']):
            name = self.rdstr(arg).encode('latin1')[:8]
            return call(st, streams.RQ_IOCTL, struct.pack('>iiI', req, 0, len(name)) + name)[0]
        if req == C['I_LOOK']:
            rval, out = call(st, streams.RQ_IOCTL, struct.pack('>iiI', req, 0, 0))
            self.wr(arg, out[:9])
            return rval
        if req == C['I_LIST']:
            rval, out = call(st, streams.RQ_IOCTL, struct.pack('>iiI', req, 0, 0))
            if arg:
                n, lst = struct.unpack('>iI', self.rd(arg, 8))
                k = min(n, rval)
                self.wr(lst, out[:9 * k])
                self.wr(arg, struct.pack('>i', k))
                return 0
            return rval
        if req == C['I_FDINSERT']:
            # struct strfdinsert: ctlbuf, databuf, flags, fildes, offset; the daemon puts
            # the queue of the other stream at offset (t_accept's ACCEPTOR_id)
            cmax, clen, cbuf, dmax, dlen, dbuf, flags, other, off = struct.unpack('>iiIiiIiii', self.rd(arg, 36))
            ost = self.fds.get(other, {}).get('stream') if other >= 0 else None
            if ost is None or clen < 0:
                raise HpuxError(EINVAL)
            ctl = bytes(self.rd(cbuf, clen))
            data = bytes(self.rd(dbuf, dlen)) if dbuf and dlen >= 0 else b''
            payload = struct.pack('>iIiii', flags, ost.sid, off, clen, dlen if dbuf and dlen >= 0 else -1) + ctl + data
            st.fd = fd
            return call(st, streams.RQ_IOCTL, struct.pack('>iiI', req, 0, len(payload)) + payload)[0]
        if req in (C['I_LINK'], C['I_PLINK']):
            lower = self.stream_of(arg) if arg in self.fds else None
            if lower is None:
                raise HpuxError(EINVAL)
            st.fd = fd
            return call(st, streams.RQ_IOCTL, struct.pack('>iiI', req, lower.sid, 0))[0]
        if req in (C['I_POP'], C['I_FLUSH'], C['I_UNLINK'], C['I_PUNLINK'], C['I_CANPUT'],
                   C['I_SETCLTIME'], C['I_GETCLTIME']):
            if req == C['I_FLUSH'] and arg & 1:
                st.msgs.clear()
            return call(st, streams.RQ_IOCTL, struct.pack('>iiI', req, arg, 0))[0]
        if req == C['I_NREAD']:
            st.ready()
            self.wr(arg, struct.pack('>i', len(st.msgs[0].data or b'') if st.msgs else 0))
            return len(st.msgs)
        if req == C['FIONREAD']:
            st.ready()
            self.wr(arg, struct.pack('>i', len(st.msgs[0].data or b'') if st.msgs else 0))
            return 0
        if req == C['I_SRDOPT']:
            st.rdopt = (arg & 0x7) or C['RNORM']
            st.rdopt |= (arg & 0x70) or C['RPROTNORM']
            return 0
        if req == C['I_GRDOPT']:
            self.wr(arg, struct.pack('>i', st.rdopt))
            return 0
        if req == C['I_SWROPT']:
            st.wropt = arg
            return 0
        if req == C['I_GWROPT']:
            self.wr(arg, struct.pack('>i', st.wropt))
            return 0
        if req == C['I_SETSIG']:
            # SIGPOLL when a message arrives: the host's SIGIO on the connection (which
            # becomes the guest's SIGPOLL, the same signal); a spurious one, for a reply
            # the emulator reads itself, is harmless to a handler that polls
            st.sigevents = arg
            try:
                fl = hfcntl.fcntl(fd, hfcntl.F_GETFL)
                if arg:
                    sig = C['SIGPOLL'] if 'SIGPOLL' in C else C['SIGIO']
                    self.install_host_handler(sig, self.sigactions.get(sig, (0,))[0])
                    hfcntl.fcntl(fd, hfcntl.F_SETOWN, os.getpid())
                    hfcntl.fcntl(fd, hfcntl.F_SETFL, fl | os.O_ASYNC)
                else:
                    hfcntl.fcntl(fd, hfcntl.F_SETFL, fl & ~os.O_ASYNC)
            except OSError:
                pass
            return 0
        if req == C['I_GETSIG']:
            if not st.sigevents:
                raise HpuxError(EINVAL)
            self.wr(arg, struct.pack('>i', st.sigevents))
            return 0
        if req == C['I_ISASTREAM']:
            return 1
        if req == C['I_PEEK']:
            st.ready()
            if not st.msgs:
                return 0
            m = st.msgs[0]
            for off, val in ((0, m.ctl), (12, m.data)):
                maxlen, ln, buf = struct.unpack('>iiI', self.rd(arg + off, 12))
                if val is None:
                    self.wr(arg + off + 4, struct.pack('>i', -1))
                else:
                    k = min(max(maxlen, 0), len(val))
                    self.wr(buf, val[:k])
                    self.wr(arg + off + 4, struct.pack('>i', k))
            self.wr(arg + 24, struct.pack('>i', C['RS_HIPRI'] if m.type == streams.M_PCPROTO else 0))
            return 1
        if req == C['FIONBIO']:
            on = struct.unpack('>i', self.rd(arg, 4))[0]
            if on:
                self.fds[fd]['flags'] |= C['O_NONBLOCK']
            else:
                self.fds[fd]['flags'] &= ~(C['O_NONBLOCK'] | C['O_NDELAY'])
            return 0
        if req == self.I_XTI_SND:
            return self.stream_xti_snd(fd, st, arg)
        if req == self.I_XTI_RCV:
            return self.stream_xti_rcv(fd, st, arg)
        # a transparent ioctl: the argument word, copies through M_COPYIN/M_COPYOUT
        return call(st, streams.RQ_IOCTL, struct.pack('>iiI', req, arg, 0))[0]

    # HP-UX's libnsl sends a TPI request and waits for its acknowledgement with one
    # ioctl: I_ASYNC_ACK, or _IO('S', 99) (not in the headers). The argument (20 bytes):
    # {short ack, short ack2, int ctl_len, int data_len, char *ctl, char *data}: ctl_len
    # bytes of ctl (data_len of data, -1 none) go down as one message, and the first
    # acknowledgement that is ack, ack2 or T_ERROR_ACK comes back in the same buffers,
    # the lengths updated.
    I_TPI_ACK = 0x20005363
    I_ASYNC_ACK = 0x20005352
    I_GET_QLEN = 0x2000535f          # 11.00
    I_XTI_USND, I_XTI_URCV = 0x2000585d, 0x2000585e     # 11.00: t_sndudata, t_rcvudata
    I_ASYNC_ACK_NEW = 0x20005353     # 11.00: XTI t_sync()'s; the same argument as I_ASYNC_ACK
    I_SET_XTI, I_GET_STH_WROFF, I_GET_STRMSGSZ, I_GET_STRCTLSZ, I_GET_PUSHCNT = (0x20005354, 0x20005355, 0x20005356,
                                                                              0x20005357, 0x20005358)
    I_SET_HIWAT, I_SET_LOWAT, I_GET_HIWAT, I_GET_LOWAT = 0x2000535b, 0x2000535c, 0x20005361, 0x20005362
    STRMSGSZ, STRCTLSZ = 65535, 1024        # HP-UX 10.20's defaults of the tunables
    TPI_REQ_SIZE = {7: 4, 12: 12}         # T_INFO_REQ, T_ADDR_REQ (T_getaddr_req): no more than that
    TPI_HIPRI = (7, 12)

    def stream_tpi_ack(self, fd, st, arg):
        ack, ack2, clen, dlen, cbuf, dbuf = struct.unpack('>hhiiII', self.rd(arg, 20))
        prim = struct.unpack('>i', self.rd(cbuf, 4))[0]
        size = min(self.TPI_REQ_SIZE.get(prim, clen), clen)
        req = bytes(self.rd(cbuf, size))
        data = bytes(self.rd(dbuf, dlen)) if dbuf and dlen >= 0 else None
        self.stream_put(fd, st, req, data, 0, prim in self.TPI_HIPRI)
        wanted = {ack, 25} | ({ack2} if ack2 else set())

        def pred(m):
            return m.ctl is not None and len(m.ctl) >= 4 and struct.unpack('>i', m.ctl[:4])[0] in wanted

        try:
            m = st.wait_msg(False, self.stream_wait, pred)
        except streams.StreamError as e:
            raise HpuxError(e.errno or C['ENXIO'])
        if m is None:
            raise HpuxError(C['ENXIO'])
        st.msgs.remove(m)
        out = m.ctl[:max(clen, 0)]
        self.wr(cbuf, out)
        self.wr(arg + 4, struct.pack('>i', len(out)))
        if dbuf and m.data is not None:
            d = m.data[:max(dlen, 0)]
            self.wr(dbuf, d)
            self.wr(arg + 8, struct.pack('>i', len(d)))
        elif dbuf:
            self.wr(arg + 8, struct.pack('>i', -1))
        if self.trace:
            sys.stderr.write('[%d] TPI request %d: ack %d, %d bytes\n' % (self.pid, prim, struct.unpack('>i', m.ctl[:4])[0], len(out)))
        return 0

    # HP-UX's libnsl sends and receives connection data (t_snd, t_rcv) with two ioctls
    # of its own, I_XTI_SND and I_XTI_RCV ('X' 89, 90), not putmsg/getmsg. The argument,
    # read from the callers in libnsl_s.1: {int 0, int 4, int flags, int len, int 16,
    # char *buf}, flags T_MORE (1) and T_EXPEDITED (2) in and out, T_MOREDATA
    # (0x10000000) out when bytes of the message are left. SND sends T_DATA_REQ or
    # T_EXDATA_REQ with the bytes; RCV puts the bytes of the T_DATA_IND or T_EXDATA_IND
    # at the head of the stream in buf and their count in len (libnsl reads it there). Anything else there (a disconnect, an
    # orderly release) fails with EIO, which libnsl turns into TLOOK; no data on a
    # non-blocking stream is EAGAIN (TNODATA).
    I_XTI_SND, I_XTI_RCV = 0x20005859, 0x2000585a
    T_DATA_REQ, T_EXDATA_REQ, T_DATA_IND, T_EXDATA_IND = 4, 6, 23, 26
    TPI_EVENTS = (21, 22, 24, 30)           # T_CONN_CON, T_CONN_IND, T_DISCON_IND, T_ORDREL_IND

    def stream_xti_snd(self, fd, st, arg):
        flags, n, buf = struct.unpack('>iiI', self.rd(arg + 8, 8) + self.rd(arg + 20, 4))
        st.ready()
        if any(m.ctl is not None and len(m.ctl) >= 4 and struct.unpack('>i', m.ctl[:4])[0] in (24, 30) for m in st.msgs):
            raise HpuxError(C['EIO'])
        prim = self.T_EXDATA_REQ if flags & 2 else self.T_DATA_REQ
        ctl = struct.pack('>ii', prim, 1 if flags & 1 else 0)
        self.stream_put(fd, st, ctl, bytes(self.rd(buf, n)) if n > 0 else b'', 0, False)
        return n

    def stream_xti_rcv(self, fd, st, arg):
        maxlen, buf = struct.unpack('>i', self.rd(arg + 12, 4))[0], struct.unpack('>I', self.rd(arg + 20, 4))[0]
        try:
            m = st.wait_msg(self.stream_nonblock(fd), self.stream_wait)
        except streams.StreamError as e:
            raise HpuxError(e.errno or C['ENXIO'])
        if m is None:
            raise HpuxError(C['EIO'])
        flags = 0
        if m.ctl is not None:
            prim = struct.unpack('>i', m.ctl[:4])[0] if len(m.ctl) >= 4 else -1
            if prim not in (self.T_DATA_IND, self.T_EXDATA_IND):
                raise HpuxError(C['EIO'])
            if len(m.ctl) >= 8 and struct.unpack('>i', m.ctl[4:8])[0]:
                flags |= 1
            if prim == self.T_EXDATA_IND:
                flags |= 2
        data = m.data or b''
        take = data[:max(maxlen, 0)]
        if take:
            self.wr(buf, take)
        m.data = data[len(take):]
        if m.data:
            flags |= 1 | 0x10000000
        else:
            st.msgs.remove(m)
        self.wr(arg + 8, struct.pack('>ii', flags, len(take)))
        return len(take)

    def stream_xti_urcv(self, fd, st, arg):
        """11.00's t_rcvudata: {?, ?, flags, ctl max, data max, ctl, data}. The
        T_UNITDATA_IND at the head of the stream (its control part holds the source
        address) and the datagram go to the buffers, flags and the two lengths back into
        the argument (T_MORE when the datagram did not fit; the rest of it stays). Anything
        else at the head (a T_UDERROR_IND) is EIO, which libnsl turns into TLOOK."""
        cmax, dmax, cbuf, dbuf = struct.unpack('>iiII', self.rd(arg + 12, 16))
        try:
            m = st.wait_msg(self.stream_nonblock(fd), self.stream_wait)
        except streams.StreamError as e:
            raise HpuxError(e.errno or C['ENXIO'])
        if m is None:
            raise HpuxError(C['EIO'])
        prim = struct.unpack('>i', m.ctl[:4])[0] if m.ctl is not None and len(m.ctl) >= 4 else -1
        if prim != C['T_UNITDATA_IND']:
            raise HpuxError(C['EIO'])
        ctl = m.ctl[:max(cmax, 0)]
        if ctl and cbuf:
            self.wr(cbuf, ctl)
        data = m.data or b''
        take = data[:max(dmax, 0)]
        if take and dbuf:
            self.wr(dbuf, take)
        m.data = data[len(take):]
        flags = 0
        if m.data:
            flags |= 1
        else:
            st.msgs.remove(m)
        self.wr(arg + 8, struct.pack('>iii', flags, len(ctl), len(take)))
        return 0

    def poll_streams(self, entries, timeout):
        """host_poll for entries among which are streams: a stream is readable when a
        message waits at its stream head here, whatever the connection shows"""
        sts = {}
        for fd, ev in entries:
            st = self.stream_of(fd) if fd >= 0 else None
            if st is not None:
                sts[fd] = st
        if not sts:
            return host_poll(entries, timeout)
        deadline = None if timeout is None or timeout < 0 else time.time() + timeout / 1000.0
        extra = select.POLLHUP | select.POLLERR | select.POLLNVAL

        def stream_bits(st, ev):
            b = 0
            if st.msgs:
                m = st.msgs[0]
                if m.type == streams.M_PCPROTO:
                    b |= select.POLLPRI
                else:
                    b |= select.POLLIN | (select.POLLRDBAND if m.band else select.POLLRDNORM)
            if st.hangup:
                b |= select.POLLHUP
            if st.rerror:
                b |= select.POLLERR
            b |= select.POLLOUT | select.POLLWRNORM
            return b & (ev | extra)

        while True:
            for st in sts.values():
                st.ready()
            ready = any(stream_bits(sts[fd], ev) for fd, ev in entries if fd in sts)
            if ready:
                t = 0
            elif deadline is None:
                t = -1
            else:
                t = max(0, int((deadline - time.time()) * 1000))
            host_entries = [(fd, select.POLLIN if fd in sts else ev) for fd, ev in entries]
            res = host_poll(host_entries, t)
            out = []
            for (fd, ev), got in zip(entries, res):
                if fd in sts:
                    if got & select.POLLNVAL:
                        out.append(select.POLLNVAL)
                        continue
                    if got & (select.POLLIN | select.POLLHUP):
                        sts[fd].fd = fd
                        sts[fd].ready()
                    out.append(stream_bits(sts[fd], ev))
                else:
                    out.append(got)
            if any(out) or t == 0:
                return out

    def sys_creat(self, path, mode, *a):
        """creat(path, mode): open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)"""
        return self.do_open(self.rdstr(path), C['O_WRONLY'] | C['O_CREAT'] | C['O_TRUNC'], mode)

    def is_tty(self, fd):
        try:
            return os.isatty(fd)
        except OSError:
            return False

    @property
    def pty_masters(self):
        """master fd -> pty number, from the fd records"""
        return {fd: rec['pty'] for fd, rec in self.fds.items() if 'pty' in rec}

    def release_stderr(self, fd):
        """When the program closes or replaces its fd 2 and that is a pipe or socket, the
        emulator's private copy of it (detach_stderr) must not keep it open: a daemon that
        forks and closes 0-2 would hold its parent's pipe for ever and the parent (a shell
        with `2>&1 | ...`, the census) would wait on it. The copy goes to /dev/null; for a
        terminal or a file it is kept, since holding those blocks no one."""
        if fd != 2:
            return
        try:
            mine = sys.stderr.fileno()
            a, b = os.fstat(2), os.fstat(mine)
            if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and (hstat.S_ISFIFO(a.st_mode) or hstat.S_ISSOCK(a.st_mode)):
                null = os.open('/dev/null', os.O_WRONLY)
                os.dup2(null, mine)
                os.close(null)
        except (OSError, ValueError, AttributeError):
            pass

    def sys_close(self, fd, *a):
        """close(fd): the host descriptor is closed and forgotten; fd 2 on a pipe releases the emulator's own copy of it too"""
        self.fd_check(fd)
        self.release_stderr(fd)
        self.nbmode.pop(fd, None)
        try:
            os.close(fd)
        except OSError as e:
            raise host_err(e)
        del self.fds[fd]
        return 0

    def sys_read(self, fd, buf, n, *a):
        """read(fd, buf, n): the host's read, through libc so a signal interrupts it; n = 0 succeeds whatever buf is"""
        self.fd_check(fd)
        st = self.stream_of(fd)
        if st is not None:
            return self.stream_read(fd, st, buf, n)
        self.joined_wait(fd)
        try:
            data = host_read(fd, n)
        except OSError as e:
            raise host_err(e)
        self.wr(buf, data)
        return len(data)

    def sys_write(self, fd, buf, n, *a):
        """write(fd, buf, n): the host's write (n = 0 succeeds whatever buf is)"""
        self.fd_check(fd)
        data = self.rd(buf, n)
        st = self.stream_of(fd)
        if st is not None:
            if n:
                self.stream_put(fd, st, None, bytes(data), 0, False)
            return n
        try:
            return host_write(fd, data)
        except OSError as e:
            raise host_err(e)

    def sys_readv(self, fd, iov, cnt, *a):
        """readv(fd, iov, cnt): one read per element until a short read"""
        total = 0
        for i in range(cnt):
            base, ln = struct.unpack('>II', self.rd(iov + 8 * i, 8))
            r = self.sys_read(fd, base, ln)
            total += r
            if r < ln:
                break
        return total

    def sys_writev(self, fd, iov, cnt, *a):
        """writev(fd, iov, cnt): the elements gathered into one write"""
        data = b''
        for i in range(cnt):
            base, ln = struct.unpack('>II', self.rd(iov + 8 * i, 8))
            data += self.rd(base, ln)
        self.fd_check(fd)
        try:
            return host_write(fd, data)
        except OSError as e:
            raise host_err(e)

    def sys_lseek(self, fd, off, whence, *a):
        """lseek(fd, offset, whence): offsets are 32-bit; lseek64 returns the high word in r29. On a directory the offset is a getdents cookie (entry index + 1; 0 rewinds): tar closes a directory after every file and seeks back to where it was"""
        self.fd_check(fd)
        off = off - (1 << 32) if off & 0x80000000 else off
        r = self.dir_seek(fd, off, whence)
        if r is not None:
            return r
        try:
            return os.lseek(fd, off, whence) & M32
        except OSError as e:
            raise host_err(e)

    def dir_seek(self, fd, off, whence):
        """lseek on a directory: the position is an index into the entries getdents
        lists (the cookies it returns are index + 1); None if fd is not a directory"""
        f = self.fds[fd]
        try:
            if not hstat.S_ISDIR(os.fstat(fd).st_mode):
                return None
        except OSError:
            return None
        if f['dirents'] is None:
            try:
                names = ['.', '..'] + sorted(os.listdir(self.hostpath(f['path'], search=False)))
            except OSError as e:
                raise host_err(e)
            f['dirents'] = names
            f['dirpos'] = 0
        if whence == 0:
            pos = off
        elif whence == 1:
            pos = f['dirpos'] + off
        else:
            pos = len(f['dirents']) + off
        f['dirpos'] = max(0, min(pos, len(f['dirents'])))
        return f['dirpos'] & M32

    def sys_lseek64(self, fd, off_hi, off_lo, whence, *a):
        """lseek64(fd, offset (r25:r24), whence): the 64-bit result in r28:r29"""
        self.fd_check(fd)
        off = (off_hi << 32) | off_lo
        if off & (1 << 63):
            off -= 1 << 64
        r = self.dir_seek(fd, off, whence)
        if r is None:
            try:
                r = os.lseek(fd, off, whence)
            except OSError as e:
                raise host_err(e)
        return ((r >> 32) & M32, r & M32)

    def sys_dup(self, fd, *a):
        """dup(fd): the lowest free descriptor, inheritable"""
        self.fd_check(fd)
        try:
            n = os.dup(fd)
        except OSError as e:
            raise host_err(e)
        os.set_inheritable(n, True)
        self.fds[n] = dict(self.fds[fd])
        self.nb_copy(fd, n)
        return n

    def sys_dup2(self, fd, fd2, *a):
        """dup2(fd, fd2)"""
        self.fd_check(fd)
        if fd == fd2:
            return fd2
        self.release_stderr(fd2)
        try:
            os.dup2(fd, fd2)
        except OSError as e:
            raise host_err(e)
        self.fds[fd2] = dict(self.fds[fd])
        self.nb_copy(fd, fd2)
        return fd2

    def sys_pipe(self, *a):
        """pipe(): the two descriptors come back in r28 and r29"""
        r, w = os.pipe()
        self.newfd(r, 'pipe')
        self.newfd(w, 'pipe')
        return (r, w)

    def load_owners(self):
        """the owners table, reloaded when another process has changed it (a forked
        child starts with its parent's copy; a chown in a sibling must show in ls)"""
        if self.owners is not None and self.owners_fresh:
            return
        self.owners_fresh = True
        p = os.path.join(self.root, 'etc/hpuxemu/owners')
        try:
            st = os.stat(p)
            stamp = (st.st_mtime_ns, st.st_size)
        except OSError:
            stamp = None
        if self.owners is None or stamp != self.owners_stamp:
            from .owners import read_owners
            self.owners = read_owners(self.root)
            self.owners_stamp = stamp

    owners_stamp = None
    owners_fresh = False        # the table's stamp was checked in this system call

    # ---- permissions: the kernel's check, with the owners table for uid/gid ----
    #
    # A file's HP-UX owner and its HFS access control list live in extended
    # attributes of the host file (user.hpux.owner "uid gid", user.hpux.acl the
    # optional entries "uid.gid=mode,..."), so that they follow the file through
    # rename and link and go with it. The owners table the root was built with
    # (etc/hpuxemu/owners, by path) is the fallback, and the store on a host file
    # system without user extended attributes.
    OWNER_XATTR = 'user.hpux.owner'
    ACL_XATTR = 'user.hpux.acl'
    NS = C['ACL_NSUSER']            # % in an ACL entry: no specific user / group (-36)

    def xattrs_ok(self):
        """does the root's file system keep user extended attributes?"""
        ok = getattr(self, '_xattrs_ok', None)
        if ok is None:
            try:
                os.getxattr(self.root, 'user.hpux.probe')
                ok = True
            except OSError as e:
                ok = e.errno in (herrno.ENODATA, getattr(herrno, 'ENOATTR', herrno.ENODATA))
            self._xattrs_ok = ok
        return ok

    def xsrc(self, gpath, st):
        """the host path (or descriptor) to reach a file's extended attributes by:
        how this system call reached it, else its guest path"""
        src = self.hpcache.get((st.st_dev, st.st_ino))
        if src is None and gpath:
            try:
                src = self.hostpath(gpath, search=False)
            except HpuxError:
                src = None
        return src

    def xget(self, gpath, st, name, src=None):
        """an emulator extended attribute of a file as text, or None (cached by inode
        and change time: setting an attribute changes the ctime)"""
        ctime = getattr(st, 'st_ctime_ns', None)      # None: a STREAMS device's made-up stat
        if ctime is None or hstat.S_ISLNK(st.st_mode) or not self.xattrs_ok():
            return None
        key = (st.st_dev, st.st_ino, ctime, name)
        if key in self.xcache:
            return self.xcache[key]
        if src is None:
            src = self.xsrc(gpath, st)
        v = None
        if src is not None:
            try:
                v = os.getxattr(src, name).decode('ascii')
            except (OSError, UnicodeError):
                v = None
        if len(self.xcache) > 4096:
            self.xcache.clear()
        self.xcache[key] = v
        return v

    def xset(self, src, name, value):
        """set (value None: remove) an emulator extended attribute; False if the host
        file system cannot keep it"""
        if not self.xattrs_ok():
            return False
        try:
            if value is None:
                try:
                    os.removexattr(src, name)
                except OSError as e:
                    if e.errno != herrno.ENODATA:
                        raise
            else:
                os.setxattr(src, name, value.encode('ascii'))
            return True
        except OSError as e:
            if e.errno in (herrno.ENOTSUP, herrno.EPERM):     # symbolic links, odd files
                return False
            raise host_err(e)

    def acl_opt(self, gpath, st, src=None):
        """a file's optional ACL entries: [(uid, gid, mode)], uid/gid NS for %"""
        v = self.xget(gpath, st, self.ACL_XATTR, src)
        out = []
        for item in (v or '').split(','):
            u, _, rest = item.partition('.')
            g, _, m = rest.partition('=')
            try:
                out.append((int(u), int(g), int(m)))
            except ValueError:
                pass
        return out

    def acl_base(self, gpath, st, src=None):
        """the three base entries, from the owner and the mode bits"""
        fuid, fgid = self.owner_of(gpath, st, src)
        m = st.st_mode
        return [(fuid, self.NS, (m >> 6) & 7), (self.NS, fgid, (m >> 3) & 7), (self.NS, self.NS, m & 7)]

    def allowed(self, gpath, st, want, uid=None, groups=None, src=None):
        """the permission bits of `want` (R 4, W 2, X 1) this process has on a file,
        as the kernel decides: the superuser has everything except execute on a file
        no ACL entry lets anyone execute; otherwise the access check of acl(5) - the
        most specific level of entries that matches the user and any of its groups
        decides, (u.g) before (u.%) before (%.g) before (%.%), the modes of several
        matching entries of one level OR-ed. Without optional entries that is the
        owner's, the group's or the others' bits."""
        if uid is None:
            uid = self.euid
        if groups is None:
            groups = [self.egid] + self.groups
        mode = st.st_mode
        opt = self.acl_opt(gpath, st, src)
        if uid == 0:
            if want & 1 and not hstat.S_ISDIR(mode) and not mode & 0o111 and not any(e[2] & 1 for e in opt):
                return want & ~1
            return want
        fuid, fgid = self.owner_of(gpath, st, src)
        if not opt:
            if uid == fuid:
                bits = (mode >> 6) & 7
            elif fgid in groups:
                bits = (mode >> 3) & 7
            else:
                bits = mode & 7
            return want & bits
        NS = self.NS
        entries = opt + [(fuid, NS, (mode >> 6) & 7), (NS, fgid, (mode >> 3) & 7), (NS, NS, mode & 7)]
        for match in (lambda u, g: u == uid and g != NS and g in groups,
                      lambda u, g: u == uid and g == NS,
                      lambda u, g: u == NS and g != NS and g in groups,
                      lambda u, g: u == NS and g == NS):
            bits = None
            for u, g, m in entries:
                if match(u, g):
                    bits = (bits or 0) | m
            if bits is not None:
                return want & bits
        return 0

    def check(self, gpath, want, follow=True):
        """EACCES unless the process may do `want` on the path; ENOENT if it is not there"""
        st = self.host_stat(gpath, follow)
        if self.allowed(self.guest_abspath(gpath), st, want) != want:
            raise HpuxError(EACCES)
        return st

    def check_owner(self, gpath, st=None, follow=True):
        """EPERM unless the process owns the file or is the superuser"""
        if self.euid == 0:
            return
        if st is None:
            st = self.host_stat(gpath, follow)
        fuid, _ = self.owner_of(self.guest_abspath(gpath), st)
        if fuid != self.euid:
            raise HpuxError(C['EPERM'])

    def check_dir_write(self, gpath, removing=None):
        """write permission on a path's parent directory, for creating or removing an
        entry; a sticky directory (/tmp) lets only the owner remove another's file"""
        if self.euid == 0:
            return
        parent = os.path.dirname(self.guest_abspath(gpath).rstrip('/')) or '/'
        pst = self.check(parent, 3)
        if removing is not None and pst.st_mode & 0o1000:
            try:
                st = self.host_stat(gpath, False)
            except HpuxError:
                return
            fuid, _ = self.owner_of(self.guest_abspath(gpath), st)
            duid, _ = self.owner_of(parent, pst)
            if self.euid not in (fuid, duid):
                raise HpuxError(C['EPERM'])

    def owner_of(self, gpath, st, src=None):
        """The HP-UX owner of a file: its user.hpux.owner attribute, else the owners
        table the root was built with (etc/hpuxemu/owners, from the depot), else the
        host's owner, the host user being the emulated user."""
        v = self.xget(gpath, st, self.OWNER_XATTR, src)
        if v:
            try:
                u, g = v.split()
                return int(u), int(g)
            except ValueError:
                pass
        self.load_owners()
        rec = self.owners.get(gpath) if gpath else None
        if rec is not None:
            return rec[1], rec[2]
        # no record: the file was made by the host user - the root builder, or a
        # process running as the superuser (which records nothing) - so it is root's;
        # a host file of another host user (a pass-through tty) keeps that owner
        uid = 0 if st.st_uid == self.host_uid else (st.st_uid if st.st_uid < 65536 else 0)
        gid = 0 if st.st_gid == self.host_gid else (st.st_gid if st.st_gid < 65536 else 0)
        return uid, gid

    def new_file_owner(self, gpath, src):
        """A file the process has just created belongs to it. Nothing needs recording
        for the superuser - unless the owners table has an entry for the path (a
        depot file that was removed or renamed), which would otherwise apply."""
        self.load_owners()
        if self.euid == 0 and gpath not in self.owners:
            return
        st = os.fstat(src) if isinstance(src, int) else os.lstat(src)
        uid, gid = (self.euid, self.egid) if self.euid != 0 else (0, 0)
        self.set_owner(gpath, st, uid, gid, src)

    def stat_buf(self, st, gpath='', size=None):
        mode = hstat.S_IMODE(st.st_mode) | (st.st_mode & 0o170000)
        if size is None:
            size = st.st_size
        uid, gid = self.owner_of(gpath, st)
        return self.with_st_acl('stat', gpath, st, pack('stat', {'st_dev': hp_dev(st.st_dev), 'st_ino': st.st_ino & M32, 'st_mode': mode, 'st_nlink': st.st_nlink,
                             'st_rdev': hp_dev(st.st_rdev), 'st_size': min(size, 0x7FFFFFFF), 'st_atime': self.gtime(st.st_atime),
                             'st_mtime': self.gtime(st.st_mtime), 'st_ctime': self.gtime(st.st_ctime), 'st_blksize': 8192,
                             'st_blocks': (size + 511) // 512, 'st_uid': uid, 'st_gid': gid, 'st_basemode': mode & 0o7777,
                             'st_fstype': 1, 'st_realdev': hp_dev(st.st_dev)}))

    def with_st_acl(self, sname, gpath, st, d):
        """st_acl: the bit after the 30-bit st_pad that follows st_blocks (mask 2 of
        that word), set when the file has optional ACL entries (ls -l shows a +)"""
        if self.acl_opt(gpath, st):
            off = sum(OFFSET[sname]['st_blocks'])
            d = bytearray(d)
            d[off + 3] |= 2
            d = bytes(d)
        return d

    def stat64_buf(self, st, gpath='', size=None):
        mode = hstat.S_IMODE(st.st_mode) | (st.st_mode & 0o170000)
        if size is None:
            size = st.st_size
        uid, gid = self.owner_of(gpath, st)
        return self.with_st_acl('stat64', gpath, st, pack('stat64', {'st_dev': hp_dev(st.st_dev), 'st_ino': st.st_ino & M32, 'st_mode': mode, 'st_nlink': st.st_nlink,
                               'st_rdev': hp_dev(st.st_rdev), 'st_size': size, 'st_atime': self.gtime(st.st_atime),
                               'st_mtime': self.gtime(st.st_mtime), 'st_ctime': self.gtime(st.st_ctime), 'st_blksize': 8192,
                               'st_blocks': (size + 511) // 512, 'st_uid': uid, 'st_gid': gid, 'st_basemode': mode & 0o7777,
                               'st_fstype': 1, 'st_realdev': hp_dev(st.st_dev)}))

    def host_stat(self, gp, follow=True, cred=None):
        devs = self.stream_devices()
        if devs:
            g = self.guest_abspath(gp)
            if g in devs:
                return streams.node_stat(devs[g][1], g)
        hp = self.hostpath(gp, follow, cred=cred)
        try:
            st = os.stat(hp) if follow else os.lstat(hp)
        except OSError as e:
            raise host_err(e)
        self.hpcache[(st.st_dev, st.st_ino)] = hp
        return st

    def sys_stat(self, path, buf, *a):
        """stat(path, buf): struct stat (ABI.md) from the host; device numbers in the HP-UX layout"""
        gp = self.rdstr(path)
        self.wr(buf, self.stat_buf(self.host_stat(gp), self.guest_abspath(gp)))
        return 0

    def sys_lstat(self, path, buf, *a):
        """lstat(path, buf): stat without following the last link"""
        gp = self.rdstr(path)
        self.wr(buf, self.stat_buf(self.host_stat(gp, False), self.guest_abspath(gp)))
        return 0

    @staticmethod
    def pipe_size(fd, st):
        """st_size of a pipe or FIFO: on HP-UX the number of unread bytes in it (Linux says
        0). dtexec fstats the pipe carrying its child's stderr when select says it is
        readable and takes size 0 for end of file: it closed the pipe and the child died
        of SIGPIPE on its next message."""
        if not hstat.S_ISFIFO(st.st_mode):
            return None
        import fcntl
        import termios
        try:
            return struct.unpack('i', fcntl.ioctl(fd, termios.FIONREAD, b'\0\0\0\0'))[0]
        except OSError:
            return None

    def sys_fstat(self, fd, buf, *a):
        """fstat(fd, buf); for a pipe st_size is the number of unread bytes, as on HP-UX"""
        self.fd_check(fd)
        try:
            st = os.fstat(fd)
        except OSError as e:
            raise host_err(e)
        if self.fds[fd].get('stream') is not None:
            path = self.fds[fd]['path']
            st = streams.node_stat(self.stream_devices().get(path, ('', None))[1], path)
        else:
            self.hpcache[(st.st_dev, st.st_ino)] = fd
        d = self.stat_buf(st, self.fds[fd]['path'], self.pipe_size(fd, st))
        if fd in self.pty_masters:
            d = self.pty_rdev(d, 'stat', self.pty_masters[fd])
        self.wr(buf, d)
        return 0

    def pty_rdev(self, d, sname, n):
        """patch st_rdev (and the mode: a character device) of a stat buffer for a pty master"""
        d = bytearray(d)
        off, sz = OFFSET[sname]['st_rdev']
        d[off:off + sz] = ((self.PTY_MAJOR << 24) | n).to_bytes(sz, 'big')
        off, sz = OFFSET[sname]['st_mode']
        mode = int.from_bytes(d[off:off + sz], 'big')
        d[off:off + sz] = ((mode & 0o7777) | 0o020000).to_bytes(sz, 'big')
        return bytes(d)

    def sys_stat64(self, path, buf, *a):
        """stat64(path, buf): struct stat64 with 64-bit sizes and inode numbers"""
        gp = self.rdstr(path)
        self.wr(buf, self.stat64_buf(self.host_stat(gp), self.guest_abspath(gp)))
        return 0

    def sys_lstat64(self, path, buf, *a):
        """lstat64(path, buf)"""
        gp = self.rdstr(path)
        self.wr(buf, self.stat64_buf(self.host_stat(gp, False), self.guest_abspath(gp)))
        return 0

    def sys_fstat64(self, fd, buf, *a):
        """fstat64(fd, buf)"""
        self.fd_check(fd)
        try:
            st = os.fstat(fd)
        except OSError as e:
            raise host_err(e)
        self.hpcache[(st.st_dev, st.st_ino)] = fd
        d = self.stat64_buf(st, self.fds[fd]['path'], self.pipe_size(fd, st))
        if fd in self.pty_masters:
            d = self.pty_rdev(d, 'stat64', self.pty_masters[fd])
        self.wr(buf, d)
        return 0

    def sys_access(self, path, mode, *a):
        """access(path, mode): the kernel's check with the *real* ids, for the path's directories too; ACLs included"""
        gp = self.rdstr(path)
        real = (self.uid, [self.gid] + self.groups)
        st = self.host_stat(gp, cred=real)
        if self.allowed(self.guest_abspath(gp), st, mode & 7, *real) != mode & 7:
            raise HpuxError(EACCES)
        return 0

    def sys_getaccess(self, path, uid, ngroups, gidset, label, privs, *a):
        """getaccess(path, uid, ngroups, gidset, label, privs): the access bits a given identity has on a path (UID_EUID -34 / UID_RUID -33 / UID_SUID -32; NGROUPS_EGID -1 ... NGROUPS_EGID_SUPP -5 name the process's own groups, else gidset lists them); R_OK|W_OK|X_OK"""
        gp = self.rdstr(path)
        st = self.host_stat(gp)
        uid = uid - (1 << 32) if uid & 0x80000000 else uid
        ngroups = ngroups - (1 << 32) if ngroups & 0x80000000 else ngroups
        uid = {-34: self.euid, -33: self.uid, -32: self.suid}.get(uid, uid)
        if ngroups >= 0:
            groups = [struct.unpack('>I', self.rd(gidset + 4 * i, 4))[0] for i in range(ngroups)]
        else:
            groups = {-1: [self.egid], -2: [self.gid], -3: [self.sgid], -4: self.groups, -5: [self.egid] + self.groups,
                      -6: [self.gid] + self.groups, -7: [self.sgid] + self.groups}.get(ngroups, [self.egid] + self.groups)
        return self.allowed(self.guest_abspath(gp), st, 7, uid, groups)

    # ---- HFS access control lists: getacl(2), setacl(2) ----
    ACL_ENTRY = 12          # struct acl_entry: long uid, long gid, unsigned char mode
    NACLENTRIES = 16

    def acl_entries(self, gpath, st, src=None):
        """the whole ACL in getacl's order: by decreasing specificity - (u.g), (u.%),
        (%.g), (%.%) - and by user and group id within each"""
        NS = self.NS
        ents = self.acl_base(gpath, st, src) + self.acl_opt(gpath, st, src)
        level = lambda e: (0 if e[1] != NS else 1) if e[0] != NS else (2 if e[1] != NS else 3)
        return sorted(ents, key=lambda e: (level(e), e[0], e[1]))

    def put_acl(self, gpath, st, src, n, buf):
        n = n - (1 << 32) if n & 0x80000000 else n
        ents = self.acl_entries(gpath, st, src)
        if n == 0:
            return len(ents)
        if n < len(ents) or n > self.NACLENTRIES:
            raise HpuxError(C['EINVAL'])
        out = b''.join(struct.pack('>iiB3x', u, g, m) for u, g, m in ents)
        self.wr(buf, out)
        return len(ents)

    def sys_getacl(self, path, n, buf, *a):
        """getacl(path, nentries, acl): the ACL - the three base entries from the owner and mode bits, then the optional ones (kept in the file's user.hpux.acl attribute); nentries 0 asks only for the count"""
        gp = self.rdstr(path)
        st = self.host_stat(gp)
        return self.put_acl(self.guest_abspath(gp), st, None, n, buf)

    def sys_fgetacl(self, fd, n, buf, *a):
        """fgetacl(fd, nentries, acl)"""
        self.fd_check(fd)
        st = os.fstat(fd)
        return self.put_acl(self.fds[fd]['path'], st, fd, n, buf)

    def set_acl(self, gpath, st, src, n, buf):
        """setacl: replaces the optional entries; base entries set the mode bits, an
        unmentioned base entry gets mode 0; nentries ACL_DELOPT (-1) deletes the
        optional entries only. The owner or the superuser."""
        n = n - (1 << 32) if n & 0x80000000 else n
        if self.euid != 0 and self.owner_of(gpath, st, src)[0] != self.euid:
            raise HpuxError(C['EPERM'])
        if not self.xattrs_ok() or hstat.S_ISLNK(st.st_mode):
            raise HpuxError(C['EOPNOTSUPP'])
        if n == C['ACL_DELOPT']:
            self.xset(src, self.ACL_XATTR, None)
            return 0
        if n < 0:
            raise HpuxError(C['EINVAL'])
        if n > self.NACLENTRIES:
            raise HpuxError(C['E2BIG'])
        NS = self.NS
        old = {65500: NS}                     # OLD_ACL_NSUSER / OLD_ACL_NSGROUP
        data = self.rd(buf, n * self.ACL_ENTRY) if n else b''
        ents = {}
        for i in range(n):
            u, g, m = struct.unpack_from('>iiB', data, i * self.ACL_ENTRY)
            if u in (-35, 65501):             # ACLUNUSED / OLD_ACLUNUSED: an unused entry
                continue
            u, g = old.get(u, u), old.get(g, g)
            if m > 7 or (u != NS and u < 0) or (g != NS and g < 0) or (u, g) in ents:
                raise HpuxError(C['EINVAL'])
            ents[(u, g)] = m
        fuid, fgid = self.owner_of(gpath, st, src)
        um = ents.pop((fuid, NS), 0)
        gm = ents.pop((NS, fgid), 0)
        om = ents.pop((NS, NS), 0)
        if len(ents) > self.NACLENTRIES - 3:
            raise HpuxError(C['E2BIG'])
        try:
            mode = (st.st_mode & 0o7000) | (um << 6) | (gm << 3) | om
            if isinstance(src, int):
                os.fchmod(src, mode)
            else:
                os.chmod(src, mode)
        except OSError as e:
            raise host_err(e)
        opt = ','.join('%d.%d=%d' % (u, g, m) for (u, g), m in sorted(ents.items()))
        self.xset(src, self.ACL_XATTR, opt or None)
        return 0

    def sys_setacl(self, path, n, buf, *a):
        """setacl(path, nentries, acl): set a file's ACL (the owner or the superuser); the optional entries are kept in the host file's user.hpux.acl attribute - EOPNOTSUPP where the host file system has no user attributes, as HP-UX says for a non-HFS file system"""
        gp = self.rdstr(path)
        st = self.host_stat(gp)
        return self.set_acl(self.guest_abspath(gp), st, self.hostpath(gp), n, buf)

    def sys_fsetacl(self, fd, n, buf, *a):
        """fsetacl(fd, nentries, acl)"""
        self.fd_check(fd)
        return self.set_acl(self.fds[fd]['path'], os.fstat(fd), fd, n, buf)

    def sys_chdir(self, path, *a):
        """chdir(path): the guest's own working directory (the host's is never changed)"""
        gp = self.rdstr(path)
        hp = self.hostpath(gp)
        if not os.path.isdir(hp):
            raise HpuxError(C['ENOTDIR'] if os.path.exists(hp) else ENOENT)
        self.check(gp, 1)
        self.cwd = self.guest_abspath(gp)
        return 0

    def sys_fchdir(self, fd, *a):
        """fchdir(fd): to the directory the descriptor was opened on"""
        self.fd_check(fd)
        self.cwd = self.fds[fd]['path']
        return 0

    def sys_chmod(self, path, mode, *a):
        """chmod(path, mode): the mode bits go to the host file (set-id bits included); the owner or the superuser; like HP-UX (POSIX.1) it deletes the file's optional ACL entries"""
        gp = self.rdstr(path)
        st = self.host_stat(gp)
        self.check_owner(gp, st)
        hp = self.hostpath(gp)
        try:
            os.chmod(hp, mode & 0o7777)
        except OSError as e:
            raise host_err(e)
        if self.acl_opt(self.guest_abspath(gp), st, hp):
            self.xset(hp, self.ACL_XATTR, None)
        return 0

    def sys_fchmod(self, fd, mode, *a):
        """fchmod(fd, mode): the owner or the superuser; deletes optional ACL entries"""
        self.fd_check(fd)
        try:
            st = os.fstat(fd)
        except OSError as e:
            raise host_err(e)
        if self.euid != 0 and self.owner_of(self.fds[fd]['path'], st, fd)[0] != self.euid:
            raise HpuxError(C['EPERM'])
        try:
            os.fchmod(fd, mode & 0o7777)
        except OSError as e:
            raise host_err(e)
        if self.acl_opt(self.fds[fd]['path'], st, fd):
            self.xset(fd, self.ACL_XATTR, None)
        return 0

    def sys_chown(self, path, uid, gid, *a):
        """chown(path, uid, gid): recorded in the file's user.hpux.owner attribute (files belong to the host user); the owner may give a file away as HP-UX allows, others need to be superuser"""
        gp = self.rdstr(path)
        st = self.host_stat(gp)
        self.check_owner(gp, st)
        self.set_owner(self.guest_abspath(gp), st, uid, gid, self.hostpath(gp))
        return 0

    def sys_lchown(self, path, uid, gid, *a):
        """lchown(path, uid, gid): as chown, for the link itself"""
        gp = self.rdstr(path)
        st = self.host_stat(gp, False)
        self.check_owner(gp, st)
        self.set_owner(self.guest_abspath(gp), st, uid, gid, None if hstat.S_ISLNK(st.st_mode) else self.hostpath(gp, False))
        return 0

    def sys_fchown(self, fd, uid, gid, *a):
        """fchown(fd, uid, gid): as chown"""
        self.fd_check(fd)
        st = os.fstat(fd)
        if self.euid != 0 and self.owner_of(self.fds[fd]['path'], st, fd)[0] != self.euid:
            raise HpuxError(C['EPERM'])
        self.set_owner(self.fds[fd]['path'], st, uid, gid, fd)
        return 0

    def set_owner(self, gpath, st, uid, gid, src=None):
        """record a file's HP-UX owner: in its user.hpux.owner attribute, else (a
        symbolic link, a file system without user attributes) in the owners table"""
        if not gpath:
            return
        ouid, ogid = self.owner_of(gpath, st, src)
        if uid & M32 == M32:
            uid = ouid
        if gid & M32 == M32:
            gid = ogid
        uid = uid - (1 << 32) if uid & 0x80000000 else uid
        gid = gid - (1 << 32) if gid & 0x80000000 else gid
        if src is None:
            src = self.xsrc(gpath, st)
        if src is not None and not hstat.S_ISLNK(st.st_mode) and \
                self.xset(src, self.OWNER_XATTR, '%d %d' % (uid, gid)):
            return
        self.load_owners()
        rec = self.owners.get(gpath)
        mode = rec[0] if rec else hstat.S_IMODE(st.st_mode)
        typ = rec[3] if rec else ('d' if hstat.S_ISDIR(st.st_mode) else 'f')
        self.owners[gpath] = (mode, uid, gid, typ)
        try:
            from .owners import write_owners
            write_owners(self.root, self.owners)
            self.owners_stamp = None
        except OSError:
            pass

    def sys_link(self, old, new, *a):
        """link(old, new): a host hard link; write permission on the new directory"""
        gn = self.rdstr(new)
        self.check_dir_write(gn)
        try:
            os.link(self.hostpath(self.rdstr(old)), self.hostpath(gn, False))
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_unlink(self, path, *a):
        """unlink(path): needs write permission on the directory (and the sticky rule)"""
        gp = self.rdstr(path)
        self.check_dir_write(gp, removing=True)
        try:
            os.unlink(self.hostpath(gp, False))
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_symlink(self, target, path, *a):
        """symlink(target, path): the target is stored as given (guest paths resolve inside the root); write permission on the directory"""
        gp = self.rdstr(path)
        self.check_dir_write(gp)
        try:
            os.symlink(self.rdstr(target), self.hostpath(gp, False))
        except OSError as e:
            raise host_err(e)
        if self.euid != 0:
            self.set_owner(self.guest_abspath(gp), self.host_stat(gp, False), self.euid, self.egid)
        return 0

    def sys_readlink(self, path, buf, n, *a):
        """readlink(path, buf, n): the stored target, not NUL-terminated"""
        try:
            t = os.readlink(self.hostpath(self.rdstr(path), False)).encode('latin1')
        except OSError as e:
            raise host_err(e)
        t = t[:n]
        self.wr(buf, t)
        return len(t)

    def sys_rename(self, old, new, *a):
        """rename(old, new): write permission on both directories; owners in the owners table move with the files (as attributes)"""
        go, gn = self.rdstr(old), self.rdstr(new)
        self.check_dir_write(go, removing=True)
        self.check_dir_write(gn)
        self.carry_owners(self.guest_abspath(go), self.guest_abspath(gn))
        try:
            os.rename(self.hostpath(go, False), self.hostpath(gn, False))
        except OSError as e:
            raise host_err(e)
        return 0

    def carry_owners(self, gold, gnew):
        """Before a rename: owners known only from the owners table (by path) would
        stay behind - and the table entry of the new path would apply to the file
        moved there. Give the file, and those under a directory, their owner as an
        attribute, which moves with them."""
        if not self.xattrs_ok():
            return
        self.load_owners()
        pre = gold.rstrip('/') + '/'
        paths = [gold] + [p for p in self.owners if p.startswith(pre)]
        if not (gold in self.owners or gnew in self.owners or len(paths) > 1):
            return
        for gp in paths:
            try:
                hp = self.hostpath(gp, False, search=False)
                st = os.lstat(hp)
            except (OSError, HpuxError):
                continue
            if hstat.S_ISLNK(st.st_mode) or self.xget(gp, st, self.OWNER_XATTR, hp):
                continue
            u, g = self.owner_of(gp, st, hp)
            self.xset(hp, self.OWNER_XATTR, '%d %d' % (u, g))

    def sys_mkdir(self, path, mode, *a):
        """mkdir(path, mode): write permission on the parent; the new directory is the caller's"""
        gp = self.rdstr(path)
        self.check_dir_write(gp)
        try:
            os.mkdir(self.hostpath(gp, False), mode & 0o7777)
        except OSError as e:
            raise host_err(e)
        self.new_file_owner(self.guest_abspath(gp), self.hostpath(gp, False))
        return 0

    def sys_rmdir(self, path, *a):
        """rmdir(path): write permission on the parent"""
        gp = self.rdstr(path)
        self.check_dir_write(gp, removing=True)
        try:
            os.rmdir(self.hostpath(gp, False))
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_mknod(self, path, mode, dev, *a):
        """mknod(path, mode, dev): FIFOs only (write permission on the directory); device nodes are refused with EPERM"""
        if (mode & 0o170000) == 0o010000:
            gp = self.rdstr(path)
            self.check_dir_write(gp)
            hp = self.hostpath(gp, False)
            try:
                os.mkfifo(hp, mode & 0o7777)
            except OSError as e:
                raise host_err(e)
            self.new_file_owner(self.guest_abspath(gp), hp)
            return 0
        raise HpuxError(C['EPERM'])

    def sys_utime(self, path, times, *a):
        """utime(path, times): access and modification times, or now when times is NULL; setting explicit times needs ownership, setting now needs write permission"""
        gp = self.rdstr(path)
        hp = self.hostpath(gp)
        if times:
            self.check_owner(gp)
        else:
            self.check(gp, 2)
        try:
            if times:
                at, mt = struct.unpack('>II', self.rd(times, 8))
                os.utime(hp, (at, mt))
            else:
                os.utime(hp, None)
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_truncate(self, path, ln, *a):
        """truncate(path, length): write permission"""
        gp = self.rdstr(path)
        self.check(gp, 2)
        try:
            os.truncate(self.hostpath(gp), ln)
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_ftruncate(self, fd, ln, *a):
        """ftruncate(fd, length)"""
        self.fd_check(fd)
        try:
            os.ftruncate(fd, ln)
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_fsync(self, fd, *a):
        """fsync(fd): nothing to do, the host writes through"""
        return 0

    def sys_sync(self, *a):
        """sync(): nothing to do"""
        return 0

    def sys_fcntl(self, fd, cmd, arg, *a):
        """fcntl(fd, cmd, arg): F_DUPFD, F_GETFD/SETFD, F_GETFL/SETFL, the locks"""
        self.fd_check(fd)
        import fcntl
        try:
            if cmd == C.get('F_DUPFD', 0):
                n = fcntl.fcntl(fd, fcntl.F_DUPFD, arg)
                os.set_inheritable(n, True)
                self.fds[n] = dict(self.fds[fd])
                self.nb_copy(fd, n)
                return n
            if cmd == C['F_GETFD']:
                return fcntl.fcntl(fd, fcntl.F_GETFD)
            if cmd == C['F_SETFD']:
                fcntl.fcntl(fd, fcntl.F_SETFD, arg & 1)
                return 0
            if cmd == C['F_GETFL']:
                hf = fcntl.fcntl(fd, fcntl.F_GETFL)
                g = hf & 3
                if hf & os.O_APPEND:
                    g |= C['O_APPEND']
                m = self.nbmode.get(fd, ())
                if 'nonblock' in m:
                    g |= C['O_NONBLOCK']
                if 'ndelay' in m:
                    g |= C['O_NDELAY']
                return g
            if cmd == C['F_SETFL']:
                hf = 0
                if arg & C['O_APPEND']:
                    hf |= os.O_APPEND
                fcntl.fcntl(fd, fcntl.F_SETFL, hf | (fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK))
                self.nb_set(fd, 'nonblock', arg & C['O_NONBLOCK'])
                self.nb_set(fd, 'ndelay', arg & C['O_NDELAY'])
                return 0
            if cmd in (C['F_GETLK'], C['F_SETLK'], C['F_SETLKW']):
                fl = unpack('flock', self.rd(arg, SIZEOF['flock']))
                htype = {C['F_RDLCK']: fcntl.F_RDLCK, C['F_WRLCK']: fcntl.F_WRLCK, C['F_UNLCK']: fcntl.F_UNLCK}.get(fl['l_type'], fcntl.F_UNLCK)
                hcmd = {C['F_GETLK']: fcntl.F_GETLK, C['F_SETLK']: fcntl.F_SETLK, C['F_SETLKW']: fcntl.F_SETLKW}[cmd]
                hfl = struct.pack(HOST_FLOCK, htype, fl['l_whence'], fl['l_start'], fl['l_len'], 0)
                res = fcntl.fcntl(fd, hcmd, hfl)
                if cmd == C['F_GETLK']:
                    t, wh, st, ln, pid = struct.unpack(HOST_FLOCK, res[:struct.calcsize(HOST_FLOCK)])
                    gt = {fcntl.F_RDLCK: C['F_RDLCK'], fcntl.F_WRLCK: C['F_WRLCK'], fcntl.F_UNLCK: C['F_UNLCK']}[t]
                    self.wr(arg, pack('flock', {'l_type': gt, 'l_whence': wh, 'l_start': st, 'l_len': ln, 'l_pid': pid}))
                return 0
            if cmd in (C['F_GETLK64'], C['F_SETLK64'], C['F_SETLKW64']):
                fl = unpack('flock64', self.rd(arg, SIZEOF['flock64']))
                htype = {C['F_RDLCK']: fcntl.F_RDLCK, C['F_WRLCK']: fcntl.F_WRLCK, C['F_UNLCK']: fcntl.F_UNLCK}.get(fl['l_type'], fcntl.F_UNLCK)
                hcmd = {C['F_GETLK64']: fcntl.F_GETLK, C['F_SETLK64']: fcntl.F_SETLK, C['F_SETLKW64']: fcntl.F_SETLKW}[cmd]
                hfl = struct.pack(HOST_FLOCK, htype, fl['l_whence'], fl['l_start'], fl['l_len'], 0)
                res = fcntl.fcntl(fd, hcmd, hfl)
                if cmd == C['F_GETLK64']:
                    t, wh, st, ln, pid = struct.unpack(HOST_FLOCK, res[:struct.calcsize(HOST_FLOCK)])
                    gt = {fcntl.F_RDLCK: C['F_RDLCK'], fcntl.F_WRLCK: C['F_WRLCK'], fcntl.F_UNLCK: C['F_UNLCK']}[t]
                    self.wr(arg, pack('flock64', {'l_type': gt, 'l_whence': wh, 'l_start': st, 'l_len': ln, 'l_pid': pid}))
                return 0
            if cmd == C.get('F_SETOWN', 12):
                # who gets SIGIO for the descriptor (O_ASYNC/FIOASYNC): a guest process is
                # a host process with the same pid, a negative number a process group
                fcntl.fcntl(fd, fcntl.F_SETOWN, arg - (1 << 32) if arg & 0x80000000 else arg)
                return 0
            if cmd == C.get('F_GETOWN', 11):
                return fcntl.fcntl(fd, fcntl.F_GETOWN) & M32
        except OSError as e:
            raise host_err(e)
        sys.stderr.write('hpuxemu: fcntl cmd %d unimplemented\n' % cmd)
        raise HpuxError(EINVAL)

    def sys_fcntl64(self, fd, cmd, arg, *a):
        """fcntl64(fd, cmd, arg): as fcntl (the 64-bit lock structures have the same layout here)"""
        return self.sys_fcntl(fd, cmd, arg)

    def sys_lockf(self, fd, func, size, *a):
        """lockf(fd, function, size): accepted; no locking between emulated processes yet"""
        return 0

    def sys_lockf64(self, fd, func, hi, lo, *a):
        """lockf64(fd, function, size): accepted; no locking"""
        return 0

    def sys_getdents(self, fd, buf, n, *a):
        """getdents(fd, buf, n): the kernel's file-system-independent entries, `struct
        __dirent` of sys/dirent.h: {u64 offset cookie, u32 ino, i16 reclen, i16 namlen,
        name[]}, 8-byte aligned; libc's readdir() copies them into `struct dirent`. The
        cookie is the entry's index + 1 (what a later lseek on the directory gets back)"""
        self.fd_check(fd)
        f = self.fds[fd]
        if f['dirents'] is None:
            try:
                names = ['.', '..'] + sorted(os.listdir(self.hostpath(f['path'], search=False)))
                gp = self.guest_abspath(f['path'])
                if gp == '/dev/pts':
                    names += sorted(n for n in os.listdir('/dev/pts') if n.isdigit())
                elif gp == '/dev':
                    names += sorted(os.path.basename(t) for t in self.my_ttys if t.count('/') == 2 and os.path.basename(t) not in names)
            except OSError as e:
                raise host_err(e)
            f['dirents'] = names
            f['dirpos'] = 0
        out = bytearray()
        while f['dirpos'] < len(f['dirents']):
            name = f['dirents'][f['dirpos']].encode('latin1')
            try:
                ino = os.lstat(os.path.join(self.hostpath(f['path'], search=False), name.decode('latin1'))).st_ino & M32
            except OSError:
                ino = 1
            reclen = (16 + len(name) + 1 + 7) & ~7
            if len(out) + reclen > n:
                break
            out += struct.pack('>QIHH', f['dirpos'] + 1, ino, reclen, len(name)) + name + b'\0' * (reclen - 16 - len(name))
            f['dirpos'] += 1
        if not out and n < 16:
            raise HpuxError(EINVAL)
        self.wr(buf, bytes(out))
        return len(out)

    def sys_getdirentries(self, fd, buf, n, basep, *a):
        """getdirentries(fd, buf, n, basep): getdents, with the position stored at basep"""
        r = self.sys_getdents(fd, buf, n)
        if basep:
            self.wr32(basep, self.fds[fd]['dirpos'])
        return r

    def sys_ioctl(self, fd, req, arg, *a):
        """ioctl(fd, request, arg): the terminal requests (termios), FIONREAD, TIOCGWINSZ"""
        self.fd_check(fd)
        import termios as ht
        import fcntl
        req &= M32
        if self.fds[fd].get('netman'):
            return self.netman_ioctl(req, arg)
        st = self.stream_of(fd)
        if st is not None:
            r = self.stream_ioctl(fd, st, req, arg)
            if self.trace:
                sys.stderr.write('[%d] stream ioctl %#x = %d\n' % (self.pid, req, r))
            return r
        try:
            if req == C['TCGETATTR']:
                attrs = ht.tcgetattr(fd)
                return self.termios_out(arg, attrs)
            if req == TCGETA:
                # struct termio (18 bytes): the termios flags narrowed to 16 bits, NCC 8
                attrs = ht.tcgetattr(fd)
                t = self.termios_bytes(attrs)
                gi, go, gc, gl = struct.unpack('>IIII', t[:16])
                self.wr(arg, struct.pack('>HHHHB', gi & 0xFFFF, go & 0xFFFF, gc & 0xFFFF, gl & 0xFFFF, 0) + t[20:28])
                return 0
            if req in (TCSETA, TCSETAW, TCSETAF):
                old = self.termios_bytes(ht.tcgetattr(fd))
                d = self.rd(arg, 18)
                gi, go, gc, gl, _ = struct.unpack('>HHHHB', d[:9])
                oi, oo, oc, ol = struct.unpack('>IIII', old[:16])
                new = struct.pack('>IIIII', (oi & 0xFFFF0000) | gi, (oo & 0xFFFF0000) | go, (oc & 0xFFFF0000) | gc,
                                  (ol & 0xFFFF0000) | gl, 0) + d[9:17] + old[28:36]
                attrs = self.termios_from_bytes(new, ht.tcgetattr(fd))
                when = {TCSETA: ht.TCSANOW, TCSETAW: ht.TCSADRAIN, TCSETAF: ht.TCSAFLUSH}[req]
                ht.tcsetattr(fd, when, attrs)
                return 0
            if req in (C['TCSETATTR'], C['TCSETATTRD'], C['TCSETATTRF']):
                attrs = self.termios_in(arg, ht.tcgetattr(fd))
                when = {C['TCSETATTR']: ht.TCSANOW, C['TCSETATTRD']: ht.TCSADRAIN, C['TCSETATTRF']: ht.TCSAFLUSH}[req]
                ht.tcsetattr(fd, when, attrs)
                return 0
            if req == C['TIOCGWINSZ']:
                r = fcntl.ioctl(fd, ht.TIOCGWINSZ, b'\0' * 8)
                row, col, xp, yp = struct.unpack('HHHH', r)
                self.wr(arg, struct.pack('>HHHH', row, col, xp, yp))
                return 0
            if req == C['TIOCSWINSZ']:
                row, col, xp, yp = struct.unpack('>HHHH', self.rd(arg, 8))
                fcntl.ioctl(fd, ht.TIOCSWINSZ, struct.pack('HHHH', row, col, xp, yp))
                return 0
            if req == C['TIOCGPGRP']:
                self.wr32(arg, os.tcgetpgrp(fd))
                return 0
            if req == C['TIOCSPGRP']:
                os.tcsetpgrp(fd, self.rd32(arg))
                return 0
            if req == C['FIONREAD']:
                r = fcntl.ioctl(fd, ht.FIONREAD, b'\0' * 4)
                self.wr32(arg, struct.unpack('i', r)[0])
                return 0
            if req == C.get('TCFLSH'):
                ht.tcflush(fd, arg & 3)
                return 0
            if req == C.get('TCSBRK'):
                return 0
            if req == C.get('TCXONC'):
                return 0
            if req in (C.get('TIOCGLTC', -1), C.get('TIOCGETC', -1)):
                # the BSD special characters: from the termios control characters
                cc = ht.tcgetattr(fd)[6]
                if req == C.get('TIOCGLTC'):
                    chars = [cc[ht.VSUSP], cc[ht.VSUSP], cc[ht.VREPRINT], cc[ht.VDISCARD], cc[ht.VWERASE], cc[ht.VLNEXT]]
                else:
                    chars = [cc[ht.VINTR], cc[ht.VQUIT], cc[ht.VSTART], cc[ht.VSTOP], cc[ht.VEOF], b'\0']
                self.wr(arg, b''.join(c if isinstance(c, bytes) else bytes([c]) for c in chars))
                return 0
            if req in (C.get('TIOCSLTC', -1), C.get('TIOCSETC', -1), C.get('TIOCLSET', -1), C.get('TIOCSETP', -1), C.get('TIOCSETN', -1)):
                # the BSD setters: accepted; the termios state is what counts
                return 0
            if req in (C.get('TIOCGETP', -1),):
                # struct sgttyb from termios: speeds, erase, kill, flags (ECHO 010, RAW 040, CRMOD 020)
                iflag, oflag, cflag, lflag, ispeed, ospeed, cc = ht.tcgetattr(fd)
                flags = (0o10 if lflag & ht.ECHO else 0) | (0o20 if oflag & ht.OPOST else 0) | (0 if lflag & ht.ICANON else 0o40)
                self.wr(arg, struct.pack('>BBBBI', 13, 13, cc[ht.VERASE][0] if isinstance(cc[ht.VERASE], bytes) else cc[ht.VERASE],
                                         cc[ht.VKILL][0] if isinstance(cc[ht.VKILL], bytes) else cc[ht.VKILL], flags))
                return 0
            if req == C.get('TIOCLGET', -1):
                self.wr32(arg, 0)
                return 0
            if req in (C['FIONBIO'], C.get('FIOSNBIO', -1)):
                self.nb_set(fd, 'fio', self.rd32(arg))
                return 0
            if req in (0x8004667d, 0x8004667a):
                # FIOASYNC, FIOSSAIOSTAT: SIGIO when the descriptor is ready (a green-threads
                # Java VM waits for it in sigsuspend); the owner is
                # the process unless F_SETOWN/FIOSSAIOOWN named another
                on = self.rd32(arg)
                if on and fcntl.fcntl(fd, fcntl.F_GETOWN) == 0:
                    fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
                fcntl.ioctl(fd, ht.FIOASYNC, struct.pack('i', 1 if on else 0))
                return 0
            if req == 0x80046678:
                # FIOSSAIOOWN: the process (group, negative) that gets SIGIO
                v = self.rd32(arg)
                fcntl.fcntl(fd, fcntl.F_SETOWN, v - (1 << 32) if v & 0x80000000 else v)
                return 0
            if req == 0x40046677:
                # FIOGSAIOOWN
                self.wr32(arg, fcntl.fcntl(fd, fcntl.F_GETOWN) & M32)
                return 0
            if (req >> 8) & 0xFF == ord('S'):
                # STREAMS: terminals are not streams here. On a pty slave I_PUSH succeeds,
                # I_FIND says the module is there and I_POP says there is nothing left to
                # pop (dtterm pops until that fails, then pushes ptem, ldterm, ttcompat);
                # everything else ENOTTY
                if req == C['I_PUSH'] and self.is_tty(fd):
                    return 0
                if req == C['I_FIND'] and self.is_tty(fd):
                    return 1
                if req == C['I_POP'] and self.is_tty(fd):
                    raise HpuxError(EINVAL)
                raise HpuxError(C['ENOTTY'])
            if req == C['SIOCGIFCONF']:
                return self.ifconf(arg)
            if req == C['SIOCJNVS']:
                # the int holds the pty descriptor in its low halfword (telnetd passes
                # 0x08010003 for fd 3; the high half is the driver's mode flags)
                v = self.rd32(arg)
                return self.join_nvs(fd, v & 0xFFFF if v > 0xFFFF else v)
            if req in (C['SIOCGIFFLAGS'], C['SIOCGIFADDR'], C['SIOCGIFNETMASK'], C['SIOCGIFBRDADDR'], C['SIOCGIFDSTADDR'], C['SIOCGIFMETRIC']):
                return self.ifreq(req, arg)
            if req in (C['SIOCGPGRP'], C.get('FIOGETOWN', -1)):
                self.wr32(arg, fcntl.fcntl(fd, fcntl.F_GETOWN))
                return 0
            if req in (C['SIOCSPGRP'], C.get('FIOSETOWN', -1)):
                fcntl.fcntl(fd, fcntl.F_SETOWN, self.rd32(arg))
                return 0
            if req == C['SIOCATMARK']:
                self.wr32(arg, 0)
                return 0
            if req == ISPTM:
                # the master's device number (ptsname derives /dev/pts/N from the minor)
                if fd not in self.pty_masters:
                    raise HpuxError(EINVAL)
                return (self.PTY_MAJOR << 24) | self.pty_masters[fd]
            if req == UNLKPT:
                return 0
            if req == ISPTS:
                # the slave's device number as stat gives it (ptsname checks the two agree)
                if fd in self.pty_masters:
                    path = '/dev/pts/%d' % self.pty_masters[fd]
                else:
                    path = self.fds[fd]['path']
                if path in self.ptys or (path.startswith('/dev/pts/') and path[9:].isdigit()):
                    return hp_dev(os.stat(self.ptys.get(path, path)).st_rdev)
                raise HpuxError(EINVAL)
            if req in (TIOCTRAP, TIOCTRAPSTATUS, TIOCREQCHECK, TIOCREQSET):
                # hpterm's pty trap mechanism (the master is told about the slave's ioctls):
                # accepted; nothing is ever trapped
                if req == TIOCTRAPSTATUS:
                    self.wr32(arg, 0)
                return 0
            if fd in self.pty_masters and (req >> 8) & 0xFF == ord('t'):
                # the other pty master controls (TIOCMONITOR, TIOCPKT ...): accepted
                return 0
            if req == TIOCSIGNAL:
                # the master sends a signal to the slave's foreground process group
                try:
                    os.killpg(os.tcgetpgrp(fd), GUEST2HOST_SIG.get(arg, 0))
                except OSError:
                    pass
                return 0
            if req in (C['MTIOCGET'], C['MTIOCTOP']) or (req >> 8) & 0xFF == ord('V'):
                # not a tape (tar, cpio and dd ask; cpio's 'V' request is not in any header)
                raise HpuxError(C['ENOTTY'])
        except (OSError, ht.error) as e:
            raise HpuxError(HOST2GUEST_ERRNO.get(e.args[0] if isinstance(e, ht.error) else e.errno, C['ENOTTY']))
        sys.stderr.write('hpuxemu: ioctl %#x unimplemented\n' % req)
        raise HpuxError(EINVAL)

    # HP-UX termios: c_iflag c_oflag c_cflag c_lflag c_reserved c_cc[16] (NCCS 16); the
    # flag values are mostly the same as Linux's for the POSIX subset, mapped by name
    IFLAGS = ['IGNBRK', 'BRKINT', 'IGNPAR', 'PARMRK', 'INPCK', 'ISTRIP', 'INLCR', 'IGNCR', 'ICRNL', 'IUCLC', 'IXON', 'IXANY', 'IXOFF']
    OFLAGS = ['OPOST', 'OLCUC', 'ONLCR', 'OCRNL', 'ONOCR', 'ONLRET', 'OFILL', 'OFDEL']
    CFLAGS = ['CSTOPB', 'CREAD', 'PARENB', 'PARODD', 'HUPCL', 'CLOCAL']
    LFLAGS = ['ISIG', 'ICANON', 'XCASE', 'ECHO', 'ECHOE', 'ECHOK', 'ECHONL', 'NOFLSH', 'TOSTOP', 'IEXTEN']
    CCS = ['VINTR', 'VQUIT', 'VERASE', 'VKILL', 'VEOF', 'VEOL', 'VEOL2', 'VMIN', 'VTIME', 'VSUSP', 'VSTART', 'VSTOP', 'VWERASE', 'VLNEXT', 'VDSUSP']
    BAUDS = [0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400]

    def termios_out(self, arg, attrs):
        self.wr(arg, self.termios_bytes(attrs))
        return 0

    def netman_ioctl(self, req, arg):
        """/dev/netman: NMIOGET(struct nmparms {objid, buffer, *len}) answers a MIB-2
        object from the host's tables (netman.py); *len is the buffer's size going in, the
        bytes filled coming out (EMSGSIZE when the object does not fit: mib2agt asks for
        a table's NumEnt first and sizes its buffer by it). The writes (NMIOSET,
        NMIODEL, NMIOCRE) are refused: the host's tables are not the guest's to change."""
        from . import netman
        if req in (netman.NMIOSET, netman.NMIODEL, netman.NMIOCRE):
            raise HpuxError(C['EPERM'])
        if req != netman.NMIOGET:
            raise HpuxError(EINVAL)
        objid, buf, lenp = struct.unpack('>iII', self.rd(arg, 12))
        ln = self.rd32(lenp) if lenp else 0
        try:
            data = self.mib_netman().get(objid, self.rd(buf, ln) if buf and ln else b'')
        except netman.NetmanError as e:
            raise HpuxError(C[e.errno])
        if len(data) > ln:
            raise HpuxError(C['EMSGSIZE'])
        if data:
            self.wr(buf, data)
        if lenp:
            self.wr32(lenp, len(data))
        return 0

    def interfaces(self):
        """[(name, address, netmask, broadcast, flags)] of the host's IPv4 interfaces (lo0
        first, named as HP-UX names them: lo0, lan0, lan1 ...)"""
        import socket as hs
        out = [('lo0', '127.0.0.1', '255.0.0.0', '127.255.255.255', C['IFF_UP'] | C['IFF_LOOPBACK'] | C['IFF_RUNNING'])]
        n = 0
        try:
            for line in open('/proc/net/route'):
                parts = line.split()
                if len(parts) < 8 or parts[1] != '00000000' or parts[0].startswith('lo'):
                    continue
                name = parts[0]
                try:
                    import fcntl
                    sk = hs.socket(hs.AF_INET, hs.SOCK_DGRAM)
                    ifr = struct.pack('16s16x', name.encode())
                    addr = hs.inet_ntoa(fcntl.ioctl(sk.fileno(), 0x8915, ifr)[20:24])
                    mask = hs.inet_ntoa(fcntl.ioctl(sk.fileno(), 0x891b, ifr)[20:24])
                    bcast = hs.inet_ntoa(fcntl.ioctl(sk.fileno(), 0x8919, ifr)[20:24])
                    sk.close()
                except OSError:
                    continue
                out.append(('lan%d' % n, addr, mask, bcast, C['IFF_UP'] | C['IFF_BROADCAST'] | C['IFF_RUNNING'] | C['IFF_MULTICAST']))
                n += 1
                break
        except OSError:
            pass
        return out

    def ifconf(self, arg):
        """SIOCGIFCONF: struct ifconf {len, buf} filled with 32-byte ifreqs (name, sockaddr_in)"""
        import socket as hs
        ln, buf = struct.unpack('>iI', self.rd(arg, 8))
        out = b''
        for name, addr, mask, bcast, flags in self.interfaces():
            sa = struct.pack('>HH', C['AF_INET'], 0) + hs.inet_aton(addr) + b'\0' * 8
            out += name.encode().ljust(16, b'\0') + sa
        out = out[:ln]
        self.wr(buf, out)
        self.wr32(arg, len(out))
        return 0

    def ifreq(self, req, arg):
        import socket as hs
        d = self.rd(arg, 32)
        name = d[:16].split(b'\0', 1)[0].decode('latin1')
        for n, addr, mask, bcast, flags in self.interfaces():
            if n == name:
                break
        else:
            raise HpuxError(C['ENXIO'])
        if req == C['SIOCGIFFLAGS']:
            self.wr(arg + 16, struct.pack('>h', flags))
        elif req == C['SIOCGIFMETRIC']:
            self.wr(arg + 16, struct.pack('>i', 0))
        else:
            a = {C['SIOCGIFADDR']: addr, C['SIOCGIFNETMASK']: mask, C['SIOCGIFBRDADDR']: bcast, C['SIOCGIFDSTADDR']: addr}[req]
            self.wr(arg + 16, struct.pack('>HH', C['AF_INET'], 0) + hs.inet_aton(a) + b'\0' * 8)
        return 0

    def termios_bytes(self, attrs):
        import termios as ht
        iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
        g = [0, 0, 0, 0]
        for names, idx, h in ((self.IFLAGS, 0, iflag), (self.OFLAGS, 1, oflag), (self.CFLAGS, 2, cflag), (self.LFLAGS, 3, lflag)):
            for nm in names:
                if nm in C and hasattr(ht, nm) and h & getattr(ht, nm):
                    g[idx] |= C[nm]
        csize = {ht.CS5: 'CS5', ht.CS6: 'CS6', ht.CS7: 'CS7', ht.CS8: 'CS8'}[cflag & ht.CSIZE]
        g[2] |= C[csize]
        # speed: HP-UX keeps it in c_cflag's CBAUD bits
        sp = 'B%d' % self.BAUDS[ospeed] if ospeed < len(self.BAUDS) else 'B9600'
        g[2] |= C.get(sp, C['B9600'])
        gcc = bytearray(16)
        for nm in self.CCS:
            if nm in C and hasattr(ht, nm):
                v = cc[getattr(ht, nm)]
                gcc[C[nm]] = v if isinstance(v, int) else (ord(v) if v != b'\0' else 0)
                if nm in ('VMIN', 'VTIME'):
                    gcc[C[nm]] = v if isinstance(v, int) else ord(v)
        return struct.pack('>IIIII', g[0], g[1], g[2], g[3], 0) + bytes(gcc)

    def termios_in(self, arg, attrs):
        return self.termios_from_bytes(self.rd(arg, 36), attrs)

    def termios_from_bytes(self, data, attrs):
        import termios as ht
        gi, go, gc, gl, _ = struct.unpack('>IIIII', data[:20])
        gcc = data[20:36]
        iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
        new = [0, 0, 0, 0]
        for names, idx, g in ((self.IFLAGS, 0, gi), (self.OFLAGS, 1, go), (self.CFLAGS, 2, gc), (self.LFLAGS, 3, gl)):
            for nm in names:
                if nm in C and hasattr(ht, nm) and g & C[nm]:
                    new[idx] |= getattr(ht, nm)
        for nm in ('CS5', 'CS6', 'CS7', 'CS8'):
            if (gc & C['CSIZE']) == C[nm]:
                new[2] |= getattr(ht, nm)
        baud = gc & C['CBAUD']
        speed = ospeed
        for i, b in enumerate(self.BAUDS):
            if C.get('B%d' % b) == baud:
                speed = getattr(ht, 'B%d' % b, ospeed)
        cc = list(cc)
        for nm in self.CCS:
            if nm in C and hasattr(ht, nm):
                v = gcc[C[nm]]
                cc[getattr(ht, nm)] = v if nm in ('VMIN', 'VTIME') else bytes([v])
        return [new[0], new[1], new[2], new[3], speed, speed, cc]

    def sys_select(self, nfds, rs, ws, es, tv, *a):
        """select(nfds, readfds, writefds, exceptfds, timeout): fd_set is an array of
        big-endian words, bit i of word i/32"""
        def rdset(addr):
            # the set bits only: servers pass nfds = the descriptor table's size (2048)
            # and call select thousands of times a second
            if not addr or nfds <= 0:
                return []
            words = (nfds + 31) // 32
            out = []
            for wi, w in enumerate(struct.unpack('>%dI' % words, self.rd(addr, 4 * words))):
                while w:
                    low = w & -w
                    i = wi * 32 + low.bit_length() - 1
                    if i < nfds:
                        out.append(i)
                    w ^= low
            return out

        def wrset(addr, fds):
            if not addr:
                return
            words = (nfds + 31) // 32
            ws_ = [0] * max(words, 1)
            for i in fds:
                ws_[i // 32] |= 1 << (i % 32)
            self.wr(addr, struct.pack('>%dI' % words, *ws_[:words]))

        r, w, e = rdset(rs), rdset(ws), rdset(es)
        timeout = -1
        if tv:
            s, us = struct.unpack('>II', self.rd(tv, 8))
            timeout = s * 1000 + us // 1000
        # through poll(2), which a signal interrupts
        joined = [fd for fd in r if self.fds.get(fd, {}).get('joined') is not None]
        if joined and not self.joined_wait(joined[0], None if timeout is None or timeout < 0 else timeout / 1000.0):
            pass        # the join ended: the socket is the guest's again
        elif joined:
            r = [fd for fd in r if fd not in joined]
            timeout = 0
        fds = sorted(set(r) | set(w) | set(e))
        entries = [(fd, (select.POLLIN if fd in r else 0) | (select.POLLOUT if fd in w else 0) | (select.POLLPRI if fd in e else 0)) for fd in fds]
        try:
            rev = self.poll_streams(entries, timeout)
        except OSError as ex:
            raise host_err(ex)
        rr, rw, re_ = [], [], []
        for (fd, ev), got in zip(entries, rev):
            if got & select.POLLNVAL:
                raise HpuxError(EBADF)
            if fd in r and got & (select.POLLIN | select.POLLHUP | select.POLLERR):
                rr.append(fd)
            if fd in w and got & (select.POLLOUT | select.POLLERR):
                rw.append(fd)
            if fd in e and got & select.POLLPRI:
                re_.append(fd)
        wrset(rs, rr)
        wrset(ws, rw)
        wrset(es, re_)
        return len(rr) + len(rw) + len(re_)

    def sys_poll(self, fds, nfds, timeout, *a):
        """poll(fds, nfds, timeout): the same event bits as the host's"""
        entries = []
        for i in range(nfds):
            fd, ev, rev = struct.unpack('>ihh', self.rd(fds + 8 * i, 8))
            entries.append((fd if fd >= 0 else -1, ev & 0xFF))
        try:
            res = self.poll_streams(entries, timeout if timeout >= 0 else -1)
        except OSError as e:
            raise host_err(e)
        n = 0
        for i, rev in enumerate(res):
            if rev:
                n += 1
            self.wr(fds + 8 * i + 6, struct.pack('>H', rev & 0xFFFF))
        return n

    def sys_pathconf(self, path, name, *a):
        """pathconf(path, name): fixed limits (NAME_MAX 255, PATH_MAX 1023, PIPE_BUF 8192 ...)"""
        return self.pathconf(name)

    def sys_fpathconf(self, fd, name, *a):
        """fpathconf(fd, name): the same limits"""
        return self.pathconf(name)

    def pathconf(self, name):
        # sys/unistd.h: _PC_LINK_MAX 0 ... _PC_VDISABLE 8, then SYNC_IO 100, ASYNC_IO 101, PRIO_IO 102,
        # FILESIZEBITS 103 (cp asks for the last one to decide whether a large file fits)
        table = {C.get('_PC_LINK_MAX', 0): 32767, C.get('_PC_MAX_CANON', 1): 256, C.get('_PC_MAX_INPUT', 2): 512,
                 C.get('_PC_NAME_MAX', 3): 255, C.get('_PC_PATH_MAX', 4): 1023, C.get('_PC_PIPE_BUF', 5): 8192,
                 C.get('_PC_CHOWN_RESTRICTED', 6): 1, C.get('_PC_NO_TRUNC', 7): 1, C.get('_PC_VDISABLE', 8): 255,
                 C.get('_PC_SYNC_IO', 100): 1, C.get('_PC_ASYNC_IO', 101): 0, C.get('_PC_PRIO_IO', 102): 0,
                 C.get('_PC_FILESIZEBITS', 103): 32}
        if name in table:
            return table[name]
        raise HpuxError(EINVAL)

    def sys_statfs(self, path, buf, *a):
        """statfs(path, buf): the host file system's figures in struct statfs"""
        st = os.statvfs(self.hostpath(self.rdstr(path)))
        self.wr(buf, pack('statfs', {'f_type': 0, 'f_bsize': st.f_bsize, 'f_blocks': st.f_blocks, 'f_bfree': st.f_bfree,
                                     'f_bavail': st.f_bavail, 'f_files': st.f_files, 'f_ffree': st.f_ffree}))
        return 0

    def sys_fstatfs(self, fd, buf, *a):
        """fstatfs(fd, buf)"""
        self.fd_check(fd)
        st = os.fstatvfs(fd)
        self.wr(buf, pack('statfs', {'f_type': 0, 'f_bsize': st.f_bsize, 'f_blocks': st.f_blocks, 'f_bfree': st.f_bfree,
                                     'f_bavail': st.f_bavail, 'f_files': st.f_files, 'f_ffree': st.f_ffree}))
        return 0

    def statvfs_out(self, buf, st, sname='statvfs'):
        """struct statvfs (or statvfs64: 64-bit counts) from a host statvfs, basetype hfs"""
        self.wr(buf, pack(sname, {'f_bsize': st.f_bsize, 'f_frsize': st.f_frsize, 'f_blocks': st.f_blocks, 'f_bfree': st.f_bfree,
                                  'f_bavail': st.f_bavail, 'f_files': st.f_files, 'f_ffree': st.f_ffree, 'f_favail': st.f_favail,
                                  'f_basetype': b'hfs', 'f_namemax': 255}))
        return 0

    def sys_statvfs(self, path, buf, *a):
        """statvfs(path, buf): struct statvfs, basetype hfs"""
        return self.statvfs_out(buf, os.statvfs(self.hostpath(self.rdstr(path))))

    def sys_fstatvfs(self, fd, buf, *a):
        """fstatvfs(fd, buf)"""
        self.fd_check(fd)
        return self.statvfs_out(buf, os.fstatvfs(fd))

    def sys_statvfs64(self, path, buf, *a):
        """statvfs64(path, buf) (11.00): struct statvfs64"""
        return self.statvfs_out(buf, os.statvfs(self.hostpath(self.rdstr(path))), 'statvfs64')

    def sys_fstatvfs64(self, fd, buf, *a):
        """fstatvfs64(fd, buf) (11.00)"""
        self.fd_check(fd)
        return self.statvfs_out(buf, os.fstatvfs(fd), 'statvfs64')

    # ---- memory ----
    # ---- memory semaphores (msem_init/msem_lock/msem_unlock/msem_remove) ----
    # struct msemaphore (sys/mman.h): msem_lock, magic, locker, wanted - 16-byte aligned,
    # in memory shared by the processes that use it. libc's msem_lock calls mcas_util()
    # on the gateway page (r26 = the semaphore: 0 got it, 1 no lock id yet, 2 page
    # fault, 3 busy, 4 misaligned) and on "busy" the msleep system call, which waits for
    # the lock; msem_unlock clears `locker` itself and calls mwakeup when `wanted` is
    # set. Every test-and-set happens under a host file lock: the processes are host
    # processes sharing the memory.
    MSEM_MAGIC = 0x6d73656d

    def msem_hostlock(self):
        import fcntl
        if getattr(self, '_msem_fd', None) is None:
            d = os.path.join(self.root, 'var/run/hpuxemu')
            os.makedirs(d, exist_ok=True)
            self._msem_fd = os.open(os.path.join(d, '.msem.lock'), os.O_RDWR | os.O_CREAT, 0o600)
        return self._msem_fd

    def msem_try(self, sem, set_wanted):
        """Take the semaphore if it is free; 0 taken, 3 busy, 2 not accessible"""
        import fcntl
        fd = self.msem_hostlock()
        fcntl.lockf(fd, fcntl.LOCK_EX)
        try:
            locker = self.mem.read32(sem + 8)
            if locker == 0:
                self.mem.write32(sem + 8, self.pid)
                return 0
            if set_wanted:
                self.mem.write32(sem + 12, 1)
            return 3
        except MemFault:
            return 2
        finally:
            fcntl.lockf(fd, fcntl.LOCK_UN)

    def mcas_util(self):
        """The gateway page's mcas_util(sem): libc's msem_lock fast path"""
        cpu = self.cpu
        sem = cpu.gr[26] & M32
        if sem & 15:
            r = 4
        elif not getattr(self, 'msem_lockid', False):
            r = 1
        else:
            r = self.msem_try(sem, False)
        if self.trace:
            sys.stderr.write('[%d] mcas_util(%#x) = %d\n' % (self.pid, sem, r))
        cpu.gr[28] = r
        cpu.set_pc(cpu.gr[31])

    def sys_msem_init(self, sem, value, *a):
        """msem_init(sem, initial): a semaphore in shared memory, unlocked or locked by this process"""
        if sem & 15:
            raise HpuxError(EINVAL)
        try:
            self.mem.write32(sem, 0)
            self.mem.write32(sem + 4, self.MSEM_MAGIC)
            self.mem.write32(sem + 8, self.pid if value == 1 else 0)
            self.mem.write32(sem + 12, 0)
        except MemFault:
            raise HpuxError(EFAULT)
        return 0

    def sys_msem_remove(self, sem, *a):
        """msem_remove(sem): the semaphore is no longer valid"""
        try:
            if self.mem.read32(sem + 4) != self.MSEM_MAGIC:
                raise HpuxError(EINVAL)
            self.mem.write32(sem + 4, 0)
            self.mem.write32(sem + 8, 0)
        except MemFault:
            raise HpuxError(EFAULT)
        return 0

    def sys_msleep(self, sem, cond, *a):
        """msleep(sem, cond): wait until the semaphore is free and take it (EAGAIN at once with MSEM_IF_NOWAIT); a signal interrupts the wait"""
        while True:
            r = self.msem_try(sem, True)
            if r == 0:
                return 0
            if r == 2:
                raise HpuxError(EFAULT)
            if cond & 1:
                raise HpuxError(C['EAGAIN'])
            host_poll([], 5)

    def sys_mwakeup(self, sem, *a):
        """mwakeup(sem): waiters poll for the lock, so nothing to wake; `wanted` is cleared"""
        try:
            self.mem.write32(sem + 12, 0)
        except MemFault:
            raise HpuxError(EFAULT)
        return 0

    def sys_mmap(self, addr, length, prot, flags, fd, off, *a):
        """mmap(addr, len, prot, flags, fd, off): MAP_FIXED honoured; otherwise private
        mappings are placed below PRIVATE_MMAP_TOP (downwards), shared ones from
        SHARED_MMAP_BASE (upwards) and shared executable ones - library text - from
        SHLIB_TEXT_BASE, as HP-UX's quadrants have them"""
        return self.do_mmap(addr, length, prot, flags, fd, off)

    def sys_mmap64(self, addr, length, prot, flags, fd, off_hi, off_lo, *a):
        """mmap64(addr, len, prot, flags, fd, offset): mmap with a 64-bit offset (two words)"""
        return self.do_mmap(addr, length, prot, flags, fd, (off_hi << 32) | off_lo)

    def do_mmap(self, addr, length, prot, flags, fd, off):
        if length == 0:
            raise HpuxError(EINVAL)
        size = (length + PAGE - 1) & ~(PAGE - 1)
        anon = bool(flags & C['MAP_ANONYMOUS'])
        if flags & C['MAP_FIXED']:
            if addr & (PAGE - 1):
                raise HpuxError(EINVAL)
            base = addr
        elif (flags & C['MAP_SHARED']) or ((flags & C['MAP_SHLIB']) and not (flags & C['MAP_PRIVATE'])):
            # a private MAP_SHLIB mapping (a library's bss, from 11.00's dld.sl) is private
            # memory, placed downwards like the rest: dld then maps the library's data
            # MAP_FIXED right below it, where a downward allocator has left room
            if prot & C['PROT_EXEC']:
                # shared-library text (and dld.sl's) in the fourth quadrant, above the
                # gateway page, as HP-UX places it: HP's JVM JIT tells a shared
                # library's code from the program's by its address, and calls a
                # library's helpers without setting r19 when they look like the latter
                base = self.find_free(size, SHLIB_TEXT_BASE, SHLIB_TEXT_END, upward=True)
            else:
                base = self.find_free(size, SHARED_MMAP_BASE, SHARED_MMAP_END, upward=True)
        else:
            base = self.find_free(size, 0x50000000, PRIVATE_MMAP_TOP, upward=False)
        if (prot & 7) == 0:
            mprot = 0
        else:
            mprot = (1 if prot & C['PROT_READ'] else 0) | (2 if prot & C['PROT_WRITE'] else 0) | (4 if prot & C['PROT_EXEC'] else 0)
        hostbase = self.mem.host_base() if hasattr(self.mem, 'host_base') else None
        if (self.release.startswith('B.11') and not anon and (flags & C['MAP_SHARED']) and
                (prot & C['PROT_EXEC']) and not (prot & C['PROT_WRITE'])):
            # PA-RISC HP-UX maps a file range MAP_SHARED at one global address, and a
            # shared executable mapping is the file's execution: a second one of a range
            # this process already has fails. 11.00's dld.sl counts on that - it maps a
            # library's text, and when the mmap fails it looks for the library among those
            # loaded (find_duplicateload) and uses that one; without the failure it loads
            # libc and libdld again for every library that names them.
            try:
                st = os.fstat(fd)
            except OSError as e:
                raise host_err(e)
            key = (st.st_dev, st.st_ino)
            for m in self.mappings:
                if len(m) > 6 and m[6] and m[6][0] == key and off < m[6][1] + m[6][2] and m[6][1] < off + size:
                    raise HpuxError(ENOMEM)
            r = self.do_mmap_inner(addr, length, prot, flags, fd, off, base, size, anon, mprot, hostbase)
            for i in range(len(self.mappings) - 1, -1, -1):
                if self.mappings[i][0] == r:
                    self.mappings[i] = tuple(self.mappings[i][:6]) + ((key, off, size),)
                    break
            self.install_natives(fd, r, off, size, prot, anon)
            return r
        r = self.do_mmap_inner(addr, length, prot, flags, fd, off, base, size, anon, mprot, hostbase)
        self.install_natives(fd, r, off, size, prot, anon)
        return r

    def install_natives(self, fd, base, off, size, prot, anon):
        """dld.sl's or libc's text mapped executable: the Rust CPU runs the routines of
        it that it knows natively from now on (native.py has which, and why it is safe). Every
        executable file mapping is noted for HPUXEMU_STATS's PC samples."""
        if anon or not (prot & C['PROT_EXEC']):
            return
        try:
            hp = os.readlink('/proc/self/fd/%d' % fd)
        except OSError:
            return
        if self.stats is not None:
            self.stats.setdefault('maps', []).append((base, size, hp, off))
        if not hasattr(self.cpu, 'set_natives'):
            return
        if not os.path.basename(hp).startswith(native.LIBRARIES):
            return
        found = native.natives_for(hp, base, off, size)
        if found:
            cur = [e for e in getattr(self.cpu, 'native_list', []) if not (base <= e[0] < base + size)]
            self.cpu.native_list = cur + found
            self.cpu.set_natives(self.cpu.native_list)

    def do_mmap_inner(self, addr, length, prot, flags, fd, off, base, size, anon, mprot, hostbase):
        if not anon and hostbase is not None and (flags & C['MAP_SHARED']) and not (flags & C['MAP_PRIVATE']):
            return self.mmap_shared_file(base, size, mprot, flags, prot, fd, off, hostbase)
        if anon and hostbase is not None and (flags & C['MAP_SHARED']) and not (flags & C['MAP_PRIVATE']):
            # shared anonymous memory stays shared with the children a fork makes (memory
            # semaphores and counters between an application's processes): a host MAP_SHARED
            # mapping, which fork does not copy
            self.mem.unmap(base, size)
            r = _libc.mmap(hostbase + base, size, 3, 0x01 | 0x10 | 0x20, -1, 0)   # MAP_SHARED|MAP_FIXED|MAP_ANONYMOUS
            if r is None or r == ctypes.c_void_p(-1).value:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), ENOMEM))
            self.mem.mark(base, size, mprot)
            self.mappings.append((base, size, None, 0, flags, prot))
            self.cpu.flush_decode(base, size)
            return base
        if flags & C['MAP_FIXED']:
            # a fixed mapping replaces what is there: dld.sl maps a library's text and
            # data as one shared range, then its data privately over the end of it (the
            # host's shared file pages must go first; they may be read-only)
            self.mem.unmap(base, size)
        self.mem.map(base, size, mprot | 2)
        if not anon:
            self.fd_check(fd)
            try:
                cur = os.lseek(fd, 0, os.SEEK_CUR)
                os.lseek(fd, off, os.SEEK_SET)
                data = os.read(fd, length)
                os.lseek(fd, cur, os.SEEK_SET)
            except OSError as e:
                raise host_err(e)
            self.mem.write(base, data)
            # a writable shared file mapping is written back at munmap and exit
            path = self.fds[fd]['path'] if (flags & C['MAP_SHARED']) and (prot & C['PROT_WRITE']) else None
            self.mappings.append((base, size, path, off, flags, prot))
        else:
            self.mappings.append((base, size, None, 0, flags, prot))
        self.mem.protect(base, size, mprot)
        self.cpu.flush_decode(base, size)
        return base

    def mmap_shared_file(self, base, size, mprot, flags, prot, fd, off, hostbase):
        """A MAP_SHARED file mapping on the Rust CPU: the host file itself is mapped at the
        guest address in the CPU's reservation, so every process mapping the file sees the
        others' writes at once, as on HP-UX. A database's clients see the pages
        its cache manager puts into a shared cache file this way; a copy made at mmap time
        (what the emulator did, and still does on the Python CPU) left them reading empty
        pages. Pages beyond the end of the file stay ordinary zeroed memory: touching
        them must not raise a host SIGBUS in the emulator."""
        self.fd_check(fd)
        if off & (PAGE - 1):
            raise HpuxError(EINVAL)
        try:
            st = os.fstat(fd)
            fl = hfcntl.fcntl(fd, hfcntl.F_GETFL)
        except OSError as e:
            raise host_err(e)
        writable = (fl & os.O_ACCMODE) == os.O_RDWR
        if (prot & C['PROT_WRITE']) and not writable:
            raise HpuxError(C['EACCES'])
        filelen = max(0, ((st.st_size - off) + PAGE - 1) & ~(PAGE - 1))
        shared = min(size, filelen)
        self.mem.unmap(base, size)
        self.mem.map(base, size, mprot | 2)
        if shared:
            r = _libc.mmap(hostbase + base, shared, 3 if writable else 1, 0x01 | 0x10, fd, off)   # MAP_SHARED | MAP_FIXED
            if r is None or r == ctypes.c_void_p(-1).value:
                self.mem.unmap(base, size)
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), ENOMEM))
        self.mem.mark(base, size, mprot)
        self.mappings.append((base, size, None, off, flags, prot))
        self.cpu.flush_decode(base, size)
        return base

    def find_free(self, size, lo, hi, upward):
        """A free range of `size` bytes between lo and hi: the lowest one from lo upwards,
        or the highest one below hi. Fixed mappings anywhere are respected: dld.sl maps a
        library's data right below the anonymous region it got for the bss."""
        if hasattr(self.mem, 'find_free'):
            # the Rust CPU searches its page flags itself (a ctypes call per page cost
            # milliseconds per mmap once hundreds of libraries are mapped)
            r = self.mem.find_free(size, lo, hi, upward)
            if r is not NotImplemented:
                if r is None:
                    raise HpuxError(ENOMEM)
                return r
        mapped = self.mem.is_mapped
        n = size // PAGE
        if upward:
            a = lo
            while a + size <= hi:
                for k in range(n):
                    if mapped(a + k * PAGE):
                        a = a + (k + 1) * PAGE
                        break
                else:
                    return a
            raise HpuxError(ENOMEM)
        a = hi - size
        while a >= lo:
            for k in range(n - 1, -1, -1):
                if mapped(a + k * PAGE):
                    a = a + k * PAGE - size
                    break
            else:
                return a
        raise HpuxError(ENOMEM)

    def sys_munmap(self, addr, length, *a):
        """munmap(addr, len): the pages are released; a writable MAP_SHARED file mapping is
        written back to the file first"""
        size = (length + PAGE - 1) & ~(PAGE - 1)
        keep = []
        for m in self.mappings:
            base, msize, path, off, flags, prot = m[:6]
            if base < addr + size and addr < base + msize:
                if path:
                    self.writeback(m)
            else:
                keep.append(m)
        self.mappings = keep
        nl = getattr(self.cpu, 'native_list', None)
        if nl and any(addr <= e[0] < addr + size for e in nl):
            self.cpu.native_list = [e for e in nl if not (addr <= e[0] < addr + size)]
            self.cpu.set_natives(self.cpu.native_list)
        self.mem.unmap(addr, size)
        self.cpu.flush_decode(addr, size)
        return 0

    def writeback(self, m):
        base, size, path, off, flags, prot = m[:6]
        try:
            data = self.mem.read(base, size)
            hp = self.hostpath(path, search=False)
            with open(hp, 'r+b') as f:
                f.seek(0, 2)
                end = f.tell()
                f.seek(off)
                f.write(data[:max(0, min(len(data), end - off))])
        except (OSError, MemFault, HpuxError):
            pass

    def writeback_all(self):
        for m in self.mappings:
            if m[2]:
                self.writeback(m)

    def sys_mprotect(self, addr, length, prot, *a):
        """mprotect(addr, len, prot): the page protection the CPU checks"""
        mprot = (1 if prot & C['PROT_READ'] else 0) | (2 if prot & C['PROT_WRITE'] else 0) | (4 if prot & C['PROT_EXEC'] else 0)
        self.mem.protect(addr, length, mprot)
        return 0

    def sys_madvise(self, *a):
        """madvise(addr, len, advice): accepted and ignored"""
        return 0

    def sys_msync(self, *a):
        """msync(addr, len, flags): nothing to do (file mappings are copies, written back at munmap/exit only for MAP_SHARED)"""
        return 0

    # ---- signals ----
    # Delivery (docs/ABI.md "Signals"): the kernel pushes a struct sigcontext on the stack
    # (the stack grows up, so above sp), whose last 48 bytes are the handler's argument
    # spill area and frame marker, calls handler(sig, code, scp) with rp = the return
    # routine libc registered with sigsetreturn (libc's _sigreturn, which makes the
    # sigcleanup system call), and sigcleanup restores the context found through the
    # frame marker's previous-sp word at sp-4.
    SC_MASK_OFF = OFFSET['siglocalx']['sl_uc'][0] + OFFSET['__ucontext']['uc_subcontext'][0] + OFFSET['__sub_ctxt']['__uc_sigmask'][0]
    SS_OFF = OFFSET['siglocal']['sl_ss'][0]
    NARROW_OFF = SS_OFF + OFFSET['__save_state']['ss_narrow'][0]
    FP_OFF = SS_OFF + OFFSET['__save_state']['ss_fpblock'][0]
    XOR_OFF = SS_OFF + OFFSET['__save_state']['ss_xor'][0]
    SC_MAGIC = b'hpuxemu sigctx 1'

    def sys_sigaction(self, sig, act, oact, *a):
        """sigaction(sig, act, oact): install a handler (sa_handler, sa_mask[8], sa_flags)"""
        if sig < 1 or sig >= 64:
            raise HpuxError(EINVAL)
        old = self.sigactions.get(sig, (0, b'\0' * 32, 0))
        if oact:
            self.wr(oact, pack('sigaction', {'sa_handler': old[0], 'sa_mask': old[1], 'sa_flags': old[2]}))
        if act:
            if sig in (C['SIGKILL'], C['SIGSTOP']):
                raise HpuxError(EINVAL)
            d = self.rd(act, SIZEOF['sigaction'])
            handler = struct.unpack('>I', d[0:4])[0]
            mask = d[4:36]
            flags = struct.unpack('>I', d[36:40])[0]
            if self.trace:
                sys.stderr.write('[%d]    sigaction: handler %#x flags %#x\n' % (self.pid, handler, flags))
            self.sigactions[sig] = (handler, mask, flags)
            self.install_host_handler(sig, handler)
        return 0

    def sys_sigvector(self, sig, vec, ovec, *a):
        """sigvector(sig, vec, ovec): the BSD-style call; sv_mask is one word, SV_RESETHAND
        and SV_ONSTACK map to the sigaction flags, the call is not restarted"""
        if sig < 1 or sig >= 64:
            raise HpuxError(EINVAL)
        old = self.sigactions.get(sig, (0, b'\0' * 32, 0))
        if ovec:
            self.wr(ovec, struct.pack('>III', old[0], struct.unpack('>I', old[1][:4])[0], old[2] & 0xFF))
        if vec:
            if sig in (C['SIGKILL'], C['SIGSTOP']):
                raise HpuxError(EINVAL)
            handler, mask, flags = struct.unpack('>III', self.rd(vec, 12))
            if self.trace:
                sys.stderr.write('[%d]    sigvector: handler %#x mask %#x flags %#x\n' % (self.pid, handler, mask, flags))
            self.sigactions[sig] = (handler, struct.pack('>I', mask) + b'\0' * 28, flags & 0xFF)
            self.install_host_handler(sig, handler)
        return 0

    def install_host_handler(self, sig, handler):
        h = GUEST2HOST_SIG.get(sig)
        if h is None or h in (hsignal.SIGKILL, hsignal.SIGSTOP):
            return
        try:
            if handler == 1 or (handler == 0 and h == hsignal.SIGIO):
                # SIGPOLL's default ignores it; the host's default for SIGIO would end
                # the process when a stream's connection signals. (Not for SIGCHLD,
                # whose SIG_IGN on the host would reap the children: wait gets ECHILD.)
                hsignal.signal(h, hsignal.SIG_IGN)
            elif handler == 0 and not (self.lwps and len(self.lwps) > 1):
                hsignal.signal(h, hsignal.SIG_DFL)
            else:
                # (with several threads a default action is taken by deliver_signals too:
                # the thread that gets the signal is the emulator's choice, and a thread
                # blocking it - one waiting in sigwait - must not see the host act first)
                hsignal.signal(h, self.host_signal)
        except (OSError, ValueError):
            pass

    def host_signal(self, signum, frame):
        """the host handler: only records the signal; delivery happens in the run loop"""
        if signum == hsignal.SIGCHLD and not chld_is_news():
            return
        g = HOST2GUEST_SIG.get(signum)
        if g:
            self.pending.add(g)

    def poll_signals(self):
        """Entering a Python function runs the host handlers of signals that arrived
        during a C call, so after this returns `pending` is current."""
        return self.pending

    def deliver_before_call(self):
        """A deliverable signal pending as a blocking call begins: its handler runs
        first and the call is made again after it (the frame returns to the gateway with
        r22 and the arguments as they are now). False when no handler frame was pushed
        (a default action that did not end the process): the call goes ahead."""
        if not any(self.deliverable(sig) for sig in self.pending):
            return False
        cpu = self.cpu
        before = (cpu.iaoq_f, cpu.iaoq_b)
        self.deliver_signals(restartable=True, force_restart=True)
        return self.exited is not None or (cpu.iaoq_f, cpu.iaoq_b) != before

    def deliver_signals(self, restartable=False, force_restart=False):
        """Deliver the pending signals the mask allows, one frame each (a handler runs
        with its signal and sa_mask blocked, and the next deliverable signal is handled
        when it returns). `restartable`: the CPU is at a syscall return with EINTR."""
        for sig in sorted(self.pending):
            if self.sigmask & sigbit(sig) and sig not in (C['SIGKILL'], C['SIGSTOP']):
                continue
            self.pending.discard(sig)
            handler, mask, flags = self.sigactions.get(sig, (0, b'\0' * 32, 0))
            if handler == 1 or (handler == 0 and sig in SIG_DEFAULT_IGNORE):
                continue
            if handler == 0:
                # the default action: stop or die with the signal
                if sig in SIG_STOPS:
                    h = GUEST2HOST_SIG.get(sig, hsignal.SIGSTOP)
                    hsignal.signal(h, hsignal.SIG_DFL)
                    os.kill(self.pid, h)
                    continue
                self.exited = ('signal', sig)
                return
            restart = (bool(flags & C['SA_RESTART']) and restartable) or force_restart
            fault = self.fault_info.pop(sig, None)
            try:
                self.push_signal_frame(sig, fault['trap'] if fault else 0, handler, restart, fault,
                                       bool(flags & C['SA_SIGINFO']))
            except HpuxError:
                # no room for the frame (the stack pointer is wild): the process dies
                # with the signal, as HP-UX kills it when the frame cannot be written
                cpu = self.cpu
                sys.stderr.write('hpuxemu: %s: cannot deliver %s: no stack for its frame (sp %#x)\n' % (
                    self.argv0, SIGNAL_NAMES.get(sig, sig), cpu.gr[30] & M32))
                sys.stderr.write('  ' + ' '.join('r%d=%08x' % (i, cpu.gr[i] & M32) for i in range(1, 32)) + '\n')
                sys.stderr.write('  pc=%08x npc=%08x\n' % (cpu.iaoq_f, cpu.iaoq_b))
                self.exited = ('signal', sig)
                return
            if flags & C['SA_RESETHAND']:
                self.sigactions[sig] = (0, b'\0' * 32, 0)
                self.install_host_handler(sig, 0)
            if not flags & C['SA_NODEFER']:
                self.sigmask |= sigbit(sig)
            self.sigmask |= int.from_bytes(mask, 'big')
            return

    def push_signal_frame(self, sig, code, handler, restart, fault=None, siginfo=False):
        """Build the signal frame and call handler(sig, code, scp). For a CPU fault, code
        is HP-UX's trap number and the saved interruption registers say what faulted:
        iir (cr19) the instruction, isr (cr20) the space, ior (cr21) the address - what a
        program that pages its own memory reads to decide whether the
        fault is one of its own. An SA_SIGINFO handler gets a siginfo_t (si_code
        SEGV_MAPERR/SEGV_ACCERR, si_addr the address) in place of code."""
        cpu = self.cpu
        sp = cpu.gr[30] & M32
        size = SIZEOF['sigcontext']
        if siginfo:
            # the siginfo_t first, then the frame above it (the stack grows up, and
            # the frame marker must end just below the handler's sp)
            si = OFFSET['siginfo_t']
            info = bytearray(SIZEOF['siginfo_t'])
            info[0:4] = struct.pack('>I', sig)
            if fault:
                if sig == C['SIGSEGV']:
                    sc = 109 if fault['mapped'] else 108      # SEGV_ACCERR / SEGV_MAPERR
                else:
                    sc = 111                                  # BUS_ADRERR
                info[si['si_code'][0]:si['si_code'][0] + 4] = struct.pack('>I', sc)
                info[si['si_addr'][0]:si['si_addr'][0] + 4] = struct.pack('>I', fault['addr'])
            elif sig in self.sigvalues:
                # sigqueue's: SI_QUEUE and the value
                info[si['si_code'][0]:si['si_code'][0] + 4] = struct.pack('>i', -2)
                info[si['si_value'][0]:si['si_value'][0] + 4] = struct.pack('>I', self.sigvalues.pop(sig) & M32)
            else:
                info[si['si_code'][0]:si['si_code'][0] + 4] = struct.pack('>i', -1)     # SI_USER
            sip = (sp + 7) & ~7
            sp = sip + len(info)
        newsp = (sp + size + 63) & ~63
        scp = newsp - size
        if not self.mem.is_mapped(newsp - 1):
            self.fatal('no room for a signal frame at %#x' % sp, C['SIGSEGV'])
            return
        f = bytearray(size)

        def w32(off, v):
            f[off:off + 4] = struct.pack('>I', v & M32)

        # siglocal_misc
        sm = OFFSET['siglocal_misc']
        if restart:
            w32(sm['sm_syscall'][0], cpu.gr[22] & M32)
            f[sm['sm_syscall_action'][0]] = C['SIG_RESTART']
        else:
            f[sm['sm_syscall_action'][0]] = C['SIG_RETURN']
        w32(sm['sm_omask'][0], self.sigmask >> (256 - 32))
        w32(sm['sm_rval1'][0], cpu.gr[28])
        w32(sm['sm_rval2'][0], cpu.gr[29])
        # save_state: flags, the narrow registers, the FP registers
        w32(self.SS_OFF, C['SS_INSYSCALL'] if restart else 0)
        nr = OFFSET['__ss_narrow']
        base = self.NARROW_OFF
        names = ['ss_gr1', 'ss_rp'] + ['ss_gr%d' % i for i in range(3, 23)] + ['ss_arg3', 'ss_arg2', 'ss_arg1', 'ss_arg0', 'ss_dp', 'ss_ret0', 'ss_ret1', 'ss_sp', 'ss_gr31']
        for i, n in enumerate(names):
            w32(base + nr[n][0], cpu.gr[i + 1])
        w32(base + nr['ss_cr11'][0], cpu.sar)
        if restart:
            # back to the gateway with r22 and the arguments intact: the call is remade
            w32(base + nr['ss_pcoq_head'][0], GATEWAY + 4)
            w32(base + nr['ss_pcoq_tail'][0], GATEWAY + 8)
        else:
            w32(base + nr['ss_pcoq_head'][0], cpu.iaoq_f)
            w32(base + nr['ss_pcoq_tail'][0], cpu.iaoq_b)
        w32(base + nr['ss_cr22'][0], self.ipsw())
        if fault:
            try:
                iir = struct.unpack('>I', self.mem.read(fault['pc'] & ~3, 4))[0]
            except MemFault:
                iir = 0
            w32(base + nr['ss_cr19'][0], iir)
            w32(base + nr['ss_cr20'][0], 0)
            w32(base + nr['ss_cr21'][0], fault['addr'])
        w32(base + nr['ss_sr7'][0], 0)
        for i in range(32):
            f[self.FP_OFF + 8 * i:self.FP_OFF + 8 * i + 8] = struct.pack('>Q', cpu.fr[i] & 0xFFFFFFFFFFFFFFFF)
        # the CPU state the architected words do not hold, in the reserved area
        f[self.XOR_OFF:self.XOR_OFF + 16] = self.SC_MAGIC
        f[self.XOR_OFF + 16:self.XOR_OFF + 40] = struct.pack('>QQQ', cpu.psw_cb & 0xFFFFFFFFFFFFFFFF, cpu.psw_cb_msb & 1, cpu.psw_v & 0xFFFFFFFFFFFFFFFF)
        f[self.XOR_OFF + 40] = 1 if cpu.psw_n else 0
        # the old mask where sc_mask is (the ucontext view)
        f[self.SC_MASK_OFF:self.SC_MASK_OFF + 32] = self.sigmask.to_bytes(32, 'big')
        # the handler's arguments as spilled by a caller (arg3 lowest), the frame marker
        args_off = OFFSET['sigcontext']['sc_args'][0]
        w32(args_off + 12, sig)
        w32(args_off + 8, code)
        w32(args_off + 4, scp)
        fm = OFFSET['sigcontext']['sc_sfm'][0]
        w32(fm + OFFSET['frame_marker']['fm_psp'][0], scp)
        # a handler reached through an export stub returns via the frame marker's RP'
        # slot (-24(sp)) rather than r2: both hold the return routine
        w32(fm + OFFSET['frame_marker']['fm_erp'][0], self.sigreturn_addr)
        w32(fm + OFFSET['frame_marker']['fm_crp'][0], self.sigreturn_addr)
        self.wr(scp, bytes(f))
        if siginfo:
            self.wr(sip, bytes(info))
            w32(args_off + 8, sip)
            self.wr(scp, bytes(f))
            code = sip
        # call the handler
        target, gp = self.resolve_plabel(handler)
        cpu.gr[30] = newsp
        cpu.gr[26] = sig
        cpu.gr[25] = code
        cpu.gr[24] = scp
        cpu.gr[2] = self.sigreturn_addr
        if gp is not None:
            cpu.gr[19] = gp
        cpu.set_pc(target)
        if self.trace:
            sys.stderr.write('[%d] -- signal %s delivered: handler %#x frame %#x%s\n' % (self.pid, SIGNAL_NAMES.get(sig, sig), target, scp, ' (restart)' if restart else ''))

    def deliverable(self, sig):
        """a pending signal that deliver_signals would act on now"""
        if self.sigmask & sigbit(sig):
            return False
        handler = self.sigactions.get(sig, (0,))[0]
        return not (handler == 1 or (handler == 0 and sig in SIG_DEFAULT_IGNORE))

    def fix_frame_mask(self, mask):
        """After sigsuspend delivered a signal, the frame on the stack must restore the
        mask from before sigsuspend, not the temporary one."""
        cpu = self.cpu
        sp = cpu.gr[30] & M32
        try:
            scp = self.mem.read32(sp - 4)
            if self.rd(scp + self.XOR_OFF, 16) == self.SC_MAGIC:
                self.wr(scp + self.SC_MASK_OFF, mask.to_bytes(32, 'big'))
                return
        except (MemFault, HpuxError):
            pass
        self.sigmask = mask

    def resolve_plabel(self, addr):
        """A function pointer in a dynamically linked program is a plabel (bit 1 set):
        the address of {entry, gp}; a plain address otherwise."""
        if addr & 2:
            try:
                return self.mem.read32(addr & ~3), self.mem.read32((addr & ~3) + 4)
            except MemFault:
                pass
        return addr & ~3, None

    def ipsw(self):
        """The PSW as a program sees it: the carry/borrow bits 8..15 from psw_cb"""
        cpu = self.cpu
        cb = cpu.psw_cb & M32
        bits = 0
        for i in range(8):
            # C/B bit i is the carry out of nibble i (nibble 0 the most significant)
            carry = (cpu.psw_cb_msb & 1) if i == 0 else (cb >> (32 - 4 * i)) & 1
            if carry:
                bits |= 1 << (7 - i)
        return 0x0004000F | (bits << 16)

    def sys_sigcleanup(self, scp, *a):
        """sigcleanup(scp): return from a handler; the context is the sigcontext the frame
        marker at sp-4 points to (the argument is the caller's r28, not to be trusted)"""
        cpu = self.cpu
        sp = cpu.gr[30] & M32
        try:
            ctx = self.mem.read32(sp - 4)
        except MemFault:
            ctx = scp
        size = SIZEOF['sigcontext']
        try:
            f = self.rd(ctx, size)
        except HpuxError:
            raise HpuxError(EFAULT)
        if f[self.XOR_OFF:self.XOR_OFF + 16] != self.SC_MAGIC:
            raise HpuxError(EINVAL)

        def r32(off):
            return struct.unpack('>I', f[off:off + 4])[0]

        nr = OFFSET['__ss_narrow']
        base = self.NARROW_OFF
        names = ['ss_gr1', 'ss_rp'] + ['ss_gr%d' % i for i in range(3, 23)] + ['ss_arg3', 'ss_arg2', 'ss_arg1', 'ss_arg0', 'ss_dp', 'ss_ret0', 'ss_ret1', 'ss_sp', 'ss_gr31']
        for i, n in enumerate(names):
            cpu.gr[i + 1] = r32(base + nr[n][0])
        cpu.sar = r32(base + nr['ss_cr11'][0])
        for i in range(32):
            cpu.fr[i] = struct.unpack('>Q', f[self.FP_OFF + 8 * i:self.FP_OFF + 8 * i + 8])[0]
        cb, cb_msb, v = struct.unpack('>QQQ', f[self.XOR_OFF + 16:self.XOR_OFF + 40])
        cpu.psw_cb = cb
        cpu.psw_cb_msb = cb_msb
        cpu.psw_v = v
        self.sigmask = int.from_bytes(f[self.SC_MASK_OFF:self.SC_MASK_OFF + 32], 'big')
        head, tail = r32(base + nr['ss_pcoq_head'][0]), r32(base + nr['ss_pcoq_tail'][0])
        cpu.iaoq_f = head | 3
        cpu.iaoq_b = tail | 3
        cpu.psw_n = f[self.XOR_OFF + 40] == 1 and not (head >= GATEWAY and head < GATEWAY + 0x1000)
        if self.trace:
            sys.stderr.write('[%d] -- sigcleanup: back at %#x\n' % (self.pid, head))
        raise _NoReturn()

    def sys_sigstack(self, ss, oss, *a):
        """sigstack(ss, oss): the alternate signal stack is recorded and reported back, never used - handlers run on the normal stack (portmap, rpc.* call it)"""
        if oss:
            self.wr(oss, struct.pack('>II', *self.sigstack_rec))
        if ss:
            self.sigstack_rec = struct.unpack('>II', self.rd(ss, 8))
        return 0

    def sys_sigaltstack(self, ss, oss, *a):
        """sigaltstack(ss, oss): as sigstack, with stack_t {ss_sp, ss_flags, ss_size}; SS_DISABLE reported when none was set"""
        if oss:
            sp, flags, size = self.sigaltstack_rec
            self.wr(oss, struct.pack('>III', sp, flags, size))
        if ss:
            self.sigaltstack_rec = struct.unpack('>III', self.rd(ss, 12))
        return 0

    sigstack_rec = (0, 0)
    sigaltstack_rec = (0, 2, 0)     # SS_DISABLE

    def sys_sigsetreturn(self, addr, magic, size, *a):
        """sigsetreturn(addr, magic, size): libc registers its _sigreturn routine (a plabel
        in dynamic programs) as where signal handlers return to; size is sizeof(sigcontext)"""
        target, gp = self.resolve_plabel(addr)
        self.sigreturn_addr = target
        return 0

    def sys_sigprocmask(self, how, set_, oset, *a):
        """sigprocmask(how, set, oset): the mask is a 256-bit sigset_t"""
        if oset:
            self.wr(oset, self.sigmask.to_bytes(32, 'big'))
        if set_:
            m = int.from_bytes(self.rd(set_, 32), 'big')
            if how == C['SIG_BLOCK']:
                self.sigmask |= m
            elif how == C['SIG_UNBLOCK']:
                self.sigmask &= ~m
            elif how == C['SIG_SETMASK']:
                self.sigmask = m
            else:
                raise HpuxError(EINVAL)
            self.sigmask &= ~(sigbit(C['SIGKILL']) | sigbit(C['SIGSTOP']))
        return 0

    def sys_siginhibit(self, arg, *a):
        """siginhibit(p) (11.00): dld.sl's cheap way to keep signals out of its critical
        sections; every maskable signal is held until the matching sigenable()"""
        self.inhibit.append(self.sigmask)
        self.sigmask = ((1 << 256) - 1) & ~(sigbit(C['SIGKILL']) | sigbit(C['SIGSTOP']))
        return 0

    def sys_sigenable(self, *a):
        """sigenable() (11.00): the mask from before the matching siginhibit() again"""
        if self.inhibit:
            self.sigmask = self.inhibit.pop()
        return 0

    def sys_set_userthreadid(self, *a):
        """set_userthreadid(...): DCE's user-level threads (libcma) tell the kernel which
        of their threads runs, for debuggers and accounting; nothing to keep here"""
        return 0

    def sys_lwp_setprivate(self, p, *a):
        """lwp_setprivate(p) (11.00): the thread pointer - control register 27, which
        thread-local storage (libc's errno, libXm ...) is addressed from (mfctl %cr27)"""
        self.cpu.cr[27] = p & M32
        return 0

    def sys_lwp_getprivate(self, *a):
        """lwp_getprivate(): the thread pointer (cr27)"""
        return self.cpu.cr[27] & M32

    def sys_sigsetstatemask(self, mask, *a):
        """sigsetstatemask(mask): used by siglongjmp; sets the first mask word, returns the old"""
        old = self.sigmask >> (256 - 32)
        self.sigmask = (self.sigmask & ((1 << (256 - 32)) - 1)) | ((mask & M32) << (256 - 32))
        return old

    def sys_sigpending(self, set_, *a):
        """sigpending(set): the signals received but blocked"""
        m = 0
        for sig in self.pending:
            m |= sigbit(sig)
        self.wr(set_, m.to_bytes(32, 'big'))
        return 0

    def sys_sigblock(self, mask, *a):
        """sigblock(mask): adds the one-word mask (signals 1-32) to the blocked set; returns the old word"""
        old = self.sigmask >> (256 - 32)
        self.sigmask |= (mask & M32) << (256 - 32)
        return old

    def sys_sigsetmask(self, mask, *a):
        """sigsetmask(mask): sets the first word of the blocked set; returns the old word"""
        old = self.sigmask >> (256 - 32)
        self.sigmask = (self.sigmask & ((1 << (256 - 32)) - 1)) | ((mask & M32) << (256 - 32))
        return old

    def sys_sigsuspend(self, set_, *a):
        """sigsuspend(set): wait with that mask for a signal; the mask is restored when the
        handler returns (it is in the frame); always EINTR"""
        m = int.from_bytes(self.rd(set_, 32), 'big')
        self.wait_for_signal(m)

    def sys_sigpause(self, mask, *a):
        """sigpause(mask): the one-word form of sigsuspend"""
        self.wait_for_signal((mask & M32) << (256 - 32))

    def wait_for_signal(self, mask):
        saved = self.sigmask
        self.sigmask = mask
        try:
            while not any(self.deliverable(s) for s in self.poll_signals()):
                try:
                    host_pause()
                except _Interrupted:
                    pass
        except KeyboardInterrupt:
            pass
        if not any(self.deliverable(s) for s in self.pending):
            self.sigmask = saved
            raise HpuxError(EINTR)
        # the frame built by deliver_signals holds the mask to restore; the EINTR return
        # is the context the handler returns to
        self.sigmask_after = saved
        raise _InterruptedWithMask(saved)

    def sys_sigtimedwait(self, set_, info, timeout, *a):
        """sigtimedwait(set, info, timeout): take one of the signals in set (they are
        blocked) when it is pending, without running a handler; returns its number and
        fills info. A deliverable signal outside the set interrupts (EINTR); the timeout
        (a timespec, none = forever) runs out with EAGAIN. 11.00's sh waits for its
        children this way."""
        wset = int.from_bytes(self.rd(set_, 32), 'big')
        deadline = None
        if timeout:
            sec, nsec = struct.unpack('>ii', self.rd(timeout, 8))
            deadline = time.time() + sec + nsec / 1e9
        while True:
            got = [g for g in sorted(self.poll_signals()) if wset & sigbit(g)]
            if got:
                g = got[0]
                self.pending.discard(g)
                if info:
                    self.wr(info, pack('siginfo_t', {'si_signo': g, 'si_code': C.get('SI_USER', 0)}))
                return g
            if any(self.deliverable(g) for g in self.pending):
                raise HpuxError(EINTR)
            if deadline is not None:
                left = deadline - time.time()
                if left <= 0:
                    raise HpuxError(C['EAGAIN'])
                try:
                    time.sleep(min(left, 0.02))
                except _Interrupted:
                    pass
                continue
            try:
                host_pause()
            except _Interrupted:
                pass

    def sys_sigwaitinfo(self, set_, info, *a):
        """sigwaitinfo(set, info): sigtimedwait without a timeout"""
        return self.sys_sigtimedwait(set_, info, 0)

    sigvalues = {}      # signal -> the value sigqueue sent with it (this process's own)

    def sys_sigqueue(self, pid, sig, value, *a):
        """sigqueue(pid, sig, value): kill with a value; the value reaches an SA_SIGINFO
        handler (si_value, si_code SI_QUEUE) when the process signals itself"""
        if pid & 0x80000000:
            pid -= 1 << 32
        if pid == self.pid and sig:
            self.sigvalues = dict(self.sigvalues)
            self.sigvalues[sig] = value
        return self.sys_kill(pid, sig)

    def sys_sigwait(self, set_, sigp, *a):
        """sigwait(set, &sig): take one of the signals in set, its number in *sig"""
        g = self.sys_sigtimedwait(set_, 0, 0)
        if sigp:
            self.wr(sigp, struct.pack('>i', g))
        return 0

    def sys_kill(self, pid, sig, *a):
        """kill(pid, sig): emulated processes are host processes with the same pids, so the
        host delivers it, through the handler the target installed"""
        if sig < 0 or sig >= 64:
            raise HpuxError(EINVAL)
        if self.euid != 0 and pid > 0 and pid != self.pid:
            # only one's own processes (the process table says whose they are)
            mine = {p[0] for p in self.proc_table() if p[4] in (self.uid, self.euid)}
            if pid not in mine and (sig != C['SIGCONT'] or os.getsid(pid) != os.getsid(0)):
                raise HpuxError(C['EPERM'])
        h = GUEST2HOST_SIG.get(sig, 0) if sig else 0
        if sig and not h:
            raise HpuxError(EINVAL)
        if pid & 0x80000000:
            pid -= 1 << 32
        try:
            os.kill(pid, h)
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_setitimer(self, which, val, oval, *a):
        """setitimer(which, value, ovalue): the host's timers (ITIMER_REAL/VIRTUAL/PROF)"""
        if which not in (0, 1, 2):
            raise HpuxError(EINVAL)
        sig = {0: 'SIGALRM', 1: 'SIGVTALRM', 2: 'SIGPROF'}[which]
        self.install_host_handler(C[sig], self.sigactions.get(C[sig], (0,))[0])
        if val:
            isec, iusec, vsec, vusec = struct.unpack('>IIII', self.rd(val, 16))
            old = hsignal.setitimer(which, vsec + vusec / 1e6, isec + iusec / 1e6)
        else:
            old = hsignal.getitimer(which)
        if oval:
            self.wr(oval, struct.pack('>IIII', int(old[1]), int(old[1] % 1 * 1e6), int(old[0]), int(old[0] % 1 * 1e6)))
        return 0

    def sys_getitimer(self, which, val, *a):
        """getitimer(which, value): the host timer"""
        if which not in (0, 1, 2):
            raise HpuxError(EINVAL)
        old = hsignal.getitimer(which)
        self.wr(val, struct.pack('>IIII', int(old[1]), int(old[1] % 1 * 1e6), int(old[0]), int(old[0] % 1 * 1e6)))
        return 0

    # ---- fork, exec, wait, process groups ----
    def sys_fork(self, *a):
        """fork(): a host fork; the child gets r28 = parent's pid, r29 = 1; the parent r28 =
        child's pid, r29 = 0 (crt0's libc stub turns this into the usual 0/pid)"""
        sys.stdout.flush()
        # the child starts with no pending signals, as on HP-UX: the host's are blocked
        # over the fork (a signal for the parent stays the parent's), and what the
        # parent had recorded but not yet delivered is not the child's
        old = _sigmask(hsignal.SIG_BLOCK, _CATCHABLE)
        try:
            pid = os.fork()
            if pid == 0:
                self.pending = set()
                self.fault_info = {}
        finally:
            _sigmask(hsignal.SIG_SETMASK, old)
        if pid == 0:
            self.pid = os.getpid()
            if self.stats:
                self.stats_begin('fork', self.stats['prog'])
            self.lwp_fork_child()
            self.publish()      # a daemon's parent exits and takes its own entry with it
            return (os.getppid(), 1)
        return (pid, 0)

    sys_vfork = sys_fork

    def sys_execve(self, path, argv, envp, *a):
        """execve(path, argv, envp): the new image replaces this one in the same host process; the set-user-id and set-group-id bits are honoured"""
        gp = self.rdstr(path)
        args = self.rdvec(argv)
        env = self.rdvec(envp) if envp else []
        return self.do_exec(gp, args, env)

    def do_exec(self, gp, args, env):
        hp = self.hostpath(gp)
        if not os.path.exists(hp):
            raise HpuxError(ENOENT)
        st = self.check(gp, 1)
        # the set-user-id and set-group-id bits: the effective and saved ids become the
        # file's owner's (su, passwd, crontab, lp ... depend on this)
        fuid, fgid = self.owner_of(self.guest_abspath(gp), st)
        if st.st_mode & 0o4000:
            self.euid = self.suid = fuid
        if st.st_mode & 0o2000:
            self.egid = self.sgid = fgid
        if self.trace:
            sys.stderr.write('[%d] exec %s uid %d/%d gid %d/%d\n' % (self.pid, gp, self.uid, self.euid, self.gid, self.egid))
        self.env = dict(kv.split('=', 1) for kv in env if '=' in kv)
        # close-on-exec
        import fcntl
        for fd in list(self.fds):
            try:
                if fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
                    os.close(fd)
                    del self.fds[fd]
            except OSError:
                del self.fds[fd]
        for sig in list(self.sigactions):
            h = GUEST2HOST_SIG.get(sig)
            if h and self.sigactions[sig][0] not in (0, 1):
                try:
                    hsignal.signal(h, hsignal.SIG_DFL)
                except (OSError, ValueError):
                    pass
        self.sigactions = {}
        self.pending = set()
        self.fault_info = {}      # signal -> details of the CPU fault that raised it
        self.sigreturn_addr = 0
        self.lwps = self.cur_lwp = None        # exec leaves one thread
        self.mappings = []
        self.priv_mmap = PRIVATE_MMAP_TOP
        self.shared_mmap = SHARED_MMAP_BASE
        self.trace_by_name(gp)
        self.stats_end('exec')
        self.stats_begin('exec', gp)
        t0 = time.perf_counter()
        self.load(gp, args, env)
        if self.stats:
            self.stats['load'] = time.perf_counter() - t0
        raise _Exec()

    def trace_by_name(self, gp):
        """HPUXEMU_TRACE=NAME[,NAME...] (host environment): a process that execs a program
        of that name traces its system calls into HPUXEMU_TRACE_DIR/NAME.PID (default
        /tmp) - one process deep inside a large application (one daemon among
        dozens), without tracing the rest"""
        names = os.environ.get('HPUXEMU_TRACE')
        if not names:
            return
        base = gp.rsplit('/', 1)[-1]
        if base in names.split(','):
            d = os.environ.get('HPUXEMU_TRACE_DIR', '/tmp')
            try:
                sys.stderr = open(os.path.join(d, '%s.%d' % (base, self.pid)), 'a', buffering=1)
                self.trace = True
            except OSError:
                pass

    def sys_execv(self, path, argv, *a):
        """execv(path, argv): execve with the current environment"""
        env = ['%s=%s' % kv for kv in self.env.items()]
        return self.do_exec(self.rdstr(path), self.rdvec(argv), env)

    def wait_status(self, status):
        """host wait status -> HP-UX (same encoding: exit<<8, signal in the low 7 bits,
        0x80 core, 0x7f = stopped) with the signal number translated"""
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status) << 8
        if os.WIFSIGNALED(status):
            return HOST2GUEST_SIG.get(os.WTERMSIG(status), os.WTERMSIG(status)) | (0x80 if os.WCOREDUMP(status) else 0)
        if os.WIFSTOPPED(status):
            return (HOST2GUEST_SIG.get(os.WSTOPSIG(status), os.WSTOPSIG(status)) << 8) | 0x7F
        return status

    def sys_waitpid(self, pid, statp, options, *a):
        """waitpid(pid, status, options): the host waitpid (WNOHANG, WUNTRACED); the status has the signal number translated"""
        hopt = 0
        if options & C['WNOHANG']:
            hopt |= os.WNOHANG
        if options & C['WUNTRACED']:
            hopt |= os.WUNTRACED
        while True:
            try:
                rpid, status = host_waitpid(pid - (1 << 32) if pid & 0x80000000 else pid, hopt)
                break
            except ChildProcessError:
                raise HpuxError(ECHILD)
            except OSError as e:
                raise host_err(e)
            except _Interrupted:
                # a child's state changed and SIGCHLD woke the host call: wait again -
                # HP-UX returns the child it changed to, the handler running after (Linux
                # also signals a child's SIGCONT, which HP-UX does not: waitpid saw EINTR
                # between a SIGCONT and the SIGTERM that followed it; chld_is_news drops
                # that SIGCHLD, leaving nothing pending). Any other signal interrupts.
                self.poll_signals()
                if not self.pending <= {C['SIGCHLD']}:
                    raise
        if rpid and statp:
            self.wr32(statp, self.wait_status(status))
        return rpid

    def sys_wait(self, statp, *a):
        """wait(status): waitpid(-1, status, 0)"""
        return self.sys_waitpid(0xFFFFFFFF, statp, 0)

    def sys_wait3(self, statp, options, rusage, *a):
        """wait3(status, options, rusage): waitpid(-1, status, options); rusage is not filled in"""
        return self.sys_waitpid(0xFFFFFFFF, statp, options)

    def sys_setpgrp2(self, pid, pgid, *a):
        """setpgrp2(pid, pgid): setpgid on the host"""
        try:
            os.setpgid(pid, pgid)
        except OSError as e:
            raise host_err(e)
        return 0

    sys_setpgid = sys_setpgrp2

    def sys_setpgrp(self, *a):
        """setpgrp(): a new process group of its own; returns it"""
        try:
            os.setpgid(0, 0)
        except OSError:
            pass
        return os.getpgrp()

    def sys_setpgrp3(self, flag, *a):
        """setpgrp3(flag): libc's setpgrp3() passes 1 (a new process group, as setpgrp) and setsid() passes 2 (a new session)"""
        if flag == 2:
            try:
                return os.setsid()
            except OSError as e:
                raise host_err(e)
        return self.sys_setpgrp()

    def sys_getgroups(self, n, buf, *a):
        """getgroups(n, list): the supplementary groups set with setgroups (initgroups at login)"""
        if n:
            if n < len(self.groups):
                raise HpuxError(EINVAL)
            self.wr(buf, b''.join(struct.pack('>I', g) for g in self.groups))
        return len(self.groups)

    def sys_setgroups(self, n, buf, *a):
        """setgroups(n, list): superuser only"""
        if self.euid != 0:
            raise HpuxError(C['EPERM'])
        if n > 20 or n < 0:
            raise HpuxError(EINVAL)
        self.groups = [struct.unpack('>I', self.rd(buf + 4 * i, 4))[0] for i in range(n)]
        return 0

    def sys_setresuid(self, ruid, euid, suid, *a):
        """setresuid(ruid, euid, suid): -1 leaves an id alone; a process whose real, effective OR saved uid is 0 sets any (setresuid(2): "if the current real, effective or saved user ID is equal to that of a user having appropriate privileges"), others only to one of their own three; lp, set-uid root, drops its euid to lp first and sets its gids after"""
        own = (self.uid, self.euid, self.suid)
        want = [own[i] if v & M32 == M32 else v for i, v in enumerate((ruid, euid, suid))]
        if 0 not in own and any(v not in own for v in want):
            raise HpuxError(C['EPERM'])
        self.uid, self.euid, self.suid = want
        return 0

    def sys_setresgid(self, rgid, egid, sgid, *a):
        """setresgid(rgid, egid, sgid): as setresuid, the privilege judged by the three uids"""
        own = (self.gid, self.egid, self.sgid)
        want = [own[i] if v & M32 == M32 else v for i, v in enumerate((rgid, egid, sgid))]
        if 0 not in (self.uid, self.euid, self.suid) and any(v not in own for v in want):
            raise HpuxError(C['EPERM'])
        self.gid, self.egid, self.sgid = want
        return 0

    def sys_setregid(self, *a):
        """setregid(rgid, egid): accepted and ignored"""
        return 0

    # ---- sockets ----
    # HP-UX's BSD sockets on the host's: the descriptors are host sockets, addresses are
    # translated between the HP-UX sockaddr (16-bit big-endian family) and the host's.
    # Unix-domain socket paths are inside the root, except /tmp/.X11-unix/* which is the
    # host's (an X server on the host is reachable that way).
    # the calls that say EWOULDBLOCK on a socket made non-blocking the BSD way
    BSD_NB_CALLS = ('accept', 'connect', 'recv', 'recvfrom', 'recvmsg', 'send', 'sendto', 'sendmsg')
    BSD_NB_IO = ('read', 'write', 'readv', 'writev')
    # the calls that return 0 for "would block" under O_NDELAY (read(2), write(2),
    # recv(2), send(2): "completes successfully, having read no data, and returns 0")
    NDELAY_ZERO = ('read', 'readv', 'write', 'writev', 'recv', 'recvfrom', 'recvmsg', 'send', 'sendto', 'sendmsg')

    def bsd_nb_call(self, name, fd):
        if name in self.BSD_NB_CALLS:
            return True
        if name in self.BSD_NB_IO:
            try:
                return hstat.S_ISSOCK(os.fstat(fd).st_mode)
            except OSError:
                return False
        return False

    def nb_set(self, fd, kind, on):
        """one way of non-blocking on or off for fd; the host descriptor is
        non-blocking while any of them is on"""
        import fcntl
        m = self.nbmode.setdefault(fd, set())
        (m.add if on else m.discard)(kind)
        if not m:
            del self.nbmode[fd]
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, (fl | os.O_NONBLOCK) if m else (fl & ~os.O_NONBLOCK))

    def nb_copy(self, fd, n):
        if fd in self.nbmode:
            self.nbmode[n] = set(self.nbmode[fd])
        else:
            self.nbmode.pop(n, None)

    def nb_result(self, name, fd, r):
        """EAGAIN of a call on a non-blocking descriptor, as HP-UX says it:
        (result, error flag)"""
        m = self.nbmode[fd]
        if 'nonblock' in m:
            return r, 1
        if 'ndelay' in m:
            if name in self.NDELAY_ZERO:
                return 0, 0
            if name == 'accept':
                return C['EWOULDBLOCK'], 1
            return r, 1
        if 'fio' in m and self.bsd_nb_call(name, fd):
            return C['EWOULDBLOCK'], 1
        return r, 1

    SOCK_LEVELS = {'SOL_SOCKET': 'SOL_SOCKET', 'IPPROTO_TCP': 'IPPROTO_TCP', 'IPPROTO_IP': 'IPPROTO_IP', 'IPPROTO_UDP': 'IPPROTO_UDP'}
    SOCK_OPTS = ('SO_REUSEADDR', 'SO_KEEPALIVE', 'SO_BROADCAST', 'SO_LINGER', 'SO_SNDBUF', 'SO_RCVBUF', 'SO_ERROR', 'SO_TYPE',
                 'SO_OOBINLINE', 'SO_DEBUG', 'SO_DONTROUTE', 'SO_REUSEPORT', 'SO_SNDLOWAT', 'SO_RCVLOWAT', 'SO_SNDTIMEO', 'SO_RCVTIMEO',
                 'TCP_NODELAY', 'TCP_MAXSEG', 'IP_TTL', 'IP_TOS', 'IP_OPTIONS', 'IP_HDRINCL')

    def sock_hostpath(self, gp):
        if gp.startswith('/tmp/.X11-unix/'):
            # the host's X servers; $HPUXEMU_CONSOLE=N puts the guest's display :0 (the
            # console, which some applications insist on) on the host's :N - an Xvnc or
            # Xephyr of its own on a server whose :0 is something else, or none
            con = os.environ.get('HPUXEMU_CONSOLE')
            if con and gp == '/tmp/.X11-unix/X0':
                return '/tmp/.X11-unix/X%s' % con
            return gp
        return self.hostpath(gp, False)

    def sockaddr_in(self, addr, length):
        """guest sockaddr bytes -> host sockaddr bytes"""
        import socket as hs
        if not addr or length < 2:
            return None
        d = self.rd(addr, min(length, 110))
        family = struct.unpack('>H', d[:2])[0]
        if family == C['AF_INET']:
            return struct.pack('=H', hs.AF_INET) + d[2:16].ljust(14, b'\0')
        if family == C['AF_UNIX']:
            path = d[2:].split(b'\0', 1)[0].decode('latin1')
            hp = self.sock_hostpath(path) if path else ''
            if len(hp.encode()) > 104 and not os.path.exists(hp):
                # too long for the host's sun_path, which would be EINVAL; what the
                # program needs to hear is that nothing is there (libX11 tries
                # /var/spool/sockets/X11/N before /tmp/.X11-unix/XN)
                raise HpuxError(ENOENT)
            return struct.pack('=H', hs.AF_UNIX) + hp.encode() + b'\0'
        if family == 0:
            return struct.pack('=H', 0) + d[2:16].ljust(14, b'\0')
        raise HpuxError(C['EAFNOSUPPORT'])

    def sockaddr_str(self, addr, length):
        """a guest sockaddr as text, for the trace"""
        try:
            d = self.rd(addr, min(length, 110))
            family = struct.unpack('>H', d[:2])[0]
            if family == C['AF_INET'] and len(d) >= 8:
                return '%d.%d.%d.%d:%d' % (d[4], d[5], d[6], d[7], struct.unpack('>H', d[2:4])[0])
            if family == C['AF_UNIX']:
                return repr(d[2:].split(b'\0', 1)[0].decode('latin1'))
            return 'af%d' % family
        except Exception:
            return '%#x' % addr

    def sockaddr_out(self, hostbytes):
        """host sockaddr bytes -> guest sockaddr bytes"""
        import socket as hs
        if len(hostbytes) < 2:
            return b''
        family = struct.unpack('=H', hostbytes[:2])[0]
        if family == hs.AF_INET:
            return struct.pack('>H', C['AF_INET']) + hostbytes[2:16].ljust(14, b'\0')
        if family == hs.AF_UNIX:
            path = hostbytes[2:].split(b'\0', 1)[0].decode('latin1')
            if path.startswith(self.root + '/'):
                path = path[len(self.root):]
            return struct.pack('>H', C['AF_UNIX']) + path.encode('latin1') + b'\0'
        return struct.pack('>H', family) + hostbytes[2:16].ljust(14, b'\0')

    def write_sockaddr(self, addr, lenp, hostbytes):
        if not addr or not lenp:
            return
        g = self.sockaddr_out(hostbytes)
        room = self.rd32(lenp)
        self.wr(addr, g[:room])
        self.wr32(lenp, len(g))

    def sys_socket(self, domain, typ, proto, *a):
        """socket(domain, type, protocol): AF_UNIX and AF_INET, SOCK_STREAM/DGRAM/RAW, on the host"""
        import socket as hs
        fam = {C['AF_UNIX']: hs.AF_UNIX, C['AF_INET']: hs.AF_INET}.get(domain)
        if fam is None:
            raise HpuxError(C['EAFNOSUPPORT'])
        st = {C['SOCK_STREAM']: hs.SOCK_STREAM, C['SOCK_DGRAM']: hs.SOCK_DGRAM, C['SOCK_RAW']: hs.SOCK_RAW}.get(typ)
        if st is None:
            raise HpuxError(C['EPROTOTYPE'])
        try:
            sock = hs.socket(fam, st, proto)
        except OSError as e:
            raise host_err(e)
        fd = sock.detach()
        return self.newfd(fd, 'socket')

    def sys_socket2(self, domain, typ, proto, *a):
        """socket2(domain, type, protocol, ...): the same as socket"""
        return self.sys_socket(domain, typ, proto)

    def sys_socketpair(self, domain, typ, proto, sv, *a):
        """socketpair(domain, type, protocol, sv[2]): AF_UNIX pairs on the host"""
        import socket as hs
        if domain != C['AF_UNIX']:
            raise HpuxError(C['EAFNOSUPPORT'])
        st = {C['SOCK_STREAM']: hs.SOCK_STREAM, C['SOCK_DGRAM']: hs.SOCK_DGRAM}.get(typ, hs.SOCK_STREAM)
        try:
            s1, s2 = hs.socketpair(hs.AF_UNIX, st, proto)
        except OSError as e:
            raise host_err(e)
        f1, f2 = s1.detach(), s2.detach()
        self.newfd(f1, 'socket')
        self.newfd(f2, 'socket')
        self.wr(sv, struct.pack('>II', f1, f2))
        return 0

    sys_socketpair2 = sys_socketpair

    def sys_bind(self, fd, addr, length, *a):
        """bind(s, addr, len)"""
        self.fd_check(fd)
        hb = self.sockaddr_in(addr, length)
        if hb is None:
            raise HpuxError(EINVAL)
        try:
            host_errno_call(_libc.bind, fd, hb, len(hb))
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_connect(self, fd, addr, length, *a):
        """connect(s, addr, len): blocking on the host (EINPROGRESS on a non-blocking socket)"""
        self.fd_check(fd)
        hb = self.sockaddr_in(addr, length)
        if hb is None:
            raise HpuxError(EINVAL)
        disp = self.x_local_display(hb)
        con = os.environ.get('HPUXEMU_CONSOLE')
        if disp is not None and con and disp == 0:
            return self.connect_x_unix(fd, int(con))
        try:
            host_errno_call(_libc.connect, fd, hb, len(hb))
        except OSError as e:
            if e.errno == herrno.ECONNREFUSED and disp is not None:
                return self.connect_x_unix(fd, disp)
            xn = _re().match(rb'..(/tmp/\.X11-unix/X(\d+))\0', hb, _re().S)
            if xn and e.errno in (herrno.ENOENT, herrno.ECONNREFUSED):
                # no socket file: an X server whose /tmp/.X11-unix it cannot write (WSLg's
                # is read-only) has only Linux's abstract one, "@/tmp/.X11-unix/XN"
                return self.connect_x_unix(fd, int(xn.group(2)))
            if e.errno == herrno.ECONNREFUSED and b'/var/spool/sockets/X11/' in hb:
                # the socket an HP X server of the root left behind (x11start's Xhp
                # starts and fails: no frame buffer): nothing there, so that libX11
                # goes on to /tmp/.X11-unix, the host's X servers
                raise HpuxError(ENOENT)
            raise host_err(e)
        return 0

    def x_local_display(self, hb):
        """the display number when a host sockaddr is TCP port 6000+N on this machine
        (127.x or one of its addresses: a display named "host:0.0"), else None"""
        import socket as hs
        if len(hb) < 8 or struct.unpack('=H', hb[:2])[0] != hs.AF_INET:
            return None
        port = struct.unpack('>H', hb[2:4])[0]
        if not 6000 <= port < 6100:
            return None
        addr = hs.inet_ntoa(hb[4:8])
        if addr.startswith('127.') or addr in [i[1] for i in self.interfaces()]:
            return port - 6000
        return None

    def connect_x_unix(self, fd, n):
        """a TCP connection to a local X display made to the X server's Unix socket
        instead (WSLg, an Xvnc for the console: they need not listen on TCP); the
        guest's descriptor becomes that socket"""
        import socket as hs
        u = hs.socket(hs.AF_UNIX, hs.SOCK_STREAM)
        try:
            # the socket file, else the abstract socket of the same name (an X server
            # that could not create the file: WSLg's /tmp/.X11-unix is read-only)
            try:
                u.connect('/tmp/.X11-unix/X%d' % n)
            except OSError:
                u.connect('\0/tmp/.X11-unix/X%d' % n)
        except OSError as e:
            u.close()
            raise host_err(e)
        os.dup2(u.fileno(), fd)
        u.close()
        return 0

    def sys_listen(self, fd, backlog, *a):
        """listen(s, backlog)"""
        self.fd_check(fd)
        try:
            import socket as hs
            hs.socket(fileno=os.dup(fd)).listen(backlog)
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_accept(self, fd, addr, lenp, *a):
        """accept(s, addr, lenp): the new descriptor; the peer's address in HP-UX form"""
        self.fd_check(fd)
        buf = ctypes.create_string_buffer(128)
        ln = ctypes.c_uint32(128)
        try:
            n = host_errno_call(_libc.accept, fd, buf, ctypes.byref(ln))
        except OSError as e:
            raise host_err(e)
        self.newfd(n, 'socket')
        self.write_sockaddr(addr, lenp, buf.raw[:ln.value])
        return n

    def sys_shutdown(self, fd, how, *a):
        """shutdown(s, how)"""
        self.fd_check(fd)
        try:
            import socket as hs
            hs.socket(fileno=os.dup(fd)).shutdown(how)
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_send(self, fd, buf, n, flags, *a):
        """send(s, buf, len, flags)"""
        self.fd_check(fd)
        data = self.rd(buf, n)
        try:
            return host_errno_call(_libc.send, fd, data, len(data), flags)
        except OSError as e:
            raise host_err(e)

    def sys_sendto(self, fd, buf, n, flags, addr, length, *a):
        """sendto(s, buf, len, flags, to, tolen)"""
        self.fd_check(fd)
        data = self.rd(buf, n)
        hb = self.sockaddr_in(addr, length) if addr else None
        try:
            if hb is None:
                return host_errno_call(_libc.send, fd, data, len(data), flags)
            return host_errno_call(_libc.sendto, fd, data, len(data), flags, hb, len(hb))
        except OSError as e:
            raise host_err(e)

    def sys_recv(self, fd, buf, n, flags, *a):
        """recv(s, buf, len, flags)"""
        self.fd_check(fd)
        self.joined_wait(fd)
        b = ctypes.create_string_buffer(max(n, 1))
        try:
            r = host_errno_call(_libc.recv, fd, b, n, flags)
        except OSError as e:
            raise host_err(e)
        self.wr(buf, b.raw[:r])
        return r

    def sys_recvfrom(self, fd, buf, n, flags, addr, lenp, *a):
        """recvfrom(s, buf, len, flags, from, fromlen)"""
        self.fd_check(fd)
        b = ctypes.create_string_buffer(max(n, 1))
        ab = ctypes.create_string_buffer(128)
        ln = ctypes.c_uint32(128)
        try:
            r = host_errno_call(_libc.recvfrom, fd, b, n, flags, ab, ctypes.byref(ln))
        except OSError as e:
            raise host_err(e)
        self.wr(buf, b.raw[:r])
        self.write_sockaddr(addr, lenp, ab.raw[:ln.value])
        return r

    def read_msghdr(self, msg):
        name, namelen, iov, iovlen, rights, rightslen = struct.unpack('>IIIIII', self.rd(msg, 24))
        iovs = [struct.unpack('>II', self.rd(iov + 8 * i, 8)) for i in range(iovlen)]
        return name, namelen, iovs, rights, rightslen

    def sys_sendmsg(self, fd, msg, flags, *a):
        """sendmsg(s, msg, flags): the iovecs gathered; access rights (descriptor passing) are not supported"""
        self.fd_check(fd)
        name, namelen, iovs, rights, rightslen = self.read_msghdr(msg)
        data = b''.join(self.rd(b, n) for b, n in iovs)
        return self._sendmsg(fd, data, flags, name, namelen)

    def _sendmsg(self, fd, data, flags, name, namelen):
        hb = self.sockaddr_in(name, namelen) if name else None
        try:
            if hb is None:
                return host_errno_call(_libc.send, fd, data, len(data), flags)
            return host_errno_call(_libc.sendto, fd, data, len(data), flags, hb, len(hb))
        except OSError as e:
            raise host_err(e)

    sys_sendmsg2 = sys_sendmsg

    def sys_recvmsg(self, fd, msg, flags, *a):
        """recvmsg(s, msg, flags): into the iovecs; no access rights"""
        self.fd_check(fd)
        name, namelen, iovs, rights, rightslen = self.read_msghdr(msg)
        total = sum(n for _, n in iovs)
        b = ctypes.create_string_buffer(max(total, 1))
        ab = ctypes.create_string_buffer(128)
        ln = ctypes.c_uint32(128)
        try:
            r = host_errno_call(_libc.recvfrom, fd, b, total, flags, ab, ctypes.byref(ln))
        except OSError as e:
            raise host_err(e)
        data = b.raw[:r]
        off = 0
        for base, n in iovs:
            chunk = data[off:off + n]
            if not chunk:
                break
            self.wr(base, chunk)
            off += len(chunk)
        if name and namelen:
            g = self.sockaddr_out(ab.raw[:ln.value])
            self.wr(name, g[:namelen])
            self.wr32(msg + 4, len(g))
        if rights:
            self.wr32(msg + 20, 0)
        return r

    sys_recvmsg2 = sys_recvmsg

    def sys_getsockname(self, fd, addr, lenp, *a):
        """getsockname(s, addr, lenp)"""
        self.fd_check(fd)
        try:
            import socket as hs
            sk = hs.socket(fileno=os.dup(fd))
            fam = sk.family
            hb = self.host_sockaddr(fam, sk.getsockname())
        except OSError as e:
            raise host_err(e)
        self.write_sockaddr(addr, lenp, hb)
        return 0

    def sys_getpeername(self, fd, addr, lenp, *a):
        """getpeername(s, addr, lenp)"""
        self.fd_check(fd)
        try:
            import socket as hs
            sk = hs.socket(fileno=os.dup(fd))
            hb = self.host_sockaddr(sk.family, sk.getpeername())
        except OSError as e:
            raise host_err(e)
        self.write_sockaddr(addr, lenp, hb)
        return 0

    def host_sockaddr(self, fam, sa):
        import socket as hs
        if fam == hs.AF_INET:
            host, port = sa
            return struct.pack('=H', hs.AF_INET) + struct.pack('>H', port) + hs.inet_aton(host) + b'\0' * 8
        if fam == hs.AF_UNIX:
            return struct.pack('=H', hs.AF_UNIX) + (sa.encode() if isinstance(sa, str) else sa) + b'\0'
        return struct.pack('=H', fam) + b'\0' * 14

    def sockopt(self, level, name):
        import socket as hs
        if level == C['SOL_SOCKET']:
            hl = hs.SOL_SOCKET
            names = [n for n in self.SOCK_OPTS if n.startswith('SO_')]
        elif level == C['IPPROTO_TCP']:
            hl = hs.IPPROTO_TCP
            names = [n for n in self.SOCK_OPTS if n.startswith('TCP_')]
        elif level == C['IPPROTO_IP']:
            hl = hs.IPPROTO_IP
            names = [n for n in self.SOCK_OPTS if n.startswith('IP_')]
        else:
            raise HpuxError(C['ENOPROTOOPT'])
        for n in names:
            if C.get(n) == name and hasattr(hs, n):
                return hl, getattr(hs, n)
        raise HpuxError(C['ENOPROTOOPT'])

    def sys_setsockopt(self, fd, level, name, val, length, *a):
        """setsockopt(s, level, optname, optval, optlen): SOL_SOCKET, TCP and IP options by name; SO_USELOOPBACK is accepted and ignored (the RPC library sets it and gives up on failure)"""
        self.fd_check(fd)
        if level == C['SOL_SOCKET'] and name == C.get('SO_USELOOPBACK', 0x40):
            return 0
        hl, hn = self.sockopt(level, name)
        data = self.rd(val, length) if val and length else b''
        try:
            import socket as hs
            sk = hs.socket(fileno=os.dup(fd))
            if length == 4:
                sk.setsockopt(hl, hn, struct.unpack('>i', data)[0])
            elif hn == hs.SO_LINGER and length == 8:
                on, lng = struct.unpack('>ii', data)
                sk.setsockopt(hl, hn, struct.pack('ii', on, lng))
            else:
                sk.setsockopt(hl, hn, data)
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_getsockopt(self, fd, level, name, val, lenp, *a):
        """getsockopt(s, level, optname, optval, optlen)"""
        self.fd_check(fd)
        hl, hn = self.sockopt(level, name)
        try:
            import socket as hs
            sk = hs.socket(fileno=os.dup(fd))
            if hn == hs.SO_LINGER:
                on, lng = struct.unpack('ii', sk.getsockopt(hl, hn, 8))
                out = struct.pack('>ii', on, lng)
            elif hn == hs.SO_TYPE:
                t = sk.getsockopt(hl, hn)
                out = struct.pack('>i', {hs.SOCK_STREAM: C['SOCK_STREAM'], hs.SOCK_DGRAM: C['SOCK_DGRAM'], hs.SOCK_RAW: C['SOCK_RAW']}.get(t, t))
            else:
                out = struct.pack('>i', sk.getsockopt(hl, hn))
        except OSError as e:
            raise host_err(e)
        room = self.rd32(lenp) if lenp else len(out)
        self.wr(val, out[:room])
        if lenp:
            self.wr32(lenp, len(out))
        return 0

    # ---- System V IPC ----
    # The host's shared memory, semaphores and message queues; keys and ids are the
    # host's, so emulated processes share them with each other. A shared memory segment
    # is attached inside the guest address space with shmat(SHM_REMAP) on the Rust CPU;
    # the Python CPU gets a private copy (written back at detach).
    SHM_LO, SHM_HI = 0x90000000, 0xC0000000

    def ipc_perm_out(self, raw):
        f = struct.unpack_from(HOST_IPC['perm'][0], raw, 0)
        d = dict(zip(HOST_IPC['perm'][1], f))
        return pack('ipc_perm', {'uid': d['uid'], 'gid': d['gid'], 'cuid': d['cuid'], 'cgid': d['cgid'],
                                 'mode': d['mode'], 'seq': d['seq'], 'key': d['key']})

    def ipc_field(self, raw, spec):
        fmt, off = spec
        return struct.unpack_from(fmt, raw, off)[0]

    def sys_shmget(self, key, size, flag, *a):
        """shmget(key, size, flag): the host's segment (IPC_CREAT/IPC_EXCL and the mode bits are the same values)"""
        r = _libc.shmget(ctypes.c_int(key if key < 0x80000000 else key - (1 << 32)).value, size, flag & 0o3777)
        if r < 0:
            raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
        return r

    def sys_shmat(self, shmid, addr, flag, *a):
        """shmat(shmid, addr, flag): attached in the third quadrant (0x90000000 up) when no address is given; SHM_RDONLY honoured"""
        buf = ctypes.create_string_buffer(HOST_IPC['shm']['size'])
        if _libc.shmctl(shmid, 2, buf) < 0:
            raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
        size = self.ipc_field(buf.raw, HOST_IPC['shm']['segsz'])
        size = (size + PAGE - 1) & ~(PAGE - 1)
        if addr:
            base = addr & ~(PAGE - 1) if flag & C['SHM_RND'] else addr
            if base & (PAGE - 1):
                raise HpuxError(EINVAL)
        else:
            base = self.find_free(size, self.SHM_LO, self.SHM_HI, upward=True)
        prot = 1 if flag & C['SHM_RDONLY'] else 3
        hostbase = self.mem.host_base() if hasattr(self.mem, 'host_base') else None
        if hostbase is not None:
            SHM_REMAP = 0o40000
            r = _libc.shmat(shmid, hostbase + base, SHM_REMAP | (0o10000 if flag & C['SHM_RDONLY'] else 0))
            if r is None or r == ctypes.c_void_p(-1).value:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), ENOMEM))
            self.mem.mark(base, size, prot)
            self.shm_attached[base] = (shmid, size, None)
        else:
            # the Python CPU: a private copy
            r = _libc.shmat(shmid, None, 0)
            if r is None or r == ctypes.c_void_p(-1).value:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), ENOMEM))
            self.mem.map(base, size, prot | 2)
            self.mem.write(base, ctypes.string_at(r, size))
            self.mem.protect(base, size, prot)
            self.shm_attached[base] = (shmid, size, r)
        return base

    def sys_shmdt(self, addr, *a):
        """shmdt(addr)"""
        rec = self.shm_attached.pop(addr, None)
        if rec is None:
            raise HpuxError(EINVAL)
        shmid, size, hostaddr = rec
        if hostaddr is not None:
            try:
                ctypes.memmove(hostaddr, self.mem.read(addr, size), size)
            except MemFault:
                pass
            _libc.shmdt(hostaddr)
        self.mem.unmap(addr, size)
        return 0

    def sys_shmctl(self, shmid, cmd, buf, *a):
        """shmctl(shmid, cmd, buf): IPC_STAT (struct shmid_ds in HP-UX layout), IPC_SET (mode), IPC_RMID"""
        if cmd == C['IPC_STAT']:
            raw = ctypes.create_string_buffer(HOST_IPC['shm']['size'])
            if _libc.shmctl(shmid, 2, raw) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            h = HOST_IPC['shm']
            d = pack('shmid_ds', {'shm_perm': self.ipc_perm_out(raw.raw), 'shm_segsz': self.ipc_field(raw.raw, h['segsz']),
                                  'shm_lpid': self.ipc_field(raw.raw, h['lpid']), 'shm_cpid': self.ipc_field(raw.raw, h['cpid']),
                                  'shm_nattch': self.ipc_field(raw.raw, h['nattch']), 'shm_atime': self.ipc_field(raw.raw, h['atime']),
                                  'shm_dtime': self.ipc_field(raw.raw, h['dtime']), 'shm_ctime': self.ipc_field(raw.raw, h['ctime'])})
            self.wr(buf, d)
            return 0
        if cmd == C['IPC_RMID']:
            if _libc.shmctl(shmid, 0, None) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            return 0
        if cmd == C['IPC_SET']:
            raw = ctypes.create_string_buffer(HOST_IPC['shm']['size'])
            if _libc.shmctl(shmid, 2, raw) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            g = self.rd(buf, SIZEOF['ipc_perm'])
            mode = struct.unpack('>H', g[16:18])[0]
            struct.pack_into('=H', raw, 20, mode)
            if _libc.shmctl(shmid, 1, raw) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            return 0
        raise HpuxError(EINVAL)

    def sys_semget(self, key, nsems, flag, *a):
        """semget(key, nsems, flag)"""
        r = _libc.semget(ctypes.c_int(key if key < 0x80000000 else key - (1 << 32)).value, nsems, flag & 0o3777)
        if r < 0:
            raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
        return r

    def sys_semop(self, semid, sops, nsops, *a):
        """semop(semid, sops, nsops): struct sembuf has the same layout on the host; blocks on the host, interruptible"""
        ops = self.rd(sops, 6 * nsops)
        hb = b''.join(struct.pack('=HhH', *struct.unpack('>HhH', ops[6 * i:6 * i + 6])) for i in range(nsops))
        try:
            host_errno_call(_libc.semop, semid, hb, nsops)
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_semctl(self, semid, semnum, cmd, arg, *a):
        """semctl(semid, semnum, cmd, arg): the BSD command numbers mapped to the host's; GETALL/SETALL/IPC_STAT through buffers"""
        hcmd = HOST_SEMCMD.get(cmd)
        if hcmd is None:
            raise HpuxError(EINVAL)
        if cmd in (C['GETVAL'], C['GETPID'], C['GETNCNT'], C['GETZCNT']):
            r = _libc.semctl(semid, semnum, hcmd, ctypes.c_long(0))
        elif cmd == C['SETVAL']:
            r = _libc.semctl(semid, semnum, hcmd, ctypes.c_long(arg if arg < 0x80000000 else arg - (1 << 32)))
        elif cmd in (C['GETALL'], C['SETALL']):
            raw = ctypes.create_string_buffer(HOST_IPC['sem']['size'])
            if _libc.semctl(semid, 0, 2, raw) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            n = self.ipc_field(raw.raw, HOST_IPC['sem']['nsems'])
            arr = (ctypes.c_ushort * max(n, 1))()
            if cmd == C['SETALL']:
                vals = struct.unpack('>%dH' % n, self.rd(arg, 2 * n))
                for i, v in enumerate(vals):
                    arr[i] = v
            r = _libc.semctl(semid, semnum, hcmd, arr)
            if r >= 0 and cmd == C['GETALL']:
                self.wr(arg, struct.pack('>%dH' % n, *arr[:n]))
        elif cmd == C['IPC_STAT']:
            raw = ctypes.create_string_buffer(HOST_IPC['sem']['size'])
            r = _libc.semctl(semid, 0, 2, raw)
            if r >= 0:
                h = HOST_IPC['sem']
                self.wr(arg, pack('semid_ds', {'sem_perm': self.ipc_perm_out(raw.raw), 'sem_otime': self.ipc_field(raw.raw, h['otime']),
                                               'sem_ctime': self.ipc_field(raw.raw, h['ctime']), 'sem_nsems': self.ipc_field(raw.raw, h['nsems'])}))
        elif cmd == C['IPC_RMID']:
            r = _libc.semctl(semid, 0, 0, ctypes.c_long(0))
        elif cmd == C['IPC_SET']:
            raw = ctypes.create_string_buffer(HOST_IPC['sem']['size'])
            if _libc.semctl(semid, 0, 2, raw) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            g = self.rd(arg, SIZEOF['ipc_perm'])
            struct.pack_into('=H', raw, 20, struct.unpack('>H', g[16:18])[0])
            r = _libc.semctl(semid, 0, 1, raw)
        else:
            raise HpuxError(EINVAL)
        if r < 0:
            raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
        return r

    def sys_msgget(self, key, flag, *a):
        """msgget(key, flag)"""
        r = _libc.msgget(ctypes.c_int(key if key < 0x80000000 else key - (1 << 32)).value, flag & 0o3777)
        if r < 0:
            raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
        return r

    def sys_msgsnd(self, msqid, msgp, size, flag, *a):
        """msgsnd(msqid, msgp, size, flag): the 32-bit mtype becomes the host's long"""
        mtype = struct.unpack('>i', self.rd(msgp, 4))[0]
        data = self.rd(msgp + 4, size)
        hb = struct.pack('@l', mtype) + data
        try:
            host_errno_call(_libc.msgsnd, msqid, hb, size, flag & C['IPC_NOWAIT'])
        except OSError as e:
            raise host_err(e)
        return 0

    def sys_msgrcv(self, msqid, msgp, size, mtype, flag, *a):
        """msgrcv(msqid, msgp, size, mtype, flag)"""
        hb = ctypes.create_string_buffer(8 + size)
        hflag = flag & (C['IPC_NOWAIT'] | C['MSG_NOERROR'])    # the same values on the host
        try:
            n = host_errno_call(_libc.msgrcv, msqid, hb, size, mtype if mtype < 0x80000000 else mtype - (1 << 32), hflag)
        except OSError as e:
            raise host_err(e)
        t = struct.unpack_from('@l', hb.raw, 0)[0]
        self.wr(msgp, struct.pack('>i', t) + hb.raw[8:8 + n])
        return n

    def sys_msgctl(self, msqid, cmd, buf, *a):
        """msgctl(msqid, cmd, buf): IPC_STAT, IPC_SET (mode, qbytes), IPC_RMID"""
        h = HOST_IPC['msg']
        if cmd == C['IPC_STAT']:
            raw = ctypes.create_string_buffer(h['size'])
            if _libc.msgctl(msqid, 2, raw) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            self.wr(buf, pack('msqid_ds', {'msg_perm': self.ipc_perm_out(raw.raw), 'msg_qnum': self.ipc_field(raw.raw, h['qnum']),
                                           'msg_qbytes': min(self.ipc_field(raw.raw, h['qbytes']), 0xFFFF), 'msg_lspid': self.ipc_field(raw.raw, h['lspid']),
                                           'msg_lrpid': self.ipc_field(raw.raw, h['lrpid']), 'msg_stime': self.ipc_field(raw.raw, h['stime']),
                                           'msg_rtime': self.ipc_field(raw.raw, h['rtime']), 'msg_ctime': self.ipc_field(raw.raw, h['ctime']),
                                           'msg_cbytes': min(self.ipc_field(raw.raw, h['cbytes']), 0xFFFF)}))
            return 0
        if cmd == C['IPC_RMID']:
            if _libc.msgctl(msqid, 0, None) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            return 0
        if cmd == C['IPC_SET']:
            raw = ctypes.create_string_buffer(h['size'])
            if _libc.msgctl(msqid, 2, raw) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            g = self.rd(buf, SIZEOF['msqid_ds'])
            struct.pack_into('=H', raw, 20, struct.unpack('>H', g[16:18])[0])
            struct.pack_into('=Q', raw, h['qbytes'][1], struct.unpack('>H', g[58:60])[0])
            if _libc.msgctl(msqid, 1, raw) < 0:
                raise HpuxError(HOST2GUEST_ERRNO.get(ctypes.get_errno(), EINVAL))
            return 0
        raise HpuxError(EINVAL)

    # ---- the process table ----
    # Every emulator process writes a line about itself into <root>/var/run/hpuxemu/
    # (removed at exit; a stale one belongs to a pid that is no longer alive). ps and
    # friends read it through pstat.
    def proc_dir(self):
        return os.path.join(self.root, 'var/run/hpuxemu')

    def publish(self):
        try:
            d = self.proc_dir()
            os.makedirs(d, exist_ok=True)
            try:
                tty = os.ttyname(0) if os.isatty(0) else ''
            except OSError:
                tty = ''
            with open(os.path.join(d, str(self.pid)), 'w') as f:
                f.write('%d %d %d %d %d %d %d %s %s\n' % (self.pid, os.getppid(), os.getpgrp(), os.getsid(0), self.uid, self.gid,
                                                            self.start_time, tty or '-', ' '.join(self.argv)))
        except OSError:
            pass

    def unpublish(self):
        try:
            os.unlink(os.path.join(self.proc_dir(), str(self.pid)))
        except OSError:
            pass

    def proc_table(self):
        """[(pid, ppid, pgrp, sid, uid, gid, start, tty, cmd)] of the live emulator processes"""
        out = []
        d = self.proc_dir()
        try:
            names = os.listdir(d)
        except OSError:
            return out
        for n in names:
            if not n.isdigit():
                continue
            pid = int(n)
            try:
                os.kill(pid, 0)
                gone = False
            except ProcessLookupError:
                gone = True
            except OSError:
                gone = False
            if not gone:
                # a zombie nobody reaps (a container's init may not) is gone too
                try:
                    with open('/proc/%d/stat' % pid) as f:
                        gone = f.read().rsplit(')', 1)[1].split()[0] == 'Z'
                except OSError:
                    pass
            if gone:
                try:
                    os.unlink(os.path.join(d, n))
                except OSError:
                    pass
                continue
            try:
                parts = open(os.path.join(d, n)).read().rstrip('\n').split(' ', 8)
                if len(parts) < 9:
                    continue
                out.append(tuple(int(x) for x in parts[:7]) + (parts[7], parts[8]))
            except (OSError, ValueError):
                continue
        out.sort()
        return out

    def pst_status(self, idx, rec, elemsize, layout=OFFSET):
        pid, ppid, pgrp, sid, uid, gid, start, tty, cmd = rec
        d = bytearray(elemsize)
        o = layout['pst_status']
        major, minor = -1, -1
        if tty != '-':
            try:
                st = os.stat(tty)
                major, minor = os.major(st.st_rdev), os.minor(st.st_rdev)
            except OSError:
                pass
        fields = [('pst_idx', idx), ('pst_pid', pid), ('pst_ppid', ppid), ('pst_uid', uid), ('pst_gid', gid), ('pst_pgrp', pgrp),
                  ('pst_sid', sid), ('pst_stat', C['PS_RUN'] if pid == self.pid else C['PS_SLEEP']), ('pst_euid', uid), ('pst_egid', gid), ('pst_suid', uid),
                  ('pst_cmd', cmd.encode('latin1')[:63]), ('pst_ucomm', os.path.basename(cmd.split(' ')[0]).encode('latin1')[:14]),
                  ('pst_start', start), ('pst_highestfd', (max(self.fds) if self.fds else 2) if pid == self.pid else 2),
                  ('pst_pri', 154), ('pst_nice', 20), ('pst_procnum', 0)]
        for k, v in fields:
            if k in o:
                off, sz = o[k]
                if isinstance(v, bytes):
                    d[off:off + min(sz, len(v))] = v[:sz]
                else:
                    d[off:off + sz] = (v & ((1 << (8 * sz)) - 1)).to_bytes(sz, 'big')
        if 'pst_term' in o:
            off, sz = o['pst_term']
            h = sz // 2        # struct psdev: two ints, or two int64s in the _PSTAT64 layout
            d[off:off + h] = (major & ((1 << (8 * h)) - 1)).to_bytes(h, 'big')
            d[off + h:off + sz] = (minor & ((1 << (8 * h)) - 1)).to_bytes(h, 'big')
        return bytes(d)

    def sys_pstat(self, req, buf, elemsize, elemcount, index, *a):
        """pstat(request, buf, elemsize, elemcount, index): PSTAT_STATIC and
        PSTAT_DYNAMIC with plausible values, PSTAT_PROC for the process itself.
        11.00's libc sets PSTAT64_INTF (0x80000000) in the request and wants the _PSTAT64
        layouts (64-bit fields, also in 32-bit programs)"""
        layout = OFFSET
        if req & 0x80000000:
            req &= 0x7FFFFFFF
            layout = OFFSET_PSTAT64
        if req == C.get('PSTAT_STATIC', 1):
            d = bytearray(elemsize)
            o = layout['pst_static']
            for k, v in (('max_proc', 1024), ('page_size', 4096), ('boot_time', int(self.now()) - 3600), ('physical_memory', 32768)):
                if k in o:
                    off, sz = o[k]
                    d[off:off + sz] = v.to_bytes(sz, 'big')
            self.wr(buf, bytes(d))
            return 1
        if req == C.get('PSTAT_DYNAMIC', 2):
            d = bytearray(elemsize)
            o = layout['pst_dynamic']
            for k, v in (('psd_proc_cnt', len(self.proc_table())), ('psd_max_proc_cnt', 1024), ('psd_last_pid', self.pid), ('psd_activecpu', 1)):
                if k in o:
                    off, sz = o[k]
                    d[off:off + sz] = v.to_bytes(sz, 'big')
            self.wr(buf, bytes(d))
            return 1
        if req == C.get('PSTAT_PROC', 4):
            table = self.proc_table()
            if elemcount == 0:
                # one process, by pid
                for i, rec in enumerate(table):
                    if rec[0] == index:
                        self.wr(buf, self.pst_status(i, rec, elemsize, layout))
                        return 1
                raise HpuxError(C['ESRCH'])
            # elemcount entries from index on (the caller continues at the last idx + 1)
            n = 0
            for i in range(index, min(len(table), index + elemcount)):
                self.wr(buf + n * elemsize, self.pst_status(i, table[i], elemsize, layout))
                n += 1
            return n
        sys.stderr.write('hpuxemu: pstat request %d unimplemented\n' % req)
        raise HpuxError(EINVAL)

    def sys_getnumfds(self, *a):
        """getnumfds(): one more than the highest open descriptor (what callers loop up to)"""
        return (max(self.fds) + 1) if self.fds else 0

    FSTYPES = ['hfs', 'nfs', 'cdfs', 'vxfs', 'autofs', 'lofs']

    def sys_sysfs(self, op, a1, a2, *a):
        """sysfs(GETFSIND, name) / (GETFSTYP, index, buf) / (GETNFSTYP): the file system types"""
        if op == 1:
            name = self.rdstr(a1)
            if name in self.FSTYPES:
                return self.FSTYPES.index(name) + 1
            raise HpuxError(EINVAL)
        if op == 2:
            if 1 <= a1 <= len(self.FSTYPES):
                self.wr(a2, self.FSTYPES[a1 - 1].encode() + b'\0')
                return 0
            raise HpuxError(EINVAL)
        if op == 3:
            return len(self.FSTYPES)
        raise HpuxError(EINVAL)

    def sys_fss(self, *a):
        """fss: used by dld.sl and libc at startup (a fair-share scheduler query); 0"""
        return 0

    def sys_sethostid(self, *a):
        """sethostid(id): accepted and ignored"""
        return 0

    def sys_gethostid(self, *a):
        """gethostid(): a fixed id (0x2000000)"""
        return 0x2000000

    def sys_get_sysinfo(self, *a):
        """get_sysinfo: EINVAL (an internal kernel interface)"""
        raise HpuxError(EINVAL)

    def sys_sysinfo(self, cmd, buf, n, *a):
        """sysinfo(command, buf, count): the SVR4 strings (1 sysname, 2 hostname, 3 release, 4 version, 5 machine, 6 architecture, 7 serial, 8 provider, 9 domain); returns the length needed"""
        table = {1: 'HP-UX', 2: self.nodename, 3: self.release, 4: 'A', 5: '9000/715', 6: 'hppa1.1', 7: '2000000000', 8: 'HP', 9: ''}
        if cmd not in table:
            raise HpuxError(EINVAL)
        v = table[cmd].encode() + b'\0'
        if buf and n:
            self.wr(buf, v[:n - 1] + b'\0' if len(v) > n else v)
        return len(v)

    def sys_audswitch(self, *a):
        """audswitch(flag): auditing is off; accepted"""
        return 0

    def sys_audwrite(self, *a):
        """audwrite(record): auditing is off, the record is dropped (passwd writes one)"""
        return 0

    def sys_audctl(self, *a):
        """audctl: no audit system; EINVAL"""
        raise HpuxError(EINVAL)

    def sys_getaudid(self, *a):
        """getaudid(): the audit id; 0"""
        return 0

    def sys_getaudproc(self, *a):
        """getaudproc(): auditing off for this process"""
        return 0

    def sys_setaudproc(self, *a):
        """setaudproc(flag): accepted"""
        return 0

    def sys_privgrp(self, *a):
        """privgrp(cmd, buf): no privileged groups; EINVAL"""
        raise HpuxError(EINVAL)

    def sys_gtty(self, fd, buf, *a):
        """gtty(fd, buf): ioctl TIOCGETP"""
        return self.sys_ioctl(fd, C['TIOCGETP'], buf)

    def sys_stty(self, fd, buf, *a):
        """stty(fd, buf): ioctl TIOCSETP"""
        return self.sys_ioctl(fd, C['TIOCSETP'], buf)

    def sys_sched_get_priority_min(self, *a):
        """sched_get_priority_min(policy): 0"""
        return 0

    def sys_sched_get_priority_max(self, *a):
        """sched_get_priority_max(policy): 31"""
        return 31

    def sys_plock(self, *a):
        """plock(op): accepted and ignored (nothing to lock in memory)"""
        return 0

    def sys_rtprio(self, *a):
        """rtprio(pid, prio): accepted; no real-time priorities"""
        return 0

    def sys_swapon(self, *a):
        """swapon(path, ...): EPERM"""
        raise HpuxError(C['EPERM'])

    def sys_mpctl(self, req, *a):
        """mpctl(request, ...): one processor: every request answers 1"""
        return 1


class _NoReturn(Exception):
    """The system call set the CPU state itself (sigcleanup): no return value to store."""


class _InterruptedWithMask(Exception):
    """sigsuspend/sigpause: a deliverable signal is pending; EINTR, with the handler's
    frame to carry the saved mask."""

    def __init__(self, mask):
        self.mask = mask


class _Exec(Exception):
    """raised inside a system call when the process image was replaced"""


def detach_stderr():
    """The emulator's own messages (traces, faults, unimplemented calls) go to a private
    copy of the original stderr at a high descriptor: an HP-UX fd *is* the host fd, so a
    daemon that closes 0-2 (portmap, ttsession) would otherwise close the emulator's
    stderr too and the next message would raise and kill it."""
    import fcntl
    try:
        fd = fcntl.fcntl(2, fcntl.F_DUPFD, 900)
    except OSError:
        return
    sys.stderr = os.fdopen(fd, 'w', buffering=1)


def lookup_user(root, who):
    """(uid, gid, groups) of a user in the root's /etc/passwd and /etc/group"""
    if not root:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from hpuxemu import rootdir
        root = rootdir.default_root()
    uid = gid = None
    name = who
    try:
        for line in open(os.path.join(root, 'etc/passwd')):
            f = line.rstrip('\n').split(':')
            if len(f) >= 4 and (f[0] == who or (who.isdigit() and f[2] == who)):
                name, uid, gid = f[0], int(f[2]), int(f[3])
                break
    except OSError:
        pass
    if uid is None:
        if who.isdigit():
            return (int(who), int(who), [])
        sys.stderr.write('hpuxemu: no such user in the root: %s\n' % who)
        sys.exit(2)
    groups = []
    try:
        for line in open(os.path.join(root, 'etc/group')):
            f = line.rstrip('\n').split(':')
            if len(f) >= 4 and name in f[3].split(',') and int(f[2]) != gid:
                groups.append(int(f[2]))
    except (OSError, ValueError):
        pass
    return (uid, gid, groups)


HPUX_MAXPID = 30000      # <sys/param.h> MAXPID


def warn_pid_max():
    """The host's process ids are the guest's, and HP-UX 10.20's are at most 30000:
    csh loses track of a child with a larger id and waits for it for ever (its job
    table keeps the id in 16 bits, as old code did). Linux's kernel.pid_max is often 4194304: say so, once."""
    if os.environ.get('HPUXEMU_PID_MAX_OK'):
        return
    os.environ['HPUXEMU_PID_MAX_OK'] = '1'
    try:
        n = int(open('/proc/sys/kernel/pid_max').read())
    except (OSError, ValueError):
        return
    if n > HPUX_MAXPID:
        sys.stderr.write('hpuxemu: warning: kernel.pid_max is %d; HP-UX programs need process ids up to %d '
                         '(csh hangs otherwise):\n    sudo sysctl -w kernel.pid_max=%d\n' % (n, HPUX_MAXPID, HPUX_MAXPID))


def main(argv):
    root = None
    trace = False
    user = None
    detach_stderr()
    env = {}
    cpu = 'python'
    argv0 = None
    cwd = '/'
    i = 1
    while i < len(argv) and argv[i].startswith('-') and argv[i] != '-':
        a = argv[i]
        if a in ('-r', '-e', '--cpu', '-0', '-C', '-u') and i + 1 >= len(argv):
            sys.stderr.write('hpuxemu: %s needs a value\n' % a)
            return 2
        if a == '-r':
            i += 1
            root = argv[i]
        elif a == '-t':
            trace = True
        elif a == '-e':
            i += 1
            k, _, v = argv[i].partition('=')
            env[k] = v
        elif a == '--cpu':
            i += 1
            cpu = argv[i]
        elif a == '-0':
            # argv[0] for the program (a login shell is started as "-sh")
            i += 1
            argv0 = argv[i]
        elif a == '-C':
            i += 1
            cwd = argv[i]
        elif a == '-u':
            # start as a user of the root's /etc/passwd (name or uid), with its groups
            i += 1
            user = lookup_user(root or os.environ.get('HPUX_ROOT') or '', argv[i])
        else:
            print(__doc__)
            return 2
        i += 1
    if i >= len(argv):
        print(__doc__)
        return 2
    root = root or rootdir.default_root()
    warn_pid_max()
    envd = {'PATH': '/usr/bin:/usr/ccs/bin:/usr/contrib/bin:/opt/langtools/bin:/sbin', 'HOME': '/', 'TERM': os.environ.get('TERM', 'vt100'),
            'LOGNAME': 'root', 'SHELL': '/usr/bin/sh', 'TZ': 'MET-1METDST'}
    envd.update(env)
    p = Process(root, trace=trace, env=envd, cpu=cpu)
    p.cwd = cwd
    if user is not None:
        p.uid = p.euid = p.suid = user[0]
        p.gid = p.egid = p.sgid = user[1]
        p.groups = user[2]
    for fd in (0, 1, 2):
        p.newfd(fd, '/dev/tty')
    prog = p.find_program(argv[i])
    args = [argv0 or argv[i]] + argv[i + 1:]
    p.stats_begin('start', prog)
    t0 = time.perf_counter()
    try:
        try:
            p.load(prog, args, ['%s=%s' % kv for kv in envd.items()])
        except HpuxError as e:
            if e.errno != C['ENOEXEC']:
                raise
            # not a SOM file and no #! line: a shell script, as execvp would run it
            p.load('/usr/bin/sh', ['sh', prog] + args[1:], ['%s=%s' % kv for kv in envd.items()])
    except (HpuxError, OSError) as e:
        sys.stderr.write('hpuxemu: %s: %s\n' % (argv[i], getattr(e, 'strerror', None) or e))
        return 127
    if p.stats:
        p.stats['load'] = time.perf_counter() - t0
    try:
        while True:
            try:
                r = p.run()
                break
            except _Exec:
                continue
    finally:
        p.unpublish()
    if r[0] == 'exit':
        return r[1]
    return 128 + r[1]


def exit_now(code):
    """End the host process at once once the guest has exited: Python's own shutdown
    (every module's objects freed, the CPU's 4 GB reservation unmapped by hand) costs
    more than a short program's whole run; the kernel frees all of it anyway. Only the
    emulator's own buffered output needs flushing."""
    mon = getattr(sys, 'monitoring', None)      # cProfile's hook from Python 3.12
    if sys.getprofile() is not None or sys.gettrace() is not None or \
            (mon is not None and (mon.get_tool(mon.PROFILER_ID) or mon.get_tool(mon.DEBUGGER_ID))):
        sys.exit(code)          # under a profiler or debugger: let it write its results
    if os.environ.get('HPPA_JIT_TRACE'):
        sys.exit(code)          # the JIT's trace prints when the CPU is freed
    for f in (sys.stdout, sys.stderr):
        try:
            f.flush()
        except (OSError, ValueError):
            pass
    os._exit(code if isinstance(code, int) else (0 if code is None else 1))


if __name__ == '__main__':
    exit_now(main(sys.argv))
