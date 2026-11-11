"""streams.py - STREAMS devices of the emulator: descriptors served by the STREAMS daemon.

A kernel STREAMS driver product (a third-party protocol stack) runs in the root's
STREAMS daemon (kernel/strd.c, built by tools/mkstrd.py into /stand/hpuxemu/strd), a
process of the emulator like any other. Opening one of its devices connects to the
daemon's socket; the connection is the stream, with its stream head in the daemon.
This module is the descriptor's side: putmsg/getmsg, read/write, the STREAMS ioctls,
and poll. The messages that reach the stream head come here as they arrive and wait in
`Stream.msgs` until the program reads them.

ROOT/etc/hpuxemu/streams names the devices: one line per device, "path driver [major
minor]" - with the numbers, stat shows the path as that character device (HP-UX's
clone driver, major 72, opens STREAMS drivers; the minor is the driver's major). A
driver "-" is a device node only: it stats, but does not open.
The daemon is started on the first open when it is not running; its output goes to
ROOT/var/adm/strd.log.
"""
import collections
import os
import struct
import sys
import time

SOCK = '/var/spool/sockets/streams'
DAEMON = '/stand/hpuxemu/strd'
CONF = '/etc/hpuxemu/streams'

# requests and messages: kernel/strd.c
RQ_OPEN, RQ_PUTMSG, RQ_IOCTL, RQ_COPYDATA, RQ_CLOSE, RQ_DEBUG = 1, 2, 3, 4, 5, 6
MS_REPLY, MS_MSG, MS_FLUSH, MS_ERROR, MS_HANGUP, MS_SIG, MS_COPYIN, MS_COPYOUT = 1, 2, 3, 4, 5, 6, 7, 8

M_DATA, M_PROTO, M_PCPROTO = 0x00, 0x01, 0x83
FLUSHR = 1


class StreamError(Exception):
    def __init__(self, err):
        Exception.__init__(self, err)
        self.errno = err


class Msg:
    __slots__ = ('type', 'band', 'ctl', 'data')

    def __init__(self, type_, band, ctl, data):
        self.type, self.band, self.ctl, self.data = type_, band, ctl, data

    def __repr__(self):
        return '<Msg %#x band %d ctl %s data %s>' % (self.type, self.band, None if self.ctl is None else len(self.ctl),
                                                     None if self.data is None else len(self.data))


def devices(root):
    """{guest path: (driver, HP-UX device number or None)} from ROOT/etc/hpuxemu/streams"""
    out = {}
    try:
        for line in open(os.path.join(root, CONF.lstrip('/'))):
            w = line.split()
            if len(w) >= 2 and not w[0].startswith('#'):
                rdev = (int(w[2], 0), int(w[3], 0)) if len(w) >= 4 else None
                out[w[0]] = (w[1], rdev)
    except (OSError, ValueError):
        pass
    return out


def node_stat(rdev, path):
    """a stat result (the attributes the emulator's stat uses) for a device node of the table"""
    import types
    now = int(time.time())
    major, minor = rdev or (0, 0)
    return types.SimpleNamespace(st_mode=0o020666, st_ino=hash(path) & 0xFFFFFF, st_dev=os.makedev(64, 0),
                                 st_nlink=1, st_uid=0, st_gid=0, st_rdev=os.makedev(major, minor), st_size=0,
                                 st_atime=now, st_mtime=now, st_ctime=now, st_blocks=0, st_blksize=8192)


def start_daemon(root, cpu):
    """the daemon of the root, as a detached process of the emulator"""
    log = open(os.path.join(root, 'var/adm/strd.log'), 'ab')
    args = [DAEMON]
    wire = os.environ.get('HPUXEMU_WIRE')
    if wire:
        args = [DAEMON, '-e', wire]
    if os.environ.get('HPUXEMU_STRD_TRACE'):
        args.insert(1, '-tt' if os.environ['HPUXEMU_STRD_TRACE'] == '2' else '-t')
    # more of strd's options (-m station address, -n NMID ...)
    args[1:1] = os.environ.get('HPUXEMU_STRD_ARGS', '').split()
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env['PYTHONPATH'] = here + os.pathsep + env.get('PYTHONPATH', '')
    env.pop('HPUXEMU_TRACE', None)
    import subprocess
    subprocess.Popen([sys.executable, '-m', 'hpuxemu.emu', '--cpu', cpu, '-r', root] + args,
                     stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, env=env, cwd=here)
    log.close()


def connect(root, cpu):
    """a connection to the daemon, starting it when needed; None when the root has no daemon.
    $HPUXEMU_STREAMS names another daemon's socket (a guest path), one started by hand
    (a second stack for a test, say): that one is not started here."""
    other = os.environ.get('HPUXEMU_STREAMS')
    path = os.path.join(root, (other or SOCK).lstrip('/'))
    started = bool(other)
    deadline = time.time() + 30
    while True:
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(path)
            return s
        except OSError:
            s.close()
        if not started:
            if not os.path.exists(os.path.join(root, DAEMON.lstrip('/'))):
                return None
            start_daemon(root, cpu)
            started = True
        if time.time() > deadline:
            return None
        time.sleep(0.2)


class Stream:
    """One open stream: the connection and the messages read from it."""

    def __init__(self, sock, driver):
        self.sock = sock
        self.fd = sock.fileno()
        self.driver = driver
        self.sid = 0
        self.msgs = collections.deque()
        self.rerror = self.werror = 0
        self.hangup = False
        self.rdopt = 0x11       # RNORM | RPROTNORM
        self.wropt = 0
        self.sigs = []          # signals the stream sent (M_SIG)
        self.sigevents = 0      # I_SETSIG

    # -- the connection --
    def send(self, op, payload):
        data = struct.pack('>II', op, len(payload)) + payload
        while data:
            try:
                n = os.write(self.fd, data)
            except InterruptedError:
                continue
            except BlockingIOError:
                import select
                select.select([], [self.fd], [])
                continue
            except OSError:
                raise StreamError(6)        # ENXIO: the daemon is gone
            data = data[n:]

    def _readn(self, n, wait):
        buf = b''
        while len(buf) < n:
            wait(self.fd)
            try:
                b = os.read(self.fd, n - len(buf))
            except InterruptedError:
                continue
            except BlockingIOError:
                continue
            except OSError:
                raise StreamError(0)
            if not b:
                raise StreamError(0)
            buf += b
        return buf

    def frame(self, wait):
        """the next message from the daemon; asynchronous ones are taken in here"""
        kind, n = struct.unpack('>II', self._readn(8, wait))
        body = self._readn(n, wait) if n else b''
        if kind == MS_MSG:
            t, band, nc, nd = struct.unpack('>IIii', body[:16])
            rest = body[16:]
            ctl = rest[:nc] if nc >= 0 else None
            data = rest[max(nc, 0):max(nc, 0) + nd] if nd >= 0 else None
            m = Msg(t, band, ctl, data)
            if t == M_PCPROTO:
                # ahead of the normal messages, as on the stream head's queue
                i = 0
                while i < len(self.msgs) and self.msgs[i].type == M_PCPROTO:
                    i += 1
                self.msgs.insert(i, m)
            else:
                self.msgs.append(m)
        elif kind == MS_FLUSH:
            if body and body[3] & FLUSHR:
                self.msgs.clear()
        elif kind == MS_ERROR:
            self.rerror, self.werror = struct.unpack('>ii', body[:8])
        elif kind == MS_HANGUP:
            self.hangup = True
        elif kind == MS_SIG:
            self.sigs.append(struct.unpack('>I', body[:4])[0])
        return kind, body

    def pending(self):
        """a whole message from the daemon is waiting to be read (or the connection is gone)"""
        import select
        r, _, _ = select.select([self.fd], [], [], 0)
        return bool(r)

    def call(self, op, payload, copyin=None, copyout=None, wait=None):
        """a request and its reply (rval, errno, data); the messages arriving meanwhile
        are kept, and a transparent ioctl's copies are made through copyin(addr, n)
        and copyout(addr, data)"""
        wait = wait or _wait_uninterruptible
        self.send(op, payload)
        while True:
            kind, body = self.frame(wait)
            if kind == MS_REPLY:
                rval, err = struct.unpack('>ii', body[:8])
                return rval, err, body[8:]
            if kind == MS_COPYIN:
                addr, n = struct.unpack('>II', body[:8])
                try:
                    data = copyin(addr, n)
                    self.send(RQ_COPYDATA, struct.pack('>i', 0) + data)
                except Exception:
                    self.send(RQ_COPYDATA, struct.pack('>i', 14))      # EFAULT
            elif kind == MS_COPYOUT:
                addr, n = struct.unpack('>II', body[:8])
                try:
                    copyout(addr, body[8:8 + n])
                    self.send(RQ_COPYDATA, struct.pack('>i', 0))
                except Exception:
                    self.send(RQ_COPYDATA, struct.pack('>i', 14))

    def open(self, flags, uid, gid, pid=0):
        rval, err, data = self.call(RQ_OPEN, struct.pack('>IIII', flags, uid, gid, pid) + self.driver.encode() + b'\0')
        if rval < 0:
            raise StreamError(err)
        # the reply's third word: the stream's number in the daemon
        self.sid = struct.unpack('>I', data[:4])[0] if len(data) >= 4 else 0
        return self.sid

    # -- what the program sees --
    def ready(self):
        """poll bits (host values): POLLIN for a normal message, POLLPRI for a priority one"""
        import select
        while self.pending():
            try:
                self.frame(_wait_none)
            except StreamError:
                self.hangup = True
                break
        ev = 0
        if self.msgs:
            ev |= select.POLLPRI if self.msgs[0].type == M_PCPROTO else select.POLLIN
        if self.hangup:
            ev |= select.POLLHUP
        if self.rerror:
            ev |= select.POLLERR
        return ev

    def wait_msg(self, nonblock, wait, pred=lambda m: True):
        """the first message that pred accepts, waiting for one unless nonblock"""
        while True:
            for m in self.msgs:
                if pred(m):
                    return m
            if self.rerror:
                raise StreamError(self.rerror)
            if self.hangup:
                return None
            if nonblock and not self.pending():
                raise StreamError(11)       # EAGAIN
            try:
                self.frame(wait)
            except StreamError as e:
                if e.errno == 0:
                    self.hangup = True
                    return None
                raise


def _wait_uninterruptible(fd):
    import select
    while True:
        try:
            r, _, _ = select.select([fd], [], [])
            if r:
                return
        except InterruptedError:
            continue


def _wait_none(fd):
    return
