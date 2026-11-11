//! streams.rs - STREAMS devices of the emulator: descriptors served by the STREAMS daemon.
//!
//! A kernel STREAMS driver product (a third-party protocol stack) runs in the root's
//! STREAMS daemon (kernel/strd.c, built by tools/mkstrd.py into /stand/hpuxemu/strd), a
//! process of the emulator like any other. Opening one of its devices connects to the
//! daemon's socket; the connection is the stream, with its stream head in the daemon. This
//! module is the descriptor's side: putmsg/getmsg, read/write, the STREAMS ioctls, and
//! poll. The messages that reach the stream head come here as they arrive and wait in
//! `Stream.msgs` until the program reads them.
//!
//! ROOT/etc/hpuxemu/streams names the devices: one line per device, "path driver [major
//! minor]" - with the numbers, stat shows the path as that character device (HP-UX's clone
//! driver, major 72, opens STREAMS drivers; the minor is the driver's major). A driver "-"
//! is a device node only: it stats, but does not open. The daemon is started on the first
//! open when it is not running; its output goes to ROOT/var/adm/strd.log.
//!
//! 11.00's /dev/ip, /dev/nuls, /dev/dlpi and /dev/lanN are streams the emulator answers
//! itself (netman.rs).

use crate::consts::*;
use crate::emsg;
use crate::host::{self, cstr};
use crate::netman::{Mib, Netman};
use crate::process::*;
use crate::syscalls::Handler;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

pub const TABLE: &[(&str, Handler)] = &[
    ("putmsg", Process::sys_putmsg),
    ("putpmsg", Process::sys_putpmsg),
    ("getmsg", Process::sys_getmsg),
    ("getpmsg", Process::sys_getpmsg),
];

const SOCK: &str = "/var/spool/sockets/streams";
const DAEMON: &str = "/stand/hpuxemu/strd";

// requests and messages: kernel/strd.c
pub const RQ_OPEN: u32 = 1;
pub const RQ_PUTMSG: u32 = 2;
pub const RQ_IOCTL: u32 = 3;
pub const RQ_COPYDATA: u32 = 4;
pub const RQ_CLOSE: u32 = 5;
const MS_REPLY: u32 = 1;
const MS_MSG: u32 = 2;
const MS_FLUSH: u32 = 3;
const MS_ERROR: u32 = 4;
const MS_HANGUP: u32 = 5;
const MS_SIG: u32 = 6;
const MS_COPYIN: u32 = 7;
const MS_COPYOUT: u32 = 8;

pub const M_PROTO: u32 = 0x01;
pub const M_PCPROTO: u32 = 0x83;

// HP-UX's libnsl sends a TPI request and waits for its acknowledgement with one ioctl:
// I_ASYNC_ACK, or _IO('S', 99) (not in the headers). The argument (20 bytes): {short ack,
// short ack2, int ctl_len, int data_len, char *ctl, char *data}: ctl_len bytes of ctl
// (data_len of data, -1 none) go down as one message, and the first acknowledgement that
// is ack, ack2 or T_ERROR_ACK comes back in the same buffers, the lengths updated.
const I_TPI_ACK: u32 = 0x2000_5363;
const I_ASYNC_ACK: u32 = 0x2000_5352;
const I_GET_QLEN: u32 = 0x2000_535f; // 11.00
const I_XTI_USND: u32 = 0x2000_585d; // 11.00: t_sndudata
const I_XTI_URCV: u32 = 0x2000_585e; // 11.00: t_rcvudata
const I_ASYNC_ACK_NEW: u32 = 0x2000_5353; // 11.00: XTI t_sync()'s; the same argument as I_ASYNC_ACK
const I_SET_XTI: u32 = 0x2000_5354;
const I_GET_STH_WROFF: u32 = 0x2000_5355;
const I_GET_STRMSGSZ: u32 = 0x2000_5356;
const I_GET_STRCTLSZ: u32 = 0x2000_5357;
const I_GET_PUSHCNT: u32 = 0x2000_5358;
const I_SET_HIWAT: u32 = 0x2000_535b;
const I_SET_LOWAT: u32 = 0x2000_535c;
const I_GET_HIWAT: u32 = 0x2000_5361;
const I_GET_LOWAT: u32 = 0x2000_5362;
// HP-UX 10.20's defaults of the tunables
const STRMSGSZ: u32 = 65535;
const STRCTLSZ: u32 = 1024;
// HP-UX's libnsl sends and receives connection data (t_snd, t_rcv) with two ioctls of its
// own, I_XTI_SND and I_XTI_RCV ('X' 89, 90), not putmsg/getmsg. The argument, read from
// the callers in libnsl_s.1: {int 0, int 4, int flags, int len, int 16, char *buf}, flags
// T_MORE (1) and T_EXPEDITED (2) in and out, T_MOREDATA (0x10000000) out when bytes of the
// message are left. SND sends T_DATA_REQ or T_EXDATA_REQ with the bytes; RCV puts the
// bytes of the T_DATA_IND or T_EXDATA_IND at the head of the stream in buf and their count
// in len (libnsl reads it there). Anything else there (a disconnect, an orderly release)
// fails with EIO, which libnsl turns into TLOOK; no data on a non-blocking stream is
// EAGAIN (TNODATA).
const I_XTI_SND: u32 = 0x2000_5859;
const I_XTI_RCV: u32 = 0x2000_585a;
const T_DATA_REQ: u32 = 4;
const T_EXDATA_REQ: u32 = 6;
const T_DATA_IND: i32 = 23;
const T_EXDATA_IND: i32 = 26;

#[derive(Debug, Clone)]
pub struct Msg {
    pub typ: u32,
    pub band: u32,
    pub ctl: Option<Vec<u8>>,
    pub data: Option<Vec<u8>>,
}

/// One open stream: the connection and the messages read from it.
#[allow(dead_code)]
pub struct Stream {
    pub fd: i32,
    pub driver: String,
    pub sid: u32,
    pub msgs: VecDeque<Msg>,
    pub rerror: u32,
    pub werror: u32,
    pub hangup: bool,
    pub rdopt: u32,
    pub wropt: u32,
    /// signals the stream sent (M_SIG)
    pub sigs: Vec<u32>,
    /// I_SETSIG
    pub sigevents: u32,
    /// a stream the emulator answers itself (11.00's MIB-2 devices)
    pub mib: Option<Mib>,
}

pub type StreamRef = Rc<RefCell<Stream>>;

/// how a read from the daemon waits
#[derive(Clone, Copy, PartialEq)]
enum Wait {
    /// until there is something, whatever signals arrive
    Unint,
    /// not at all (something is known to be there)
    No,
    /// a signal interrupts: EINTR
    Sig,
}

/// why a stream operation stopped: the connection is gone (StreamError(0)), an errno of
/// the stream, or what ends the system call
enum SErr {
    Gone,
    Errno(u32),
    Stop(Stop),
}

fn gb32(b: &[u8], o: usize) -> u32 {
    if o + 4 <= b.len() {
        be32(b, o)
    } else {
        0
    }
}

fn i32be(v: i32) -> [u8; 4] {
    v.to_be_bytes()
}

fn readable(fd: i32, timeout_ms: i32) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    loop {
        let r = unsafe { libc::poll(&mut p, 1, timeout_ms) };
        if r < 0 && host::errno() == libc::EINTR {
            if timeout_ms == 0 {
                return false;
            }
            continue;
        }
        return r > 0;
    }
}

/// {guest path: (driver, (major, minor) as an HP-UX device number or None)} from
/// ROOT/etc/hpuxemu/streams
fn devices(root: &str) -> HashMap<String, (String, Option<u32>)> {
    let mut out = HashMap::new();
    let num = |s: &str| -> Option<u64> {
        if let Some(h) = s.strip_prefix("0x") {
            u64::from_str_radix(h, 16).ok()
        } else if s.len() > 1 && s.starts_with('0') {
            u64::from_str_radix(&s[1..].trim_start_matches('o'), 8).ok()
        } else {
            s.parse().ok()
        }
    };
    if let Ok(txt) = std::fs::read_to_string(format!("{}/etc/hpuxemu/streams", root)) {
        for line in txt.lines() {
            let w: Vec<&str> = line.split_whitespace().collect();
            if w.len() >= 2 && !w[0].starts_with('#') {
                let rdev = if w.len() >= 4 {
                    match (num(w[2]), num(w[3])) {
                        (Some(ma), Some(mi)) => Some((((ma & 0xFF) << 24) | (mi & 0xFF_FFFF)) as u32),
                        _ => return HashMap::new(),
                    }
                } else {
                    None
                };
                out.insert(w[0].to_string(), (w[1].to_string(), rdev));
            }
        }
    }
    out
}

/// a stat result for a device node of the table (rdev: the HP-UX device number)
pub fn node_stat(rdev: Option<u32>, path: &str) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let now = host::now_f64() as i64;
    let rdev = rdev.unwrap_or(0);
    st.st_mode = 0o020666;
    // (any stable number for the path)
    st.st_ino = path.bytes().fold(5381u64, |h, c| h.wrapping_mul(33) ^ c as u64) & 0xFF_FFFF;
    st.st_dev = libc::makedev(64, 0);
    st.st_nlink = 1;
    st.st_rdev = libc::makedev(rdev >> 24, rdev & 0xFF_FFFF);
    st.st_atime = now;
    st.st_mtime = now;
    st.st_ctime = now;
    st.st_ctime_nsec = -1; // made up: see process::is_fake
    st.st_blksize = 8192;
    st
}

/// /dev/ip, /dev/nuls, /dev/dlpi, /dev/lanN
pub fn is_mib_device(gabs: &str) -> bool {
    match gabs.strip_prefix("/dev/") {
        Some("ip") | Some("nuls") | Some("dlpi") => true,
        Some(n) => n.len() > 3 && n.starts_with("lan") && n[3..].bytes().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// the daemon of the root, as a detached process of the emulator
fn start_daemon(root: &str) {
    let log = unsafe { libc::open(cstr(&format!("{}/var/adm/strd.log", root)).as_ptr(), libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT, 0o644) };
    if log < 0 {
        return;
    }
    let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "hpuxemu".to_string());
    let mut args: Vec<String> = vec![exe, "-r".to_string(), root.to_string(), DAEMON.to_string()];
    // more of strd's options (-m station address, -n NMID ...)
    if let Some(more) = host::getenv("HPUXEMU_STRD_ARGS") {
        args.extend(more.split_whitespace().map(|s| s.to_string()));
    }
    if let Some(t) = host::getenv("HPUXEMU_STRD_TRACE").filter(|t| !t.is_empty()) {
        args.push(if t == "2" { "-tt" } else { "-t" }.to_string());
    }
    if let Some(w) = host::getenv("HPUXEMU_WIRE").filter(|w| !w.is_empty()) {
        args.push("-e".to_string());
        args.push(w);
    }
    let cargs: Vec<std::ffi::CString> = args.iter().map(|a| cstr(a)).collect();
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            // a session of its own; the grandchild is the daemon, so that nobody has to
            // wait for it
            libc::setsid();
            if libc::fork() != 0 {
                libc::_exit(0);
            }
            let null = libc::open(cstr("/dev/null").as_ptr(), libc::O_RDONLY);
            libc::dup2(null, 0);
            libc::dup2(log, 1);
            libc::dup2(log, 2);
            for fd in 3..1024 {
                libc::close(fd);
            }
            libc::unsetenv(cstr("HPUXEMU_TRACE").as_ptr());
            for s in 1..32 {
                libc::signal(s, libc::SIG_DFL);
            }
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            libc::execv(ptrs[0], ptrs.as_ptr());
            libc::_exit(127);
        }
        libc::close(log);
        if pid > 0 {
            let mut st = 0;
            while libc::waitpid(pid, &mut st, 0) < 0 && host::errno() == libc::EINTR {}
        }
    }
}

/// a connection to the daemon, starting it when needed; None when the root has no daemon.
/// $HPUXEMU_STREAMS names another daemon's socket (a guest path), one started by hand (a
/// second stack for a test, say): that one is not started here.
fn connect(root: &str) -> Option<i32> {
    let other = host::getenv("HPUXEMU_STREAMS").filter(|o| !o.is_empty());
    let path = format!("{}/{}", root, other.as_deref().unwrap_or(SOCK).trim_start_matches('/'));
    let mut started = other.is_some();
    let deadline = host::now_f64() + 30.0;
    loop {
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if s < 0 {
            return None;
        }
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as u16;
        if path.len() < sa.sun_path.len() {
            for (i, c) in path.bytes().enumerate() {
                sa.sun_path[i] = c as libc::c_char;
            }
            if host::retry(|| unsafe { libc::connect(s, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_un>() as u32) as isize }) == 0 {
                return Some(s);
            }
        }
        unsafe { libc::close(s) };
        if !started {
            if !host::exists(&format!("{}{}", root, DAEMON)) {
                return None;
            }
            start_daemon(root);
            started = true;
        }
        if host::now_f64() > deadline {
            return None;
        }
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 200_000_000 };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    }
}

impl Stream {
    fn new(fd: i32, driver: &str, mib: Option<Mib>) -> Stream {
        Stream { fd, driver: driver.to_string(), sid: 0, msgs: VecDeque::new(), rerror: 0, werror: 0, hangup: false, rdopt: 0x11, wropt: 0, sigs: Vec::new(), sigevents: 0, mib }
    }

    // -- the connection --
    fn send(&mut self, op: u32, payload: &[u8]) -> Result<(), SErr> {
        let mut data = op.to_be_bytes().to_vec();
        data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        data.extend_from_slice(payload);
        let mut off = 0;
        while off < data.len() {
            let n = unsafe { libc::write(self.fd, data[off..].as_ptr() as *const libc::c_void, data.len() - off) };
            if n < 0 {
                match host::errno() {
                    libc::EINTR => continue,
                    libc::EAGAIN => {
                        let mut p = libc::pollfd { fd: self.fd, events: libc::POLLOUT, revents: 0 };
                        unsafe { libc::poll(&mut p, 1, -1) };
                        continue;
                    }
                    _ => return Err(SErr::Errno(6)), // ENXIO: the daemon is gone
                }
            }
            off += n as usize;
        }
        Ok(())
    }

    /// a whole message from the daemon is waiting to be read (or the connection is gone)
    fn pending(&self) -> bool {
        self.mib.is_none() && readable(self.fd, 0)
    }
}

impl Process {
    pub fn stream_devices(&mut self) -> Rc<HashMap<String, (String, Option<u32>)>> {
        if self.stream_devs.is_none() {
            self.stream_devs = Some(Rc::new(devices(&self.root)));
        }
        self.stream_devs.clone().unwrap()
    }

    fn sread(&mut self, st: &StreamRef, n: usize, wait: Wait) -> Result<Vec<u8>, SErr> {
        let fd = st.borrow().fd;
        let mut buf = vec![0u8; n];
        let mut got = 0;
        while got < n {
            match wait {
                Wait::Unint => {
                    readable(fd, -1);
                }
                Wait::Sig => {
                    // wait for the daemon (a signal interrupts: EINTR)
                    let rev = self.host_poll(&[(fd, libc::POLLIN)], -1).map_err(SErr::Stop)?;
                    if rev[0] & libc::POLLNVAL != 0 {
                        return Err(SErr::Stop(Stop::Errno(EBADF)));
                    }
                }
                Wait::No => {}
            }
            let r = unsafe { libc::read(fd, buf[got..].as_mut_ptr() as *mut libc::c_void, n - got) };
            if r < 0 {
                match host::errno() {
                    libc::EINTR | libc::EAGAIN => continue,
                    _ => return Err(SErr::Gone),
                }
            }
            if r == 0 {
                return Err(SErr::Gone);
            }
            got += r as usize;
        }
        Ok(buf)
    }

    /// the next message from the daemon; asynchronous ones are taken in here
    fn frame(&mut self, st: &StreamRef, wait: Wait) -> Result<(u32, Vec<u8>), SErr> {
        let h = self.sread(st, 8, wait)?;
        let (kind, n) = (be32(&h, 0), be32(&h, 4) as usize);
        let body = if n != 0 { self.sread(st, n, wait)? } else { Vec::new() };
        let mut s = st.borrow_mut();
        match kind {
            MS_MSG if body.len() >= 16 => {
                let (t, band, nc, nd) = (be32(&body, 0), be32(&body, 4), be32(&body, 8) as i32, be32(&body, 12) as i32);
                let rest = &body[16..];
                let cl = (nc.max(0) as usize).min(rest.len());
                let ctl = if nc >= 0 { Some(rest[..cl].to_vec()) } else { None };
                let data = if nd >= 0 { Some(rest[cl..(cl + nd as usize).min(rest.len())].to_vec()) } else { None };
                let m = Msg { typ: t, band, ctl, data };
                if t == M_PCPROTO {
                    // ahead of the normal messages, as on the stream head's queue
                    let i = s.msgs.iter().take_while(|m| m.typ == M_PCPROTO).count();
                    s.msgs.insert(i, m);
                } else {
                    s.msgs.push_back(m);
                }
            }
            MS_FLUSH => {
                if body.len() >= 4 && body[3] & 1 != 0 {
                    s.msgs.clear(); // FLUSHR
                }
            }
            MS_ERROR => {
                s.rerror = gb32(&body, 0);
                s.werror = gb32(&body, 4);
            }
            MS_HANGUP => s.hangup = true,
            MS_SIG => {
                let v = gb32(&body, 0);
                s.sigs.push(v);
            }
            _ => {}
        }
        Ok((kind, body))
    }

    /// take in what the daemon has sent
    fn stream_ready(&mut self, st: &StreamRef) {
        while st.borrow().pending() {
            if self.frame(st, Wait::No).is_err() {
                st.borrow_mut().hangup = true;
                break;
            }
        }
    }

    /// the index of the first message that pred accepts, waiting for one unless nonblock;
    /// None: the stream hung up
    fn wait_msg(&mut self, st: &StreamRef, nonblock: bool, wait: Wait, pred: &dyn Fn(&Msg) -> bool) -> Res<Option<usize>> {
        loop {
            {
                let s = st.borrow();
                if let Some(i) = s.msgs.iter().position(pred) {
                    return Ok(Some(i));
                }
                if s.mib.is_some() {
                    return err(EAGAIN); // nothing will come: EAGAIN rather than a wait forever
                }
                if s.rerror != 0 {
                    return err(s.rerror);
                }
                if s.hangup {
                    return Ok(None);
                }
                if nonblock && !s.pending() {
                    return err(EAGAIN);
                }
            }
            match self.frame(st, wait) {
                Ok(_) => {}
                Err(SErr::Gone) => {
                    st.borrow_mut().hangup = true;
                    return Ok(None);
                }
                Err(SErr::Errno(e)) => return err(if e != 0 { e } else { ENXIO }),
                Err(SErr::Stop(s)) => return Err(s),
            }
        }
    }

    /// a request and its reply (rval, data); the messages arriving meanwhile are kept, and
    /// a transparent ioctl's copies are made from and to the guest's memory
    fn stream_call(&mut self, st: &StreamRef, op: u32, payload: &[u8]) -> Res<(i32, Vec<u8>)> {
        let (rval, e, data) = self.stream_call_raw(st, op, payload)?;
        if rval < 0 {
            return err(if e != 0 { e } else { EINVAL });
        }
        Ok((rval, data))
    }

    fn stream_call_raw(&mut self, st: &StreamRef, op: u32, payload: &[u8]) -> Res<(i32, u32, Vec<u8>)> {
        if st.borrow().mib.is_some() {
            let me: *mut Process = self;
            let mut s = st.borrow_mut();
            let s = &mut *s;
            // (the tables are read when a request asks for them)
            let nm = || unsafe { (*me).mib_netman(true) };
            return Ok(s.mib.as_mut().unwrap().call(&nm, op, payload, &mut s.msgs));
        }
        let gone = |e: SErr| match e {
            SErr::Gone => Stop::Errno(ENXIO),
            SErr::Errno(e) => Stop::Errno(if e != 0 { e } else { ENXIO }),
            SErr::Stop(s) => s,
        };
        st.borrow_mut().send(op, payload).map_err(gone)?;
        loop {
            let (kind, body) = self.frame(st, Wait::Unint).map_err(gone)?;
            if kind == MS_REPLY {
                return Ok((gb32(&body, 0) as i32, gb32(&body, 4), body[8.min(body.len())..].to_vec()));
            }
            if kind == MS_COPYIN {
                let (addr, n) = (gb32(&body, 0), gb32(&body, 4));
                let reply = match self.rd(addr, n as usize) {
                    Ok(d) => {
                        let mut r = vec![0u8; 4];
                        r.extend(d);
                        r
                    }
                    Err(_) => i32be(14).to_vec(), // EFAULT
                };
                st.borrow_mut().send(RQ_COPYDATA, &reply).map_err(gone)?;
            } else if kind == MS_COPYOUT {
                let (addr, n) = (gb32(&body, 0), gb32(&body, 4) as usize);
                let d = &body[8.min(body.len())..(8 + n).min(body.len())];
                let r = if self.wr(addr, d).is_ok() { 0 } else { 14 };
                st.borrow_mut().send(RQ_COPYDATA, &i32be(r)).map_err(gone)?;
            }
        }
    }

    /// a STREAMS device: a connection to the daemon, which opens the driver; None when the
    /// root has no daemon (then the path is an ordinary one)
    pub fn open_stream(&mut self, gabs: &str, flags: u32) -> Res<Option<u32>> {
        let sock = match connect(&self.root) {
            Some(s) => s,
            None => return Ok(None),
        };
        let driver = self.stream_devices()[gabs].0.clone();
        let st = Rc::new(RefCell::new(Stream::new(sock, &driver, None)));
        let mut payload = Vec::new();
        for v in [flags, self.euid, self.egid, self.pid] {
            payload.extend_from_slice(&v.to_be_bytes());
        }
        payload.extend_from_slice(driver.as_bytes());
        payload.push(0);
        match self.stream_call_raw(&st, RQ_OPEN, &payload) {
            Ok((rval, _, data)) if rval >= 0 => {
                // the reply's third word: the stream's number in the daemon
                st.borrow_mut().sid = gb32(&data, 0);
            }
            Ok((_, e, _)) => {
                unsafe { libc::close(sock) };
                return err(if e != 0 { e } else { ENXIO });
            }
            Err(e) => {
                unsafe { libc::close(sock) };
                return Err(e);
            }
        }
        self.newfd(sock, gabs, flags);
        if self.trace {
            emsg!("[{}] open {}: stream {} of the STREAMS daemon\n", self.pid, gabs, st.borrow().sid);
        }
        self.fds.get_mut(&(sock as u32)).unwrap().stream = Some(st);
        Ok(Some(sock as u32))
    }

    /// 11.00's /dev/ip (and /dev/nuls, where libnm pushes tcpm and udpm): a stream the
    /// emulator answers itself, MIB-2 for libnm's mibget (netman::Mib). The host
    /// descriptor is an eventfd, never readable, so a poll waits on the messages.
    pub fn open_mib_stream(&mut self, gabs: &str, flags: u32) -> Res<u32> {
        let r = unsafe { libc::eventfd(0, 0) };
        if r < 0 {
            return Err(herr());
        }
        let driver = gabs.rsplit('/').next().unwrap_or("");
        let st = Stream::new(r, driver, Some(Mib::new(driver)));
        self.newfd(r, gabs, flags);
        self.fds.get_mut(&(r as u32)).unwrap().stream = Some(Rc::new(RefCell::new(st)));
        Ok(r as u32)
    }

    /// the host's MIB-2 tables (netman::Netman): /dev/netman's, or 11.00's /dev/ip's
    /// (lan_first: numbered as 11.00 numbers the interfaces)
    pub fn mib_netman(&mut self, lan_first: bool) -> Rc<Netman> {
        if let Some(n) = &self.netmans[lan_first as usize] {
            return n.clone();
        }
        let ifs = self.interfaces();
        let n = Rc::new(Netman::new(ifs, self.now() - 3600.0 - self.clock_offset as f64, self.is11, lan_first));
        self.netmans[lan_first as usize] = Some(n.clone());
        n
    }

    /// the Stream of a descriptor (None for any other), set to use this descriptor
    pub fn stream_of(&mut self, fd: u32) -> Option<StreamRef> {
        let st = self.fds.get(&fd)?.stream.clone()?;
        st.borrow_mut().fd = fd as i32;
        Some(st)
    }

    fn stream_nonblock(&self, fd: u32) -> bool {
        self.fds[&fd].flags & (O_NONBLOCK | O_NDELAY) != 0
    }

    pub fn stream_put(&mut self, _fd: u32, st: StreamRef, ctl: Option<&[u8]>, data: &[u8], band: u32, hipri: bool) -> Res<()> {
        self.stream_put2(&st, ctl, Some(data), band, hipri)
    }

    fn stream_put2(&mut self, st: &StreamRef, ctl: Option<&[u8]>, data: Option<&[u8]>, band: u32, hipri: bool) -> Res<()> {
        {
            let s = st.borrow();
            if s.hangup {
                return err(ENXIO);
            }
            if s.werror != 0 {
                return err(s.werror);
            }
        }
        if hipri && ctl.is_none() {
            return err(EINVAL);
        }
        if ctl.is_none() && data.is_none() {
            return Ok(());
        }
        let mut p = Vec::new();
        p.extend_from_slice(&i32be(hipri as i32));
        p.extend_from_slice(&band.to_be_bytes());
        p.extend_from_slice(&i32be(ctl.map(|c| c.len() as i32).unwrap_or(-1)));
        p.extend_from_slice(&i32be(data.map(|d| d.len() as i32).unwrap_or(-1)));
        p.extend_from_slice(ctl.unwrap_or(&[]));
        p.extend_from_slice(data.unwrap_or(&[]));
        self.stream_call(st, RQ_PUTMSG, &p)?;
        Ok(())
    }

    /// a struct strbuf to send: its bytes, None for no part
    fn strbuf_in(&self, ptr: u32) -> Res<Option<Vec<u8>>> {
        if ptr == 0 {
            return Ok(None);
        }
        let d = self.rd(ptr, 12)?;
        let ln = be32(&d, 4) as i32;
        if ln < 0 {
            return Ok(None);
        }
        Ok(Some(self.rd(be32(&d, 8), ln as usize)?))
    }

    /// putmsg(fd, ctlptr, dataptr, flags): a message down a stream (RS_HIPRI: M_PCPROTO)
    pub fn sys_putmsg(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let st = match self.stream_of(a[0]) {
            Some(s) => s,
            None => return err(ENOSTR),
        };
        if a[3] & !RS_HIPRI != 0 {
            return err(EINVAL);
        }
        let (c, d) = (self.strbuf_in(a[1])?, self.strbuf_in(a[2])?);
        self.stream_put2(&st, c.as_deref(), d.as_deref(), 0, a[3] & RS_HIPRI != 0)?;
        ok(0)
    }

    /// putpmsg(fd, ctlptr, dataptr, band, flags): putmsg with a priority band (MSG_BAND)
    /// or MSG_HIPRI
    pub fn sys_putpmsg(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let st = match self.stream_of(a[0]) {
            Some(s) => s,
            None => return err(ENOSTR),
        };
        let (band, flags) = (a[3], a[4]);
        let hipri = flags == MSG_HIPRI;
        if (flags != MSG_HIPRI && flags != MSG_BAND) || (hipri && band != 0) {
            return err(EINVAL);
        }
        let (c, d) = (self.strbuf_in(a[1])?, self.strbuf_in(a[2])?);
        self.stream_put2(&st, c.as_deref(), d.as_deref(), band, hipri)?;
        ok(0)
    }

    /// one part of a message into the caller's strbuf: what is left of it, and whether
    /// MORECTL/MOREDATA applies
    fn msg_part(&mut self, ptr: u32, val: Option<Vec<u8>>) -> Res<(Option<Vec<u8>>, bool)> {
        if ptr == 0 {
            let more = val.is_some();
            return Ok((val, more));
        }
        let d = self.rd(ptr, 12)?;
        let (maxlen, buf) = (be32(&d, 0) as i32, be32(&d, 8));
        let val = match val {
            Some(v) => v,
            None => {
                self.wr(ptr + 4, &i32be(-1))?;
                return Ok((None, false));
            }
        };
        if maxlen < 0 {
            return Ok((Some(val), true));
        }
        let n = (maxlen as usize).min(val.len());
        if n != 0 {
            self.wr(buf, &val[..n])?;
        }
        self.wr(ptr + 4, &i32be(n as i32))?;
        if n < val.len() {
            return Ok((Some(val[n..].to_vec()), true));
        }
        Ok((None, false))
    }

    /// the common part of getmsg/getpmsg: the message's (type, band), the return value
    /// (MORECTL, MOREDATA)
    fn stream_get(&mut self, fd: u32, ctlp: u32, datap: u32, pred: &dyn Fn(&Msg) -> bool) -> Res<(Option<(u32, u32)>, u32)> {
        let st = match self.stream_of(fd) {
            Some(s) => s,
            None => return err(ENOSTR),
        };
        let nb = self.stream_nonblock(fd);
        let i = match self.wait_msg(&st, nb, Wait::Sig, pred)? {
            Some(i) => i,
            None => {
                // hung up: an empty message, end of file
                for ptr in [ctlp, datap] {
                    if ptr != 0 {
                        self.wr(ptr + 4, &i32be(0))?;
                    }
                }
                return Ok((None, 0));
            }
        };
        let (typ, band, ctl, data) = {
            let mut s = st.borrow_mut();
            let m = &mut s.msgs[i];
            (m.typ, m.band, m.ctl.take(), m.data.take())
        };
        let mut ret = 0;
        let (ctl, more) = self.msg_part(ctlp, ctl)?;
        if more {
            ret |= MORECTL;
        }
        let (data, more) = self.msg_part(datap, data)?;
        if more {
            ret |= MOREDATA;
        }
        let mut s = st.borrow_mut();
        if ctl.is_none() && data.is_none() {
            s.msgs.remove(i);
        } else {
            s.msgs[i].ctl = ctl;
            s.msgs[i].data = data;
        }
        Ok((Some((typ, band)), ret))
    }

    /// getmsg(fd, ctlptr, dataptr, flagsp): the next message of a stream (*flagsp
    /// RS_HIPRI: a priority one); MORECTL/MOREDATA when parts are left
    pub fn sys_getmsg(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let want = self.rd32(a[3])?;
        if want & !RS_HIPRI != 0 {
            return err(EINVAL);
        }
        let pred: &dyn Fn(&Msg) -> bool = if want != 0 { &|m: &Msg| m.typ == M_PCPROTO } else { &|_: &Msg| true };
        let (m, ret) = self.stream_get(a[0], a[1], a[2], pred)?;
        self.wr32(a[3], if matches!(m, Some((M_PCPROTO, _))) { RS_HIPRI } else { 0 })?;
        ok(ret)
    }

    /// getpmsg(fd, ctlptr, dataptr, bandp, flagsp): getmsg by band (MSG_ANY, MSG_BAND,
    /// MSG_HIPRI)
    pub fn sys_getpmsg(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let want = self.rd32(a[4])?;
        let band = self.rd32(a[3])?;
        let by_band = move |m: &Msg| m.typ == M_PCPROTO || m.band as i32 >= band as i32;
        let pred: &dyn Fn(&Msg) -> bool = if want == MSG_HIPRI {
            &|m: &Msg| m.typ == M_PCPROTO
        } else if want == MSG_BAND {
            &by_band
        } else if want == MSG_ANY {
            &|_: &Msg| true
        } else {
            return err(EINVAL);
        };
        let (m, ret) = self.stream_get(a[0], a[1], a[2], pred)?;
        if let Some((typ, band)) = m {
            self.wr32(a[3], band)?;
            self.wr32(a[4], if typ == M_PCPROTO { MSG_HIPRI } else { MSG_BAND })?;
        }
        ok(ret)
    }

    /// read(2) on a stream, by the read mode (I_SRDOPT)
    pub fn stream_read(&mut self, fd: u32, st: StreamRef, buf: u32, n: u32) -> SysResult {
        let n = n as usize;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let nb = self.stream_nonblock(fd) || !out.is_empty();
            let i = match self.wait_msg(&st, nb, Wait::Sig, &|_| true) {
                Ok(Some(i)) => i,
                Ok(None) => break,
                Err(e) => {
                    if !out.is_empty() {
                        break;
                    }
                    return Err(e);
                }
            };
            let mut s = st.borrow_mut();
            let rdopt = s.rdopt;
            let m = &mut s.msgs[i];
            if let Some(c) = m.ctl.take() {
                if rdopt & RPROTDAT != 0 {
                    let mut d = c;
                    d.extend(m.data.take().unwrap_or_default());
                    m.data = Some(d);
                } else if rdopt & RPROTDIS != 0 {
                    // the control part is discarded
                } else {
                    m.ctl = Some(c);
                    if !out.is_empty() {
                        break;
                    }
                    return err(EBADMSG);
                }
            }
            let data = m.data.take().unwrap_or_default();
            let take = data.len().min(n - out.len());
            out.extend_from_slice(&data[..take]);
            let rest = data[take..].to_vec();
            let empty = rest.is_empty();
            m.data = Some(rest);
            if empty || rdopt & RMSGD != 0 {
                s.msgs.remove(i);
            }
            if rdopt & RNORM == 0 || out.len() >= n || data.is_empty() {
                break;
            }
            if s.msgs.is_empty() {
                break;
            }
        }
        if !out.is_empty() {
            self.wr(buf, &out)?;
        }
        ok(out.len() as u32)
    }

    fn ioc(&mut self, st: &StreamRef, req: u32, arg: u32, body: &[u8]) -> Res<(i32, Vec<u8>)> {
        let mut p = Vec::new();
        p.extend_from_slice(&req.to_be_bytes());
        p.extend_from_slice(&arg.to_be_bytes());
        p.extend_from_slice(&(body.len() as u32).to_be_bytes());
        p.extend_from_slice(body);
        self.stream_call(st, RQ_IOCTL, &p)
    }

    /// the STREAMS ioctls; others go down the stream as transparent ioctls
    pub fn stream_ioctl(&mut self, fd: u32, st: StreamRef, req: u32, arg: u32) -> Res<u32> {
        let st = &st;
        if req == I_STR {
            let d = self.rd(arg, 16)?;
            let (cmd, tmo, ln, dp) = (be32(&d, 0), be32(&d, 4), be32(&d, 8) as i32, be32(&d, 12));
            let data = if ln > 0 { self.rd(dp, ln as usize)? } else { Vec::new() };
            let mut body = Vec::new();
            body.extend_from_slice(&cmd.to_be_bytes());
            body.extend_from_slice(&tmo.to_be_bytes());
            body.extend_from_slice(&i32be(ln));
            body.extend_from_slice(&data);
            let (rval, out) = self.ioc(st, req, 0, &body)?;
            if !out.is_empty() {
                self.wr(dp, &out)?;
            }
            self.wr(arg + 8, &i32be(out.len() as i32))?;
            return Ok(rval as u32);
        }
        if req == I_TPI_ACK || req == I_ASYNC_ACK || req == I_ASYNC_ACK_NEW {
            return self.stream_tpi_ack(st, arg);
        }
        // HP-UX's stream head queries (sys/stropts.h): the answer in *arg
        if [I_GET_STH_WROFF, I_GET_STRMSGSZ, I_GET_STRCTLSZ, I_GET_PUSHCNT, I_GET_HIWAT, I_GET_LOWAT].contains(&req) {
            let v = match req {
                I_GET_PUSHCNT => (self.ioc(st, I_LIST, 0, &[])?.0 - 1) as u32,
                I_GET_STH_WROFF => 0,
                I_GET_STRMSGSZ => STRMSGSZ,
                I_GET_STRCTLSZ => STRCTLSZ,
                I_GET_HIWAT => 65536,
                _ => 8192,
            };
            self.wr32(arg, v)?;
            return Ok(0);
        }
        if req == I_SET_XTI || req == I_SET_HIWAT || req == I_SET_LOWAT {
            return Ok(0);
        }
        if req == I_XTI_USND {
            // 11.00's t_sndudata: {?, ?, flags, ctl length, data length, ctl, data} - a
            // T_UNITDATA_REQ and the datagram, as putmsg would send them
            let d = self.rd(arg + 8, 20)?;
            let (clen, dlen, cbuf, dbuf) = (be32(&d, 4) as i32, be32(&d, 8) as i32, be32(&d, 12), be32(&d, 16));
            let ctl = if clen > 0 { self.rd(cbuf, clen as usize)? } else { Vec::new() };
            let data = if dbuf != 0 && dlen >= 0 { self.rd(dbuf, dlen as usize)? } else { Vec::new() };
            self.stream_put2(st, Some(&ctl), Some(&data), 0, false)?;
            return Ok(0);
        }
        if req == I_XTI_URCV {
            return self.stream_xti_urcv(fd, st, arg);
        }
        if req == I_GET_QLEN {
            // 11.00: the messages waiting at the stream head
            self.stream_ready(st);
            let n = st.borrow().msgs.len() as u32;
            self.wr32(arg, n)?;
            return Ok(0);
        }
        if req == I_PUSH || req == I_FIND {
            let mut name = self.rdbytes(arg, 4096)?;
            name.truncate(8);
            return Ok(self.ioc(st, req, 0, &name)?.0 as u32);
        }
        if req == I_LOOK {
            let (rval, out) = self.ioc(st, req, 0, &[])?;
            self.wr(arg, &out[..out.len().min(9)])?;
            return Ok(rval as u32);
        }
        if req == I_LIST {
            let (rval, out) = self.ioc(st, req, 0, &[])?;
            if arg != 0 {
                let d = self.rd(arg, 8)?;
                let (n, lst) = (be32(&d, 0) as i32, be32(&d, 4));
                let k = n.min(rval).max(0);
                self.wr(lst, &out[..out.len().min(9 * k as usize)])?;
                self.wr(arg, &i32be(k))?;
                return Ok(0);
            }
            return Ok(rval as u32);
        }
        if req == I_FDINSERT {
            // struct strfdinsert: ctlbuf, databuf, flags, fildes, offset; the daemon puts
            // the queue of the other stream at offset (t_accept's ACCEPTOR_id)
            let d = self.rd(arg, 36)?;
            let (clen, cbuf, dlen, dbuf) = (be32(&d, 4) as i32, be32(&d, 8), be32(&d, 16) as i32, be32(&d, 20));
            let (flags, other, off) = (be32(&d, 24), be32(&d, 28) as i32, be32(&d, 32));
            let ost = if other >= 0 { self.fds.get(&(other as u32)).and_then(|f| f.stream.clone()) } else { None };
            let ost = match ost {
                Some(o) if clen >= 0 => o,
                _ => return err(EINVAL),
            };
            let ctl = self.rd(cbuf, clen as usize)?;
            let has_data = dbuf != 0 && dlen >= 0;
            let data = if has_data { self.rd(dbuf, dlen as usize)? } else { Vec::new() };
            let mut p = Vec::new();
            p.extend_from_slice(&flags.to_be_bytes());
            p.extend_from_slice(&ost.borrow().sid.to_be_bytes());
            p.extend_from_slice(&off.to_be_bytes());
            p.extend_from_slice(&i32be(clen));
            p.extend_from_slice(&i32be(if has_data { dlen } else { -1 }));
            p.extend_from_slice(&ctl);
            p.extend_from_slice(&data);
            st.borrow_mut().fd = fd as i32;
            return Ok(self.ioc(st, req, 0, &p)?.0 as u32);
        }
        if req == I_LINK || req == I_PLINK {
            let lower = match self.stream_of(arg) {
                Some(l) => l,
                None => return err(EINVAL),
            };
            let sid = lower.borrow().sid;
            st.borrow_mut().fd = fd as i32;
            return Ok(self.ioc(st, req, sid, &[])?.0 as u32);
        }
        if [I_POP, I_FLUSH, I_UNLINK, I_PUNLINK, I_CANPUT, I_SETCLTIME, I_GETCLTIME].contains(&req) {
            if req == I_FLUSH && arg & 1 != 0 {
                st.borrow_mut().msgs.clear();
            }
            return Ok(self.ioc(st, req, arg, &[])?.0 as u32);
        }
        if req == I_NREAD || req == FIONREAD {
            self.stream_ready(st);
            let (first, count) = {
                let s = st.borrow();
                (s.msgs.front().map(|m| m.data.as_ref().map(|d| d.len()).unwrap_or(0)).unwrap_or(0), s.msgs.len())
            };
            self.wr32(arg, first as u32)?;
            return Ok(if req == I_NREAD { count as u32 } else { 0 });
        }
        if req == I_SRDOPT {
            let mut s = st.borrow_mut();
            s.rdopt = if arg & 7 != 0 { arg & 7 } else { RNORM };
            s.rdopt |= if arg & 0x70 != 0 { arg & 0x70 } else { RPROTNORM };
            return Ok(0);
        }
        if req == I_GRDOPT {
            let v = st.borrow().rdopt;
            self.wr32(arg, v)?;
            return Ok(0);
        }
        if req == I_SWROPT {
            st.borrow_mut().wropt = arg;
            return Ok(0);
        }
        if req == I_GWROPT {
            let v = st.borrow().wropt;
            self.wr32(arg, v)?;
            return Ok(0);
        }
        if req == I_SETSIG {
            // SIGPOLL when a message arrives: the host's SIGIO on the connection (which
            // becomes the guest's SIGPOLL, the same signal); a spurious one, for a reply
            // the emulator reads itself, is harmless to a handler that polls
            st.borrow_mut().sigevents = arg;
            unsafe {
                let fl = libc::fcntl(fd as i32, libc::F_GETFL);
                if fl >= 0 {
                    if arg != 0 {
                        self.install_host_handler(SIGPOLL, self.sigact(SIGPOLL).handler);
                        libc::fcntl(fd as i32, libc::F_SETOWN, libc::getpid());
                        libc::fcntl(fd as i32, libc::F_SETFL, fl | libc::O_ASYNC);
                    } else {
                        libc::fcntl(fd as i32, libc::F_SETFL, fl & !libc::O_ASYNC);
                    }
                }
            }
            return Ok(0);
        }
        if req == I_GETSIG {
            let v = st.borrow().sigevents;
            if v == 0 {
                return err(EINVAL);
            }
            self.wr32(arg, v)?;
            return Ok(0);
        }
        if req == I_ISASTREAM {
            return Ok(1);
        }
        if req == I_PEEK {
            self.stream_ready(st);
            let m = match st.borrow().msgs.front() {
                Some(m) => m.clone(),
                None => return Ok(0),
            };
            for (off, val) in [(0u32, &m.ctl), (12, &m.data)] {
                let d = self.rd(arg + off, 12)?;
                let (maxlen, buf) = (be32(&d, 0) as i32, be32(&d, 8));
                match val {
                    None => self.wr(arg + off + 4, &i32be(-1))?,
                    Some(v) => {
                        let k = (maxlen.max(0) as usize).min(v.len());
                        self.wr(buf, &v[..k])?;
                        self.wr(arg + off + 4, &i32be(k as i32))?;
                    }
                }
            }
            self.wr32(arg + 24, if m.typ == M_PCPROTO { RS_HIPRI } else { 0 })?;
            return Ok(1);
        }
        if req == FIONBIO {
            let on = self.rd32(arg)?;
            let f = self.fds.get_mut(&fd).unwrap();
            if on != 0 {
                f.flags |= O_NONBLOCK;
            } else {
                f.flags &= !(O_NONBLOCK | O_NDELAY);
            }
            return Ok(0);
        }
        if req == I_XTI_SND {
            return self.stream_xti_snd(st, arg);
        }
        if req == I_XTI_RCV {
            return self.stream_xti_rcv(fd, st, arg);
        }
        // a transparent ioctl: the argument word, copies through M_COPYIN/M_COPYOUT
        Ok(self.ioc(st, req, arg, &[])?.0 as u32)
    }

    fn stream_tpi_ack(&mut self, st: &StreamRef, arg: u32) -> Res<u32> {
        let d = self.rd(arg, 20)?;
        let (ack, ack2) = (be16(&d, 0) as i16 as i32, be16(&d, 2) as i16 as i32);
        let (clen, dlen, cbuf, dbuf) = (be32(&d, 4) as i32, be32(&d, 8) as i32, be32(&d, 12), be32(&d, 16));
        let prim = self.rd32(cbuf)? as i32;
        // T_INFO_REQ, T_ADDR_REQ (T_getaddr_req): no more than that
        let size = match prim {
            7 => 4.min(clen),
            12 => 12.min(clen),
            _ => clen,
        };
        let req = self.rd(cbuf, size.max(0) as usize)?;
        let data = if dbuf != 0 && dlen >= 0 { Some(self.rd(dbuf, dlen as usize)?) } else { None };
        self.stream_put2(st, Some(&req), data.as_deref(), 0, prim == 7 || prim == 12)?;
        let pred = move |m: &Msg| match &m.ctl {
            Some(c) if c.len() >= 4 => {
                let p = be32(c, 0) as i32;
                p == ack || p == 25 || (ack2 != 0 && p == ack2)
            }
            _ => false,
        };
        let i = match self.wait_msg(st, false, Wait::Sig, &pred)? {
            Some(i) => i,
            None => return err(ENXIO),
        };
        let m = st.borrow_mut().msgs.remove(i).unwrap();
        let c = m.ctl.unwrap_or_default();
        let out = &c[..c.len().min(clen.max(0) as usize)];
        self.wr(cbuf, out)?;
        self.wr(arg + 4, &i32be(out.len() as i32))?;
        if dbuf != 0 {
            match &m.data {
                Some(md) => {
                    let dd = &md[..md.len().min(dlen.max(0) as usize)];
                    self.wr(dbuf, dd)?;
                    self.wr(arg + 8, &i32be(dd.len() as i32))?;
                }
                None => self.wr(arg + 8, &i32be(-1))?,
            }
        }
        if self.trace {
            emsg!("[{}] TPI request {}: ack {}, {} bytes\n", self.pid, prim, gb32(&c, 0) as i32, out.len());
        }
        Ok(0)
    }

    fn stream_xti_snd(&mut self, st: &StreamRef, arg: u32) -> Res<u32> {
        let d = self.rd(arg + 8, 8)?;
        let (flags, n) = (be32(&d, 0), be32(&d, 4) as i32);
        let buf = self.rd32(arg + 20)?;
        self.stream_ready(st);
        // T_DISCON_IND, T_ORDREL_IND
        if st.borrow().msgs.iter().any(|m| matches!(&m.ctl, Some(c) if c.len() >= 4 && [24, 30].contains(&be32(c, 0)))) {
            return err(EIO);
        }
        let prim = if flags & 2 != 0 { T_EXDATA_REQ } else { T_DATA_REQ };
        let mut ctl = prim.to_be_bytes().to_vec();
        ctl.extend_from_slice(&(flags & 1).to_be_bytes());
        let data = if n > 0 { self.rd(buf, n as usize)? } else { Vec::new() };
        self.stream_put2(st, Some(&ctl), Some(&data), 0, false)?;
        Ok(n as u32)
    }

    fn stream_xti_rcv(&mut self, fd: u32, st: &StreamRef, arg: u32) -> Res<u32> {
        let maxlen = self.rd32(arg + 12)? as i32;
        let buf = self.rd32(arg + 20)?;
        let nb = self.stream_nonblock(fd);
        let i = match self.wait_msg(st, nb, Wait::Sig, &|_| true)? {
            Some(i) => i,
            None => return err(EIO),
        };
        let mut flags = 0u32;
        let take;
        {
            let mut s = st.borrow_mut();
            let m = &mut s.msgs[i];
            if let Some(c) = &m.ctl {
                let prim = if c.len() >= 4 { be32(c, 0) as i32 } else { -1 };
                if prim != T_DATA_IND && prim != T_EXDATA_IND {
                    return err(EIO);
                }
                if c.len() >= 8 && be32(c, 4) != 0 {
                    flags |= 1;
                }
                if prim == T_EXDATA_IND {
                    flags |= 2;
                }
            }
            let data = m.data.take().unwrap_or_default();
            let k = data.len().min(maxlen.max(0) as usize);
            take = data[..k].to_vec();
            if k < data.len() {
                m.data = Some(data[k..].to_vec());
                flags |= 1 | 0x1000_0000;
            } else {
                s.msgs.remove(i);
            }
        }
        if !take.is_empty() {
            self.wr(buf, &take)?;
        }
        let mut o = flags.to_be_bytes().to_vec();
        o.extend_from_slice(&(take.len() as u32).to_be_bytes());
        self.wr(arg + 8, &o)?;
        Ok(take.len() as u32)
    }

    /// 11.00's t_rcvudata: {?, ?, flags, ctl max, data max, ctl, data}. The T_UNITDATA_IND
    /// at the head of the stream (its control part holds the source address) and the
    /// datagram go to the buffers, flags and the two lengths back into the argument
    /// (T_MORE when the datagram did not fit; the rest of it stays). Anything else at the
    /// head (a T_UDERROR_IND) is EIO, which libnsl turns into TLOOK.
    fn stream_xti_urcv(&mut self, fd: u32, st: &StreamRef, arg: u32) -> Res<u32> {
        let d = self.rd(arg + 12, 16)?;
        let (cmax, dmax, cbuf, dbuf) = (be32(&d, 0) as i32, be32(&d, 4) as i32, be32(&d, 8), be32(&d, 12));
        let nb = self.stream_nonblock(fd);
        let i = match self.wait_msg(st, nb, Wait::Sig, &|_| true)? {
            Some(i) => i,
            None => return err(EIO),
        };
        let (ctl, take, flags);
        {
            let mut s = st.borrow_mut();
            let m = &mut s.msgs[i];
            let prim = match &m.ctl {
                Some(c) if c.len() >= 4 => be32(c, 0),
                _ => u32::MAX,
            };
            if prim != T_UNITDATA_IND {
                return err(EIO);
            }
            let c = m.ctl.clone().unwrap_or_default();
            ctl = c[..c.len().min(cmax.max(0) as usize)].to_vec();
            let data = m.data.take().unwrap_or_default();
            let k = data.len().min(dmax.max(0) as usize);
            take = data[..k].to_vec();
            if k < data.len() {
                m.data = Some(data[k..].to_vec());
                flags = 1u32;
            } else {
                flags = 0;
                s.msgs.remove(i);
            }
        }
        if !ctl.is_empty() && cbuf != 0 {
            self.wr(cbuf, &ctl)?;
        }
        if !take.is_empty() && dbuf != 0 {
            self.wr(dbuf, &take)?;
        }
        let mut o = flags.to_be_bytes().to_vec();
        o.extend_from_slice(&(ctl.len() as u32).to_be_bytes());
        o.extend_from_slice(&(take.len() as u32).to_be_bytes());
        self.wr(arg + 8, &o)?;
        Ok(0)
    }

    /// host_poll for entries among which are streams: a stream is readable when a message
    /// waits at its stream head here, whatever the connection shows
    pub fn poll_streams(&mut self, entries: &[(i32, i16)], timeout: i64) -> Res<Vec<i16>> {
        let mut sts: HashMap<i32, StreamRef> = HashMap::new();
        for &(fd, _) in entries {
            if fd >= 0 {
                if let Some(st) = self.stream_of(fd as u32) {
                    sts.insert(fd, st);
                }
            }
        }
        if sts.is_empty() {
            return self.host_poll(entries, timeout);
        }
        let deadline = if timeout < 0 { None } else { Some(host::now_f64() + timeout as f64 / 1000.0) };
        let extra = libc::POLLHUP | libc::POLLERR | libc::POLLNVAL;
        let bits = |st: &StreamRef, ev: i16| -> i16 {
            let s = st.borrow();
            let mut b = 0;
            if let Some(m) = s.msgs.front() {
                if m.typ == M_PCPROTO {
                    b |= libc::POLLPRI;
                } else {
                    b |= libc::POLLIN | if m.band != 0 { libc::POLLRDBAND } else { libc::POLLRDNORM };
                }
            }
            if s.hangup {
                b |= libc::POLLHUP;
            }
            if s.rerror != 0 {
                b |= libc::POLLERR;
            }
            b |= libc::POLLOUT | libc::POLLWRNORM;
            b & (ev | extra)
        };
        loop {
            let all: Vec<StreamRef> = sts.values().cloned().collect();
            for st in &all {
                self.stream_ready(st);
            }
            let ready = entries.iter().any(|(fd, ev)| sts.get(fd).map(|st| bits(st, *ev) != 0).unwrap_or(false));
            let t = if ready {
                0
            } else {
                match deadline {
                    None => -1,
                    Some(d) => (((d - host::now_f64()) * 1000.0) as i64).max(0),
                }
            };
            let host_entries: Vec<(i32, i16)> = entries.iter().map(|&(fd, ev)| (fd, if sts.contains_key(&fd) { libc::POLLIN } else { ev })).collect();
            let res = self.host_poll(&host_entries, t)?;
            let mut out = Vec::with_capacity(entries.len());
            for (&(fd, ev), &got) in entries.iter().zip(res.iter()) {
                if let Some(st) = sts.get(&fd).cloned() {
                    if got & libc::POLLNVAL != 0 {
                        out.push(libc::POLLNVAL);
                        continue;
                    }
                    if got & (libc::POLLIN | libc::POLLHUP) != 0 {
                        st.borrow_mut().fd = fd;
                        self.stream_ready(&st);
                    }
                    out.push(bits(&st, ev));
                } else {
                    out.push(got);
                }
            }
            if out.iter().any(|&x| x != 0) || t == 0 {
                return Ok(out);
            }
        }
    }
}
