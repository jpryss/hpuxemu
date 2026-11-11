//! ioctl (terminals, sockets, pseudo-terminals), select and poll, the telnet join

use super::files::PTY_MAJOR;
use super::net::inet_aton;
use super::Handler;
use crate::consts::*;
use crate::emsg;
use crate::host::{self, guest_errno, host_sig};
use crate::netman;
use crate::process::*;
use std::sync::{Arc, Condvar, Mutex};

pub const TABLE: &[(&str, Handler)] = &[("ioctl", Process::sys_ioctl), ("select", Process::sys_select), ("poll", Process::sys_poll)];

// sys/termio.h: _IOR/_IOW('T', 1-4, struct termio)
const TCGETA: u32 = 0x4012_5401;
const TCSETA: u32 = 0x8012_5402;
const TCSETAW: u32 = 0x8012_5403;
const TCSETAF: u32 = 0x8012_5404;
// the STREAMS pseudo-terminal ioctls of sys/strtio.h (_IO('t', n))
const UNLKPT: u32 = 0x2000_7446;
const ISPTM: u32 = 0x2000_7447;
const ISPTS: u32 = 0x2000_7449;
const TIOCSIGNAL: u32 = 0x2000_7478;
// sys/ptyio.h: TIOCTRAP _IOW('t',103,int), TIOCTRAPSTATUS _IOR('t',102,int)
const TIOCTRAP: u32 = 0x8004_7467;
const TIOCTRAPSTATUS: u32 = 0x4004_7466;

// HP-UX termios: c_iflag c_oflag c_cflag c_lflag c_reserved c_cc[16] (NCCS 16); the flag
// values are mostly the same as Linux's for the POSIX subset, mapped by name
const IFLAGS: &[(u32, libc::tcflag_t)] = &[
    (IGNBRK, libc::IGNBRK),
    (BRKINT, libc::BRKINT),
    (IGNPAR, libc::IGNPAR),
    (PARMRK, libc::PARMRK),
    (INPCK, libc::INPCK),
    (ISTRIP, libc::ISTRIP),
    (INLCR, libc::INLCR),
    (IGNCR, libc::IGNCR),
    (ICRNL, libc::ICRNL),
    (IUCLC, libc::IUCLC),
    (IXON, libc::IXON),
    (IXANY, libc::IXANY),
    (IXOFF, libc::IXOFF),
];
const OFLAGS: &[(u32, libc::tcflag_t)] = &[
    (OPOST, libc::OPOST),
    (OLCUC, libc::OLCUC),
    (ONLCR, libc::ONLCR),
    (OCRNL, libc::OCRNL),
    (ONOCR, libc::ONOCR),
    (ONLRET, libc::ONLRET),
    (OFILL, libc::OFILL),
    (OFDEL, libc::OFDEL),
];
const CFLAGS: &[(u32, libc::tcflag_t)] =
    &[(CSTOPB, libc::CSTOPB), (CREAD, libc::CREAD), (PARENB, libc::PARENB), (PARODD, libc::PARODD), (HUPCL, libc::HUPCL), (CLOCAL, libc::CLOCAL)];
const LFLAGS: &[(u32, libc::tcflag_t)] = &[
    (ISIG, libc::ISIG),
    (ICANON, libc::ICANON),
    (XCASE, libc::XCASE),
    (ECHO, libc::ECHO),
    (ECHOE, libc::ECHOE),
    (ECHOK, libc::ECHOK),
    (ECHONL, libc::ECHONL),
    (NOFLSH, libc::NOFLSH),
    (TOSTOP, libc::TOSTOP),
    (IEXTEN, libc::IEXTEN),
];
const CSIZES: &[(u32, libc::tcflag_t)] = &[(CS5, libc::CS5), (CS6, libc::CS6), (CS7, libc::CS7), (CS8, libc::CS8)];
const CCS: &[(u32, usize)] = &[
    (VINTR, libc::VINTR),
    (VQUIT, libc::VQUIT),
    (VERASE, libc::VERASE),
    (VKILL, libc::VKILL),
    (VEOF, libc::VEOF),
    (VEOL, libc::VEOL),
    (VEOL2, libc::VEOL2),
    (VMIN, libc::VMIN),
    (VTIME, libc::VTIME),
    (VSUSP, libc::VSUSP),
    (VSTART, libc::VSTART),
    (VSTOP, libc::VSTOP),
    (VWERASE, libc::VWERASE),
    (VLNEXT, libc::VLNEXT),
];
/// HP-UX's B0 ... B38400 (the speed is in c_cflag's CBAUD bits), in the order of the
/// host's speed numbers 0..15
const BAUDS: [u32; 16] = [B0, B50, B75, B110, B134, B150, B200, B300, B600, B1200, B1800, B2400, B4800, B9600, B19200, B38400];

/// the host's errno of a terminal request, ENOTTY for one HP-UX has no name for
fn tty_err() -> Stop {
    let e = host::errno();
    Stop::Errno(if HOST_ERRNO.iter().any(|x| x.0 == e) { guest_errno(e) } else { ENOTTY })
}

fn tcget(fd: u32) -> Res<libc::termios> {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd as i32, &mut t) } < 0 {
        return Err(tty_err());
    }
    Ok(t)
}

fn tcset(fd: u32, when: i32, t: &libc::termios) -> Res<()> {
    if host::retry(|| unsafe { libc::tcsetattr(fd as i32, when, t) as isize }) < 0 {
        return Err(tty_err());
    }
    Ok(())
}

/// a host termios as HP-UX's struct termios (36 bytes)
fn termios_bytes(t: &libc::termios) -> [u8; 36] {
    let mut g = [0u32; 4];
    for (idx, names, h) in [(0, IFLAGS, t.c_iflag), (1, OFLAGS, t.c_oflag), (2, CFLAGS, t.c_cflag), (3, LFLAGS, t.c_lflag)] {
        for &(gv, hv) in names {
            if h & hv != 0 {
                g[idx] |= gv;
            }
        }
    }
    for &(gv, hv) in CSIZES {
        if t.c_cflag & libc::CSIZE == hv {
            g[2] |= gv;
        }
    }
    // speed: HP-UX keeps it in c_cflag's CBAUD bits
    let sp = unsafe { libc::cfgetospeed(t) } as usize;
    g[2] |= if sp < 16 { BAUDS[sp] } else { B9600 };
    let mut out = [0u8; 36];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&g[i].to_be_bytes());
    }
    for &(gi, hi) in CCS {
        out[20 + gi as usize] = t.c_cc[hi];
    }
    out
}

/// HP-UX's struct termios onto the host's (`cur`: what the terminal has now)
fn termios_from_bytes(data: &[u8], cur: &libc::termios) -> libc::termios {
    let g = [be32(data, 0), be32(data, 4), be32(data, 8), be32(data, 12)];
    let mut new = [0 as libc::tcflag_t; 4];
    for (idx, names) in [(0, IFLAGS), (1, OFLAGS), (2, CFLAGS), (3, LFLAGS)] {
        for &(gv, hv) in names {
            if g[idx] & gv != 0 {
                new[idx] |= hv;
            }
        }
    }
    for &(gv, hv) in CSIZES {
        if g[2] & CSIZE == gv {
            new[2] |= hv;
        }
    }
    let baud = g[2] & CBAUD;
    let mut speed = unsafe { libc::cfgetospeed(cur) };
    for (i, &b) in BAUDS.iter().enumerate() {
        if b == baud {
            speed = i as libc::speed_t;
        }
    }
    let mut t = *cur;
    t.c_iflag = new[0];
    t.c_oflag = new[1];
    t.c_cflag = new[2];
    t.c_lflag = new[3];
    unsafe {
        libc::cfsetispeed(&mut t, speed);
        libc::cfsetospeed(&mut t, speed);
    }
    for &(gi, hi) in CCS {
        t.c_cc[hi] = data[20 + gi as usize];
    }
    t
}

/// a socket joined to a pseudo-terminal (SIOCJNVS): the helper thread's end
pub struct Joined {
    done: Mutex<bool>,
    cv: Condvar,
}

/// HP-UX's telnet driver, in a thread: it peeks at the socket, forwards up to the first
/// IAC (CR NUL and CR LF become CR and LF), and ends when it sees one, when either side
/// closes, or when the pty's reader is gone; 0xFF going out is doubled.
fn nvs_pump(s: i32, p: i32, trace: bool) {
    let mut why = "";
    let mut buf = vec![0u8; 4096];
    let write_all = |fd: i32, d: &[u8], sock: bool| -> bool {
        let mut off = 0;
        while off < d.len() {
            let r = unsafe {
                if sock {
                    libc::send(fd, d[off..].as_ptr() as *const libc::c_void, d.len() - off, libc::MSG_NOSIGNAL)
                } else {
                    libc::write(fd, d[off..].as_ptr() as *const libc::c_void, d.len() - off)
                }
            };
            if r < 0 {
                if host::errno() == libc::EINTR {
                    continue;
                }
                return false;
            }
            off += r as usize;
        }
        true
    };
    unsafe {
        // the pump's copy of the socket blocks
        let fl = libc::fcntl(s, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(s, libc::F_SETFL, fl & !libc::O_NONBLOCK);
        }
    }
    'pump: loop {
        let mut fds = [libc::pollfd { fd: s, events: libc::POLLIN, revents: 0 }, libc::pollfd { fd: p, events: libc::POLLIN, revents: 0 }];
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            if host::errno() == libc::EINTR {
                continue;
            }
            break;
        }
        if fds[0].revents != 0 {
            let n = unsafe { libc::recv(s, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_PEEK) };
            if n <= 0 {
                why = "client closed";
                break;
            }
            let data = &buf[..n as usize];
            let i = data.iter().position(|&c| c == 0xFF);
            if i == Some(0) {
                why = "telnet command for telnetd";
                break;
            }
            let mut chunk = match i {
                Some(i) => &data[..i],
                None => data,
            };
            if chunk.ends_with(b"\r") && chunk.len() == data.len() {
                chunk = &chunk[..chunk.len() - 1]; // wait for what follows the CR
                if chunk.is_empty() {
                    let mut one = [libc::pollfd { fd: s, events: libc::POLLIN, revents: 0 }];
                    unsafe { libc::poll(one.as_mut_ptr(), 1, 200) };
                    continue;
                }
            }
            let chunk = chunk.to_vec();
            unsafe { libc::recv(s, buf.as_mut_ptr() as *mut libc::c_void, chunk.len(), 0) };
            let mut out = Vec::with_capacity(chunk.len());
            let mut k = 0;
            while k < chunk.len() {
                if chunk[k] == b'\r' && k + 1 < chunk.len() && chunk[k + 1] == b'\n' {
                    out.push(b'\n');
                    k += 2;
                } else if chunk[k] == b'\r' && k + 1 < chunk.len() && chunk[k + 1] == 0 {
                    out.push(b'\r');
                    k += 2;
                } else {
                    out.push(chunk[k]);
                    k += 1;
                }
            }
            if !write_all(p, &out, false) {
                why = "pty gone";
                break 'pump;
            }
        }
        if fds[1].revents != 0 {
            let n = unsafe { libc::read(p, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                why = "pty closed";
                break;
            }
            let mut out = Vec::with_capacity(n as usize);
            for &c in &buf[..n as usize] {
                out.push(c);
                if c == 0xFF {
                    out.push(c);
                }
            }
            if !write_all(s, &out, true) {
                why = "client gone";
                break;
            }
        }
    }
    if trace {
        emsg!("hpuxemu: telnet join ends: {}\n", why);
    }
    unsafe {
        libc::close(s);
        libc::close(p);
    }
}

impl Process {
    /// SIOCJNVS(socket, &ptyfd): HP-UX's telnet driver joins a connection to a
    /// pseudo-terminal in the kernel: data goes between the two without telnetd, and when
    /// a telnet command (IAC) arrives from the client the driver unjoins, leaving it for
    /// telnetd, which handles the option and joins again. A helper thread does that here
    /// (not a child: telnetd would take a child's exit for login's).
    fn join_nvs(&mut self, sock: u32, pty: u32) -> Res<u32> {
        self.fd_check(sock)?;
        self.fd_check(pty)?;
        let (s, p) = unsafe { (libc::dup(sock as i32), libc::dup(pty as i32)) };
        if s < 0 || p < 0 {
            return Err(herr());
        }
        let j = Arc::new(Joined { done: Mutex::new(false), cv: Condvar::new() });
        let j2 = j.clone();
        let trace = self.trace;
        std::thread::spawn(move || {
            // the emulator's signals are the main thread's
            unsafe {
                let mut all: libc::sigset_t = std::mem::zeroed();
                libc::sigfillset(&mut all);
                libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
            }
            nvs_pump(s, p, trace);
            *j2.done.lock().unwrap() = true;
            j2.cv.notify_all();
        });
        self.fds.get_mut(&sock).unwrap().joined = Some(j);
        Ok(0)
    }

    /// While a telnet join owns a socket, the guest sees nothing on it: a read or recv
    /// waits for the join to end (an IAC arrived or a side closed), a select/poll with a
    /// timeout gives up after it. True if the fd is (still) joined.
    pub fn joined_wait(&mut self, fd: u32, timeout: Option<f64>) -> Res<bool> {
        let j = match self.fds.get(&fd).and_then(|f| f.joined.clone()) {
            Some(j) => j,
            None => return Ok(false),
        };
        let deadline = timeout.map(|t| host::now_f64() + t);
        let mut done = j.done.lock().unwrap();
        while !*done {
            // (in slices: a signal for the guest ends the wait)
            if self.poll_signals() != 0 && self.any_deliverable() {
                return Err(Stop::Interrupted);
            }
            let mut slice = 0.05;
            if let Some(d) = deadline {
                let left = d - host::now_f64();
                if left <= 0.0 {
                    return Ok(true);
                }
                slice = left.min(slice);
            }
            done = j.cv.wait_timeout(done, std::time::Duration::from_secs_f64(slice)).unwrap().0;
        }
        drop(done);
        self.fds.get_mut(&fd).unwrap().joined = None;
        Ok(false)
    }

    /// /dev/ptym/clone: a host pseudo-terminal pair; the master's device number names the
    /// slave (/dev/pty/ttyp0 for minor 0 ...), which libc's ptsname derives from fstat and
    /// the guest opens by name
    pub fn open_pty_master(&mut self, flags: u32) -> Res<u32> {
        let (mut master, mut slave) = (0, 0);
        if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) } < 0 {
            return Err(herr());
        }
        let host_slave = host::ttyname(slave).unwrap_or_default();
        unsafe { libc::close(slave) };
        // the slave is /dev/pts/N with the host's number: ptsname() asks the master for
        // its device number (ISPTM) and names the slave after the minor
        let last = host_slave.rsplit('/').next().unwrap_or("");
        let n = if !last.is_empty() && last.bytes().all(|c| c.is_ascii_digit()) { last.parse().unwrap_or(0) } else { self.ptys.len() as u32 };
        self.ptys.insert(format!("/dev/pts/{}", n), host_slave);
        self.newfd(master, "/dev/ptym/clone", flags);
        self.fds.get_mut(&(master as u32)).unwrap().pty = Some(n);
        Ok(master as u32)
    }

    /// ioctl(fd, request, arg): the terminal requests (termios), FIONREAD, TIOCGWINSZ
    pub fn sys_ioctl(&mut self, a: &[u32; 8]) -> SysResult {
        let (fd, req, arg) = (a[0], a[1], a[2]);
        self.fd_check(fd)?;
        if self.fds[&fd].netman {
            return self.netman_ioctl(req, arg);
        }
        if let Some(st) = self.stream_of(fd) {
            let r = self.stream_ioctl(fd, st, req, arg)?;
            if self.trace {
                emsg!("[{}] stream ioctl {:#x} = {}\n", self.pid, req, r as i32);
            }
            return ok(r);
        }
        let h = fd as i32;
        if req == TCGETATTR {
            let t = tcget(fd)?;
            self.wr(arg, &termios_bytes(&t))?;
            return ok(0);
        }
        if req == TCGETA {
            // struct termio (18 bytes): the termios flags narrowed to 16 bits, NCC 8
            let t = termios_bytes(&tcget(fd)?);
            let mut o = Vec::new();
            for i in 0..4 {
                o.extend_from_slice(&t[4 * i + 2..4 * i + 4]);
            }
            o.push(0);
            o.extend_from_slice(&t[20..28]);
            self.wr(arg, &o)?;
            return ok(0);
        }
        if req == TCSETA || req == TCSETAW || req == TCSETAF {
            let cur = tcget(fd)?;
            let old = termios_bytes(&cur);
            let d = self.rd(arg, 18)?;
            let mut new = [0u8; 36];
            for i in 0..4 {
                new[4 * i..4 * i + 2].copy_from_slice(&old[4 * i..4 * i + 2]);
                new[4 * i + 2..4 * i + 4].copy_from_slice(&d[2 * i..2 * i + 2]);
            }
            new[20..28].copy_from_slice(&d[9..17]);
            new[28..36].copy_from_slice(&old[28..36]);
            let t = termios_from_bytes(&new, &cur);
            let when = if req == TCSETA { libc::TCSANOW } else if req == TCSETAW { libc::TCSADRAIN } else { libc::TCSAFLUSH };
            tcset(fd, when, &t)?;
            return ok(0);
        }
        if req == TCSETATTR || req == TCSETATTRD || req == TCSETATTRF {
            let cur = tcget(fd)?;
            let t = termios_from_bytes(&self.rd(arg, 36)?, &cur);
            let when = if req == TCSETATTR { libc::TCSANOW } else if req == TCSETATTRD { libc::TCSADRAIN } else { libc::TCSAFLUSH };
            tcset(fd, when, &t)?;
            return ok(0);
        }
        if req == TIOCGWINSZ {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(h, libc::TIOCGWINSZ, &mut ws) } < 0 {
                return Err(tty_err());
            }
            let mut o = Vec::new();
            for v in [ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel] {
                o.extend_from_slice(&v.to_be_bytes());
            }
            self.wr(arg, &o)?;
            return ok(0);
        }
        if req == TIOCSWINSZ {
            let d = self.rd(arg, 8)?;
            let ws = libc::winsize { ws_row: be16(&d, 0), ws_col: be16(&d, 2), ws_xpixel: be16(&d, 4), ws_ypixel: be16(&d, 6) };
            if unsafe { libc::ioctl(h, libc::TIOCSWINSZ, &ws) } < 0 {
                return Err(tty_err());
            }
            return ok(0);
        }
        if req == TIOCGPGRP {
            let r = unsafe { libc::tcgetpgrp(h) };
            if r < 0 {
                return Err(tty_err());
            }
            self.wr32(arg, r as u32)?;
            return ok(0);
        }
        if req == TIOCSPGRP {
            let pg = self.rd32(arg)?;
            if unsafe { libc::tcsetpgrp(h, pg as i32) } < 0 {
                return Err(tty_err());
            }
            return ok(0);
        }
        if req == FIONREAD {
            let mut n: libc::c_int = 0;
            if unsafe { libc::ioctl(h, libc::FIONREAD, &mut n) } < 0 {
                return Err(tty_err());
            }
            self.wr32(arg, n as u32)?;
            return ok(0);
        }
        if req == TCFLSH {
            if unsafe { libc::tcflush(h, (arg & 3) as i32) } < 0 {
                return Err(tty_err());
            }
            return ok(0);
        }
        if req == TCSBRK || req == TCXONC {
            return ok(0);
        }
        if req == TIOCGLTC {
            // the BSD special characters: from the termios control characters
            let cc = tcget(fd)?.c_cc;
            self.wr(arg, &[cc[libc::VSUSP], cc[libc::VSUSP], cc[libc::VREPRINT], cc[libc::VDISCARD], cc[libc::VWERASE], cc[libc::VLNEXT]])?;
            return ok(0);
        }
        if req == TIOCSLTC || req == TIOCLSET || req == TIOCSETP {
            // the BSD setters: accepted; the termios state is what counts
            return ok(0);
        }
        if req == TIOCGETP {
            // struct sgttyb from termios: speeds, erase, kill, flags (ECHO 010, RAW 040, CRMOD 020)
            let t = tcget(fd)?;
            let flags: u32 = (if t.c_lflag & libc::ECHO != 0 { 0o10 } else { 0 })
                | (if t.c_oflag & libc::OPOST != 0 { 0o20 } else { 0 })
                | (if t.c_lflag & libc::ICANON != 0 { 0 } else { 0o40 });
            let mut o = vec![13, 13, t.c_cc[libc::VERASE], t.c_cc[libc::VKILL]];
            o.extend_from_slice(&flags.to_be_bytes());
            self.wr(arg, &o)?;
            return ok(0);
        }
        if req == TIOCLGET {
            self.wr32(arg, 0)?;
            return ok(0);
        }
        if req == FIONBIO || req == FIOSNBIO {
            let on = self.rd32(arg)?;
            self.nb_set(fd, 'f', on != 0);
            return ok(0);
        }
        if req == 0x8004_667d || req == 0x8004_667a {
            // FIOASYNC, FIOSSAIOSTAT: SIGIO when the descriptor is ready (a green-threads
            // Java VM waits for it in sigsuspend); the owner is the
            // process unless F_SETOWN/FIOSSAIOOWN named another
            let on = self.rd32(arg)?;
            unsafe {
                if on != 0 && libc::fcntl(h, libc::F_GETOWN) == 0 {
                    libc::fcntl(h, libc::F_SETOWN, libc::getpid());
                }
                let v: libc::c_int = (on != 0) as libc::c_int;
                if libc::ioctl(h, libc::FIOASYNC, &v) < 0 {
                    return Err(tty_err());
                }
            }
            return ok(0);
        }
        if req == 0x8004_6678 {
            // FIOSSAIOOWN: the process (group, negative) that gets SIGIO
            let v = self.rd32(arg)?;
            if unsafe { libc::fcntl(h, libc::F_SETOWN, v as i32) } < 0 {
                return Err(tty_err());
            }
            return ok(0);
        }
        if req == 0x4004_6677 {
            // FIOGSAIOOWN
            let r = unsafe { libc::fcntl(h, libc::F_GETOWN) };
            self.wr32(arg, r as u32)?;
            return ok(0);
        }
        if (req >> 8) & 0xFF == b'S' as u32 {
            // STREAMS: terminals are not streams here. On a pty slave I_PUSH succeeds,
            // I_FIND says the module is there and I_POP says there is nothing left to pop
            // (dtterm pops until that fails, then pushes ptem, ldterm, ttcompat);
            // everything else ENOTTY
            if req == I_PUSH && self.is_tty(fd) {
                return ok(0);
            }
            if req == I_FIND && self.is_tty(fd) {
                return ok(1);
            }
            if req == I_POP && self.is_tty(fd) {
                return err(EINVAL);
            }
            return err(ENOTTY);
        }
        if req == SIOCGIFCONF {
            return self.ifconf(arg);
        }
        if req == SIOCJNVS {
            // the int holds the pty descriptor in its low halfword (telnetd passes
            // 0x08010003 for fd 3; the high half is the driver's mode flags)
            let v = self.rd32(arg)?;
            return ok(self.join_nvs(fd, if v > 0xFFFF { v & 0xFFFF } else { v })?);
        }
        if [SIOCGIFFLAGS, SIOCGIFADDR, SIOCGIFNETMASK, SIOCGIFBRDADDR, SIOCGIFDSTADDR, SIOCGIFMETRIC].contains(&req) {
            return self.ifreq(req, arg);
        }
        if req == SIOCGPGRP {
            let r = unsafe { libc::fcntl(h, libc::F_GETOWN) };
            self.wr32(arg, r as u32)?;
            return ok(0);
        }
        if req == SIOCSPGRP {
            let v = self.rd32(arg)?;
            if unsafe { libc::fcntl(h, libc::F_SETOWN, v as i32) } < 0 {
                return Err(tty_err());
            }
            return ok(0);
        }
        if req == SIOCATMARK {
            self.wr32(arg, 0)?;
            return ok(0);
        }
        let pty = self.fds[&fd].pty;
        if req == ISPTM {
            // the master's device number (ptsname derives /dev/pts/N from the minor)
            return match pty {
                Some(n) => ok((PTY_MAJOR << 24) | n),
                None => err(EINVAL),
            };
        }
        if req == UNLKPT {
            return ok(0);
        }
        if req == ISPTS {
            // the slave's device number as stat gives it (ptsname checks the two agree)
            let path = match pty {
                Some(n) => format!("/dev/pts/{}", n),
                None => self.fds[&fd].path.clone(),
            };
            let known = self.ptys.get(&path).cloned();
            if known.is_some() || (path.starts_with("/dev/pts/") && path.len() > 9 && path[9..].bytes().all(|c| c.is_ascii_digit())) {
                let st = host::stat(&known.unwrap_or(path), true).map_err(|_| tty_err())?;
                return ok(hp_dev(st.st_rdev));
            }
            return err(EINVAL);
        }
        if req == TIOCTRAP || req == TIOCTRAPSTATUS || req == TIOCREQCHECK || req == TIOCREQSET {
            // hpterm's pty trap mechanism (the master is told about the slave's ioctls):
            // accepted; nothing is ever trapped
            if req == TIOCTRAPSTATUS {
                self.wr32(arg, 0)?;
            }
            return ok(0);
        }
        if pty.is_some() && (req >> 8) & 0xFF == b't' as u32 {
            // the other pty master controls (TIOCMONITOR, TIOCPKT ...): accepted
            return ok(0);
        }
        if req == TIOCSIGNAL {
            // the master sends a signal to the slave's foreground process group
            unsafe {
                let pg = libc::tcgetpgrp(h);
                if pg > 0 {
                    libc::killpg(pg, host_sig(arg));
                }
            }
            return ok(0);
        }
        if req == MTIOCGET || req == MTIOCTOP || (req >> 8) & 0xFF == b'V' as u32 {
            // not a tape (tar, cpio and dd ask; cpio's 'V' request is not in any header)
            return err(ENOTTY);
        }
        emsg!("hpuxemu: ioctl {:#x} unimplemented\n", req);
        err(EINVAL)
    }

    /// /dev/netman: NMIOGET(struct nmparms {objid, buffer, *len}) answers a MIB-2 object
    /// from the host's tables (netman.rs); *len is the buffer's size going in, the bytes
    /// filled coming out (EMSGSIZE when the object does not fit: mib2agt asks for a
    /// table's NumEnt first and sizes its buffer by it). The writes (NMIOSET, NMIODEL,
    /// NMIOCRE) are refused: the host's tables are not the guest's to change.
    fn netman_ioctl(&mut self, req: u32, arg: u32) -> SysResult {
        if req == netman::NMIOSET || req == netman::NMIODEL || req == netman::NMIOCRE {
            return err(EPERM);
        }
        if req != netman::NMIOGET {
            return err(EINVAL);
        }
        let d = self.rd(arg, 12)?;
        let (objid, buf, lenp) = (be32(&d, 0), be32(&d, 4), be32(&d, 8));
        let ln = if lenp != 0 { self.rd32(lenp)? } else { 0 };
        let key = if buf != 0 && ln != 0 { self.rd(buf, ln as usize)? } else { Vec::new() };
        let data = match self.mib_netman(false).get(objid, &key) {
            Ok(d) => d,
            Err(name) => return err(if name == "ENOENT" { ENOENT } else { EINVAL }),
        };
        if data.len() > ln as usize {
            return err(EMSGSIZE);
        }
        if !data.is_empty() {
            self.wr(buf, &data)?;
        }
        if lenp != 0 {
            self.wr32(lenp, data.len() as u32)?;
        }
        ok(0)
    }

    /// SIOCGIFCONF: struct ifconf {len, buf} filled with 32-byte ifreqs (name, sockaddr_in)
    fn ifconf(&mut self, arg: u32) -> SysResult {
        let d = self.rd(arg, 8)?;
        let (ln, buf) = (be32(&d, 0) as i32, be32(&d, 4));
        let mut out = Vec::new();
        for (name, addr, _, _, _) in self.interfaces() {
            let mut rec = name.as_bytes().to_vec();
            rec.resize(16, 0);
            rec.extend_from_slice(&(AF_INET as u16).to_be_bytes());
            rec.extend_from_slice(&[0, 0]);
            rec.extend_from_slice(&inet_aton(&addr));
            rec.extend_from_slice(&[0; 8]);
            out.extend(rec);
        }
        out.truncate(ln.max(0) as usize);
        self.wr(buf, &out)?;
        self.wr32(arg, out.len() as u32)?;
        ok(0)
    }

    fn ifreq(&mut self, req: u32, arg: u32) -> SysResult {
        let d = self.rd(arg, 32)?;
        let name = &d[..16];
        let name = host::latin1(&name[..name.iter().position(|&c| c == 0).unwrap_or(16)]);
        let (_, addr, mask, bcast, flags) = match self.interfaces().into_iter().find(|i| i.0 == name) {
            Some(i) => i,
            None => return err(ENXIO),
        };
        if req == SIOCGIFFLAGS {
            self.wr(arg + 16, &(flags as u16).to_be_bytes())?;
        } else if req == SIOCGIFMETRIC {
            self.wr32(arg + 16, 0)?;
        } else {
            let a = if req == SIOCGIFNETMASK { &mask } else if req == SIOCGIFBRDADDR { &bcast } else { &addr };
            let mut o = (AF_INET as u16).to_be_bytes().to_vec();
            o.extend_from_slice(&[0, 0]);
            o.extend_from_slice(&inet_aton(a));
            o.extend_from_slice(&[0; 8]);
            self.wr(arg + 16, &o)?;
        }
        ok(0)
    }

    /// select(nfds, readfds, writefds, exceptfds, timeout): fd_set is an array of
    /// big-endian words, bit i of word i/32
    pub fn sys_select(&mut self, a: &[u32; 8]) -> SysResult {
        let (nfds, rs, ws, es, tv) = (a[0] as i32, a[1], a[2], a[3], a[4]);
        let words = if nfds > 0 { ((nfds + 31) / 32) as usize } else { 0 };
        // (events per descriptor: 1 read, 2 write, 4 except)
        let mut want: Vec<(i32, u8)> = Vec::new();
        for (addr, bit) in [(rs, 1u8), (ws, 2), (es, 4)] {
            if addr == 0 || words == 0 {
                continue;
            }
            // the set bits only: servers pass nfds = the descriptor table's size (2048)
            // and call select thousands of times a second
            let d = self.rd(addr, 4 * words)?;
            for wi in 0..words {
                let mut w = be32(&d, 4 * wi);
                while w != 0 {
                    let i = (wi * 32) as i32 + w.trailing_zeros() as i32;
                    w &= w - 1;
                    if i < nfds {
                        match want.iter_mut().find(|e| e.0 == i) {
                            Some(e) => e.1 |= bit,
                            None => want.push((i, bit)),
                        }
                    }
                }
            }
        }
        let mut timeout: i64 = -1;
        if tv != 0 {
            let d = self.rd(tv, 8)?;
            timeout = be32(&d, 0) as i64 * 1000 + be32(&d, 4) as i64 / 1000;
        }
        // through poll(2), which a signal interrupts
        let joined: Vec<i32> = want.iter().filter(|e| e.1 & 1 != 0 && self.fds.get(&(e.0 as u32)).map(|f| f.joined.is_some()).unwrap_or(false)).map(|e| e.0).collect();
        if !joined.is_empty() && self.joined_wait(joined[0] as u32, if timeout < 0 { None } else { Some(timeout as f64 / 1000.0) })? {
            // still joined: the socket shows nothing
            for e in want.iter_mut() {
                if joined.contains(&e.0) {
                    e.1 &= !1;
                }
            }
            want.retain(|e| e.1 != 0);
            timeout = 0;
        }
        want.sort();
        let entries: Vec<(i32, i16)> = want
            .iter()
            .map(|&(fd, b)| (fd, (if b & 1 != 0 { libc::POLLIN } else { 0 }) | (if b & 2 != 0 { libc::POLLOUT } else { 0 }) | (if b & 4 != 0 { libc::POLLPRI } else { 0 })))
            .collect();
        let rev = self.poll_streams(&entries, timeout)?;
        let mut sets = [vec![0u32; words.max(1)], vec![0u32; words.max(1)], vec![0u32; words.max(1)]];
        let mut count = 0;
        for (&(fd, b), &got) in want.iter().zip(rev.iter()) {
            if got & libc::POLLNVAL != 0 {
                return err(EBADF);
            }
            let (w, m) = ((fd / 32) as usize, 1u32 << (fd % 32));
            if b & 1 != 0 && got & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                sets[0][w] |= m;
                count += 1;
            }
            if b & 2 != 0 && got & (libc::POLLOUT | libc::POLLERR) != 0 {
                sets[1][w] |= m;
                count += 1;
            }
            if b & 4 != 0 && got & libc::POLLPRI != 0 {
                sets[2][w] |= m;
                count += 1;
            }
        }
        for (k, addr) in [rs, ws, es].into_iter().enumerate() {
            if addr != 0 {
                let mut o = Vec::with_capacity(4 * words);
                for w in &sets[k][..words] {
                    o.extend_from_slice(&w.to_be_bytes());
                }
                self.wr(addr, &o)?;
            }
        }
        ok(count)
    }

    /// poll(fds, nfds, timeout): the same event bits as the host's
    pub fn sys_poll(&mut self, a: &[u32; 8]) -> SysResult {
        let (fds, nfds, timeout) = (a[0], a[1], a[2] as i32);
        let d = self.rd(fds, 8 * nfds as usize)?;
        let mut entries = Vec::with_capacity(nfds as usize);
        for i in 0..nfds as usize {
            let fd = be32(&d, 8 * i) as i32;
            entries.push((if fd >= 0 { fd } else { -1 }, (be16(&d, 8 * i + 4) & 0xFF) as i16));
        }
        let res = self.poll_streams(&entries, if timeout >= 0 { timeout as i64 } else { -1 })?;
        let mut n = 0;
        for (i, rev) in res.iter().enumerate() {
            if *rev != 0 {
                n += 1;
            }
            self.wr(fds + 8 * i as u32 + 6, &(*rev as u16).to_be_bytes())?;
        }
        ok(n)
    }
}
