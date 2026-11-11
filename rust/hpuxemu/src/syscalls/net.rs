//! sockets: HP-UX's BSD sockets on the host's. The descriptors are host sockets, addresses
//! are translated between the HP-UX sockaddr (16-bit big-endian family) and the host's.
//! Unix-domain socket paths are inside the root, except /tmp/.X11-unix/* which is the
//! host's (an X server on the host is reachable that way).

use super::Handler;
use crate::consts::*;
use crate::host::{self, latin1};
use crate::kernel::pyrepr;
use crate::process::*;

pub const TABLE: &[(&str, Handler)] = &[
    ("socket", Process::sys_socket),
    ("socket2", Process::sys_socket),
    ("socketpair", Process::sys_socketpair),
    ("socketpair2", Process::sys_socketpair),
    ("bind", Process::sys_bind),
    ("connect", Process::sys_connect),
    ("listen", Process::sys_listen),
    ("accept", Process::sys_accept),
    ("shutdown", Process::sys_shutdown),
    ("send", Process::sys_send),
    ("sendto", Process::sys_sendto),
    ("recv", Process::sys_recv),
    ("recvfrom", Process::sys_recvfrom),
    ("sendmsg", Process::sys_sendmsg),
    ("sendmsg2", Process::sys_sendmsg),
    ("recvmsg", Process::sys_recvmsg),
    ("recvmsg2", Process::sys_recvmsg),
    ("getsockname", Process::sys_getsockname),
    ("getpeername", Process::sys_getpeername),
    ("setsockopt", Process::sys_setsockopt),
    ("getsockopt", Process::sys_getsockopt),
];

/// the calls that say EWOULDBLOCK on a socket made non-blocking the BSD way
const BSD_NB_CALLS: &[&str] = &["accept", "connect", "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg"];
const BSD_NB_IO: &[&str] = &["read", "write", "readv", "writev"];
/// the calls that return 0 for "would block" under O_NDELAY (read(2), write(2), recv(2),
/// send(2): "completes successfully, having read no data, and returns 0")
const NDELAY_ZERO: &[&str] = &["read", "readv", "write", "writev", "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg"];

/// (HP-UX level, HP-UX option, host level, host option)
const SOCK_OPTS: &[(u32, u32, i32, i32)] = &[
    (SOL_SOCKET, SO_REUSEADDR, libc::SOL_SOCKET, libc::SO_REUSEADDR),
    (SOL_SOCKET, SO_KEEPALIVE, libc::SOL_SOCKET, libc::SO_KEEPALIVE),
    (SOL_SOCKET, SO_BROADCAST, libc::SOL_SOCKET, libc::SO_BROADCAST),
    (SOL_SOCKET, SO_LINGER, libc::SOL_SOCKET, libc::SO_LINGER),
    (SOL_SOCKET, SO_SNDBUF, libc::SOL_SOCKET, libc::SO_SNDBUF),
    (SOL_SOCKET, SO_RCVBUF, libc::SOL_SOCKET, libc::SO_RCVBUF),
    (SOL_SOCKET, SO_ERROR, libc::SOL_SOCKET, libc::SO_ERROR),
    (SOL_SOCKET, SO_TYPE, libc::SOL_SOCKET, libc::SO_TYPE),
    (SOL_SOCKET, SO_OOBINLINE, libc::SOL_SOCKET, libc::SO_OOBINLINE),
    (SOL_SOCKET, SO_DEBUG, libc::SOL_SOCKET, libc::SO_DEBUG),
    (SOL_SOCKET, SO_DONTROUTE, libc::SOL_SOCKET, libc::SO_DONTROUTE),
    (SOL_SOCKET, SO_REUSEPORT, libc::SOL_SOCKET, libc::SO_REUSEPORT),
    (SOL_SOCKET, SO_SNDLOWAT, libc::SOL_SOCKET, libc::SO_SNDLOWAT),
    (SOL_SOCKET, SO_RCVLOWAT, libc::SOL_SOCKET, libc::SO_RCVLOWAT),
    (SOL_SOCKET, SO_SNDTIMEO, libc::SOL_SOCKET, libc::SO_SNDTIMEO),
    (SOL_SOCKET, SO_RCVTIMEO, libc::SOL_SOCKET, libc::SO_RCVTIMEO),
    (IPPROTO_TCP, TCP_NODELAY, libc::IPPROTO_TCP, libc::TCP_NODELAY),
    (IPPROTO_TCP, TCP_MAXSEG, libc::IPPROTO_TCP, libc::TCP_MAXSEG),
    (IPPROTO_IP, IP_TTL, libc::IPPROTO_IP, libc::IP_TTL),
    (IPPROTO_IP, IP_TOS, libc::IPPROTO_IP, libc::IP_TOS),
    (IPPROTO_IP, IP_OPTIONS, libc::IPPROTO_IP, libc::IP_OPTIONS),
];

fn fam_bytes(f: u16) -> [u8; 2] {
    f.to_ne_bytes()
}

fn padded14(d: &[u8]) -> Vec<u8> {
    let mut v = d[2.min(d.len())..16.min(d.len())].to_vec();
    v.resize(14, 0);
    v
}

impl Process {
    fn bsd_nb_call(&self, name: &str, fd: u32) -> bool {
        if BSD_NB_CALLS.contains(&name) {
            return true;
        }
        if BSD_NB_IO.contains(&name) {
            return host::fstat(fd as i32).map(|s| host::is_sock(&s)).unwrap_or(false);
        }
        false
    }

    /// one way of non-blocking ('n' O_NONBLOCK, 'd' O_NDELAY, 'f' FIOSNBIO) on or off for
    /// fd; the host descriptor is non-blocking while any of them is on
    pub fn nb_set(&mut self, fd: u32, kind: char, on: bool) {
        let m = self.nbmode.entry(fd).or_default();
        match kind {
            'n' => m.nonblock = on,
            'd' => m.ndelay = on,
            _ => m.fio = on,
        }
        let any = m.any();
        if !any {
            self.nbmode.remove(&fd);
        }
        unsafe {
            let fl = libc::fcntl(fd as i32, libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(fd as i32, libc::F_SETFL, if any { fl | libc::O_NONBLOCK } else { fl & !libc::O_NONBLOCK });
            }
        }
    }

    pub fn nb_copy(&mut self, fd: u32, n: u32) {
        match self.nbmode.get(&fd).copied() {
            Some(m) => {
                self.nbmode.insert(n, m);
            }
            None => {
                self.nbmode.remove(&n);
            }
        }
    }

    /// EAGAIN of a call on a non-blocking descriptor, as HP-UX says it: (result, error flag)
    pub fn nb_result(&self, name: &str, fd: u32, r: u32) -> (u32, u32) {
        let m = self.nbmode[&fd];
        if m.nonblock {
            return (r, 1);
        }
        if m.ndelay {
            if NDELAY_ZERO.contains(&name) {
                return (0, 0);
            }
            if name == "accept" {
                return (EWOULDBLOCK, 1);
            }
            return (r, 1);
        }
        if m.fio && self.bsd_nb_call(name, fd) {
            return (EWOULDBLOCK, 1);
        }
        (r, 1)
    }

    fn sock_hostpath(&mut self, gp: &str) -> Res<String> {
        if gp.starts_with("/tmp/.X11-unix/") {
            // the host's X servers; $HPUXEMU_CONSOLE=N puts the guest's display :0 (the
            // console, which some applications insist on) on the host's :N - an Xvnc or Xephyr
            // of its own on a server whose :0 is something else, or none
            if let Some(con) = host::getenv("HPUXEMU_CONSOLE") {
                if !con.is_empty() && gp == "/tmp/.X11-unix/X0" {
                    return Ok(format!("/tmp/.X11-unix/X{}", con));
                }
            }
            return Ok(gp.to_string());
        }
        self.hostpath_nf(gp)
    }

    /// guest sockaddr bytes -> host sockaddr bytes
    fn sockaddr_in(&mut self, addr: u32, length: u32) -> Res<Option<Vec<u8>>> {
        if addr == 0 || length < 2 {
            return Ok(None);
        }
        let d = self.rd(addr, length.min(110) as usize)?;
        let family = be16(&d, 0) as u32;
        if family == AF_INET || family == 0 {
            let mut v = fam_bytes(if family == 0 { 0 } else { libc::AF_INET as u16 }).to_vec();
            v.extend(padded14(&d));
            return Ok(Some(v));
        }
        if family == AF_UNIX {
            let p = &d[2..];
            let p = &p[..p.iter().position(|&c| c == 0).unwrap_or(p.len())];
            let path = latin1(p);
            let hp = if path.is_empty() { String::new() } else { self.sock_hostpath(&path)? };
            if hp.len() > 104 && !host::exists(&hp) {
                // too long for the host's sun_path, which would be EINVAL; what the
                // program needs to hear is that nothing is there (libX11 tries
                // /var/spool/sockets/X11/N before /tmp/.X11-unix/XN)
                return err(ENOENT);
            }
            let mut v = fam_bytes(libc::AF_UNIX as u16).to_vec();
            v.extend_from_slice(hp.as_bytes());
            v.push(0);
            return Ok(Some(v));
        }
        err(EAFNOSUPPORT)
    }

    /// a guest sockaddr as text, for the trace
    pub fn sockaddr_str(&self, addr: u32, length: u32) -> String {
        if let Ok(d) = self.rd(addr, length.min(110) as usize) {
            if d.len() >= 2 {
                let family = be16(&d, 0) as u32;
                if family == AF_INET && d.len() >= 8 {
                    return format!("{}.{}.{}.{}:{}", d[4], d[5], d[6], d[7], be16(&d, 2));
                }
                if family == AF_UNIX {
                    let p = &d[2..];
                    return pyrepr(&latin1(&p[..p.iter().position(|&c| c == 0).unwrap_or(p.len())]));
                }
                return format!("af{}", family);
            }
        }
        format!("{:#x}", addr)
    }

    /// host sockaddr bytes -> guest sockaddr bytes
    fn sockaddr_out(&self, hb: &[u8]) -> Vec<u8> {
        if hb.len() < 2 {
            return Vec::new();
        }
        let family = u16::from_ne_bytes([hb[0], hb[1]]) as i32;
        if family == libc::AF_INET {
            let mut v = (AF_INET as u16).to_be_bytes().to_vec();
            v.extend(padded14(hb));
            return v;
        }
        if family == libc::AF_UNIX {
            let p = &hb[2..];
            let mut p = &p[..p.iter().position(|&c| c == 0).unwrap_or(p.len())];
            let pre = format!("{}/", self.root);
            if p.starts_with(pre.as_bytes()) {
                p = &p[self.root.len()..];
            }
            let mut v = (AF_UNIX as u16).to_be_bytes().to_vec();
            v.extend_from_slice(p);
            v.push(0);
            return v;
        }
        let mut v = (family as u16).to_be_bytes().to_vec();
        v.extend(padded14(hb));
        v
    }

    fn write_sockaddr(&mut self, addr: u32, lenp: u32, hb: &[u8]) -> Res<()> {
        if addr == 0 || lenp == 0 {
            return Ok(());
        }
        let g = self.sockaddr_out(hb);
        let room = self.rd32(lenp)? as usize;
        self.wr(addr, &g[..room.min(g.len())])?;
        self.wr32(lenp, g.len() as u32)
    }

    /// socket(domain, type, protocol): AF_UNIX and AF_INET, SOCK_STREAM/DGRAM/RAW, on the host
    pub fn sys_socket(&mut self, a: &[u32; 8]) -> SysResult {
        let fam = match a[0] {
            AF_UNIX => libc::AF_UNIX,
            AF_INET => libc::AF_INET,
            _ => return err(EAFNOSUPPORT),
        };
        let st = match a[1] {
            SOCK_STREAM => libc::SOCK_STREAM,
            SOCK_DGRAM => libc::SOCK_DGRAM,
            SOCK_RAW => libc::SOCK_RAW,
            _ => return err(EPROTOTYPE),
        };
        let fd = unsafe { libc::socket(fam, st, a[2] as i32) };
        if fd < 0 {
            return Err(herr());
        }
        ok(self.newfd(fd, "socket", 0))
    }

    /// socketpair(domain, type, protocol, sv[2]): AF_UNIX pairs on the host
    pub fn sys_socketpair(&mut self, a: &[u32; 8]) -> SysResult {
        if a[0] != AF_UNIX {
            return err(EAFNOSUPPORT);
        }
        let st = if a[1] == SOCK_DGRAM { libc::SOCK_DGRAM } else { libc::SOCK_STREAM };
        let mut sv = [0i32; 2];
        if unsafe { libc::socketpair(libc::AF_UNIX, st, a[2] as i32, sv.as_mut_ptr()) } < 0 {
            return Err(herr());
        }
        self.newfd(sv[0], "socket", 0);
        self.newfd(sv[1], "socket", 0);
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&(sv[0] as u32).to_be_bytes());
        b[4..].copy_from_slice(&(sv[1] as u32).to_be_bytes());
        self.wr(a[3], &b)?;
        ok(0)
    }

    /// bind(s, addr, len)
    pub fn sys_bind(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let hb = match self.sockaddr_in(a[1], a[2])? {
            Some(h) => h,
            None => return err(EINVAL),
        };
        if unsafe { libc::bind(a[0] as i32, hb.as_ptr() as *const libc::sockaddr, hb.len() as u32) } < 0 {
            return Err(herr_intr());
        }
        ok(0)
    }

    /// connect(s, addr, len): blocking on the host (EINPROGRESS on a non-blocking socket)
    pub fn sys_connect(&mut self, a: &[u32; 8]) -> SysResult {
        let fd = a[0];
        self.fd_check(fd)?;
        let hb = match self.sockaddr_in(a[1], a[2])? {
            Some(h) => h,
            None => return err(EINVAL),
        };
        let disp = self.x_local_display(&hb);
        let con = host::getenv("HPUXEMU_CONSOLE").filter(|c| !c.is_empty());
        if let (Some(0), Some(c)) = (disp, &con) {
            if let Ok(n) = c.parse::<u32>() {
                return self.connect_x_unix(fd, n);
            }
        }
        if unsafe { libc::connect(fd as i32, hb.as_ptr() as *const libc::sockaddr, hb.len() as u32) } < 0 {
            let e = host::errno();
            if e == libc::EINTR {
                return Err(Stop::Interrupted);
            }
            if e == libc::ECONNREFUSED {
                if let Some(d) = disp {
                    return self.connect_x_unix(fd, d);
                }
            }
            // no socket file: an X server whose /tmp/.X11-unix it cannot write (WSLg's is
            // read-only) has only Linux's abstract one, "@/tmp/.X11-unix/XN"
            let pre = b"/tmp/.X11-unix/X";
            if hb.len() > 2 + pre.len() && hb[2..].starts_with(pre) && (e == libc::ENOENT || e == libc::ECONNREFUSED) {
                let rest = &hb[2 + pre.len()..];
                let nd = rest.iter().take_while(|c| c.is_ascii_digit()).count();
                if nd > 0 && rest.get(nd) == Some(&0) {
                    if let Ok(n) = std::str::from_utf8(&rest[..nd]).unwrap_or("").parse::<u32>() {
                        return self.connect_x_unix(fd, n);
                    }
                }
            }
            if e == libc::ECONNREFUSED && hb.windows(23).any(|w| w == b"/var/spool/sockets/X11/") {
                // the socket an HP X server of the root left behind (x11start's Xhp starts
                // and fails: no frame buffer): nothing there, so that libX11 goes on to
                // /tmp/.X11-unix, the host's X servers
                return err(ENOENT);
            }
            return Err(herrno(e));
        }
        ok(0)
    }

    /// the display number when a host sockaddr is TCP port 6000+N on this machine (127.x
    /// or one of its addresses: a display named "host:0.0"), else None
    fn x_local_display(&mut self, hb: &[u8]) -> Option<u32> {
        if hb.len() < 8 || u16::from_ne_bytes([hb[0], hb[1]]) as i32 != libc::AF_INET {
            return None;
        }
        let port = be16(hb, 2) as u32;
        if !(6000..6100).contains(&port) {
            return None;
        }
        let addr = format!("{}.{}.{}.{}", hb[4], hb[5], hb[6], hb[7]);
        if addr.starts_with("127.") || self.interfaces().iter().any(|i| i.1 == addr) {
            return Some(port - 6000);
        }
        None
    }

    /// a TCP connection to a local X display made to the X server's Unix socket instead
    /// (WSLg, an Xvnc for the console: they need not listen on TCP); the guest's
    /// descriptor becomes that socket
    fn connect_x_unix(&mut self, fd: u32, n: u32) -> SysResult {
        let u = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if u < 0 {
            return Err(herr());
        }
        let path = format!("/tmp/.X11-unix/X{}", n);
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as u16;
        for (i, c) in path.bytes().enumerate() {
            sa.sun_path[i] = c as libc::c_char;
        }
        // the socket file, else the abstract socket of the same name (an X server that
        // could not create the file: WSLg's /tmp/.X11-unix is read-only)
        let mut r = host::retry(|| unsafe { libc::connect(u, &sa as *const _ as *const libc::sockaddr, (2 + path.len() + 1) as u32) as isize });
        if r < 0 {
            let mut sb: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            sb.sun_family = libc::AF_UNIX as u16;
            for (i, c) in path.bytes().enumerate() {
                sb.sun_path[i + 1] = c as libc::c_char;
            }
            r = host::retry(|| unsafe { libc::connect(u, &sb as *const _ as *const libc::sockaddr, (2 + 1 + path.len()) as u32) as isize });
        }
        if r < 0 {
            let e = host::errno();
            unsafe { libc::close(u) };
            return Err(herrno(e));
        }
        unsafe {
            libc::dup2(u, fd as i32);
            libc::close(u);
        }
        ok(0)
    }

    /// listen(s, backlog)
    pub fn sys_listen(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        if unsafe { libc::listen(a[0] as i32, a[1] as i32) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// accept(s, addr, lenp): the new descriptor; the peer's address in HP-UX form
    pub fn sys_accept(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let mut buf = [0u8; 128];
        let mut ln: libc::socklen_t = 128;
        let n = unsafe { libc::accept(a[0] as i32, buf.as_mut_ptr() as *mut libc::sockaddr, &mut ln) };
        if n < 0 {
            return Err(herr_intr());
        }
        self.newfd(n, "socket", 0);
        self.write_sockaddr(a[1], a[2], &buf[..(ln as usize).min(128)])?;
        ok(n as u32)
    }

    /// shutdown(s, how)
    pub fn sys_shutdown(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        if unsafe { libc::shutdown(a[0] as i32, a[1] as i32) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    fn host_send(&mut self, fd: u32, data: &[u8], flags: u32, addr: u32, length: u32) -> SysResult {
        let hb = if addr != 0 { self.sockaddr_in(addr, length)? } else { None };
        let r = unsafe {
            match &hb {
                None => libc::send(fd as i32, data.as_ptr() as *const libc::c_void, data.len(), flags as i32),
                Some(h) => libc::sendto(fd as i32, data.as_ptr() as *const libc::c_void, data.len(), flags as i32, h.as_ptr() as *const libc::sockaddr, h.len() as u32),
            }
        };
        if r < 0 {
            return Err(herr_intr());
        }
        ok(r as u32)
    }

    /// send(s, buf, len, flags)
    pub fn sys_send(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let data = self.rd(a[1], a[2] as usize)?;
        self.host_send(a[0], &data, a[3], 0, 0)
    }

    /// sendto(s, buf, len, flags, to, tolen)
    pub fn sys_sendto(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let data = self.rd(a[1], a[2] as usize)?;
        self.host_send(a[0], &data, a[3], a[4], a[5])
    }

    /// recv(s, buf, len, flags)
    pub fn sys_recv(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        self.joined_wait(a[0], None)?;
        let mut b = vec![0u8; (a[2] as usize).max(1)];
        let r = unsafe { libc::recv(a[0] as i32, b.as_mut_ptr() as *mut libc::c_void, a[2] as usize, a[3] as i32) };
        if r < 0 {
            return Err(herr_intr());
        }
        self.wr(a[1], &b[..r as usize])?;
        ok(r as u32)
    }

    fn host_recvfrom(&mut self, fd: u32, n: usize, flags: u32) -> Res<(Vec<u8>, Vec<u8>)> {
        let mut b = vec![0u8; n.max(1)];
        let mut ab = [0u8; 128];
        let mut ln: libc::socklen_t = 128;
        let r = unsafe { libc::recvfrom(fd as i32, b.as_mut_ptr() as *mut libc::c_void, n, flags as i32, ab.as_mut_ptr() as *mut libc::sockaddr, &mut ln) };
        if r < 0 {
            return Err(herr_intr());
        }
        b.truncate(r as usize);
        Ok((b, ab[..(ln as usize).min(128)].to_vec()))
    }

    /// recvfrom(s, buf, len, flags, from, fromlen)
    pub fn sys_recvfrom(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let (b, ab) = self.host_recvfrom(a[0], a[2] as usize, a[3])?;
        self.wr(a[1], &b)?;
        self.write_sockaddr(a[4], a[5], &ab)?;
        ok(b.len() as u32)
    }

    /// (name, namelen, iovecs, rights)
    fn read_msghdr(&self, msg: u32) -> Res<(u32, u32, Vec<(u32, u32)>, u32)> {
        let d = self.rd(msg, 24)?;
        let (name, namelen, iov, iovlen, rights) = (be32(&d, 0), be32(&d, 4), be32(&d, 8), be32(&d, 12), be32(&d, 16));
        let mut iovs = Vec::new();
        for i in 0..iovlen.min(1024) {
            let v = self.rd(iov + 8 * i, 8)?;
            iovs.push((be32(&v, 0), be32(&v, 4)));
        }
        Ok((name, namelen, iovs, rights))
    }

    /// sendmsg(s, msg, flags): the iovecs gathered; access rights (descriptor passing)
    /// are not supported
    pub fn sys_sendmsg(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let (name, namelen, iovs, _) = self.read_msghdr(a[1])?;
        let mut data = Vec::new();
        for (b, n) in iovs {
            data.extend_from_slice(&self.rd(b, n as usize)?);
        }
        self.host_send(a[0], &data, a[2], name, namelen)
    }

    /// recvmsg(s, msg, flags): into the iovecs; no access rights
    pub fn sys_recvmsg(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let msg = a[1];
        let (name, namelen, iovs, rights) = self.read_msghdr(msg)?;
        let total: usize = iovs.iter().map(|x| x.1 as usize).sum();
        let (data, ab) = self.host_recvfrom(a[0], total, a[2])?;
        let mut off = 0;
        for (base, n) in iovs {
            let end = (off + n as usize).min(data.len());
            if off >= end {
                break;
            }
            self.wr(base, &data[off..end])?;
            off = end;
        }
        if name != 0 && namelen != 0 {
            let g = self.sockaddr_out(&ab);
            self.wr(name, &g[..(namelen as usize).min(g.len())])?;
            self.wr32(msg + 4, g.len() as u32)?;
        }
        if rights != 0 {
            self.wr32(msg + 20, 0)?;
        }
        ok(data.len() as u32)
    }

    fn sockname(&mut self, a: &[u32; 8], peer: bool) -> SysResult {
        self.fd_check(a[0])?;
        let mut buf = [0u8; 128];
        let mut ln: libc::socklen_t = 128;
        let r = unsafe {
            if peer {
                libc::getpeername(a[0] as i32, buf.as_mut_ptr() as *mut libc::sockaddr, &mut ln)
            } else {
                libc::getsockname(a[0] as i32, buf.as_mut_ptr() as *mut libc::sockaddr, &mut ln)
            }
        };
        if r < 0 {
            return Err(herr());
        }
        let mut hb = buf[..(ln as usize).min(128)].to_vec();
        if hb.len() >= 2 && u16::from_ne_bytes([hb[0], hb[1]]) as i32 != libc::AF_UNIX {
            hb.resize(16, 0);
        }
        self.write_sockaddr(a[1], a[2], &hb)?;
        ok(0)
    }

    /// getsockname(s, addr, lenp)
    pub fn sys_getsockname(&mut self, a: &[u32; 8]) -> SysResult {
        self.sockname(a, false)
    }

    /// getpeername(s, addr, lenp)
    pub fn sys_getpeername(&mut self, a: &[u32; 8]) -> SysResult {
        self.sockname(a, true)
    }

    fn sockopt(&self, level: u32, name: u32) -> Res<(i32, i32)> {
        for &(gl, gn, hl, hn) in SOCK_OPTS {
            if gl == level && gn == name {
                return Ok((hl, hn));
            }
        }
        err(ENOPROTOOPT)
    }

    /// setsockopt(s, level, optname, optval, optlen): SOL_SOCKET, TCP and IP options by
    /// name; SO_USELOOPBACK is accepted and ignored (the RPC library sets it and gives up
    /// on failure)
    pub fn sys_setsockopt(&mut self, a: &[u32; 8]) -> SysResult {
        let (fd, level, name, val, length) = (a[0], a[1], a[2], a[3], a[4]);
        self.fd_check(fd)?;
        if level == SOL_SOCKET && name == SO_USELOOPBACK {
            return ok(0);
        }
        let (hl, hn) = self.sockopt(level, name)?;
        let mut data = if val != 0 && length != 0 { self.rd(val, length as usize)? } else { Vec::new() };
        if length == 4 && data.len() == 4 {
            data = (be32(&data, 0) as i32).to_ne_bytes().to_vec();
        } else if hl == libc::SOL_SOCKET && hn == libc::SO_LINGER && length == 8 && data.len() == 8 {
            let mut v = (be32(&data, 0) as i32).to_ne_bytes().to_vec();
            v.extend_from_slice(&(be32(&data, 4) as i32).to_ne_bytes());
            data = v;
        }
        if unsafe { libc::setsockopt(fd as i32, hl, hn, data.as_ptr() as *const libc::c_void, data.len() as u32) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// getsockopt(s, level, optname, optval, optlen)
    pub fn sys_getsockopt(&mut self, a: &[u32; 8]) -> SysResult {
        let (fd, level, name, val, lenp) = (a[0], a[1], a[2], a[3], a[4]);
        self.fd_check(fd)?;
        let (hl, hn) = self.sockopt(level, name)?;
        let mut raw = [0i32; 2];
        let linger = hl == libc::SOL_SOCKET && hn == libc::SO_LINGER;
        let mut ln: libc::socklen_t = if linger { 8 } else { 4 };
        if unsafe { libc::getsockopt(fd as i32, hl, hn, raw.as_mut_ptr() as *mut libc::c_void, &mut ln) } < 0 {
            return Err(herr());
        }
        let mut out = Vec::new();
        if linger {
            out.extend_from_slice(&raw[0].to_be_bytes());
            out.extend_from_slice(&raw[1].to_be_bytes());
        } else if hl == libc::SOL_SOCKET && hn == libc::SO_TYPE {
            let t = match raw[0] {
                libc::SOCK_STREAM => SOCK_STREAM as i32,
                libc::SOCK_DGRAM => SOCK_DGRAM as i32,
                libc::SOCK_RAW => SOCK_RAW as i32,
                t => t,
            };
            out.extend_from_slice(&t.to_be_bytes());
        } else if hl == libc::SOL_SOCKET && hn == libc::SO_ERROR && raw[0] != 0 {
            // the pending error, as HP-UX numbers it
            out.extend_from_slice(&host::guest_errno(raw[0]).to_be_bytes());
        } else {
            out.extend_from_slice(&raw[0].to_be_bytes());
        }
        let room = if lenp != 0 { self.rd32(lenp)? as usize } else { out.len() };
        self.wr(val, &out[..room.min(out.len())])?;
        if lenp != 0 {
            self.wr32(lenp, out.len() as u32)?;
        }
        ok(0)
    }

    // -- the host's interfaces, as HP-UX names them (ioctl SIOCGIFCONF and friends) --------

    /// [(name, address, netmask, broadcast, flags)] of the host's IPv4 interfaces (lo0
    /// first, named as HP-UX names them: lo0, lan0, lan1 ...)
    pub fn interfaces(&mut self) -> Vec<(String, String, String, String, u32)> {
        let mut out = vec![("lo0".to_string(), "127.0.0.1".to_string(), "255.0.0.0".to_string(), "127.255.255.255".to_string(), IFF_UP | IFF_LOOPBACK | IFF_RUNNING)];
        let txt = match std::fs::read_to_string("/proc/net/route") {
            Ok(t) => t,
            Err(_) => return out,
        };
        for line in txt.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 || parts[1] != "00000000" || parts[0].starts_with("lo") {
                continue;
            }
            let sk = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if sk < 0 {
                continue;
            }
            let ask = |req: libc::c_ulong| -> Option<String> {
                let mut ifr = [0u8; 40];
                let n = parts[0].as_bytes();
                ifr[..n.len().min(15)].copy_from_slice(&n[..n.len().min(15)]);
                if unsafe { libc::ioctl(sk, req, ifr.as_mut_ptr()) } < 0 {
                    return None;
                }
                Some(format!("{}.{}.{}.{}", ifr[20], ifr[21], ifr[22], ifr[23]))
            };
            let got = (ask(0x8915), ask(0x891b), ask(0x8919));
            unsafe { libc::close(sk) };
            if let (Some(addr), Some(mask), Some(bcast)) = got {
                out.push(("lan0".to_string(), addr, mask, bcast, IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST));
                break;
            }
        }
        out
    }
}

pub fn inet_aton(s: &str) -> [u8; 4] {
    let mut o = [0u8; 4];
    for (i, p) in s.split('.').take(4).enumerate() {
        o[i] = p.parse().unwrap_or(0);
    }
    o
}
