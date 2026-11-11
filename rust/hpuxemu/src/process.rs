//! process.rs - the process: its state, guest paths inside the root, guest memory access,
//! and the kernel's permission check (owners and access control lists).

use crate::consts::*;
use crate::host::{self, cstr, guest_errno, latin1};
use crate::signals::{SigAct, SigSet};
use hppa32_jit::Cpu;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

pub const GATEWAY: u32 = 0xC000_0000;
/// where mcas_util() lives on the gateway page (sysconf(_SC_MCAS_OFFSET) tells libc)
pub const MCAS_OFFSET: u32 = 0x800;
/// where HP-UX 10.20 puts a 32-bit process's stack (it grows up)
pub const STACK_BASE: u32 = 0x7B03_A000;
pub const STACK_LIMIT: u32 = 0x7B03_A000 + 8 * 1024 * 1024;
/// instructions per CPU run between checks for pending signals
pub const RUN_CHUNK: u64 = 4_000_000;
pub const PRIVATE_MMAP_TOP: u32 = 0x7A00_0000;
pub const SHARED_MMAP_BASE: u32 = 0x8000_0000;
pub const SHARED_MMAP_END: u32 = 0xC000_0000;
pub const SHLIB_TEXT_BASE: u32 = 0xC000_1000;
pub const SHLIB_TEXT_END: u32 = 0xF000_0000;
pub const PAGE: u32 = 4096;
pub const M32: u64 = 0xFFFF_FFFF;

/// How a system call handler ends without a plain return value.
#[derive(Debug, Clone)]
pub enum Stop {
    /// an HP-UX errno
    Errno(u32),
    /// a blocking host call returned EINTR: a signal is pending for the guest
    Interrupted,
    /// sigsuspend/sigpause: a deliverable signal is pending; EINTR, with the handler's
    /// frame to carry the saved mask
    InterruptedWithMask(SigSet),
    /// the call set the CPU state itself (sigcleanup): no return value to store
    NoReturn,
    /// the thread blocked (or ended) and another runs: its registers are loaded
    Switched,
    /// the process image was replaced
    Exec,
}

pub type Res<T> = Result<T, Stop>;

/// r28 and, when set, r29
#[derive(Debug, Clone, Copy)]
pub struct Ret(pub u32, pub Option<u32>);
pub type SysResult = Res<Ret>;

pub fn ok(v: u32) -> SysResult {
    Ok(Ret(v, None))
}
pub fn ok2(a: u32, b: u32) -> SysResult {
    Ok(Ret(a, Some(b)))
}
pub fn err<T>(e: u32) -> Res<T> {
    Err(Stop::Errno(e))
}
/// the host's errno as an HP-UX error
pub fn herr() -> Stop {
    Stop::Errno(guest_errno(host::errno()))
}
pub fn herrno(e: i32) -> Stop {
    Stop::Errno(guest_errno(e))
}
/// the host's errno of an interruptible call: EINTR means a signal is pending
pub fn herr_intr() -> Stop {
    let e = host::errno();
    if e == libc::EINTR {
        Stop::Interrupted
    } else {
        Stop::Errno(guest_errno(e))
    }
}

/// How a descriptor was made non-blocking (HP-UX's three kinds, recv(2), socket(7)):
/// O_NONBLOCK (EAGAIN), O_NDELAY (a read or write that would block returns 0, accept says
/// EWOULDBLOCK), ioctl FIOSNBIO/FIONBIO (EWOULDBLOCK on sockets).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Nb {
    pub nonblock: bool,
    pub ndelay: bool,
    pub fio: bool,
}

impl Nb {
    pub fn any(&self) -> bool {
        self.nonblock || self.ndelay || self.fio
    }
}

#[derive(Clone, Default)]
pub struct Fd {
    pub path: String,
    pub flags: u32,
    pub dirpos: usize,
    pub dirents: Option<Rc<Vec<String>>>,
    /// a pty master from the clone device: its number
    pub pty: Option<u32>,
    pub netman: bool,
    pub stream: Option<crate::streams::StreamRef>,
    /// a socket a telnet join (SIOCJNVS) owns for now
    pub joined: Option<std::sync::Arc<crate::syscalls::ioctl::Joined>>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Mapping {
    pub base: u32,
    pub size: u32,
    /// the guest path a writable shared file mapping is written back to
    pub path: Option<String>,
    pub off: u64,
    pub flags: u32,
    pub prot: u32,
    /// 11.00: the file range of a shared executable mapping ((dev, ino), offset, size)
    pub key: Option<((u64, u64), u64, u32)>,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct FaultInfo {
    pub addr: u32,
    pub write: bool,
    pub pc: u32,
    pub trap: u32,
    pub mapped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Exited {
    Exit(u32),
    Signal(u32),
}

/// how a system call reached a file: for its extended attributes
#[derive(Clone, Debug)]
pub enum Src {
    Path(String),
    Fd(i32),
}

use crate::owners::Owners;

pub struct Process {
    pub root: String,
    pub trace: bool,
    pub cpu: Cpu,
    /// the CPU has not run a program yet (the first load uses it as it is)
    pub cpu_fresh: bool,
    pub cwd: String,
    pub brk: u32,
    pub brk_base: u32,
    pub mappings: Vec<Mapping>,
    pub fds: BTreeMap<u32, Fd>,
    pub nbmode: HashMap<u32, Nb>,
    pub umask: u32,
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub groups: Vec<u32>,
    pub host_uid: u32,
    pub host_gid: u32,
    pub owners: Option<Owners>,
    pub owners_stamp: Option<(i64, i64)>,
    pub owners_fresh: bool,
    pub hpcache: HashMap<(u64, u64), Src>,
    pub xcache: HashMap<(u64, u64, i64, &'static str), Option<String>>,
    pub xattrs: Option<bool>,
    pub shm_attached: HashMap<u32, (i32, u32, usize)>,
    pub ptys: HashMap<String, String>,
    pub pid: u32,
    pub env: Vec<(String, String)>,
    pub sigactions: HashMap<u32, SigAct>,
    pub sigmask: SigSet,
    /// pending guest signals (bit = signal number)
    pub pending: u64,
    pub fault_info: HashMap<u32, FaultInfo>,
    pub sigreturn_addr: u32,
    pub exited: Option<Exited>,
    pub have_tty: bool,
    pub my_ttys: HashSet<String>,
    pub argv0: String,
    pub argv: Vec<String>,
    pub release: String,
    pub is11: bool,
    pub clock_offset: i64,
    pub clock_anchor: Option<f64>,
    pub inhibit: Vec<SigSet>,
    pub nodename: String,
    pub text_base: u32,
    pub text_size: u32,
    pub start_time: i64,
    pub stack_mapped_end: u32,
    pub msem_lockid: bool,
    pub msem_fd: Option<i32>,
    pub sigstack_rec: (u32, u32),
    pub sigaltstack_rec: (u32, u32, u32),
    pub sigvalues: HashMap<u32, u32>,
    pub native_list: Vec<(u32, u8)>,
    pub stream_devs: Option<Rc<HashMap<String, (String, Option<u32>)>>>,
    pub threads: crate::threads::Threads,
    pub stats: Option<Box<crate::stats::Stats>>,
    pub published: bool,
    /// the host's MIB-2 tables: /dev/netman's, and 11.00's numbering
    pub netmans: [Option<Rc<crate::netman::Netman>>; 2],
}

pub fn read_file(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

impl Process {
    pub fn new(root: &str, trace: bool, env: Vec<(String, String)>) -> Process {
        let root = root.trim_end_matches('/').to_string();
        let cpu = new_cpu();
        let have_tty = host::isatty(0);
        let mut my_ttys = HashSet::new();
        for fd in 0..3 {
            if host::isatty(fd) {
                if let Some(n) = host::ttyname(fd) {
                    my_ttys.insert(n);
                }
            }
        }
        let release = read_file(&format!("{}/etc/hpuxemu/release", root))
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .unwrap_or_else(|| "B.10.20".to_string());
        // the guest clock: etc/hpuxemu/clock holds a date ("1999-06-01" or "1999-06-01
        // 12:00[:00]", local time), the guest's time when the file was written; from then
        // on it runs with the host's. No file: the host's time.
        let (mut clock_offset, mut clock_anchor) = (0i64, None);
        let cf = format!("{}/etc/hpuxemu/clock", root);
        if let Some(b) = read_file(&cf) {
            let txt = String::from_utf8_lossy(&b);
            let txt = txt.split('#').next().unwrap_or("").trim().to_string();
            if let Some(t) = parse_local_time(&txt) {
                if let Ok(st) = host::stat(&cf, true) {
                    let anchor = st.st_mtime as f64 + st.st_mtime_nsec as f64 / 1e9;
                    clock_anchor = Some(anchor);
                    clock_offset = (t as f64 - anchor) as i64;
                }
            }
        }
        // the node name: etc/hpuxemu/hostname, else "hpux" - never the host's own, which
        // the root's /etc/hosts could not resolve
        let nodename = read_file(&format!("{}/etc/hpuxemu/hostname", root))
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "hpux".to_string());
        let is11 = release.starts_with("B.11");
        let p = Process {
            root,
            trace,
            cpu,
            cpu_fresh: true,
            cwd: "/".to_string(),
            brk: 0,
            brk_base: 0,
            mappings: Vec::new(),
            fds: BTreeMap::new(),
            nbmode: HashMap::new(),
            umask: 0o022,
            uid: 0,
            euid: 0,
            suid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
            groups: Vec::new(),
            host_uid: unsafe { libc::getuid() },
            host_gid: unsafe { libc::getgid() },
            owners: None,
            owners_stamp: None,
            owners_fresh: false,
            hpcache: HashMap::new(),
            xcache: HashMap::new(),
            xattrs: None,
            shm_attached: HashMap::new(),
            ptys: HashMap::new(),
            pid: unsafe { libc::getpid() } as u32,
            env,
            sigactions: HashMap::new(),
            sigmask: SigSet::default(),
            pending: 0,
            fault_info: HashMap::new(),
            sigreturn_addr: 0,
            exited: None,
            have_tty,
            my_ttys,
            argv0: String::new(),
            argv: Vec::new(),
            release,
            is11,
            clock_offset,
            clock_anchor,
            inhibit: Vec::new(),
            nodename,
            text_base: 0,
            text_size: 0,
            start_time: 0,
            stack_mapped_end: 0,
            msem_lockid: false,
            msem_fd: None,
            sigstack_rec: (0, 0),
            sigaltstack_rec: (0, 2, 0), // SS_DISABLE
            sigvalues: HashMap::new(),
            native_list: Vec::new(),
            stream_devs: None,
            threads: crate::threads::Threads::default(),
            stats: None,
            published: false,
            netmans: [None, None],
        };
        // /etc/mnttab (the text form getmntent reads): the root is one hfs file system
        let mt = format!("{}/etc/mnttab", p.root);
        if host::stat(&mt, true).map(|s| s.st_size == 0).unwrap_or(true) {
            let _ = std::fs::write(&mt, format!("/dev/root / hfs defaults 0 1 {} 0\n", host::now_f64() as i64));
        }
        p
    }

    pub fn env_get(&self, k: &str) -> Option<&str> {
        self.env.iter().find(|kv| kv.0 == k).map(|kv| kv.1.as_str())
    }

    // -- paths (chroot-style) ------------------------------------------------------------

    /// The host path of a guest path, resolved inside the root (symbolic links included).
    /// Like the kernel's lookup it needs search permission on every directory it looks a
    /// name up in - with the effective ids, or `cred` (uid, groups) for access(); a
    /// relative path starts in the working directory, whose own path is not searched
    /// again. search=false is for the emulator's own use.
    pub fn hostpath_c(&mut self, gpath: &str, follow_last: bool, search: bool, cred: Option<(u32, Vec<u32>)>) -> Res<String> {
        if gpath.is_empty() {
            return err(ENOENT);
        }
        let cred = if search {
            let c = cred.unwrap_or_else(|| {
                let mut g = vec![self.egid];
                g.extend_from_slice(&self.groups);
                (self.euid, g)
            });
            if c.0 == 0 {
                None
            } else {
                Some(c)
            }
        } else {
            None
        };
        // (name, checked) from the back: the next component is the last element
        let mut parts: Vec<(String, bool)> = Vec::new();
        for x in gpath.split('/').rev() {
            if !x.is_empty() && x != "." {
                parts.push((x.to_string(), true));
            }
        }
        if !gpath.starts_with('/') {
            for x in self.cwd.split('/').rev() {
                if !x.is_empty() && x != "." {
                    parts.push((x.to_string(), false));
                }
            }
        }
        let mut resolved: Vec<String> = Vec::new();
        let mut cur: Option<libc::stat> = None;
        let mut hops = 0;
        let mut cand = String::with_capacity(self.root.len() + gpath.len() + 16);
        while let Some((seg, chk)) = parts.pop() {
            if chk {
                if let Some(c) = &cred {
                    let gdir = format!("/{}", resolved.join("/"));
                    self.search_ok(&gdir, c, cur)?;
                }
            }
            if seg == ".." {
                resolved.pop();
                cur = None;
                continue;
            }
            cand.clear();
            cand.push_str(&self.root);
            for r in &resolved {
                cand.push('/');
                cand.push_str(r);
            }
            cand.push('/');
            cand.push_str(&seg);
            let mut lst = None;
            if !parts.is_empty() || follow_last {
                lst = host::stat(&cand, false).ok();
            }
            if let Some(st) = &lst {
                if host::is_lnk(st) {
                    hops += 1;
                    if hops > 40 {
                        return err(ELOOP);
                    }
                    let target = host::readlink(&cand).map_err(herrno)?;
                    if target.starts_with('/') {
                        resolved.clear();
                    }
                    for x in target.split('/').rev() {
                        if !x.is_empty() && x != "." {
                            parts.push((x.to_string(), chk));
                        }
                    }
                    cur = None;
                    continue;
                }
            }
            resolved.push(seg);
            cur = lst;
        }
        let norm = format!("/{}", resolved.join("/"));
        if norm.starts_with("/dev/") {
            if matches!(norm.as_str(), "/dev/null" | "/dev/tty" | "/dev/zero" | "/dev/urandom" | "/dev/random") {
                return Ok(norm);
            }
            if norm == "/dev/console" {
                return Ok(if self.have_tty { "/dev/tty".to_string() } else { format!("{}/var/adm/console.log", self.root) });
            }
            if self.my_ttys.contains(&norm)
                || (norm.starts_with("/dev/pts/") && norm.len() > 9 && norm[9..].bytes().all(|c| c.is_ascii_digit()))
            {
                // the host's pseudo-terminals are the guest's
                return Ok(norm);
            }
        }
        // no host realpath() check after this: the walk above looked every component up
        // inside the root and followed each link itself (an absolute target from the
        // root, '..' never above it), so root + norm names nothing outside it
        Ok(format!("{}{}", self.root, norm))
    }

    pub fn hostpath(&mut self, gpath: &str) -> Res<String> {
        self.hostpath_c(gpath, true, true, None)
    }

    pub fn hostpath_nf(&mut self, gpath: &str) -> Res<String> {
        self.hostpath_c(gpath, false, true, None)
    }

    /// for the emulator's own use: no search permission needed
    pub fn hostpath_own(&mut self, gpath: &str, follow_last: bool) -> Res<String> {
        self.hostpath_c(gpath, follow_last, false, None)
    }

    /// EACCES unless `cred` may search the directory gdir (a resolved guest path: no
    /// links in it; st its lstat if the lookup has it); ENOTDIR if it is not a directory
    fn search_ok(&mut self, gdir: &str, cred: &(u32, Vec<u32>), st: Option<libc::stat>) -> Res<()> {
        let hp = format!("{}{}", self.root, gdir);
        let st = match st {
            Some(s) => s,
            None => match host::stat(&hp, true) {
                Ok(s) => s,
                Err(_) => return Ok(()), // the lookup itself reports it
            },
        };
        if !host::is_dir(&st) {
            return err(ENOTDIR);
        }
        if self.allowed(gdir, &st, 1, Some(cred.0), Some(&cred.1), Some(&Src::Path(hp)))? == 0 {
            return err(EACCES);
        }
        Ok(())
    }

    pub fn guest_abspath(&self, gpath: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        let full;
        let g = if gpath.starts_with('/') {
            gpath
        } else {
            full = format!("{}/{}", self.cwd.trim_end_matches('/'), gpath);
            &full
        };
        for x in g.split('/') {
            if x.is_empty() || x == "." {
                continue;
            }
            if x == ".." {
                parts.pop();
            } else {
                parts.push(x);
            }
        }
        format!("/{}", parts.join("/"))
    }

    // -- memory helpers ------------------------------------------------------------------

    pub fn rd(&self, addr: u32, n: usize) -> Res<Vec<u8>> {
        let mut v = vec![0u8; n];
        if n == 0 {
            return Ok(v);
        }
        match self.cpu.mem.read(addr, &mut v) {
            Ok(()) => Ok(v),
            Err(_) => err(EFAULT),
        }
    }

    pub fn wr(&mut self, addr: u32, data: &[u8]) -> Res<()> {
        if data.is_empty() {
            return Ok(());
        }
        match self.cpu.mem.write(addr, data) {
            Ok(()) => Ok(()),
            Err(_) => err(EFAULT),
        }
    }

    pub fn rd32(&self, addr: u32) -> Res<u32> {
        self.cpu.mem.ld32(addr).or(err(EFAULT))
    }

    pub fn wr32(&mut self, addr: u32, v: u32) -> Res<()> {
        self.wr(addr, &v.to_be_bytes())
    }

    /// a NUL-terminated string, at most `limit` bytes of it
    pub fn rdbytes(&self, addr: u32, limit: usize) -> Res<Vec<u8>> {
        let mut out = Vec::new();
        let mut addr = addr;
        while out.len() < limit {
            // read to the end of the page at a time
            let n = ((PAGE - (addr & (PAGE - 1))) as usize).min(limit - out.len());
            let chunk = self.rd(addr, n)?;
            if let Some(i) = chunk.iter().position(|&c| c == 0) {
                out.extend_from_slice(&chunk[..i]);
                break;
            }
            out.extend_from_slice(&chunk);
            addr = addr.wrapping_add(n as u32);
        }
        Ok(out)
    }

    pub fn rdstr(&self, addr: u32) -> Res<String> {
        Ok(latin1(&self.rdbytes(addr, 4096)?))
    }

    pub fn rdstr_n(&self, addr: u32, limit: usize) -> Res<String> {
        Ok(latin1(&self.rdbytes(addr, limit)?))
    }

    pub fn rdvec(&self, addr: u32) -> Res<Vec<String>> {
        let mut out = Vec::new();
        let mut a = addr;
        loop {
            let p = self.rd32(a)?;
            if p == 0 {
                break;
            }
            out.push(self.rdstr(p)?);
            a = a.wrapping_add(4);
        }
        Ok(out)
    }

    pub fn gr(&self, i: usize) -> u32 {
        self.cpu.gr[i] as u32
    }

    pub fn set_gr(&mut self, i: usize, v: u32) {
        if i != 0 {
            self.cpu.gr[i] = v as u64;
        }
    }

    // -- time ----------------------------------------------------------------------------

    /// the guest's time (etc/hpuxemu/clock)
    pub fn now(&self) -> f64 {
        host::now_f64() + self.clock_offset as f64
    }

    /// a host file time as the guest sees it: shifted like the clock when the file changed
    /// after the clock was set (made "now" in the guest's time), as it is before
    pub fn gtime(&self, t: i64) -> i64 {
        if let Some(a) = self.clock_anchor {
            if t >= a as i64 {
                return t + self.clock_offset;
            }
        }
        t
    }

    // -- descriptors ---------------------------------------------------------------------

    pub fn fd_check(&self, fd: u32) -> Res<()> {
        if self.fds.contains_key(&fd) {
            Ok(())
        } else {
            err(EBADF)
        }
    }

    pub fn newfd(&mut self, hostfd: i32, path: &str, flags: u32) -> u32 {
        self.fds.insert(hostfd as u32, Fd { path: path.to_string(), flags, ..Default::default() });
        hostfd as u32
    }

    // -- the owners table ------------------------------------------------------------------

    /// the owners table (etc/hpuxemu/owners: the HP-UX mode, owner, group and type of
    /// every file the depots delivered, by guest path), reloaded when another process has
    /// changed it (a forked child starts with its parent's copy; a chown in a sibling
    /// must show in ls)
    pub fn load_owners(&mut self) {
        if self.owners.is_some() && self.owners_fresh {
            return;
        }
        self.owners_fresh = true;
        let p = format!("{}/etc/hpuxemu/owners", self.root);
        let stamp = host::stat(&p, true).ok().map(|st| (st.st_mtime * 1_000_000_000 + st.st_mtime_nsec, st.st_size));
        if self.owners.is_none() || stamp != self.owners_stamp {
            self.owners = Some(Owners::load(&p, stamp));
            self.owners_stamp = stamp;
        }
    }

    fn write_owners(&mut self) {
        let dir = format!("{}/etc/hpuxemu", self.root);
        let _ = std::fs::create_dir_all(&dir);
        let mut out = String::new();
        if let Some(o) = self.owners.as_mut().map(|o| o.map()) {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            for k in keys {
                let (mode, uid, gid, typ) = &o[k];
                out.push_str(&format!("{:04o} {} {} {} {}\n", mode, uid, gid, typ, k));
            }
        }
        if std::fs::write(format!("{}/owners", dir), out).is_ok() {
            self.owners_stamp = None;
        }
    }

    // ---- permissions: the kernel's check, with the owners table for uid/gid ----
    //
    // A file's HP-UX owner and its HFS access control list live in extended attributes of
    // the host file (user.hpux.owner "uid gid", user.hpux.acl the optional entries
    // "uid.gid=mode,..."), so that they follow the file through rename and link and go
    // with it. The owners table the root was built with (etc/hpuxemu/owners, by path) is
    // the fallback, and the store on a host file system without user extended attributes.

    /// does the root's file system keep user extended attributes?
    pub fn xattrs_ok(&mut self) -> bool {
        if let Some(v) = self.xattrs {
            return v;
        }
        let c = cstr(&self.root);
        let n = cstr("user.hpux.probe");
        let r = unsafe { libc::getxattr(c.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
        let okv = r >= 0 || host::errno() == libc::ENODATA;
        self.xattrs = Some(okv);
        okv
    }

    /// the host path (or descriptor) to reach a file's extended attributes by: how this
    /// system call reached it, else its guest path
    pub fn xsrc(&mut self, gpath: &str, st: &libc::stat) -> Option<Src> {
        if let Some(s) = self.hpcache.get(&(st.st_dev, st.st_ino)) {
            return Some(s.clone());
        }
        if !gpath.is_empty() {
            if let Ok(hp) = self.hostpath_own(gpath, true) {
                return Some(Src::Path(hp));
            }
        }
        None
    }

    /// an emulator extended attribute of a file as text, or None (cached by inode and
    /// change time: setting an attribute changes the ctime)
    pub fn xget(&mut self, gpath: &str, st: &libc::stat, name: &'static str, src: Option<&Src>) -> Option<String> {
        if is_fake(st) || host::is_lnk(st) || !self.xattrs_ok() {
            return None;
        }
        let key = (st.st_dev, st.st_ino, st.st_ctime * 1_000_000_000 + st.st_ctime_nsec, name);
        if let Some(v) = self.xcache.get(&key) {
            return v.clone();
        }
        let src = match src {
            Some(s) => Some(s.clone()),
            None => self.xsrc(gpath, st),
        };
        let mut v = None;
        if let Some(src) = src {
            let n = cstr(name);
            let mut buf = [0u8; 1024];
            let r = unsafe {
                match &src {
                    Src::Path(p) => libc::getxattr(cstr(p).as_ptr(), n.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()),
                    Src::Fd(fd) => libc::fgetxattr(*fd, n.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()),
                }
            };
            if r >= 0 {
                if let Ok(s) = std::str::from_utf8(&buf[..r as usize]) {
                    if s.is_ascii() {
                        v = Some(s.to_string());
                    }
                }
            }
        }
        if self.xcache.len() > 4096 {
            self.xcache.clear();
        }
        self.xcache.insert(key, v.clone());
        v
    }

    /// set (value None: remove) an emulator extended attribute; false if the host file
    /// system cannot keep it
    pub fn xset(&mut self, src: &Src, name: &str, value: Option<&str>) -> Res<bool> {
        if !self.xattrs_ok() {
            return Ok(false);
        }
        let n = cstr(name);
        let r = unsafe {
            match (value, src) {
                (None, Src::Path(p)) => libc::removexattr(cstr(p).as_ptr(), n.as_ptr()),
                (None, Src::Fd(fd)) => libc::fremovexattr(*fd, n.as_ptr()),
                (Some(v), Src::Path(p)) => libc::setxattr(cstr(p).as_ptr(), n.as_ptr(), v.as_ptr() as *const libc::c_void, v.len(), 0),
                (Some(v), Src::Fd(fd)) => libc::fsetxattr(*fd, n.as_ptr(), v.as_ptr() as *const libc::c_void, v.len(), 0),
            }
        };
        if r < 0 {
            let e = host::errno();
            if value.is_none() && e == libc::ENODATA {
                return Ok(true);
            }
            if e == libc::ENOTSUP || e == libc::EPERM {
                return Ok(false); // symbolic links, odd files
            }
            return Err(herrno(e));
        }
        Ok(true)
    }

    /// a file's optional ACL entries: [(uid, gid, mode)], uid/gid NS for %
    pub fn acl_opt(&mut self, gpath: &str, st: &libc::stat, src: Option<&Src>) -> Vec<(i64, i64, i64)> {
        let v = self.xget(gpath, st, ACL_XATTR, src);
        let mut out = Vec::new();
        if let Some(v) = v {
            for item in v.split(',') {
                let (u, rest) = match item.split_once('.') {
                    Some(x) => x,
                    None => continue,
                };
                let (g, m) = match rest.split_once('=') {
                    Some(x) => x,
                    None => continue,
                };
                if let (Ok(u), Ok(g), Ok(m)) = (u.trim().parse(), g.trim().parse(), m.trim().parse()) {
                    out.push((u, g, m));
                }
            }
        }
        out
    }

    /// the three base entries, from the owner and the mode bits
    pub fn acl_base(&mut self, gpath: &str, st: &libc::stat, src: Option<&Src>) -> Vec<(i64, i64, i64)> {
        let (fuid, fgid) = self.owner_of(gpath, st, src);
        let m = st.st_mode as i64;
        vec![(fuid, NS, (m >> 6) & 7), (NS, fgid, (m >> 3) & 7), (NS, NS, m & 7)]
    }

    /// the permission bits of `want` (R 4, W 2, X 1) this process has on a file, as the
    /// kernel decides: the superuser has everything except execute on a file no ACL entry
    /// lets anyone execute; otherwise the access check of acl(5) - the most specific level
    /// of entries that matches the user and any of its groups decides, (u.g) before (u.%)
    /// before (%.g) before (%.%), the modes of several matching entries of one level
    /// OR-ed. Without optional entries that is the owner's, the group's or the others'
    /// bits.
    pub fn allowed(&mut self, gpath: &str, st: &libc::stat, want: u32, uid: Option<u32>, groups: Option<&[u32]>, src: Option<&Src>) -> Res<u32> {
        let uid = uid.unwrap_or(self.euid);
        let own;
        let groups: &[u32] = match groups {
            Some(g) => g,
            None => {
                let mut g = vec![self.egid];
                g.extend_from_slice(&self.groups);
                own = g;
                &own
            }
        };
        let mode = st.st_mode;
        let opt = self.acl_opt(gpath, st, src);
        if uid == 0 {
            if want & 1 != 0 && !host::is_dir(st) && mode & 0o111 == 0 && !opt.iter().any(|e| e.2 & 1 != 0) {
                return Ok(want & !1);
            }
            return Ok(want);
        }
        let (fuid, fgid) = self.owner_of(gpath, st, src);
        let ingroups = |g: i64| g >= 0 && groups.contains(&(g as u32));
        if opt.is_empty() {
            let bits = if uid as i64 == fuid {
                (mode >> 6) & 7
            } else if ingroups(fgid) {
                (mode >> 3) & 7
            } else {
                mode & 7
            };
            return Ok(want & bits);
        }
        let mut entries = opt;
        entries.push((fuid, NS, ((mode >> 6) & 7) as i64));
        entries.push((NS, fgid, ((mode >> 3) & 7) as i64));
        entries.push((NS, NS, (mode & 7) as i64));
        let uid = uid as i64;
        for level in 0..4 {
            let mut bits: Option<i64> = None;
            for &(u, g, m) in &entries {
                let hit = match level {
                    0 => u == uid && g != NS && ingroups(g),
                    1 => u == uid && g == NS,
                    2 => u == NS && g != NS && ingroups(g),
                    _ => u == NS && g == NS,
                };
                if hit {
                    bits = Some(bits.unwrap_or(0) | m);
                }
            }
            if let Some(b) = bits {
                return Ok(want & b as u32);
            }
        }
        Ok(0)
    }

    /// EACCES unless the process may do `want` on the path; ENOENT if it is not there
    pub fn check(&mut self, gpath: &str, want: u32, follow: bool) -> Res<libc::stat> {
        let st = self.host_stat(gpath, follow, None)?;
        let ga = self.guest_abspath(gpath);
        if self.allowed(&ga, &st, want, None, None, None)? != want {
            return err(EACCES);
        }
        Ok(st)
    }

    /// EPERM unless the process owns the file or is the superuser
    pub fn check_owner(&mut self, gpath: &str, st: Option<&libc::stat>, follow: bool) -> Res<()> {
        if self.euid == 0 {
            return Ok(());
        }
        let st = match st {
            Some(s) => *s,
            None => self.host_stat(gpath, follow, None)?,
        };
        let ga = self.guest_abspath(gpath);
        let (fuid, _) = self.owner_of(&ga, &st, None);
        if fuid != self.euid as i64 {
            return err(EPERM);
        }
        Ok(())
    }

    /// write permission on a path's parent directory, for creating or removing an entry;
    /// a sticky directory (/tmp) lets only the owner remove another's file
    pub fn check_dir_write(&mut self, gpath: &str, removing: bool) -> Res<()> {
        if self.euid == 0 {
            return Ok(());
        }
        let ga = self.guest_abspath(gpath);
        let trimmed = ga.trim_end_matches('/');
        let parent = match trimmed.rfind('/') {
            Some(0) | None => "/".to_string(),
            Some(i) => trimmed[..i].to_string(),
        };
        let pst = self.check(&parent, 3, true)?;
        if removing && pst.st_mode & 0o1000 != 0 {
            let st = match self.host_stat(gpath, false, None) {
                Ok(s) => s,
                Err(_) => return Ok(()),
            };
            let (fuid, _) = self.owner_of(&ga, &st, None);
            let (duid, _) = self.owner_of(&parent, &pst, None);
            if self.euid as i64 != fuid && self.euid as i64 != duid {
                return err(EPERM);
            }
        }
        Ok(())
    }

    /// The HP-UX owner of a file: its user.hpux.owner attribute, else the owners table
    /// the root was built with (etc/hpuxemu/owners, from the depot), else the host's
    /// owner, the host user being the emulated user.
    pub fn owner_of(&mut self, gpath: &str, st: &libc::stat, src: Option<&Src>) -> (i64, i64) {
        if let Some(v) = self.xget(gpath, st, OWNER_XATTR, src) {
            let mut it = v.split_whitespace();
            if let (Some(u), Some(g), None) = (it.next(), it.next(), it.next()) {
                if let (Ok(u), Ok(g)) = (u.parse(), g.parse()) {
                    return (u, g);
                }
            }
        }
        self.load_owners();
        if !gpath.is_empty() {
            if let Some(rec) = self.owners.as_ref().and_then(|o| o.get(gpath)) {
                return (rec.1, rec.2);
            }
        }
        // no record: the file was made by the host user - the root builder, or a process
        // running as the superuser (which records nothing) - so it is root's; a host file
        // of another host user (a pass-through tty) keeps that owner
        let uid = if st.st_uid == self.host_uid { 0 } else if st.st_uid < 65536 { st.st_uid } else { 0 };
        let gid = if st.st_gid == self.host_gid { 0 } else if st.st_gid < 65536 { st.st_gid } else { 0 };
        (uid as i64, gid as i64)
    }

    /// A file the process has just created belongs to it. Nothing needs recording for the
    /// superuser - unless the owners table has an entry for the path (a depot file that
    /// was removed or renamed), which would otherwise apply.
    pub fn new_file_owner(&mut self, gpath: &str, src: &Src) -> Res<()> {
        self.load_owners();
        if self.euid == 0 && self.owners.as_ref().and_then(|o| o.get(gpath)).is_none() {
            return Ok(());
        }
        let st = match src {
            Src::Fd(fd) => host::fstat(*fd).map_err(herrno)?,
            Src::Path(p) => host::stat(p, false).map_err(herrno)?,
        };
        let (uid, gid) = if self.euid != 0 { (self.euid, self.egid) } else { (0, 0) };
        self.set_owner(gpath, &st, uid, gid, Some(src))
    }

    /// record a file's HP-UX owner: in its user.hpux.owner attribute, else (a symbolic
    /// link, a file system without user attributes) in the owners table
    pub fn set_owner(&mut self, gpath: &str, st: &libc::stat, uid: u32, gid: u32, src: Option<&Src>) -> Res<()> {
        if gpath.is_empty() {
            return Ok(());
        }
        let (ouid, ogid) = self.owner_of(gpath, st, src);
        let uid = if uid == 0xFFFF_FFFF { ouid } else { uid as i32 as i64 };
        let gid = if gid == 0xFFFF_FFFF { ogid } else { gid as i32 as i64 };
        let src = match src {
            Some(s) => Some(s.clone()),
            None => self.xsrc(gpath, st),
        };
        if let Some(s) = &src {
            if !host::is_lnk(st) && self.xset(s, OWNER_XATTR, Some(&format!("{} {}", uid, gid)))? {
                return Ok(());
            }
        }
        self.load_owners();
        let o = self.owners.get_or_insert_with(|| Owners::Map(HashMap::new())).map();
        let (mode, typ) = match o.get(gpath) {
            Some(rec) => (rec.0, rec.3.clone()),
            None => (st.st_mode & 0o7777, if host::is_dir(st) { "d".to_string() } else { "f".to_string() }),
        };
        o.insert(gpath.to_string(), (mode, uid, gid, typ));
        self.write_owners();
        Ok(())
    }

    /// Before a rename: owners known only from the owners table (by path) would stay
    /// behind - and the table entry of the new path would apply to the file moved there.
    /// Give the file, and those under a directory, their owner as an attribute, which
    /// moves with them.
    pub fn carry_owners(&mut self, gold: &str, gnew: &str) {
        if !self.xattrs_ok() {
            return;
        }
        self.load_owners();
        let pre = format!("{}/", gold.trim_end_matches('/'));
        let o = self.owners.as_ref().unwrap();
        let mut paths = vec![gold.to_string()];
        paths.extend(o.with_prefix(&pre));
        if !(o.get(gold).is_some() || o.get(gnew).is_some() || paths.len() > 1) {
            return;
        }
        for gp in paths {
            let hp = match self.hostpath_own(&gp, false) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let st = match host::stat(&hp, false) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let src = Src::Path(hp);
            if host::is_lnk(&st) || self.xget(&gp, &st, OWNER_XATTR, Some(&src)).map(|v| !v.is_empty()).unwrap_or(false) {
                continue;
            }
            let (u, g) = self.owner_of(&gp, &st, Some(&src));
            let _ = self.xset(&src, OWNER_XATTR, Some(&format!("{} {}", u, g)));
        }
    }

    // -- stat ------------------------------------------------------------------------------

    pub fn host_stat(&mut self, gp: &str, follow: bool, cred: Option<(u32, Vec<u32>)>) -> Res<libc::stat> {
        let devs = self.stream_devices();
        if !devs.is_empty() {
            let g = self.guest_abspath(gp);
            if let Some(d) = devs.get(&g) {
                return Ok(crate::streams::node_stat(d.1, &g));
            }
        }
        let hp = self.hostpath_c(gp, follow, true, cred)?;
        let st = host::stat(&hp, follow).map_err(herrno)?;
        self.hpcache.insert((st.st_dev, st.st_ino), Src::Path(hp));
        Ok(st)
    }

    fn stat_fields(&mut self, st: &libc::stat, gpath: &str, size: Option<i64>) -> (u32, i64, i64, i64) {
        let mode = st.st_mode & 0o177777;
        let size = size.unwrap_or(st.st_size);
        let (uid, gid) = self.owner_of(gpath, st, None);
        (mode, size, uid, gid)
    }

    pub fn stat_buf(&mut self, st: &libc::stat, gpath: &str, size: Option<i64>) -> Vec<u8> {
        use off::stat as S;
        let (mode, size, uid, gid) = self.stat_fields(st, gpath, size);
        let mut b = Pk::new(S::SIZE);
        b.put(S::st_dev, hp_dev(st.st_dev) as u64);
        b.put(S::st_ino, st.st_ino & M32);
        b.put(S::st_mode, mode as u64);
        b.put(S::st_nlink, st.st_nlink);
        b.put(S::st_rdev, hp_dev(st.st_rdev) as u64);
        b.put(S::st_size, size.min(0x7FFF_FFFF) as u64);
        b.put(S::st_atime, self.gtime(st.st_atime) as u64);
        b.put(S::st_mtime, self.gtime(st.st_mtime) as u64);
        b.put(S::st_ctime, self.gtime(st.st_ctime) as u64);
        b.put(S::st_blksize, 8192);
        b.put(S::st_blocks, ((size + 511) / 512) as u64);
        b.put(S::st_uid, uid as u64);
        b.put(S::st_gid, gid as u64);
        b.put(S::st_basemode, (mode & 0o7777) as u64);
        b.put(S::st_fstype, 1);
        b.put(S::st_realdev, hp_dev(st.st_dev) as u64);
        // st_acl: the bit after the 30-bit st_pad that follows st_blocks (mask 2 of that
        // word), set when the file has optional ACL entries (ls -l shows a +)
        if !self.acl_opt(gpath, st, None).is_empty() {
            b.0[S::st_blocks.0 + S::st_blocks.1 + 3] |= 2;
        }
        b.0
    }

    pub fn stat64_buf(&mut self, st: &libc::stat, gpath: &str, size: Option<i64>) -> Vec<u8> {
        use off::stat64 as S;
        let (mode, size, uid, gid) = self.stat_fields(st, gpath, size);
        let mut b = Pk::new(S::SIZE);
        b.put(S::st_dev, hp_dev(st.st_dev) as u64);
        b.put(S::st_ino, st.st_ino & M32);
        b.put(S::st_mode, mode as u64);
        b.put(S::st_nlink, st.st_nlink);
        b.put(S::st_rdev, hp_dev(st.st_rdev) as u64);
        b.put(S::st_size, size as u64);
        b.put(S::st_atime, self.gtime(st.st_atime) as u64);
        b.put(S::st_mtime, self.gtime(st.st_mtime) as u64);
        b.put(S::st_ctime, self.gtime(st.st_ctime) as u64);
        b.put(S::st_blksize, 8192);
        b.put(S::st_blocks, ((size + 511) / 512) as u64);
        b.put(S::st_uid, uid as u64);
        b.put(S::st_gid, gid as u64);
        b.put(S::st_basemode, (mode & 0o7777) as u64);
        b.put(S::st_fstype, 1);
        b.put(S::st_realdev, hp_dev(st.st_dev) as u64);
        if !self.acl_opt(gpath, st, None).is_empty() {
            b.0[S::st_blocks.0 + S::st_blocks.1 + 3] |= 2;
        }
        b.0
    }
}

pub const OWNER_XATTR: &str = "user.hpux.owner";
pub const ACL_XATTR: &str = "user.hpux.acl";
/// % in an ACL entry: no specific user / group (-36)
pub const NS: i64 = ACL_NSUSER as i64;

/// a made-up stat (a STREAMS device): no extended attributes to look for
pub fn is_fake(st: &libc::stat) -> bool {
    st.st_ctime_nsec == -1
}

/// A host device number as an HP-UX dev_t: major in bits 24..31, minor below.
pub fn hp_dev(dev: u64) -> u32 {
    ((libc::major(dev) & 0xFF) << 24) | (libc::minor(dev) & 0xFF_FFFF)
}

/// the CPU, with the JIT as HPUXEMU_JIT says: 'off'/'0', 'on'/'1' (the defaults), or
/// 'THRESHOLD,MAXLEN'
pub fn new_cpu() -> Cpu {
    let mut cpu = match Cpu::new(false) {
        Some(mut c) => {
            c.syscall_page = Some(GATEWAY);
            c
        }
        None => {
            crate::emsg!("hpuxemu: cannot reserve the guest address space\n");
            std::process::exit(2);
        }
    };
    let cfg = host::getenv("HPUXEMU_JIT").unwrap_or_else(|| "on".to_string()).trim().to_lowercase();
    let jit = match cfg.as_str() {
        "0" | "off" | "no" | "false" => None,
        "1" | "on" | "yes" | "true" | "" => Some((10, 64)),
        s => {
            let mut it = s.split(',').map(|x| x.trim().parse::<u32>());
            match (it.next(), it.next()) {
                (Some(Ok(t)), Some(Ok(l))) => Some((t, l)),
                _ => Some((10, 64)),
            }
        }
    };
    cpu.set_jit(jit);
    // compiled loads without the page-flag check (HPUXEMU_FASTMEM=0: with it); the CPU's
    // fault handler then owns SIGSEGV and SIGBUS
    if jit.is_some() && host::getenv("HPUXEMU_FASTMEM").map(|v| v != "0").unwrap_or(true) {
        hppa32_jit::set_fault_fallback(host::fault_fallback);
        cpu.set_fast_mem(true);
        host::FAULTS_OWNED.store(1, std::sync::atomic::Ordering::Relaxed);
    }
    cpu
}

/// "1999-06-01", "1999-06-01 12:00" or "1999-06-01 12:00:00" as local time
fn parse_local_time(txt: &str) -> Option<i64> {
    let (date, time) = match txt.split_once(' ') {
        Some((d, t)) => (d, t.trim()),
        None => (txt, ""),
    };
    let d: Vec<&str> = date.split('-').collect();
    if d.len() != 3 {
        return None;
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = d[0].parse::<i32>().ok()? - 1900;
    tm.tm_mon = d[1].parse::<i32>().ok()? - 1;
    tm.tm_mday = d[2].parse().ok()?;
    if !time.is_empty() {
        let t: Vec<&str> = time.split(':').collect();
        if t.len() < 2 || t.len() > 3 {
            return None;
        }
        tm.tm_hour = t[0].parse().ok()?;
        tm.tm_min = t[1].parse().ok()?;
        if t.len() == 3 {
            tm.tm_sec = t[2].parse().ok()?;
        }
    }
    tm.tm_isdst = -1;
    let r = unsafe { libc::mktime(&mut tm) };
    if r == -1 {
        None
    } else {
        Some(r)
    }
}

/// A guest structure being filled in: big-endian members at the offsets of consts.rs.
pub struct Pk(pub Vec<u8>);

impl Pk {
    pub fn new(size: usize) -> Pk {
        Pk(vec![0u8; size])
    }
    pub fn put(&mut self, f: F, v: u64) {
        put(&mut self.0, f, v)
    }
    pub fn bytes(&mut self, f: F, b: &[u8]) {
        let n = f.1.min(b.len());
        self.0[f.0..f.0 + n].copy_from_slice(&b[..n]);
    }
}

pub fn put(buf: &mut [u8], f: F, v: u64) {
    let b = v.to_be_bytes();
    if f.1 <= 8 {
        buf[f.0..f.0 + f.1].copy_from_slice(&b[8 - f.1..]);
    }
}

/// a member of a guest structure, unsigned
pub fn get(buf: &[u8], f: F) -> u64 {
    let mut v = 0u64;
    for &c in &buf[f.0..f.0 + f.1.min(8)] {
        v = (v << 8) | c as u64;
    }
    v
}

pub fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
pub fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
pub fn be64(b: &[u8], o: usize) -> u64 {
    ((be32(b, o) as u64) << 32) | be32(b, o + 4) as u64
}

/// sysconf(_SC_CPU_VERSION): PA-RISC 1.1 (sys/unistd.h's CPU_PA_RISC1_1)
pub const CPU_PA_RISC1_1: u32 = 0x210;
