//! files: open, read, write, stat, directories, permissions, access control lists, fcntl

use super::Handler;
use crate::consts::*;
use crate::emsg;
use crate::host::{self, cstr, to_latin1};
use crate::process::*;
use std::rc::Rc;

pub const TABLE: &[(&str, Handler)] = &[
    ("open", Process::sys_open),
    ("creat", Process::sys_creat),
    ("close", Process::sys_close),
    ("read", Process::sys_read),
    ("write", Process::sys_write),
    ("readv", Process::sys_readv),
    ("writev", Process::sys_writev),
    ("lseek", Process::sys_lseek),
    ("lseek64", Process::sys_lseek64),
    ("dup", Process::sys_dup),
    ("dup2", Process::sys_dup2),
    ("pipe", Process::sys_pipe),
    ("stat", Process::sys_stat),
    ("lstat", Process::sys_lstat),
    ("fstat", Process::sys_fstat),
    ("stat64", Process::sys_stat64),
    ("lstat64", Process::sys_lstat64),
    ("fstat64", Process::sys_fstat64),
    ("access", Process::sys_access),
    ("getaccess", Process::sys_getaccess),
    ("getacl", Process::sys_getacl),
    ("fgetacl", Process::sys_fgetacl),
    ("setacl", Process::sys_setacl),
    ("fsetacl", Process::sys_fsetacl),
    ("chdir", Process::sys_chdir),
    ("fchdir", Process::sys_fchdir),
    ("chmod", Process::sys_chmod),
    ("fchmod", Process::sys_fchmod),
    ("chown", Process::sys_chown),
    ("lchown", Process::sys_lchown),
    ("fchown", Process::sys_fchown),
    ("link", Process::sys_link),
    ("unlink", Process::sys_unlink),
    ("symlink", Process::sys_symlink),
    ("readlink", Process::sys_readlink),
    ("rename", Process::sys_rename),
    ("mkdir", Process::sys_mkdir),
    ("rmdir", Process::sys_rmdir),
    ("mknod", Process::sys_mknod),
    ("utime", Process::sys_utime),
    ("truncate", Process::sys_truncate),
    ("ftruncate", Process::sys_ftruncate),
    ("fsync", Process::sys_zero),
    ("sync", Process::sys_zero),
    ("fcntl", Process::sys_fcntl),
    ("fcntl64", Process::sys_fcntl),
    ("lockf", Process::sys_zero),
    ("lockf64", Process::sys_zero),
    ("getdents", Process::sys_getdents),
    ("getdirentries", Process::sys_getdirentries),
    ("pathconf", Process::sys_pathconf),
    ("fpathconf", Process::sys_pathconf),
    ("statfs", Process::sys_statfs),
    ("fstatfs", Process::sys_fstatfs),
    ("statvfs", Process::sys_statvfs),
    ("fstatvfs", Process::sys_fstatvfs),
    ("statvfs64", Process::sys_statvfs64),
    ("fstatvfs64", Process::sys_fstatvfs64),
];

/// HP-UX's pty master driver; slaves are /dev/pty/tty[p-z][0-9a-f]
pub const PTY_MAJOR: u32 = 16;
/// struct acl_entry: long uid, long gid, unsigned char mode
const ACL_ENTRY: usize = 12;
const NACLENTRIES: i32 = 16;

fn list_dir(hp: &str) -> Result<Vec<String>, i32> {
    let rd = std::fs::read_dir(hp).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    let mut v: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    Ok(v)
}

impl Process {
    /// open(path, flags, mode): HP-UX O_ flags are mapped to the host's
    pub fn sys_open(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        ok(self.do_open(&gp, a[1], a[2])?)
    }

    /// creat(path, mode): open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)
    pub fn sys_creat(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        ok(self.do_open(&gp, O_WRONLY | O_CREAT | O_TRUNC, a[1])?)
    }

    pub fn do_open(&mut self, gp: &str, flags: u32, mode: u32) -> Res<u32> {
        let mut hflags = (flags & 3) as i32;
        for (g, h) in [
            (O_APPEND, libc::O_APPEND),
            (O_CREAT, libc::O_CREAT),
            (O_TRUNC, libc::O_TRUNC),
            (O_EXCL, libc::O_EXCL),
            (O_NONBLOCK, libc::O_NONBLOCK),
            (O_NDELAY, libc::O_NONBLOCK),
            (O_NOCTTY, libc::O_NOCTTY),
            (O_SYNC, libc::O_SYNC),
        ] {
            if flags & g != 0 {
                hflags |= h;
            }
        }
        let gabs = self.guest_abspath(gp);
        if gabs == "/dev/ptym/clone" || gabs == "/dev/ptmx" {
            return self.open_pty_master(flags);
        }
        if gabs == "/dev/netman" {
            // HP-UX's network management driver: its ioctls are answered here (netman.rs)
            let fd = unsafe { libc::open(cstr("/dev/null").as_ptr(), libc::O_RDWR) };
            if fd < 0 {
                return Err(herr());
            }
            self.newfd(fd, &gabs, flags);
            self.fds.get_mut(&(fd as u32)).unwrap().netman = true;
            return Ok(fd as u32);
        }
        let devs = self.stream_devices();
        if self.is11 && !devs.contains_key(&gabs) && crate::streams::is_mib_device(&gabs) {
            return self.open_mib_stream(&gabs, flags);
        }
        if let Some(d) = devs.get(&gabs) {
            if !d.0.starts_with('-') {
                if let Some(fd) = self.open_stream(&gabs, flags)? {
                    return Ok(fd);
                }
            }
        }
        if let Some(host_slave) = self.ptys.get(&gabs).cloned() {
            // a pseudo-terminal slave the guest got from the clone device
            let fd = unsafe { libc::open(cstr(&host_slave).as_ptr(), hflags) };
            if fd < 0 {
                return Err(herr());
            }
            self.my_ttys.insert(host_slave);
            return Ok(self.newfd(fd, &gabs, flags));
        }
        let hp = self.hostpath(gp)?;
        let acc = hflags & 3;
        let want = if acc == libc::O_RDONLY || acc == libc::O_RDWR { 4 } else { 0 }
            + if acc == libc::O_WRONLY || acc == libc::O_RDWR || flags & O_TRUNC != 0 { 2 } else { 0 };
        let existed = host::lexists(&hp);
        if existed {
            self.check(gp, want, true)?;
        } else if hflags & libc::O_CREAT != 0 {
            self.check_dir_write(gp, false)?;
        } else {
            return err(ENOENT);
        }
        let fd = host::retry(|| unsafe { libc::open(cstr(&hp).as_ptr(), hflags, (mode & 0o7777) as libc::c_uint) as isize }) as i32;
        if fd < 0 {
            return Err(herr());
        }
        if !existed {
            let _ = self.new_file_owner(&gabs, &Src::Fd(fd));
        }
        Ok(self.newfd(fd, &gabs, flags))
    }

    pub fn is_tty(&self, fd: u32) -> bool {
        host::isatty(fd as i32)
    }

    /// When the program closes or replaces its fd 2 and that is a pipe or socket, the
    /// emulator's private copy of it (detach_stderr) must not keep it open: a daemon that
    /// forks and closes 0-2 would hold its parent's pipe for ever and the parent (a shell
    /// with `2>&1 | ...`) would wait on it. The copy goes to /dev/null; for a terminal or
    /// a file it is kept, since holding those blocks no one.
    fn release_stderr(&mut self, fd: u32) {
        if fd != 2 {
            return;
        }
        let mine = host::err_fd();
        if let (Ok(a), Ok(b)) = (host::fstat(2), host::fstat(mine)) {
            if a.st_dev == b.st_dev && a.st_ino == b.st_ino && (host::is_fifo(&a) || host::is_sock(&a)) {
                unsafe {
                    let null = libc::open(cstr("/dev/null").as_ptr(), libc::O_WRONLY);
                    if null >= 0 {
                        libc::dup3(null, mine, libc::O_CLOEXEC);
                        libc::close(null);
                    }
                }
            }
        }
    }

    /// close(fd): the host descriptor is closed and forgotten; fd 2 on a pipe releases
    /// the emulator's own copy of it too
    pub fn sys_close(&mut self, a: &[u32; 8]) -> SysResult {
        let fd = a[0];
        self.fd_check(fd)?;
        self.release_stderr(fd);
        self.nbmode.remove(&fd);
        if unsafe { libc::close(fd as i32) } < 0 {
            return Err(herr());
        }
        self.fds.remove(&fd);
        ok(0)
    }

    /// read(fd, buf, n): the host's read, straight into the guest's memory, so a signal
    /// interrupts it; n = 0 succeeds whatever buf is
    pub fn sys_read(&mut self, a: &[u32; 8]) -> SysResult {
        let (fd, buf, n) = (a[0], a[1], a[2]);
        self.fd_check(fd)?;
        if let Some(st) = self.stream_of(fd) {
            return self.stream_read(fd, st, buf, n);
        }
        self.joined_wait(fd, None)?;
        if n != 0 && self.cpu.mem.range_ok(buf, n, 2) && !self.cpu.mem.has_code(buf, n) {
            // every page writable and none holding compiled code: read in place
            let r = unsafe { libc::read(fd as i32, self.cpu.mem.host(buf) as *mut libc::c_void, n as usize) };
            if r < 0 {
                return Err(herr_intr());
            }
            return ok(r as u32);
        }
        let mut data = vec![0u8; n as usize];
        let r = unsafe { libc::read(fd as i32, data.as_mut_ptr() as *mut libc::c_void, n as usize) };
        if r < 0 {
            return Err(herr_intr());
        }
        self.wr(buf, &data[..r as usize])?;
        ok(r as u32)
    }

    /// write(fd, buf, n): the host's write (n = 0 succeeds whatever buf is)
    pub fn sys_write(&mut self, a: &[u32; 8]) -> SysResult {
        let (fd, buf, n) = (a[0], a[1], a[2]);
        self.fd_check(fd)?;
        if let Some(st) = self.stream_of(fd) {
            let data = self.rd(buf, n as usize)?;
            if n != 0 {
                self.stream_put(fd, st, None, &data, 0, false)?;
            }
            return ok(n);
        }
        if n == 0 {
            let r = unsafe { libc::write(fd as i32, std::ptr::null(), 0) };
            if r < 0 {
                return Err(herr_intr());
            }
            return ok(0);
        }
        if !self.cpu.mem.range_ok(buf, n, 1) {
            return err(EFAULT);
        }
        let r = unsafe { libc::write(fd as i32, self.cpu.mem.host(buf) as *const libc::c_void, n as usize) };
        if r < 0 {
            return Err(herr_intr());
        }
        ok(r as u32)
    }

    /// readv(fd, iov, cnt): one read per element until a short read
    pub fn sys_readv(&mut self, a: &[u32; 8]) -> SysResult {
        let mut total = 0u32;
        for i in 0..a[2] {
            let d = self.rd(a[1] + 8 * i, 8)?;
            let (base, ln) = (be32(&d, 0), be32(&d, 4));
            let r = self.sys_read(&[a[0], base, ln, 0, 0, 0, 0, 0])?.0;
            total += r;
            if r < ln {
                break;
            }
        }
        ok(total)
    }

    /// writev(fd, iov, cnt): the elements gathered into one write
    pub fn sys_writev(&mut self, a: &[u32; 8]) -> SysResult {
        let mut data = Vec::new();
        for i in 0..a[2] {
            let d = self.rd(a[1] + 8 * i, 8)?;
            data.extend_from_slice(&self.rd(be32(&d, 0), be32(&d, 4) as usize)?);
        }
        self.fd_check(a[0])?;
        let r = unsafe { libc::write(a[0] as i32, data.as_ptr() as *const libc::c_void, data.len()) };
        if r < 0 {
            return Err(herr_intr());
        }
        ok(r as u32)
    }

    /// lseek(fd, offset, whence): offsets are 32-bit; lseek64 returns the high word in
    /// r29. On a directory the offset is a getdents cookie (entry index + 1; 0 rewinds):
    /// tar closes a directory after every file and seeks back to where it was
    pub fn sys_lseek(&mut self, a: &[u32; 8]) -> SysResult {
        let (fd, off, whence) = (a[0], a[1] as i32 as i64, a[2]);
        self.fd_check(fd)?;
        if let Some(r) = self.dir_seek(fd, off, whence)? {
            return ok(r as u32);
        }
        let r = unsafe { libc::lseek(fd as i32, off, whence as i32) };
        if r < 0 {
            return Err(herr());
        }
        ok(r as u32)
    }

    fn dir_names(&mut self, fd: u32) -> Res<Rc<Vec<String>>> {
        if let Some(d) = &self.fds[&fd].dirents {
            return Ok(d.clone());
        }
        let path = self.fds[&fd].path.clone();
        let hp = self.hostpath_own(&path, true)?;
        let mut names = vec![".".to_string(), "..".to_string()];
        names.extend(list_dir(&hp).map_err(herrno)?);
        let gp = self.guest_abspath(&path);
        if gp == "/dev/pts" {
            let mut more: Vec<String> = list_dir("/dev/pts").map_err(herrno)?.into_iter().filter(|n| n.bytes().all(|c| c.is_ascii_digit())).collect();
            more.sort();
            names.extend(more);
        } else if gp == "/dev" {
            let mut more: Vec<String> = self
                .my_ttys
                .iter()
                .filter(|t| t.matches('/').count() == 2)
                .map(|t| t.rsplit('/').next().unwrap_or("").to_string())
                .filter(|b| !names.contains(b))
                .collect();
            more.sort();
            names.extend(more);
        }
        let rc = Rc::new(names);
        let f = self.fds.get_mut(&fd).unwrap();
        f.dirents = Some(rc.clone());
        f.dirpos = 0;
        Ok(rc)
    }

    /// lseek on a directory: the position is an index into the entries getdents lists
    /// (the cookies it returns are index + 1); None if fd is not a directory
    fn dir_seek(&mut self, fd: u32, off: i64, whence: u32) -> Res<Option<u64>> {
        match host::fstat(fd as i32) {
            Ok(st) if host::is_dir(&st) => {}
            _ => return Ok(None),
        }
        let names = self.dir_names(fd)?;
        let f = self.fds.get_mut(&fd).unwrap();
        let pos = match whence {
            0 => off,
            1 => f.dirpos as i64 + off,
            _ => names.len() as i64 + off,
        };
        f.dirpos = pos.clamp(0, names.len() as i64) as usize;
        Ok(Some(f.dirpos as u64))
    }

    /// lseek64(fd, offset (r25:r24), whence): the 64-bit result in r28:r29
    pub fn sys_lseek64(&mut self, a: &[u32; 8]) -> SysResult {
        let fd = a[0];
        self.fd_check(fd)?;
        let off = (((a[1] as u64) << 32) | a[2] as u64) as i64;
        let r = match self.dir_seek(fd, off, a[3])? {
            Some(r) => r,
            None => {
                let r = unsafe { libc::lseek(fd as i32, off, a[3] as i32) };
                if r < 0 {
                    return Err(herr());
                }
                r as u64
            }
        };
        ok2((r >> 32) as u32, r as u32)
    }

    fn dup_record(&mut self, fd: u32, n: u32) {
        let rec = self.fds[&fd].clone();
        self.fds.insert(n, rec);
        self.nb_copy(fd, n);
    }

    /// dup(fd): the lowest free descriptor, inheritable
    pub fn sys_dup(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let n = unsafe { libc::dup(a[0] as i32) };
        if n < 0 {
            return Err(herr());
        }
        self.dup_record(a[0], n as u32);
        ok(n as u32)
    }

    /// dup2(fd, fd2)
    pub fn sys_dup2(&mut self, a: &[u32; 8]) -> SysResult {
        let (fd, fd2) = (a[0], a[1]);
        self.fd_check(fd)?;
        if fd == fd2 {
            return ok(fd2);
        }
        self.release_stderr(fd2);
        if host::retry(|| unsafe { libc::dup2(fd as i32, fd2 as i32) as isize }) < 0 {
            return Err(herr());
        }
        self.dup_record(fd, fd2);
        ok(fd2)
    }

    /// pipe(): the two descriptors come back in r28 and r29
    pub fn sys_pipe(&mut self, _a: &[u32; 8]) -> SysResult {
        let mut p = [0i32; 2];
        if unsafe { libc::pipe(p.as_mut_ptr()) } < 0 {
            return Err(herr());
        }
        self.newfd(p[0], "pipe", 0);
        self.newfd(p[1], "pipe", 0);
        ok2(p[0] as u32, p[1] as u32)
    }

    /// stat(path, buf): struct stat (ABI.md) from the host; device numbers in the HP-UX layout
    pub fn sys_stat(&mut self, a: &[u32; 8]) -> SysResult {
        self.stat_path(a, true, false)
    }

    /// lstat(path, buf): stat without following the last link
    pub fn sys_lstat(&mut self, a: &[u32; 8]) -> SysResult {
        self.stat_path(a, false, false)
    }

    /// stat64(path, buf): struct stat64 with 64-bit sizes and inode numbers
    pub fn sys_stat64(&mut self, a: &[u32; 8]) -> SysResult {
        self.stat_path(a, true, true)
    }

    /// lstat64(path, buf)
    pub fn sys_lstat64(&mut self, a: &[u32; 8]) -> SysResult {
        self.stat_path(a, false, true)
    }

    fn stat_path(&mut self, a: &[u32; 8], follow: bool, wide: bool) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let st = self.host_stat(&gp, follow, None)?;
        let ga = self.guest_abspath(&gp);
        let d = if wide { self.stat64_buf(&st, &ga, None) } else { self.stat_buf(&st, &ga, None) };
        self.wr(a[1], &d)?;
        ok(0)
    }

    /// fstat(fd, buf); for a pipe st_size is the number of unread bytes, as on HP-UX
    pub fn sys_fstat(&mut self, a: &[u32; 8]) -> SysResult {
        self.fstat_any(a, false)
    }

    /// fstat64(fd, buf)
    pub fn sys_fstat64(&mut self, a: &[u32; 8]) -> SysResult {
        self.fstat_any(a, true)
    }

    fn fstat_any(&mut self, a: &[u32; 8], wide: bool) -> SysResult {
        let fd = a[0];
        self.fd_check(fd)?;
        let mut st = host::fstat(fd as i32).map_err(herrno)?;
        let path = self.fds[&fd].path.clone();
        if self.fds[&fd].stream.is_some() && !wide {
            let dev = self.stream_devices().get(&path).and_then(|d| d.1);
            st = crate::streams::node_stat(dev, &path);
        } else {
            self.hpcache.insert((st.st_dev, st.st_ino), Src::Fd(fd as i32));
        }
        // st_size of a pipe or FIFO: on HP-UX the number of unread bytes in it (Linux says
        // 0). dtexec fstats the pipe carrying its child's stderr when select says it is
        // readable and takes size 0 for end of file: it closed the pipe and the child
        // died of SIGPIPE on its next message.
        let mut size = None;
        if host::is_fifo(&st) {
            let mut n: libc::c_int = 0;
            if unsafe { libc::ioctl(fd as i32, libc::FIONREAD, &mut n) } == 0 {
                size = Some(n as i64);
            }
        }
        let mut d = if wide { self.stat64_buf(&st, &path, size) } else { self.stat_buf(&st, &path, size) };
        if let Some(n) = self.fds[&fd].pty {
            // st_rdev (and the mode: a character device) of a pty master
            let (rdev, mode) = if wide { (off::stat64::st_rdev, off::stat64::st_mode) } else { (off::stat::st_rdev, off::stat::st_mode) };
            put(&mut d, rdev, ((PTY_MAJOR << 24) | n) as u64);
            let m = get(&d, mode);
            put(&mut d, mode, (m & 0o7777) | 0o020000);
        }
        self.wr(a[1], &d)?;
        ok(0)
    }

    /// access(path, mode): the kernel's check with the *real* ids, for the path's
    /// directories too; ACLs included
    pub fn sys_access(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let mut groups = vec![self.gid];
        groups.extend_from_slice(&self.groups);
        let st = self.host_stat(&gp, true, Some((self.uid, groups.clone())))?;
        let ga = self.guest_abspath(&gp);
        if self.allowed(&ga, &st, a[1] & 7, Some(self.uid), Some(&groups), None)? != a[1] & 7 {
            return err(EACCES);
        }
        ok(0)
    }

    /// getaccess(path, uid, ngroups, gidset, label, privs): the access bits a given
    /// identity has on a path (UID_EUID -34 / UID_RUID -33 / UID_SUID -32; NGROUPS_EGID -1
    /// ... NGROUPS_EGID_SUPP -5 name the process's own groups, else gidset lists them);
    /// R_OK|W_OK|X_OK
    pub fn sys_getaccess(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let st = self.host_stat(&gp, true, None)?;
        let uid = match a[1] as i32 {
            -34 => self.euid,
            -33 => self.uid,
            -32 => self.suid,
            _ => a[1],
        };
        let ng = a[2] as i32;
        let with = |first: u32, me: &Process| {
            let mut v = vec![first];
            v.extend_from_slice(&me.groups);
            v
        };
        let groups: Vec<u32> = if ng >= 0 {
            let mut v = Vec::new();
            for i in 0..ng as u32 {
                v.push(self.rd32(a[3] + 4 * i)?);
            }
            v
        } else {
            match ng {
                -1 => vec![self.egid],
                -2 => vec![self.gid],
                -3 => vec![self.sgid],
                -4 => self.groups.clone(),
                -6 => with(self.gid, self),
                -7 => with(self.sgid, self),
                _ => with(self.egid, self),
            }
        };
        let ga = self.guest_abspath(&gp);
        ok(self.allowed(&ga, &st, 7, Some(uid), Some(&groups), None)?)
    }

    // ---- HFS access control lists: getacl(2), setacl(2) ----

    /// the whole ACL in getacl's order: by decreasing specificity - (u.g), (u.%), (%.g),
    /// (%.%) - and by user and group id within each
    fn acl_entries(&mut self, gpath: &str, st: &libc::stat, src: Option<&Src>) -> Vec<(i64, i64, i64)> {
        let mut ents = self.acl_base(gpath, st, src);
        ents.extend(self.acl_opt(gpath, st, src));
        let level = |e: &(i64, i64, i64)| {
            if e.0 != NS {
                if e.1 != NS { 0 } else { 1 }
            } else if e.1 != NS {
                2
            } else {
                3
            }
        };
        ents.sort_by_key(|e| (level(e), e.0, e.1));
        ents
    }

    fn put_acl(&mut self, gpath: &str, st: &libc::stat, src: Option<&Src>, n: u32, buf: u32) -> SysResult {
        let n = n as i32;
        let ents = self.acl_entries(gpath, st, src);
        if n == 0 {
            return ok(ents.len() as u32);
        }
        if n < ents.len() as i32 || n > NACLENTRIES {
            return err(EINVAL);
        }
        let mut out = Vec::new();
        for (u, g, m) in &ents {
            out.extend_from_slice(&(*u as i32).to_be_bytes());
            out.extend_from_slice(&(*g as i32).to_be_bytes());
            out.extend_from_slice(&[*m as u8, 0, 0, 0]);
        }
        self.wr(buf, &out)?;
        ok(ents.len() as u32)
    }

    /// getacl(path, nentries, acl): the ACL - the three base entries from the owner and
    /// mode bits, then the optional ones (kept in the file's user.hpux.acl attribute);
    /// nentries 0 asks only for the count
    pub fn sys_getacl(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let st = self.host_stat(&gp, true, None)?;
        let ga = self.guest_abspath(&gp);
        self.put_acl(&ga, &st, None, a[1], a[2])
    }

    /// fgetacl(fd, nentries, acl)
    pub fn sys_fgetacl(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let st = host::fstat(a[0] as i32).map_err(herrno)?;
        let path = self.fds[&a[0]].path.clone();
        self.put_acl(&path, &st, Some(&Src::Fd(a[0] as i32)), a[1], a[2])
    }

    /// setacl: replaces the optional entries; base entries set the mode bits, an
    /// unmentioned base entry gets mode 0; nentries ACL_DELOPT (-1) deletes the optional
    /// entries only. The owner or the superuser.
    fn set_acl(&mut self, gpath: &str, st: &libc::stat, src: &Src, n: u32, buf: u32) -> SysResult {
        let n = n as i32;
        if self.euid != 0 && self.owner_of(gpath, st, Some(src)).0 != self.euid as i64 {
            return err(EPERM);
        }
        if !self.xattrs_ok() || host::is_lnk(st) {
            return err(EOPNOTSUPP);
        }
        if n == ACL_DELOPT {
            self.xset(src, ACL_XATTR, None)?;
            return ok(0);
        }
        if n < 0 {
            return err(EINVAL);
        }
        if n > NACLENTRIES {
            return err(E2BIG);
        }
        let data = self.rd(buf, n as usize * ACL_ENTRY)?;
        let mut ents: Vec<((i64, i64), i64)> = Vec::new();
        for i in 0..n as usize {
            let mut u = be32(&data, i * ACL_ENTRY) as i32 as i64;
            let mut g = be32(&data, i * ACL_ENTRY + 4) as i32 as i64;
            let m = data[i * ACL_ENTRY + 8] as i64;
            if u == -35 || u == 65501 {
                continue; // ACLUNUSED / OLD_ACLUNUSED: an unused entry
            }
            // OLD_ACL_NSUSER / OLD_ACL_NSGROUP
            if u == 65500 {
                u = NS;
            }
            if g == 65500 {
                g = NS;
            }
            if m > 7 || (u != NS && u < 0) || (g != NS && g < 0) || ents.iter().any(|e| e.0 == (u, g)) {
                return err(EINVAL);
            }
            ents.push(((u, g), m));
        }
        let (fuid, fgid) = self.owner_of(gpath, st, Some(src));
        let mut take = |k: (i64, i64)| match ents.iter().position(|e| e.0 == k) {
            Some(i) => ents.remove(i).1,
            None => 0,
        };
        let um = take((fuid, NS));
        let gm = take((NS, fgid));
        let om = take((NS, NS));
        if ents.len() as i32 > NACLENTRIES - 3 {
            return err(E2BIG);
        }
        let mode = (st.st_mode & 0o7000) | ((um as u32) << 6) | ((gm as u32) << 3) | om as u32;
        let r = unsafe {
            match src {
                Src::Fd(fd) => libc::fchmod(*fd, mode),
                Src::Path(p) => libc::chmod(cstr(p).as_ptr(), mode),
            }
        };
        if r < 0 {
            return Err(herr());
        }
        ents.sort();
        let opt: Vec<String> = ents.iter().map(|((u, g), m)| format!("{}.{}={}", u, g, m)).collect();
        let opt = opt.join(",");
        self.xset(src, ACL_XATTR, if opt.is_empty() { None } else { Some(&opt) })?;
        ok(0)
    }

    /// setacl(path, nentries, acl): set a file's ACL (the owner or the superuser); the
    /// optional entries are kept in the host file's user.hpux.acl attribute - EOPNOTSUPP
    /// where the host file system has no user attributes, as HP-UX says for a non-HFS
    /// file system
    pub fn sys_setacl(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let st = self.host_stat(&gp, true, None)?;
        let ga = self.guest_abspath(&gp);
        let hp = self.hostpath(&gp)?;
        self.set_acl(&ga, &st, &Src::Path(hp), a[1], a[2])
    }

    /// fsetacl(fd, nentries, acl)
    pub fn sys_fsetacl(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        let st = host::fstat(a[0] as i32).map_err(herrno)?;
        let path = self.fds[&a[0]].path.clone();
        self.set_acl(&path, &st, &Src::Fd(a[0] as i32), a[1], a[2])
    }

    /// chdir(path): the guest's own working directory (the host's is never changed)
    pub fn sys_chdir(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let hp = self.hostpath(&gp)?;
        match host::stat(&hp, true) {
            Ok(st) if host::is_dir(&st) => {}
            Ok(_) => return err(ENOTDIR),
            Err(_) => return err(ENOENT),
        }
        self.check(&gp, 1, true)?;
        self.cwd = self.guest_abspath(&gp);
        ok(0)
    }

    /// fchdir(fd): to the directory the descriptor was opened on
    pub fn sys_fchdir(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        self.cwd = self.fds[&a[0]].path.clone();
        ok(0)
    }

    /// chmod(path, mode): the mode bits go to the host file (set-id bits included); the
    /// owner or the superuser; like HP-UX (POSIX.1) it deletes the file's optional ACL
    /// entries
    pub fn sys_chmod(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let st = self.host_stat(&gp, true, None)?;
        self.check_owner(&gp, Some(&st), true)?;
        let hp = self.hostpath(&gp)?;
        if unsafe { libc::chmod(cstr(&hp).as_ptr(), a[1] & 0o7777) } < 0 {
            return Err(herr());
        }
        let ga = self.guest_abspath(&gp);
        let src = Src::Path(hp);
        if !self.acl_opt(&ga, &st, Some(&src)).is_empty() {
            self.xset(&src, ACL_XATTR, None)?;
        }
        ok(0)
    }

    /// fchmod(fd, mode): the owner or the superuser; deletes optional ACL entries
    pub fn sys_fchmod(&mut self, a: &[u32; 8]) -> SysResult {
        let fd = a[0];
        self.fd_check(fd)?;
        let st = host::fstat(fd as i32).map_err(herrno)?;
        let path = self.fds[&fd].path.clone();
        let src = Src::Fd(fd as i32);
        if self.euid != 0 && self.owner_of(&path, &st, Some(&src)).0 != self.euid as i64 {
            return err(EPERM);
        }
        if unsafe { libc::fchmod(fd as i32, a[1] & 0o7777) } < 0 {
            return Err(herr());
        }
        if !self.acl_opt(&path, &st, Some(&src)).is_empty() {
            self.xset(&src, ACL_XATTR, None)?;
        }
        ok(0)
    }

    /// chown(path, uid, gid): recorded in the file's user.hpux.owner attribute (files
    /// belong to the host user); the owner may give a file away as HP-UX allows, others
    /// need to be superuser
    pub fn sys_chown(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let st = self.host_stat(&gp, true, None)?;
        self.check_owner(&gp, Some(&st), true)?;
        let ga = self.guest_abspath(&gp);
        let hp = self.hostpath(&gp)?;
        self.set_owner(&ga, &st, a[1], a[2], Some(&Src::Path(hp)))?;
        ok(0)
    }

    /// lchown(path, uid, gid): as chown, for the link itself
    pub fn sys_lchown(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let st = self.host_stat(&gp, false, None)?;
        self.check_owner(&gp, Some(&st), true)?;
        let ga = self.guest_abspath(&gp);
        let src = if host::is_lnk(&st) { None } else { Some(Src::Path(self.hostpath_nf(&gp)?)) };
        self.set_owner(&ga, &st, a[1], a[2], src.as_ref())?;
        ok(0)
    }

    /// fchown(fd, uid, gid): as chown
    pub fn sys_fchown(&mut self, a: &[u32; 8]) -> SysResult {
        let fd = a[0];
        self.fd_check(fd)?;
        let st = host::fstat(fd as i32).map_err(herrno)?;
        let path = self.fds[&fd].path.clone();
        let src = Src::Fd(fd as i32);
        if self.euid != 0 && self.owner_of(&path, &st, Some(&src)).0 != self.euid as i64 {
            return err(EPERM);
        }
        self.set_owner(&path, &st, a[1], a[2], Some(&src))?;
        ok(0)
    }

    /// link(old, new): a host hard link; write permission on the new directory
    pub fn sys_link(&mut self, a: &[u32; 8]) -> SysResult {
        let gn = self.rdstr(a[1])?;
        self.check_dir_write(&gn, false)?;
        let go = self.rdstr(a[0])?;
        let ho = self.hostpath(&go)?;
        let hn = self.hostpath_nf(&gn)?;
        if unsafe { libc::link(cstr(&ho).as_ptr(), cstr(&hn).as_ptr()) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// unlink(path): needs write permission on the directory (and the sticky rule)
    pub fn sys_unlink(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        self.check_dir_write(&gp, true)?;
        let hp = self.hostpath_nf(&gp)?;
        if unsafe { libc::unlink(cstr(&hp).as_ptr()) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// symlink(target, path): the target is stored as given (guest paths resolve inside
    /// the root); write permission on the directory
    pub fn sys_symlink(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[1])?;
        self.check_dir_write(&gp, false)?;
        let target = self.rdstr(a[0])?;
        let hp = self.hostpath_nf(&gp)?;
        if unsafe { libc::symlink(cstr(&target).as_ptr(), cstr(&hp).as_ptr()) } < 0 {
            return Err(herr());
        }
        if self.euid != 0 {
            let st = self.host_stat(&gp, false, None)?;
            let ga = self.guest_abspath(&gp);
            self.set_owner(&ga, &st, self.euid, self.egid, None)?;
        }
        ok(0)
    }

    /// readlink(path, buf, n): the stored target, not NUL-terminated
    pub fn sys_readlink(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let hp = self.hostpath_nf(&gp)?;
        let mut t = to_latin1(&host::readlink(&hp).map_err(herrno)?);
        t.truncate(a[2] as usize);
        self.wr(a[1], &t)?;
        ok(t.len() as u32)
    }

    /// rename(old, new): write permission on both directories; owners in the owners
    /// table move with the files (as attributes)
    pub fn sys_rename(&mut self, a: &[u32; 8]) -> SysResult {
        let (go, gn) = (self.rdstr(a[0])?, self.rdstr(a[1])?);
        self.check_dir_write(&go, true)?;
        self.check_dir_write(&gn, false)?;
        let (ao, an) = (self.guest_abspath(&go), self.guest_abspath(&gn));
        self.carry_owners(&ao, &an);
        let (ho, hn) = (self.hostpath_nf(&go)?, self.hostpath_nf(&gn)?);
        if unsafe { libc::rename(cstr(&ho).as_ptr(), cstr(&hn).as_ptr()) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// mkdir(path, mode): write permission on the parent; the new directory is the caller's
    pub fn sys_mkdir(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        self.check_dir_write(&gp, false)?;
        let hp = self.hostpath_nf(&gp)?;
        if unsafe { libc::mkdir(cstr(&hp).as_ptr(), a[1] & 0o7777) } < 0 {
            return Err(herr());
        }
        let ga = self.guest_abspath(&gp);
        self.new_file_owner(&ga, &Src::Path(hp))?;
        ok(0)
    }

    /// rmdir(path): write permission on the parent
    pub fn sys_rmdir(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        self.check_dir_write(&gp, true)?;
        let hp = self.hostpath_nf(&gp)?;
        if unsafe { libc::rmdir(cstr(&hp).as_ptr()) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// mknod(path, mode, dev): FIFOs only (write permission on the directory); device
    /// nodes are refused with EPERM
    pub fn sys_mknod(&mut self, a: &[u32; 8]) -> SysResult {
        if a[1] & 0o170000 == 0o010000 {
            let gp = self.rdstr(a[0])?;
            self.check_dir_write(&gp, false)?;
            let hp = self.hostpath_nf(&gp)?;
            if unsafe { libc::mkfifo(cstr(&hp).as_ptr(), a[1] & 0o7777) } < 0 {
                return Err(herr());
            }
            let ga = self.guest_abspath(&gp);
            self.new_file_owner(&ga, &Src::Path(hp))?;
            return ok(0);
        }
        err(EPERM)
    }

    /// utime(path, times): access and modification times, or now when times is NULL;
    /// setting explicit times needs ownership, setting now needs write permission
    pub fn sys_utime(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let hp = self.hostpath(&gp)?;
        let r = if a[1] != 0 {
            self.check_owner(&gp, None, true)?;
            let d = self.rd(a[1], 8)?;
            let t = libc::utimbuf { actime: be32(&d, 0) as libc::time_t, modtime: be32(&d, 4) as libc::time_t };
            unsafe { libc::utime(cstr(&hp).as_ptr(), &t) }
        } else {
            self.check(&gp, 2, true)?;
            unsafe { libc::utime(cstr(&hp).as_ptr(), std::ptr::null()) }
        };
        if r < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// truncate(path, length): write permission
    pub fn sys_truncate(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        self.check(&gp, 2, true)?;
        let hp = self.hostpath(&gp)?;
        if unsafe { libc::truncate(cstr(&hp).as_ptr(), a[1] as libc::off_t) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// ftruncate(fd, length)
    pub fn sys_ftruncate(&mut self, a: &[u32; 8]) -> SysResult {
        self.fd_check(a[0])?;
        if unsafe { libc::ftruncate(a[0] as i32, a[1] as libc::off_t) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// fcntl(fd, cmd, arg): F_DUPFD, F_GETFD/SETFD, F_GETFL/SETFL, the locks (fcntl64:
    /// the same, the 64-bit lock structures by their own commands)
    pub fn sys_fcntl(&mut self, a: &[u32; 8]) -> SysResult {
        let (fd, cmd, arg) = (a[0], a[1], a[2]);
        self.fd_check(fd)?;
        let h = fd as i32;
        let chk = |r: i32| if r < 0 { Err(herr()) } else { Ok(r) };
        if cmd == F_DUPFD {
            let n = chk(unsafe { libc::fcntl(h, libc::F_DUPFD, arg as i32) })?;
            self.dup_record(fd, n as u32);
            return ok(n as u32);
        }
        if cmd == F_GETFD {
            return ok(chk(unsafe { libc::fcntl(h, libc::F_GETFD) })? as u32);
        }
        if cmd == F_SETFD {
            chk(unsafe { libc::fcntl(h, libc::F_SETFD, (arg & 1) as i32) })?;
            return ok(0);
        }
        if cmd == F_GETFL {
            let hf = chk(unsafe { libc::fcntl(h, libc::F_GETFL) })?;
            let mut g = (hf & 3) as u32;
            if hf & libc::O_APPEND != 0 {
                g |= O_APPEND;
            }
            let m = self.nbmode.get(&fd).copied().unwrap_or_default();
            if m.nonblock {
                g |= O_NONBLOCK;
            }
            if m.ndelay {
                g |= O_NDELAY;
            }
            return ok(g);
        }
        if cmd == F_SETFL {
            let hf = if arg & O_APPEND != 0 { libc::O_APPEND } else { 0 };
            let cur = chk(unsafe { libc::fcntl(h, libc::F_GETFL) })?;
            chk(unsafe { libc::fcntl(h, libc::F_SETFL, hf | (cur & libc::O_NONBLOCK)) })?;
            self.nb_set(fd, 'n', arg & O_NONBLOCK != 0);
            self.nb_set(fd, 'd', arg & O_NDELAY != 0);
            return ok(0);
        }
        let lock = [F_GETLK, F_SETLK, F_SETLKW].contains(&cmd);
        let lock64 = [F_GETLK64, F_SETLK64, F_SETLKW64].contains(&cmd);
        if lock || lock64 {
            let (size, f_type, f_whence, f_start, f_len, f_pid) = if lock {
                use off::flock as L;
                (L::SIZE, L::l_type, L::l_whence, L::l_start, L::l_len, L::l_pid)
            } else {
                use off::flock64 as L;
                (L::SIZE, L::l_type, L::l_whence, L::l_start, L::l_len, L::l_pid)
            };
            let d = self.rd(arg, size)?;
            let sget = |f: F| {
                let v = get(&d, f);
                // (signed members: sign-extend from their size)
                let sh = 64 - 8 * f.1 as u32;
                ((v << sh) as i64) >> sh
            };
            let gtype = get(&d, f_type) as u32;
            let mut fl: libc::flock = unsafe { std::mem::zeroed() };
            fl.l_type = if gtype == F_RDLCK {
                libc::F_RDLCK
            } else if gtype == F_WRLCK {
                libc::F_WRLCK
            } else {
                libc::F_UNLCK
            } as libc::c_short;
            fl.l_whence = get(&d, f_whence) as libc::c_short;
            fl.l_start = sget(f_start);
            fl.l_len = sget(f_len);
            let get_cmd = cmd == F_GETLK || cmd == F_GETLK64;
            let hcmd = if get_cmd {
                libc::F_GETLK
            } else if cmd == F_SETLK || cmd == F_SETLK64 {
                libc::F_SETLK
            } else {
                libc::F_SETLKW
            };
            if unsafe { libc::fcntl(h, hcmd, &mut fl) } < 0 {
                return Err(if hcmd == libc::F_SETLKW { herr_intr() } else { herr() });
            }
            if get_cmd {
                let gt = match fl.l_type as i32 {
                    libc::F_RDLCK => F_RDLCK,
                    libc::F_WRLCK => F_WRLCK,
                    _ => F_UNLCK,
                };
                let mut b = Pk::new(size);
                b.put(f_type, gt as u64);
                b.put(f_whence, fl.l_whence as u64);
                b.put(f_start, fl.l_start as u64);
                b.put(f_len, fl.l_len as u64);
                b.put(f_pid, fl.l_pid as u64);
                self.wr(arg, &b.0)?;
            }
            return ok(0);
        }
        if cmd == F_SETOWN {
            // who gets SIGIO for the descriptor (O_ASYNC/FIOASYNC): a guest process is a
            // host process with the same pid, a negative number a process group
            chk(unsafe { libc::fcntl(h, libc::F_SETOWN, arg as i32) })?;
            return ok(0);
        }
        if cmd == F_GETOWN {
            return ok(chk(unsafe { libc::fcntl(h, libc::F_GETOWN) })? as u32);
        }
        emsg!("hpuxemu: fcntl cmd {} unimplemented\n", cmd);
        err(EINVAL)
    }

    /// getdents(fd, buf, n): the kernel's file-system-independent entries, `struct
    /// __dirent` of sys/dirent.h: {u64 offset cookie, u32 ino, i16 reclen, i16 namlen,
    /// name[]}, 8-byte aligned; libc's readdir() copies them into `struct dirent`. The
    /// cookie is the entry's index + 1 (what a later lseek on the directory gets back)
    pub fn sys_getdents(&mut self, a: &[u32; 8]) -> SysResult {
        let (fd, buf, n) = (a[0], a[1], a[2] as usize);
        self.fd_check(fd)?;
        let names = self.dir_names(fd)?;
        let path = self.fds[&fd].path.clone();
        let dir = self.hostpath_own(&path, true)?;
        let mut pos = self.fds[&fd].dirpos;
        let mut out: Vec<u8> = Vec::new();
        while pos < names.len() {
            let name = to_latin1(&names[pos]);
            let ino = host::stat(&format!("{}/{}", dir, names[pos]), false).map(|s| s.st_ino as u32).unwrap_or(1);
            let reclen = (16 + name.len() + 1 + 7) & !7;
            if out.len() + reclen > n {
                break;
            }
            let start = out.len();
            out.extend_from_slice(&(pos as u64 + 1).to_be_bytes());
            out.extend_from_slice(&ino.to_be_bytes());
            out.extend_from_slice(&(reclen as u16).to_be_bytes());
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(&name);
            out.resize(start + reclen, 0);
            pos += 1;
        }
        self.fds.get_mut(&fd).unwrap().dirpos = pos;
        if out.is_empty() && n < 16 {
            return err(EINVAL);
        }
        self.wr(buf, &out)?;
        ok(out.len() as u32)
    }

    /// getdirentries(fd, buf, n, basep): getdents, with the position stored at basep
    pub fn sys_getdirentries(&mut self, a: &[u32; 8]) -> SysResult {
        let r = self.sys_getdents(a)?;
        if a[3] != 0 {
            self.wr32(a[3], self.fds[&a[0]].dirpos as u32)?;
        }
        Ok(r)
    }

    /// pathconf(path, name), fpathconf(fd, name): fixed limits (NAME_MAX 255, PATH_MAX
    /// 1023, PIPE_BUF 8192 ...)
    pub fn sys_pathconf(&mut self, a: &[u32; 8]) -> SysResult {
        // sys/unistd.h: _PC_LINK_MAX 0 ... _PC_VDISABLE 8, then SYNC_IO 100, ASYNC_IO 101,
        // PRIO_IO 102, FILESIZEBITS 103 (cp asks for the last one to decide whether a
        // large file fits)
        ok(match a[1] {
            _PC_LINK_MAX => 32767,
            _PC_MAX_CANON => 256,
            _PC_MAX_INPUT => 512,
            _PC_NAME_MAX => 255,
            _PC_PATH_MAX => 1023,
            _PC_PIPE_BUF => 8192,
            _PC_CHOWN_RESTRICTED => 1,
            _PC_NO_TRUNC => 1,
            _PC_VDISABLE => 255,
            100 => 1,
            101 | 102 => 0,
            103 => 32,
            _ => return err(EINVAL),
        })
    }

    fn host_statvfs(&mut self, path: Option<u32>, fd: u32) -> Res<libc::statvfs> {
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        let r = match path {
            Some(p) => {
                let gp = self.rdstr(p)?;
                let hp = self.hostpath(&gp)?;
                unsafe { libc::statvfs(cstr(&hp).as_ptr(), &mut st) }
            }
            None => {
                self.fd_check(fd)?;
                unsafe { libc::fstatvfs(fd as i32, &mut st) }
            }
        };
        if r < 0 {
            return Err(herr());
        }
        Ok(st)
    }

    fn statfs_out(&mut self, buf: u32, st: &libc::statvfs) -> SysResult {
        use off::statfs as S;
        let mut b = Pk::new(S::SIZE);
        b.put(S::f_type, 0);
        b.put(S::f_bsize, st.f_bsize);
        b.put(S::f_blocks, st.f_blocks);
        b.put(S::f_bfree, st.f_bfree);
        b.put(S::f_bavail, st.f_bavail);
        b.put(S::f_files, st.f_files);
        b.put(S::f_ffree, st.f_ffree);
        self.wr(buf, &b.0)?;
        ok(0)
    }

    /// statfs(path, buf): the host file system's figures in struct statfs
    pub fn sys_statfs(&mut self, a: &[u32; 8]) -> SysResult {
        let st = self.host_statvfs(Some(a[0]), 0)?;
        self.statfs_out(a[1], &st)
    }

    /// fstatfs(fd, buf)
    pub fn sys_fstatfs(&mut self, a: &[u32; 8]) -> SysResult {
        let st = self.host_statvfs(None, a[0])?;
        self.statfs_out(a[1], &st)
    }

    /// struct statvfs (or statvfs64: 64-bit counts) from a host statvfs, basetype hfs
    fn statvfs_out(&mut self, buf: u32, st: &libc::statvfs, wide: bool) -> SysResult {
        macro_rules! fill {
            ($m:ident) => {{
                use off::$m as S;
                let mut b = Pk::new(S::SIZE);
                b.put(S::f_bsize, st.f_bsize);
                b.put(S::f_frsize, st.f_frsize);
                b.put(S::f_blocks, st.f_blocks);
                b.put(S::f_bfree, st.f_bfree);
                b.put(S::f_bavail, st.f_bavail);
                b.put(S::f_files, st.f_files);
                b.put(S::f_ffree, st.f_ffree);
                b.put(S::f_favail, st.f_favail);
                b.bytes(S::f_basetype, b"hfs");
                b.put(S::f_namemax, 255);
                b.0
            }};
        }
        let d = if wide { fill!(statvfs64) } else { fill!(statvfs) };
        self.wr(buf, &d)?;
        ok(0)
    }

    /// statvfs(path, buf): struct statvfs, basetype hfs
    pub fn sys_statvfs(&mut self, a: &[u32; 8]) -> SysResult {
        let st = self.host_statvfs(Some(a[0]), 0)?;
        self.statvfs_out(a[1], &st, false)
    }

    /// fstatvfs(fd, buf)
    pub fn sys_fstatvfs(&mut self, a: &[u32; 8]) -> SysResult {
        let st = self.host_statvfs(None, a[0])?;
        self.statvfs_out(a[1], &st, false)
    }

    /// statvfs64(path, buf) (11.00): struct statvfs64
    pub fn sys_statvfs64(&mut self, a: &[u32; 8]) -> SysResult {
        let st = self.host_statvfs(Some(a[0]), 0)?;
        self.statvfs_out(a[1], &st, true)
    }

    /// fstatvfs64(fd, buf) (11.00)
    pub fn sys_fstatvfs64(&mut self, a: &[u32; 8]) -> SysResult {
        let st = self.host_statvfs(None, a[0])?;
        self.statvfs_out(a[1], &st, true)
    }
}
