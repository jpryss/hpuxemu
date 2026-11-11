//! processes: fork, exec, wait, process groups, ids; the process table pstat reads; the
//! small calls that only answer.

use super::Handler;
use crate::consts::*;
use crate::emsg;
use crate::host::{self, cstr, guest_sig, host_sig};
use crate::process::*;

pub const TABLE: &[(&str, Handler)] = &[
    ("fork", Process::sys_fork),
    ("vfork", Process::sys_fork),
    ("execve", Process::sys_execve),
    ("execv", Process::sys_execv),
    ("waitpid", Process::sys_waitpid),
    ("wait", Process::sys_wait),
    ("wait3", Process::sys_wait3),
    ("setpgrp2", Process::sys_setpgrp2),
    ("setpgid", Process::sys_setpgrp2),
    ("setpgrp", Process::sys_setpgrp),
    ("setpgrp3", Process::sys_setpgrp3),
    ("getgroups", Process::sys_getgroups),
    ("setgroups", Process::sys_setgroups),
    ("setresuid", Process::sys_setresuid),
    ("setresgid", Process::sys_setresgid),
    ("setregid", Process::sys_zero),
    ("pstat", Process::sys_pstat),
    ("getnumfds", Process::sys_getnumfds),
    ("sysfs", Process::sys_sysfs),
    ("fss", Process::sys_zero),
    ("sethostid", Process::sys_zero),
    ("gethostid", Process::sys_gethostid),
    ("get_sysinfo", Process::sys_einval),
    ("sysinfo", Process::sys_sysinfo),
    ("audswitch", Process::sys_zero),
    ("audwrite", Process::sys_zero),
    ("audctl", Process::sys_einval),
    ("getaudid", Process::sys_zero),
    ("getaudproc", Process::sys_zero),
    ("setaudproc", Process::sys_zero),
    ("privgrp", Process::sys_einval),
    ("gtty", Process::sys_gtty),
    ("stty", Process::sys_stty),
    ("sched_get_priority_min", Process::sys_zero),
    ("sched_get_priority_max", Process::sys_sched_max),
    ("plock", Process::sys_zero),
    ("rtprio", Process::sys_zero),
    ("swapon", Process::sys_eperm),
    ("mpctl", Process::sys_mpctl),
    ("set_userthreadid", Process::sys_zero),
    ("lwp_setprivate", Process::sys_lwp_setprivate),
    ("lwp_getprivate", Process::sys_lwp_getprivate),
];

/// a live emulator process, as it published itself
#[derive(Debug, Clone)]
pub struct ProcRec {
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub sid: u32,
    pub uid: u32,
    pub gid: u32,
    pub start: i64,
    pub tty: String,
    pub cmd: String,
}

const FSTYPES: [&str; 6] = ["hfs", "nfs", "cdfs", "vxfs", "autofs", "lofs"];

fn pst_field(l64: bool, sname: &str, member: &str) -> Option<F> {
    let t = if l64 { PST_64 } else { PST_10 };
    t.iter().find(|x| x.0 == sname && x.1 == member).map(|x| x.2)
}

fn put_opt(d: &mut [u8], f: Option<F>, v: u64) {
    if let Some(f) = f {
        if f.0 + f.1 <= d.len() {
            put(d, f, v);
        }
    }
}

impl Process {
    pub fn sys_einval(&mut self, _a: &[u32; 8]) -> SysResult {
        err(EINVAL)
    }

    // Every emulated process publishes itself in ROOT/var/run/hpuxemu/PID (removed at
    // exit; a stale one belongs to a pid that is no longer alive). ps and friends read it
    // through pstat.
    fn proc_dir(&self) -> String {
        format!("{}/var/run/hpuxemu", self.root)
    }

    pub fn publish(&mut self) {
        let d = self.proc_dir();
        let _ = std::fs::create_dir_all(&d);
        let tty = if host::isatty(0) { host::ttyname(0).unwrap_or_default() } else { String::new() };
        let line = unsafe {
            format!(
                "{} {} {} {} {} {} {} {} {}\n",
                self.pid,
                libc::getppid(),
                libc::getpgrp(),
                libc::getsid(0),
                self.uid,
                self.gid,
                self.start_time,
                if tty.is_empty() { "-" } else { &tty },
                self.argv.join(" ")
            )
        };
        let _ = std::fs::write(format!("{}/{}", d, self.pid), host::to_latin1(&line));
        self.published = true;
    }

    pub fn unpublish(&mut self) {
        let _ = std::fs::remove_file(format!("{}/{}", self.proc_dir(), self.pid));
    }

    /// the live emulator processes, by pid
    pub fn proc_table(&self) -> Vec<ProcRec> {
        let mut out = Vec::new();
        let d = self.proc_dir();
        let rd = match std::fs::read_dir(&d) {
            Ok(r) => r,
            Err(_) => return out,
        };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let pid: i32 = match n.parse() {
                Ok(p) if n.bytes().all(|c| c.is_ascii_digit()) => p,
                _ => continue,
            };
            let mut gone = unsafe { libc::kill(pid, 0) } < 0 && host::errno() == libc::ESRCH;
            if !gone {
                // a zombie nobody reaps (a container's init may not) is gone too
                if let Ok(s) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                    if let Some(i) = s.rfind(')') {
                        gone = s[i + 1..].split_whitespace().next() == Some("Z");
                    }
                }
            }
            if gone {
                let _ = std::fs::remove_file(format!("{}/{}", d, n));
                continue;
            }
            let data = match std::fs::read(format!("{}/{}", d, n)) {
                Ok(b) => host::latin1(&b),
                Err(_) => continue,
            };
            let parts: Vec<&str> = data.trim_end_matches('\n').splitn(9, ' ').collect();
            if parts.len() < 9 {
                continue;
            }
            let nums: Vec<i64> = parts[..7].iter().filter_map(|x| x.parse().ok()).collect();
            if nums.len() < 7 {
                continue;
            }
            out.push(ProcRec {
                pid: nums[0] as u32,
                ppid: nums[1] as u32,
                pgrp: nums[2] as u32,
                sid: nums[3] as u32,
                uid: nums[4] as u32,
                gid: nums[5] as u32,
                start: nums[6],
                tty: parts[7].to_string(),
                cmd: parts[8].to_string(),
            });
        }
        out.sort_by_key(|p| p.pid);
        out
    }

    fn pst_status(&self, idx: usize, rec: &ProcRec, elemsize: usize, l64: bool) -> Vec<u8> {
        let mut d = vec![0u8; elemsize];
        let (mut major, mut minor) = (-1i64, -1i64);
        if rec.tty != "-" {
            if let Ok(st) = host::stat(&rec.tty, true) {
                major = libc::major(st.st_rdev) as i64;
                minor = libc::minor(st.st_rdev) as i64;
            }
        }
        let me = rec.pid == self.pid;
        let f = |m: &str| pst_field(l64, "pst_status", m);
        put_opt(&mut d, f("pst_idx"), idx as u64);
        put_opt(&mut d, f("pst_pid"), rec.pid as u64);
        put_opt(&mut d, f("pst_ppid"), rec.ppid as u64);
        put_opt(&mut d, f("pst_uid"), rec.uid as u64);
        put_opt(&mut d, f("pst_gid"), rec.gid as u64);
        put_opt(&mut d, f("pst_pgrp"), rec.pgrp as u64);
        put_opt(&mut d, f("pst_sid"), rec.sid as u64);
        put_opt(&mut d, f("pst_stat"), if me { PS_RUN } else { PS_SLEEP } as u64);
        put_opt(&mut d, f("pst_euid"), rec.uid as u64);
        put_opt(&mut d, f("pst_egid"), rec.gid as u64);
        put_opt(&mut d, f("pst_suid"), rec.uid as u64);
        put_opt(&mut d, f("pst_start"), rec.start as u64);
        let hi = if me { self.fds.keys().next_back().copied().unwrap_or(2) } else { 2 };
        put_opt(&mut d, f("pst_highestfd"), hi as u64);
        put_opt(&mut d, f("pst_pri"), 154);
        put_opt(&mut d, f("pst_nice"), 20);
        put_opt(&mut d, f("pst_procnum"), 0);
        let mut bytes = |m: &str, v: &[u8], max: usize| {
            if let Some(fl) = f(m) {
                let n = v.len().min(max).min(fl.1);
                if fl.0 + n <= d.len() {
                    d[fl.0..fl.0 + n].copy_from_slice(&v[..n]);
                }
            }
        };
        let cmd = host::to_latin1(&rec.cmd);
        bytes("pst_cmd", &cmd, 63);
        let first = rec.cmd.split(' ').next().unwrap_or("");
        let base = first.rsplit('/').next().unwrap_or("");
        bytes("pst_ucomm", &host::to_latin1(base), 14);
        if let Some(fl) = f("pst_term") {
            // struct psdev: two ints, or two int64s in the _PSTAT64 layout
            let h = fl.1 / 2;
            if fl.0 + fl.1 <= d.len() {
                put(&mut d, F(fl.0, h), major as u64);
                put(&mut d, F(fl.0 + h, h), minor as u64);
            }
        }
        d
    }

    /// pstat(request, buf, elemsize, elemcount, index): PSTAT_STATIC and PSTAT_DYNAMIC
    /// with plausible values, PSTAT_PROC for the process itself. 11.00's libc sets
    /// PSTAT64_INTF (0x80000000) in the request and wants the _PSTAT64 layouts (64-bit
    /// fields, also in 32-bit programs)
    pub fn sys_pstat(&mut self, a: &[u32; 8]) -> SysResult {
        let (mut req, buf, elemsize, elemcount, index) = (a[0], a[1], a[2] as usize, a[3], a[4]);
        let l64 = req & 0x8000_0000 != 0;
        req &= 0x7FFF_FFFF;
        if elemsize > 1 << 20 {
            return err(EINVAL);
        }
        if req == PSTAT_STATIC {
            let mut d = vec![0u8; elemsize];
            let f = |m: &str| pst_field(l64, "pst_static", m);
            put_opt(&mut d, f("max_proc"), 1024);
            put_opt(&mut d, f("page_size"), 4096);
            put_opt(&mut d, f("boot_time"), (self.now() as i64 - 3600) as u64);
            put_opt(&mut d, f("physical_memory"), 32768);
            self.wr(buf, &d)?;
            return ok(1);
        }
        if req == PSTAT_DYNAMIC {
            let mut d = vec![0u8; elemsize];
            let f = |m: &str| pst_field(l64, "pst_dynamic", m);
            put_opt(&mut d, f("psd_proc_cnt"), self.proc_table().len() as u64);
            put_opt(&mut d, f("psd_max_proc_cnt"), 1024);
            put_opt(&mut d, f("psd_last_pid"), self.pid as u64);
            put_opt(&mut d, f("psd_activecpu"), 1);
            self.wr(buf, &d)?;
            return ok(1);
        }
        if req == PSTAT_PROC {
            let table = self.proc_table();
            if elemcount == 0 {
                // one process, by pid
                for (i, rec) in table.iter().enumerate() {
                    if rec.pid == index {
                        let d = self.pst_status(i, rec, elemsize, l64);
                        self.wr(buf, &d)?;
                        return ok(1);
                    }
                }
                return err(ESRCH);
            }
            // elemcount entries from index on (the caller continues at the last idx + 1)
            let mut n = 0u32;
            let end = (table.len() as u64).min(index as u64 + elemcount as u64) as usize;
            for i in index as usize..end {
                let d = self.pst_status(i, &table[i], elemsize, l64);
                self.wr(buf.wrapping_add(n * elemsize as u32), &d)?;
                n += 1;
            }
            return ok(n);
        }
        emsg!("hpuxemu: pstat request {} unimplemented\n", req);
        err(EINVAL)
    }

    /// getnumfds(): one more than the highest open descriptor (what callers loop up to)
    pub fn sys_getnumfds(&mut self, _a: &[u32; 8]) -> SysResult {
        ok(self.fds.keys().next_back().map(|&m| m + 1).unwrap_or(0))
    }

    /// sysfs(GETFSIND, name) / (GETFSTYP, index, buf) / (GETNFSTYP): the file system types
    pub fn sys_sysfs(&mut self, a: &[u32; 8]) -> SysResult {
        match a[0] {
            1 => {
                let name = self.rdstr(a[1])?;
                match FSTYPES.iter().position(|&x| x == name) {
                    Some(i) => ok(i as u32 + 1),
                    None => err(EINVAL),
                }
            }
            2 => {
                if a[1] >= 1 && a[1] as usize <= FSTYPES.len() {
                    let mut v = FSTYPES[a[1] as usize - 1].as_bytes().to_vec();
                    v.push(0);
                    self.wr(a[2], &v)?;
                    return ok(0);
                }
                err(EINVAL)
            }
            3 => ok(FSTYPES.len() as u32),
            _ => err(EINVAL),
        }
    }

    /// gethostid(): a fixed id (0x2000000)
    pub fn sys_gethostid(&mut self, _a: &[u32; 8]) -> SysResult {
        ok(0x200_0000)
    }

    /// sysinfo(command, buf, count): the SVR4 strings (1 sysname, 2 hostname, 3 release,
    /// 4 version, 5 machine, 6 architecture, 7 serial, 8 provider, 9 domain); returns the
    /// length needed
    pub fn sys_sysinfo(&mut self, a: &[u32; 8]) -> SysResult {
        let (cmd, buf, n) = (a[0], a[1], a[2] as usize);
        let s = match cmd {
            1 => "HP-UX".to_string(),
            2 => self.nodename.clone(),
            3 => self.release.clone(),
            4 => "A".to_string(),
            5 => "9000/715".to_string(),
            6 => "hppa1.1".to_string(),
            7 => "2000000000".to_string(),
            8 => "HP".to_string(),
            9 => String::new(),
            _ => return err(EINVAL),
        };
        let mut v = host::to_latin1(&s);
        v.push(0);
        let need = v.len() as u32;
        if buf != 0 && n != 0 {
            if v.len() > n {
                v.truncate(n - 1);
                v.push(0);
            }
            self.wr(buf, &v)?;
        }
        ok(need)
    }

    /// gtty(fd, buf): ioctl TIOCGETP
    pub fn sys_gtty(&mut self, a: &[u32; 8]) -> SysResult {
        self.sys_ioctl(&[a[0], TIOCGETP, a[1], 0, 0, 0, 0, 0])
    }

    /// stty(fd, buf): ioctl TIOCSETP
    pub fn sys_stty(&mut self, a: &[u32; 8]) -> SysResult {
        self.sys_ioctl(&[a[0], TIOCSETP, a[1], 0, 0, 0, 0, 0])
    }

    /// sched_get_priority_max(policy): 31
    pub fn sys_sched_max(&mut self, _a: &[u32; 8]) -> SysResult {
        ok(31)
    }

    /// mpctl(request, ...): one processor: every request answers 1
    pub fn sys_mpctl(&mut self, _a: &[u32; 8]) -> SysResult {
        ok(1)
    }

    /// lwp_setprivate(p) (11.00): the thread pointer - control register 27, which
    /// thread-local storage (libc's errno, libXm ...) is addressed from (mfctl %cr27)
    pub fn sys_lwp_setprivate(&mut self, a: &[u32; 8]) -> SysResult {
        self.cpu.cr[27] = a[0] as u64;
        ok(0)
    }

    /// lwp_getprivate(): the thread pointer (cr27)
    pub fn sys_lwp_getprivate(&mut self, _a: &[u32; 8]) -> SysResult {
        ok(self.cpu.cr[27] as u32)
    }

    // ---- fork, exec, wait, process groups ----

    /// fork(): a host fork; the child gets r28 = parent's pid, r29 = 1; the parent r28 =
    /// child's pid, r29 = 0 (crt0's libc stub turns this into the usual 0/pid)
    pub fn sys_fork(&mut self, _a: &[u32; 8]) -> SysResult {
        // the child starts with no pending signals, as on HP-UX: the host's are blocked
        // over the fork (a signal for the parent stays the parent's), and what the parent
        // had recorded but not yet delivered is not the child's
        let old = host::block_all();
        let pid = unsafe { libc::fork() };
        let e = host::errno();
        if pid == 0 {
            host::take_host_pending();
            self.pending = 0;
            self.fault_info.clear();
        }
        host::restore_mask(&old);
        if pid < 0 {
            return Err(herrno(e));
        }
        if pid == 0 {
            self.pid = unsafe { libc::getpid() } as u32;
            if let Some(prog) = self.stats.as_ref().map(|s| s.prog.clone()) {
                self.stats_begin("fork", &prog);
            }
            self.lwp_fork_child();
            self.publish(); // a daemon's parent exits and takes its own entry with it
            return ok2(unsafe { libc::getppid() } as u32, 1);
        }
        ok2(pid as u32, 0)
    }

    /// execve(path, argv, envp): the new image replaces this one in the same host
    /// process; the set-user-id and set-group-id bits are honoured
    pub fn sys_execve(&mut self, a: &[u32; 8]) -> SysResult {
        let gp = self.rdstr(a[0])?;
        let args = self.rdvec(a[1])?;
        let env = if a[2] != 0 { self.rdvec(a[2])? } else { Vec::new() };
        self.do_exec(&gp, args, env)
    }

    /// execv(path, argv): execve with the current environment
    pub fn sys_execv(&mut self, a: &[u32; 8]) -> SysResult {
        let env: Vec<String> = self.env.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        let gp = self.rdstr(a[0])?;
        let args = self.rdvec(a[1])?;
        self.do_exec(&gp, args, env)
    }

    fn do_exec(&mut self, gp: &str, args: Vec<String>, env: Vec<String>) -> SysResult {
        let hp = self.hostpath(gp)?;
        if !host::exists(&hp) {
            return err(ENOENT);
        }
        let st = self.check(gp, 1, true)?;
        // the set-user-id and set-group-id bits: the effective and saved ids become the
        // file's owner's (su, passwd, crontab, lp ... depend on this)
        let ga = self.guest_abspath(gp);
        let (fuid, fgid) = self.owner_of(&ga, &st, None);
        if st.st_mode & 0o4000 != 0 {
            self.euid = fuid as u32;
            self.suid = fuid as u32;
        }
        if st.st_mode & 0o2000 != 0 {
            self.egid = fgid as u32;
            self.sgid = fgid as u32;
        }
        if self.trace {
            emsg!("[{}] exec {} uid {}/{} gid {}/{}\n", self.pid, gp, self.uid, self.euid, self.gid, self.egid);
        }
        let mut newenv: Vec<(String, String)> = Vec::new();
        for kv in &env {
            if let Some((k, v)) = kv.split_once('=') {
                match newenv.iter_mut().find(|e| e.0 == k) {
                    Some(e) => e.1 = v.to_string(),
                    None => newenv.push((k.to_string(), v.to_string())),
                }
            }
        }
        self.env = newenv;
        // close-on-exec
        let fds: Vec<u32> = self.fds.keys().copied().collect();
        for fd in fds {
            let fl = unsafe { libc::fcntl(fd as i32, libc::F_GETFD) };
            if fl < 0 {
                self.fds.remove(&fd);
            } else if fl & libc::FD_CLOEXEC != 0 {
                unsafe { libc::close(fd as i32) };
                self.fds.remove(&fd);
            }
        }
        for (&sig, act) in &self.sigactions {
            let h = host_sig(sig);
            if h != 0 && act.handler > 1 {
                host::host_signal_set(h, 0);
            }
        }
        self.sigactions.clear();
        self.pending = 0;
        host::take_host_pending();
        self.fault_info.clear();
        self.sigreturn_addr = 0;
        self.threads = Default::default(); // exec leaves one thread
        self.mappings.clear();
        self.native_list.clear();
        self.trace_by_name(gp);
        self.stats_end("exec", false);
        self.stats_begin("exec", gp);
        let t0 = host::monotonic();
        self.load(gp, args, env)?;
        if let Some(s) = self.stats.as_mut() {
            s.load = host::monotonic() - t0;
        }
        Err(Stop::Exec)
    }

    /// HPUXEMU_TRACE=NAME[,NAME...] (host environment): a process that execs a program of
    /// that name traces its system calls into HPUXEMU_TRACE_DIR/NAME.PID (default /tmp) -
    /// one process deep inside a large application (one daemon among dozens), without
    /// tracing the rest
    fn trace_by_name(&mut self, gp: &str) {
        let names = match host::getenv("HPUXEMU_TRACE") {
            Some(n) if !n.is_empty() => n,
            _ => return,
        };
        let base = gp.rsplit('/').next().unwrap_or("");
        if names.split(',').any(|n| n == base) {
            let d = host::getenv("HPUXEMU_TRACE_DIR").unwrap_or_else(|| "/tmp".to_string());
            let path = format!("{}/{}.{}", d, base, self.pid);
            let fd = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC, 0o644) };
            if fd >= 0 {
                let hi = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 900) };
                if hi >= 0 {
                    unsafe {
                        libc::close(fd);
                        host::ERR_FD = hi;
                    }
                    self.trace = true;
                } else {
                    unsafe { libc::close(fd) };
                }
            }
        }
    }

    /// waitpid(pid, status, options): the host waitpid (WNOHANG, WUNTRACED); the status
    /// has the signal number translated
    pub fn sys_waitpid(&mut self, a: &[u32; 8]) -> SysResult {
        let (pid, statp, options) = (a[0] as i32, a[1], a[2]);
        let mut hopt = 0;
        if options & WNOHANG != 0 {
            hopt |= libc::WNOHANG;
        }
        if options & WUNTRACED != 0 {
            hopt |= libc::WUNTRACED;
        }
        let mut status: libc::c_int = 0;
        let rpid = loop {
            let r = unsafe { libc::waitpid(pid, &mut status, hopt) };
            if r >= 0 {
                break r;
            }
            let e = host::errno();
            if e != libc::EINTR {
                return Err(herrno(e));
            }
            // a child's state changed and SIGCHLD woke the host call: wait again - HP-UX
            // returns the child it changed to, the handler running after (Linux also
            // signals a child's SIGCONT, which HP-UX does not: waitpid saw EINTR between
            // a SIGCONT and the SIGTERM that followed it; chld_is_news drops that
            // SIGCHLD, leaving nothing pending). Any other signal interrupts.
            if self.poll_signals() & !(1u64 << SIGCHLD) != 0 {
                return Err(Stop::Interrupted);
            }
        };
        if rpid != 0 && statp != 0 {
            self.wr32(statp, wait_status(status))?;
        }
        ok(rpid as u32)
    }

    /// wait(status): waitpid(-1, status, 0)
    pub fn sys_wait(&mut self, a: &[u32; 8]) -> SysResult {
        self.sys_waitpid(&[0xFFFF_FFFF, a[0], 0, 0, 0, 0, 0, 0])
    }

    /// wait3(status, options, rusage): waitpid(-1, status, options); rusage is not filled in
    pub fn sys_wait3(&mut self, a: &[u32; 8]) -> SysResult {
        self.sys_waitpid(&[0xFFFF_FFFF, a[0], a[1], 0, 0, 0, 0, 0])
    }

    /// setpgrp2(pid, pgid): setpgid on the host
    pub fn sys_setpgrp2(&mut self, a: &[u32; 8]) -> SysResult {
        if unsafe { libc::setpgid(a[0] as i32, a[1] as i32) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// setpgrp(): a new process group of its own; returns it
    pub fn sys_setpgrp(&mut self, _a: &[u32; 8]) -> SysResult {
        unsafe {
            libc::setpgid(0, 0);
            ok(libc::getpgrp() as u32)
        }
    }

    /// setpgrp3(flag): libc's setpgrp3() passes 1 (a new process group, as setpgrp) and
    /// setsid() passes 2 (a new session)
    pub fn sys_setpgrp3(&mut self, a: &[u32; 8]) -> SysResult {
        if a[0] == 2 {
            let r = unsafe { libc::setsid() };
            if r < 0 {
                return Err(herr());
            }
            return ok(r as u32);
        }
        self.sys_setpgrp(a)
    }

    /// getgroups(n, list): the supplementary groups set with setgroups (initgroups at login)
    pub fn sys_getgroups(&mut self, a: &[u32; 8]) -> SysResult {
        if a[0] != 0 {
            if (a[0] as usize) < self.groups.len() {
                return err(EINVAL);
            }
            let mut b = Vec::new();
            for g in &self.groups {
                b.extend_from_slice(&g.to_be_bytes());
            }
            self.wr(a[1], &b)?;
        }
        ok(self.groups.len() as u32)
    }

    /// setgroups(n, list): superuser only
    pub fn sys_setgroups(&mut self, a: &[u32; 8]) -> SysResult {
        if self.euid != 0 {
            return err(EPERM);
        }
        if a[0] > 20 {
            return err(EINVAL);
        }
        let mut g = Vec::new();
        for i in 0..a[0] {
            g.push(self.rd32(a[1] + 4 * i)?);
        }
        self.groups = g;
        ok(0)
    }

    /// setresuid(ruid, euid, suid): -1 leaves an id alone; a process whose real, effective
    /// OR saved uid is 0 sets any (setresuid(2): "if the current real, effective or saved
    /// user ID is equal to that of a user having appropriate privileges"), others only to
    /// one of their own three; lp, set-uid root, drops its euid to lp first and sets its
    /// gids after
    pub fn sys_setresuid(&mut self, a: &[u32; 8]) -> SysResult {
        let own = [self.uid, self.euid, self.suid];
        let want: Vec<u32> = (0..3).map(|i| if a[i] == 0xFFFF_FFFF { own[i] } else { a[i] }).collect();
        if !own.contains(&0) && want.iter().any(|v| !own.contains(v)) {
            return err(EPERM);
        }
        self.uid = want[0];
        self.euid = want[1];
        self.suid = want[2];
        ok(0)
    }

    /// setresgid(rgid, egid, sgid): as setresuid, the privilege judged by the three uids
    pub fn sys_setresgid(&mut self, a: &[u32; 8]) -> SysResult {
        let own = [self.gid, self.egid, self.sgid];
        let want: Vec<u32> = (0..3).map(|i| if a[i] == 0xFFFF_FFFF { own[i] } else { a[i] }).collect();
        if ![self.uid, self.euid, self.suid].contains(&0) && want.iter().any(|v| !own.contains(v)) {
            return err(EPERM);
        }
        self.gid = want[0];
        self.egid = want[1];
        self.sgid = want[2];
        ok(0)
    }
}

/// host wait status -> HP-UX (same encoding: exit<<8, signal in the low 7 bits, 0x80
/// core, 0x7f = stopped) with the signal number translated
pub fn wait_status(status: i32) -> u32 {
    let tr = |s: i32| {
        let g = guest_sig(s);
        if g != 0 { g } else { s as u32 }
    };
    if libc::WIFEXITED(status) {
        return (libc::WEXITSTATUS(status) as u32) << 8;
    }
    if libc::WIFSIGNALED(status) {
        return tr(libc::WTERMSIG(status)) | if libc::WCOREDUMP(status) { 0x80 } else { 0 };
    }
    if libc::WIFSTOPPED(status) {
        return (tr(libc::WSTOPSIG(status)) << 8) | 0x7F;
    }
    status as u32
}
