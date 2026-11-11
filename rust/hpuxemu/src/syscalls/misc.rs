//! identity, limits and time

use super::Handler;
use crate::consts::*;
use crate::emsg;
use crate::host::{self, cstr};
use crate::process::*;

pub const TABLE: &[(&str, Handler)] = &[
    ("exit", Process::sys_exit),
    ("getpid", Process::sys_getpid),
    ("getuid", Process::sys_getuid),
    ("getgid", Process::sys_getgid),
    ("setuid", Process::sys_setuid),
    ("setgid", Process::sys_setgid),
    ("getpgrp2", Process::sys_getpgrp2),
    ("getsid", Process::sys_getsid),
    ("umask", Process::sys_umask),
    ("brk", Process::sys_brk),
    ("sysconf", Process::sys_sysconf),
    ("utssys", Process::sys_utssys),
    ("getdomainname", Process::sys_getdomainname),
    ("clock_gettime", Process::sys_clock_gettime),
    ("clock_getres", Process::sys_clock_getres),
    ("time", Process::sys_time),
    ("gettimeofday", Process::sys_gettimeofday),
    ("times", Process::sys_times),
    ("nice", Process::sys_nice),
    ("mount", Process::sys_eperm),
    ("vfsmount", Process::sys_eperm),
    ("umount", Process::sys_eperm),
    ("chroot", Process::sys_eperm),
    ("ulimit", Process::sys_ulimit),
    ("getrlimit", Process::sys_getrlimit),
    ("getrlimit64", Process::sys_getrlimit64),
    ("setrlimit", Process::sys_zero),
    ("setrlimit64", Process::sys_zero),
    ("getrusage", Process::sys_getrusage),
    ("getpriority", Process::sys_getpriority),
    ("setpriority", Process::sys_zero),
];

fn be2(a: u32, b: u32) -> [u8; 8] {
    let mut o = [0u8; 8];
    o[..4].copy_from_slice(&a.to_be_bytes());
    o[4..].copy_from_slice(&b.to_be_bytes());
    o
}

impl Process {
    /// accepted and ignored
    pub fn sys_zero(&mut self, _a: &[u32; 8]) -> SysResult {
        ok(0)
    }

    /// mount(), umount(), chroot(): refused with EPERM - there is nothing to mount; the
    /// root is the host's file system and fixed when the emulator starts
    pub fn sys_eperm(&mut self, _a: &[u32; 8]) -> SysResult {
        err(EPERM)
    }

    /// exit(status): end the process (shared file mappings are written back)
    pub fn sys_exit(&mut self, a: &[u32; 8]) -> SysResult {
        self.writeback_all();
        self.exited = Some(Exited::Exit(a[0] & 0xFF));
        ok(0)
    }

    /// getpid(): the host pid; r29 = the parent's
    pub fn sys_getpid(&mut self, _a: &[u32; 8]) -> SysResult {
        ok2(self.pid, unsafe { libc::getppid() } as u32)
    }

    /// getuid(): r28 = real uid, r29 = effective uid
    pub fn sys_getuid(&mut self, _a: &[u32; 8]) -> SysResult {
        ok2(self.uid, self.euid)
    }

    /// getgid(): r28 = real gid, r29 = effective gid
    pub fn sys_getgid(&mut self, _a: &[u32; 8]) -> SysResult {
        ok2(self.gid, self.egid)
    }

    /// setuid(uid): the superuser sets all three ids; anyone else only to the real or
    /// saved id (EPERM otherwise). The host user never changes: the emulator's own access
    /// checks are what the ids govern
    pub fn sys_setuid(&mut self, a: &[u32; 8]) -> SysResult {
        let uid = a[0];
        if self.euid == 0 {
            self.uid = uid;
            self.euid = uid;
            self.suid = uid;
        } else if uid == self.uid || uid == self.suid {
            self.euid = uid;
        } else {
            return err(EPERM);
        }
        ok(0)
    }

    /// setgid(gid): as setuid, for the group ids
    pub fn sys_setgid(&mut self, a: &[u32; 8]) -> SysResult {
        let gid = a[0];
        if self.euid == 0 {
            self.gid = gid;
            self.egid = gid;
            self.sgid = gid;
        } else if gid == self.gid || gid == self.sgid {
            self.egid = gid;
        } else {
            return err(EPERM);
        }
        ok(0)
    }

    /// getpgrp2(pid): the process group of pid (0 = this process)
    pub fn sys_getpgrp2(&mut self, a: &[u32; 8]) -> SysResult {
        let r = unsafe { libc::getpgid(a[0] as i32) };
        if r < 0 {
            return Err(herr());
        }
        ok(r as u32)
    }

    /// getsid(pid): the session of pid (0 = this process)
    pub fn sys_getsid(&mut self, a: &[u32; 8]) -> SysResult {
        let r = unsafe { libc::getsid(a[0] as i32) };
        if r < 0 {
            return Err(herr());
        }
        ok(r as u32)
    }

    /// umask(mask): the file creation mask, applied to the host's too
    pub fn sys_umask(&mut self, a: &[u32; 8]) -> SysResult {
        let old = self.umask;
        self.umask = a[0] & 0o777;
        unsafe { libc::umask(self.umask) };
        ok(old)
    }

    /// brk(addr): set the break; the heap grows up from the end of bss. One page beyond
    /// the break is always mapped: HP-UX's libc reads past the break (its string functions
    /// work by words), which the HP-UX kernel tolerates - Linux's HP-UX emulation did the
    /// same (`sys_brk(addr + PAGE_SIZE)`, "libc relies on kernel bugs")
    pub fn sys_brk(&mut self, a: &[u32; 8]) -> SysResult {
        let addr = ((a[0] as u64 + PAGE as u64 - 1) & !(PAGE as u64 - 1)) as u64;
        if addr < self.brk_base as u64 || addr > self.brk_base as u64 + 256 * 1024 * 1024 {
            return err(ENOMEM);
        }
        let addr = addr as u32;
        if addr > self.brk {
            self.cpu.mem.map(self.brk, addr + PAGE - self.brk, 7);
        } else if addr < self.brk {
            self.cpu.mem.unmap(addr + PAGE, self.brk - addr);
        }
        self.brk = addr;
        ok(0)
    }

    /// sysconf(name): the values of a 10.20 system
    pub fn sys_sysconf(&mut self, a: &[u32; 8]) -> SysResult {
        let which = a[0];
        if which == 10003 {
            // _SC_MSEM_LOCKID: the id msem_lock writes into a semaphore it holds; the
            // pid, so a forked child has its own
            self.msem_lockid = true;
            return ok(self.pid);
        }
        let v: i64 = match which {
            _SC_ARG_MAX => 20478,
            _SC_CHILD_MAX => 1024,
            _SC_CLK_TCK => 100,
            _SC_NGROUPS_MAX => 20,
            _SC_OPEN_MAX => 1024,
            _SC_JOB_CONTROL => 1,
            _SC_SAVED_IDS => 1,
            _SC_VERSION => 199309,
            _SC_PAGE_SIZE => 4096,
            _SC_CPU_VERSION => CPU_PA_RISC1_1 as i64,
            10004 => MCAS_OFFSET as i64, // _SC_MCAS_OFFSET
            // POSIX.1b and POSIX threads (11.00's sys/unistd.h numbers and limits.h
            // values; libpthread asks for _SC_THREAD_THREADS_MAX at start-up)
            400 => 32,
            401..=404 => 1,
            405 => 32,
            406..=415 => 1,
            416 => 2,
            417 => 2048,
            418 => 20,
            419 => 8,
            420 => 32,
            421 => 8,
            422 => 256,
            423 => 32767,
            424 => 32,
            430 => 4,
            431 => 128,
            432 => 4096,
            433 => 64,
            434 => 199506,
            435..=437 => 1,
            438 | 439 => -1,
            440 | 441 => 1,
            442 | 443 => 1024,
            444 => 64,
            10010 => 37, // _SC_SIGRTMIN
            10011 => 44, // _SC_SIGRTMAX
            _ => {
                if self.trace {
                    emsg!("hpuxemu: sysconf({}) unknown\n", which);
                }
                return err(EINVAL);
            }
        };
        ok(v as u32)
    }

    /// utssys(buf, n, type): uname (0), ustat (2), gethostname (5)
    pub fn sys_utssys(&mut self, a: &[u32; 8]) -> SysResult {
        let (buf, n, typ) = (a[0], a[1], a[2]);
        match typ {
            0 => {
                use off::utsname as U;
                let mut b = Pk::new(U::SIZE);
                let node = host::to_latin1(&self.nodename);
                b.bytes(U::sysname, b"HP-UX");
                b.bytes(U::nodename, &node[..node.len().min(8)]);
                b.bytes(U::release, self.release.as_bytes());
                b.bytes(U::version, b"A");
                b.bytes(U::machine, b"9000/715");
                b.bytes(U::__idnumber, b"2000000000");
                self.wr(buf, &b.0)?;
                ok(0)
            }
            5 => {
                let mut v = host::to_latin1(&self.nodename);
                v.truncate((n as usize).saturating_sub(1));
                v.push(0);
                self.wr(buf, &v)?;
                ok(0)
            }
            2 => {
                use off::ustat as U;
                let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::statvfs(cstr(&self.root).as_ptr(), &mut st) } < 0 {
                    return Err(herr());
                }
                let mut b = Pk::new(U::SIZE);
                b.put(U::f_tfree, st.f_bfree);
                b.put(U::f_tinode, st.f_ffree);
                b.put(U::f_blksize, st.f_bsize);
                self.wr(buf, &b.0)?;
                ok(0)
            }
            _ => err(EFAULT),
        }
    }

    /// getdomainname(buf, len): an empty NIS domain
    pub fn sys_getdomainname(&mut self, a: &[u32; 8]) -> SysResult {
        if a[1] > 0 {
            self.wr(a[0], &[0])?;
        }
        ok(0)
    }

    /// clock_gettime(clock_id, &timespec): CLOCK_REALTIME (1) is the guest's time; the
    /// CPU-time clocks (CLOCK_VIRTUAL 2, CLOCK_PROFILE 4) the process's
    pub fn sys_clock_gettime(&mut self, a: &[u32; 8]) -> SysResult {
        let t = match a[0] {
            1 => self.now(),
            2 | 4 => host::process_time(),
            _ => return err(EINVAL),
        };
        let sec = t as i64;
        self.wr(a[1], &be2(sec as u32, ((t - sec as f64) * 1e9) as u32))?;
        ok(0)
    }

    /// clock_getres(clock_id, &timespec): 10 ms, the HP-UX clock tick
    pub fn sys_clock_getres(&mut self, a: &[u32; 8]) -> SysResult {
        if !matches!(a[0], 1 | 2 | 4) {
            return err(EINVAL);
        }
        if a[1] != 0 {
            self.wr(a[1], &be2(0, 10_000_000))?;
        }
        ok(0)
    }

    /// time(tloc): seconds since the epoch, also stored at tloc when it is not null - the
    /// kernel does that store, not libc (telnetd's utmp records had stack garbage for
    /// their logout time)
    pub fn sys_time(&mut self, a: &[u32; 8]) -> SysResult {
        let t = self.now() as i64 as u32;
        if a[0] != 0 {
            let _ = self.wr32(a[0], t);
        }
        ok(t)
    }

    /// gettimeofday(tv, tz): the guest clock (the host's, or etc/hpuxemu/clock); tz is
    /// all zeros
    pub fn sys_gettimeofday(&mut self, a: &[u32; 8]) -> SysResult {
        let t = self.now();
        if a[0] != 0 {
            self.wr(a[0], &be2(t as i64 as u32, ((t - t.floor()) * 1e6) as u32))?;
        }
        if a[1] != 0 {
            self.wr(a[1], &be2(0, 0))?;
        }
        ok(0)
    }

    /// times(buf): the host process times in ticks of 1/100 s, elapsed ticks returned
    pub fn sys_times(&mut self, a: &[u32; 8]) -> SysResult {
        let t = host::times();
        let mut b = [0u8; 16];
        for (i, v) in [t.0, t.1, t.2, t.3].iter().enumerate() {
            b[4 * i..4 * i + 4].copy_from_slice(&((v * 100.0) as u32).to_be_bytes());
        }
        self.wr(a[0], &b)?;
        ok(((host::monotonic() * 100.0) as u64 & 0x7FFF_FFFF) as u32)
    }

    /// nice(inc): accepted; the priority stays 20
    pub fn sys_nice(&mut self, _a: &[u32; 8]) -> SysResult {
        ok(20)
    }

    /// getpriority(which, who): always 20
    pub fn sys_getpriority(&mut self, _a: &[u32; 8]) -> SysResult {
        ok(20)
    }

    /// ulimit(cmd, arg): UL_GETFSIZE a 2 GB file size limit, UL_GETMAXBRK the top of the
    /// heap; setting is ignored
    pub fn sys_ulimit(&mut self, a: &[u32; 8]) -> SysResult {
        match a[0] {
            1 => ok(0x7FFF_FFFF >> 9),
            2 => ok(0),
            4 => ok(1024),
            3 => ok(0x7FFF_FFFF),
            _ => err(EINVAL),
        }
    }

    fn rlimit(&self, res: u32) -> Res<(u32, u32)> {
        let inf = 0x7FFF_FFFF;
        Ok(match res {
            0 | 1 | 4 | 5 | 7 => (inf, inf),
            2 => (0x0400_0000, 0x0400_0000),
            3 => (0x0080_0000, 0x0080_0000),
            6 => (1024, 1024),
            _ => return err(EINVAL),
        })
    }

    /// getrlimit(resource, rlp): the limits of rlimit()
    pub fn sys_getrlimit(&mut self, a: &[u32; 8]) -> SysResult {
        let (c, m) = self.rlimit(a[0])?;
        self.wr(a[1], &be2(c, m))?;
        ok(0)
    }

    /// getrlimit64(resource, rlp): the same, 64-bit values
    pub fn sys_getrlimit64(&mut self, a: &[u32; 8]) -> SysResult {
        let (c, m) = self.rlimit(a[0])?;
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&(c as u64).to_be_bytes());
        b[8..].copy_from_slice(&(m as u64).to_be_bytes());
        self.wr(a[1], &b)?;
        ok(0)
    }

    /// getrusage(who, buf): user and system time of the process (RUSAGE_SELF) or its
    /// children; the other fields are zero
    pub fn sys_getrusage(&mut self, a: &[u32; 8]) -> SysResult {
        use off::rusage as R;
        let t = host::times();
        let (u, s) = if a[0] == 0 { (t.0, t.1) } else { (t.2, t.3) };
        let mut b = Pk::new(R::SIZE);
        b.bytes(R::ru_utime, &be2(u as u32, ((u - u.floor()) * 1e6) as u32));
        b.bytes(R::ru_stime, &be2(s as u32, ((s - s.floor()) * 1e6) as u32));
        self.wr(a[1], &b.0)?;
        ok(0)
    }
}
