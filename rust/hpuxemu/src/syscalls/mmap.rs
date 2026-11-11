//! memory: mmap and friends, memory semaphores

use super::Handler;
use crate::consts::*;
use crate::emsg;
use crate::host::{self, cstr};
use crate::process::*;

pub const TABLE: &[(&str, Handler)] = &[
    ("mmap", Process::sys_mmap),
    ("mmap64", Process::sys_mmap64),
    ("munmap", Process::sys_munmap),
    ("mprotect", Process::sys_mprotect),
    ("madvise", Process::sys_zero),
    ("msync", Process::sys_zero),
    ("msem_init", Process::sys_msem_init),
    ("msem_remove", Process::sys_msem_remove),
    ("msleep", Process::sys_msleep),
    ("mwakeup", Process::sys_mwakeup),
];

// ---- memory semaphores (msem_init/msem_lock/msem_unlock/msem_remove) ----
// struct msemaphore (sys/mman.h): msem_lock, magic, locker, wanted - 16-byte aligned, in
// memory shared by the processes that use it. libc's msem_lock calls mcas_util() on the
// gateway page (r26 = the semaphore: 0 got it, 1 no lock id yet, 2 page fault, 3 busy, 4
// misaligned) and on "busy" the msleep system call, which waits for the lock; msem_unlock
// clears `locker` itself and calls mwakeup when `wanted` is set. Every test-and-set
// happens under a host file lock: the processes are host processes sharing the memory.
const MSEM_MAGIC: u32 = 0x6d73_656d;

fn mprot_of(prot: u32) -> u8 {
    (if prot & PROT_READ != 0 { 1 } else { 0 }) | (if prot & PROT_WRITE != 0 { 2 } else { 0 }) | (if prot & PROT_EXEC != 0 { 4 } else { 0 })
}

fn lock_file(fd: i32, lock: bool) {
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = if lock { libc::F_WRLCK } else { libc::F_UNLCK } as libc::c_short;
    fl.l_whence = libc::SEEK_SET as libc::c_short;
    host::retry(|| unsafe { libc::fcntl(fd, libc::F_SETLKW, &fl) as isize });
}

impl Process {
    fn msem_hostlock(&mut self) -> i32 {
        if let Some(fd) = self.msem_fd {
            return fd;
        }
        let d = format!("{}/var/run/hpuxemu", self.root);
        let _ = std::fs::create_dir_all(&d);
        let fd = unsafe { libc::open(cstr(&format!("{}/.msem.lock", d)).as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600) };
        // (kept above the guest's descriptors, which it may close in a loop)
        let hi = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 901) };
        let fd = if hi >= 0 {
            unsafe { libc::close(fd) };
            hi
        } else {
            fd
        };
        self.msem_fd = Some(fd);
        fd
    }

    /// Take the semaphore if it is free; 0 taken, 3 busy, 2 not accessible
    fn msem_try(&mut self, sem: u32, set_wanted: bool) -> u32 {
        let fd = self.msem_hostlock();
        lock_file(fd, true);
        let r = match self.cpu.mem.ld32(sem.wrapping_add(8)) {
            Ok(0) => {
                if self.cpu.mem.st32(sem + 8, self.pid).is_ok() { 0 } else { 2 }
            }
            Ok(_) => {
                if set_wanted && self.cpu.mem.st32(sem + 12, 1).is_err() { 2 } else { 3 }
            }
            Err(_) => 2,
        };
        lock_file(fd, false);
        r
    }

    /// The gateway page's mcas_util(sem): libc's msem_lock fast path
    pub fn mcas_util(&mut self) {
        let sem = self.gr(26);
        let r = if sem & 15 != 0 {
            4
        } else if !self.msem_lockid {
            1
        } else {
            self.msem_try(sem, false)
        };
        if self.trace {
            emsg!("[{}] mcas_util({:#x}) = {}\n", self.pid, sem, r);
        }
        self.set_gr(28, r);
        self.cpu.set_pc(self.gr(31));
    }

    /// msem_init(sem, initial): a semaphore in shared memory, unlocked or locked by this
    /// process
    pub fn sys_msem_init(&mut self, a: &[u32; 8]) -> SysResult {
        let sem = a[0];
        if sem & 15 != 0 {
            return err(EINVAL);
        }
        self.wr32(sem, 0)?;
        self.wr32(sem + 4, MSEM_MAGIC)?;
        self.wr32(sem + 8, if a[1] == 1 { self.pid } else { 0 })?;
        self.wr32(sem + 12, 0)?;
        ok(0)
    }

    /// msem_remove(sem): the semaphore is no longer valid
    pub fn sys_msem_remove(&mut self, a: &[u32; 8]) -> SysResult {
        if self.rd32(a[0].wrapping_add(4))? != MSEM_MAGIC {
            return err(EINVAL);
        }
        self.wr32(a[0] + 4, 0)?;
        self.wr32(a[0] + 8, 0)?;
        ok(0)
    }

    /// msleep(sem, cond): wait until the semaphore is free and take it (EAGAIN at once
    /// with MSEM_IF_NOWAIT); a signal interrupts the wait
    pub fn sys_msleep(&mut self, a: &[u32; 8]) -> SysResult {
        loop {
            match self.msem_try(a[0], true) {
                0 => return ok(0),
                2 => return err(EFAULT),
                _ => {}
            }
            if a[1] & 1 != 0 {
                return err(EAGAIN);
            }
            self.host_poll(&[], 5)?;
        }
    }

    /// mwakeup(sem): waiters poll for the lock, so nothing to wake; `wanted` is cleared
    pub fn sys_mwakeup(&mut self, a: &[u32; 8]) -> SysResult {
        self.wr32(a[0].wrapping_add(12), 0)?;
        ok(0)
    }

    /// mmap(addr, len, prot, flags, fd, off): MAP_FIXED honoured; otherwise private
    /// mappings are placed below PRIVATE_MMAP_TOP (downwards), shared ones from
    /// SHARED_MMAP_BASE (upwards) and shared executable ones - library text - from
    /// SHLIB_TEXT_BASE, as HP-UX's quadrants have them
    pub fn sys_mmap(&mut self, a: &[u32; 8]) -> SysResult {
        ok(self.do_mmap(a[0], a[1], a[2], a[3], a[4], a[5] as u64)?)
    }

    /// mmap64(addr, len, prot, flags, fd, offset): mmap with a 64-bit offset (two words)
    pub fn sys_mmap64(&mut self, a: &[u32; 8]) -> SysResult {
        ok(self.do_mmap(a[0], a[1], a[2], a[3], a[4], ((a[5] as u64) << 32) | a[6] as u64)?)
    }

    fn do_mmap(&mut self, addr: u32, length: u32, prot: u32, flags: u32, fd: u32, off: u64) -> Res<u32> {
        if length == 0 || length > 0xFFFF_F000 {
            return err(EINVAL);
        }
        let size = (length + PAGE - 1) & !(PAGE - 1);
        let anon = flags & MAP_ANONYMOUS != 0;
        let base = if flags & MAP_FIXED != 0 {
            if addr & (PAGE - 1) != 0 {
                return err(EINVAL);
            }
            addr
        } else if flags & MAP_SHARED != 0 || (flags & MAP_SHLIB != 0 && flags & MAP_PRIVATE == 0) {
            // a private MAP_SHLIB mapping (a library's bss, from 11.00's dld.sl) is private
            // memory, placed downwards like the rest: dld then maps the library's data
            // MAP_FIXED right below it, where a downward allocator has left room
            if prot & PROT_EXEC != 0 {
                // shared-library text (and dld.sl's) in the fourth quadrant, above the
                // gateway page, as HP-UX places it: HP's JVM JIT tells a shared library's
                // code from the program's by its address, and calls a library's helpers
                // without setting r19 when they look like the latter
                self.find_free(size, SHLIB_TEXT_BASE, SHLIB_TEXT_END, true)?
            } else {
                self.find_free(size, SHARED_MMAP_BASE, SHARED_MMAP_END, true)?
            }
        } else {
            self.find_free(size, 0x5000_0000, PRIVATE_MMAP_TOP, false)?
        };
        let mprot = if prot & 7 == 0 { 0 } else { mprot_of(prot) };
        if self.is11 && !anon && flags & MAP_SHARED != 0 && prot & PROT_EXEC != 0 && prot & PROT_WRITE == 0 {
            // PA-RISC HP-UX maps a file range MAP_SHARED at one global address, and a
            // shared executable mapping is the file's execution: a second one of a range
            // this process already has fails. 11.00's dld.sl counts on that - it maps a
            // library's text, and when the mmap fails it looks for the library among those
            // loaded (find_duplicateload) and uses that one; without the failure it loads
            // libc and libdld again for every library that names them.
            let st = host::fstat(fd as i32).map_err(herrno)?;
            let key = (st.st_dev, st.st_ino);
            for m in &self.mappings {
                if let Some((k, moff, msize)) = m.key {
                    if k == key && off < moff + msize as u64 && moff < off + size as u64 {
                        return err(ENOMEM);
                    }
                }
            }
            let r = self.do_mmap_inner(length, prot, flags, fd, off, base, size, anon, mprot)?;
            if let Some(m) = self.mappings.iter_mut().rev().find(|m| m.base == r) {
                m.key = Some((key, off, size));
            }
            self.install_natives(fd, r, off, size, prot, anon);
            return Ok(r);
        }
        let r = self.do_mmap_inner(length, prot, flags, fd, off, base, size, anon, mprot)?;
        self.install_natives(fd, r, off, size, prot, anon);
        Ok(r)
    }

    #[allow(clippy::too_many_arguments)]
    fn do_mmap_inner(&mut self, length: u32, prot: u32, flags: u32, fd: u32, off: u64, base: u32, size: u32, anon: bool, mprot: u8) -> Res<u32> {
        let shared = flags & MAP_SHARED != 0 && flags & MAP_PRIVATE == 0;
        if !anon && shared {
            return self.mmap_shared_file(base, size, mprot, flags, prot, fd, off);
        }
        if anon && shared {
            // shared anonymous memory stays shared with the children a fork makes (memory
            // semaphores and counters between an application's processes): a host MAP_SHARED
            // mapping, which fork does not copy
            self.cpu.mem.unmap(base, size);
            let r = unsafe {
                libc::mmap(
                    self.cpu.mem.host(base) as *mut libc::c_void,
                    size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_FIXED | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if r == libc::MAP_FAILED {
                return Err(herr());
            }
            self.cpu.mem.mark(base, size, mprot);
            self.mappings.push(Mapping { base, size, path: None, off: 0, flags, prot, key: None });
            return Ok(base);
        }
        if !anon {
            self.fd_check(fd)?;
        }
        if flags & MAP_FIXED != 0 {
            // a fixed mapping replaces what is there: dld.sl maps a library's text and
            // data as one shared range, then its data privately over the end of it (the
            // host's shared file pages must go first; they may be read-only)
            self.cpu.mem.unmap(base, size);
        }
        if !self.cpu.mem.map(base, size, mprot | 2) {
            return err(ENOMEM);
        }
        if !anon {
            // the file's bytes, read straight into the new pages
            let host = self.cpu.mem.host(base);
            let mut done = 0usize;
            while done < length as usize {
                let r = unsafe { libc::pread(fd as i32, host.add(done) as *mut libc::c_void, length as usize - done, (off + done as u64) as libc::off_t) };
                if r < 0 {
                    if host::errno() == libc::EINTR {
                        continue;
                    }
                    return Err(herr());
                }
                if r == 0 {
                    break;
                }
                done += r as usize;
            }
            // a writable shared file mapping is written back at munmap and exit
            let path = if flags & MAP_SHARED != 0 && prot & PROT_WRITE != 0 { Some(self.fds[&fd].path.clone()) } else { None };
            self.mappings.push(Mapping { base, size, path, off, flags, prot, key: None });
        } else {
            self.mappings.push(Mapping { base, size, path: None, off: 0, flags, prot, key: None });
        }
        self.cpu.mem.protect(base, size, mprot);
        Ok(base)
    }

    /// A MAP_SHARED file mapping: the host file itself is mapped at the guest address in
    /// the CPU's reservation, so every process mapping the file sees the others' writes at
    /// once, as on HP-UX. A database's clients see the pages its cache manager puts into
    /// a shared cache file this way. Pages beyond the end of the file stay
    /// ordinary zeroed memory: touching them must not raise a host SIGBUS in the emulator.
    #[allow(clippy::too_many_arguments)]
    fn mmap_shared_file(&mut self, base: u32, size: u32, mprot: u8, flags: u32, prot: u32, fd: u32, off: u64) -> Res<u32> {
        self.fd_check(fd)?;
        if off & (PAGE as u64 - 1) != 0 {
            return err(EINVAL);
        }
        let st = host::fstat(fd as i32).map_err(herrno)?;
        let fl = unsafe { libc::fcntl(fd as i32, libc::F_GETFL) };
        if fl < 0 {
            return Err(herr());
        }
        let writable = fl & libc::O_ACCMODE == libc::O_RDWR;
        if prot & PROT_WRITE != 0 && !writable {
            return err(EACCES);
        }
        let filelen = (((st.st_size - off as i64) + PAGE as i64 - 1) & !(PAGE as i64 - 1)).max(0) as u64;
        let shared = (size as u64).min(filelen) as usize;
        self.cpu.mem.unmap(base, size);
        if !self.cpu.mem.map(base, size, mprot | 2) {
            return err(ENOMEM);
        }
        if shared != 0 {
            let r = unsafe {
                libc::mmap(
                    self.cpu.mem.host(base) as *mut libc::c_void,
                    shared,
                    if writable { libc::PROT_READ | libc::PROT_WRITE } else { libc::PROT_READ },
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    fd as i32,
                    off as libc::off_t,
                )
            };
            if r == libc::MAP_FAILED {
                let e = host::errno();
                self.cpu.mem.unmap(base, size);
                return Err(herrno(e));
            }
        }
        self.cpu.mem.mark(base, size, mprot);
        self.mappings.push(Mapping { base, size, path: None, off, flags, prot, key: None });
        Ok(base)
    }

    /// A free range of `size` bytes between lo and hi: the lowest one from lo upwards, or
    /// the highest one below hi. Fixed mappings anywhere are respected: dld.sl maps a
    /// library's data right below the anonymous region it got for the bss.
    pub fn find_free(&mut self, size: u32, lo: u32, hi: u32, upward: bool) -> Res<u32> {
        match self.cpu.mem.find_free(size, lo, hi, upward) {
            Some(a) => Ok(a),
            None => err(ENOMEM),
        }
    }

    /// munmap(addr, len): the pages are released; a writable MAP_SHARED file mapping is
    /// written back to the file first
    pub fn sys_munmap(&mut self, a: &[u32; 8]) -> SysResult {
        let addr = a[0];
        let size = ((a[1] as u64 + PAGE as u64 - 1) & !(PAGE as u64 - 1)).min(1 << 32);
        let end = addr as u64 + size;
        let maps = std::mem::take(&mut self.mappings);
        let mut keep = Vec::with_capacity(maps.len());
        for m in maps {
            if (m.base as u64) < end && (addr as u64) < m.base as u64 + m.size as u64 {
                if m.path.is_some() {
                    self.writeback(&m);
                }
            } else {
                keep.push(m);
            }
        }
        self.mappings = keep;
        let inside = |e: &(u32, u8)| addr <= e.0 && (e.0 as u64) < end;
        if self.native_list.iter().any(inside) {
            self.native_list.retain(|e| !inside(e));
            self.set_natives();
        }
        self.cpu.mem.unmap(addr, size.min(0xFFFF_F000) as u32);
        ok(0)
    }

    fn writeback(&mut self, m: &Mapping) {
        let path = match &m.path {
            Some(p) => p.clone(),
            None => return,
        };
        let data = match self.rd(m.base, m.size as usize) {
            Ok(d) => d,
            Err(_) => return,
        };
        let hp = match self.hostpath_own(&path, true) {
            Ok(h) => h,
            Err(_) => return,
        };
        let fd = unsafe { libc::open(cstr(&hp).as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return;
        }
        if let Ok(st) = host::fstat(fd) {
            let n = (data.len() as i64).min(st.st_size - m.off as i64).max(0) as usize;
            let mut done = 0;
            while done < n {
                let r = unsafe { libc::pwrite(fd, data[done..].as_ptr() as *const libc::c_void, n - done, (m.off + done as u64) as libc::off_t) };
                if r <= 0 {
                    break;
                }
                done += r as usize;
            }
        }
        unsafe { libc::close(fd) };
    }

    pub fn writeback_all(&mut self) {
        let maps: Vec<Mapping> = self.mappings.iter().filter(|m| m.path.is_some()).cloned().collect();
        for m in maps {
            self.writeback(&m);
        }
    }

    /// mprotect(addr, len, prot): the page protection the CPU checks
    pub fn sys_mprotect(&mut self, a: &[u32; 8]) -> SysResult {
        self.cpu.mem.protect(a[0], a[1], mprot_of(a[2]));
        ok(0)
    }
}
