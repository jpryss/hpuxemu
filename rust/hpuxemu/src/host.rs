//! host.rs - the host (Linux) side: errno and signal numbers, interruptible calls, the
//! record of host signals, waiting without losing a wake-up.

use crate::consts::*;
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, Ordering};

pub fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// host errno -> HP-UX errno (EIO for one HP-UX has no name for)
pub fn guest_errno(e: i32) -> u32 {
    match HOST_ERRNO.binary_search_by_key(&e, |x| x.0) {
        Ok(i) => HOST_ERRNO[i].1,
        Err(_) => EIO,
    }
}

/// HP-UX signal -> host signal (0: none). 11.00's signals past 10.20's 32: SIGXCPU 33,
/// SIGXFSZ 34 (the host's own), SIGCANCEL 35, SIGGFAULT 36 and the realtime signals
/// 37..44 on the host's realtime signals.
pub fn host_sig(g: u32) -> i32 {
    if let Ok(i) = HOST_SIGNALS.binary_search_by_key(&g, |x| x.0) {
        return HOST_SIGNALS[i].1;
    }
    let rt = libc::SIGRTMIN();
    match g {
        37..=44 => rt + (g as i32 - 37),
        35 => rt + 8,
        36 => rt + 9,
        _ => 0,
    }
}

/// host signal -> HP-UX signal (0: none)
pub fn guest_sig(h: i32) -> u32 {
    for &(g, hh) in HOST_SIGNALS {
        if hh == h {
            return g;
        }
    }
    let rt = libc::SIGRTMIN();
    if h >= rt && h < rt + 8 {
        return 37 + (h - rt) as u32;
    }
    if h == rt + 8 {
        return 35;
    }
    if h == rt + 9 {
        return 36;
    }
    0
}

pub fn cstr(s: &str) -> CString {
    CString::new(s.as_bytes()).unwrap_or_else(|_| CString::new("").unwrap())
}

/// Guest strings are Latin-1 bytes; inside the emulator they are Strings of the characters
/// U+0000..U+00FF (so the host sees a non-ASCII name as UTF-8, as the Python emulator
/// has it).
pub fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

pub fn to_latin1(s: &str) -> Vec<u8> {
    s.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect()
}

// ---- host signals: the handler only records ------------------------------------------

/// host signals received and not yet looked at (bit = host signal number)
pub static HOST_PENDING: AtomicU64 = AtomicU64::new(0);

pub extern "C" fn record_signal(sig: libc::c_int) {
    if (1..64).contains(&sig) {
        HOST_PENDING.fetch_or(1u64 << sig, Ordering::SeqCst);
    }
}

pub fn take_host_pending() -> u64 {
    if HOST_PENDING.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    HOST_PENDING.swap(0, Ordering::SeqCst)
}

/// the disposition of a host signal: 0 default, 1 ignore, 2 the recording handler
/// (without SA_RESTART: a blocking host call returns EINTR)
pub fn host_signal_set(h: i32, how: u32) {
    if (h == libc::SIGSEGV || h == libc::SIGBUS) && FAULTS_OWNED.load(Ordering::Relaxed) != 0 {
        // the CPU's fault handler has these two (compiled loads fault instead of
        // checking); it passes on what is not its own, and fault_fallback acts by this
        FAULT_HOW[(h == libc::SIGBUS) as usize].store(how as u64, Ordering::SeqCst);
        return;
    }
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = match how {
            0 => libc::SIG_DFL,
            1 => libc::SIG_IGN,
            _ => record_signal as *const () as usize,
        };
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(h, &sa, std::ptr::null_mut());
    }
}

/// the CPU's fault handler owns the host's SIGSEGV and SIGBUS
pub static FAULTS_OWNED: AtomicU64 = AtomicU64::new(0);
/// what the guest's disposition asks of the host for SIGSEGV and SIGBUS (as host_signal_set)
static FAULT_HOW: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// A SIGSEGV or SIGBUS that was not a compiled load's: one another process sent is
/// handled as the guest's disposition says; a real fault is the emulator's own, and ends it.
pub unsafe extern "C" fn fault_fallback(sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    if (*info).si_code <= 0 {
        match FAULT_HOW[(sig == libc::SIGBUS) as usize].load(Ordering::SeqCst) {
            2 => return record_signal(sig),
            1 => return,
            _ => {
                libc::signal(sig, libc::SIG_DFL);
                libc::raise(sig);
                return;
            }
        }
    }
    libc::signal(sig, libc::SIG_DFL);
}

/// Whether a host SIGCHLD is one HP-UX would send: a child exited or stopped. Linux also
/// sends one when a child is continued (SIGCONT), which HP-UX does not - and a SIGCHLD
/// handler without SA_RESTART then makes the parent's waitpid fail with EINTR. Looked at
/// without reaping (WNOWAIT); a continue alone is taken off the host's record and the
/// signal dropped.
pub fn chld_is_news() -> bool {
    unsafe {
        let mut si: libc::siginfo_t = std::mem::zeroed();
        let r = libc::waitid(libc::P_ALL, 0, &mut si, libc::WEXITED | libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT);
        if r != 0 {
            return true;
        }
        if si.si_pid() != 0 {
            return true;
        }
        let mut si: libc::siginfo_t = std::mem::zeroed();
        let r = libc::waitid(libc::P_ALL, 0, &mut si, libc::WCONTINUED | libc::WNOHANG);
        if r != 0 {
            return true;
        }
        if si.si_pid() != 0 {
            return false;
        }
    }
    true
}

/// every signal a handler can catch, blocked: returns the old mask
pub fn block_all() -> libc::sigset_t {
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old);
        old
    }
}

pub fn restore_mask(old: &libc::sigset_t) {
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, old, std::ptr::null_mut());
    }
}

/// `f` retried while the host call is interrupted (the calls a signal must not cut short)
pub fn retry<F: FnMut() -> isize>(mut f: F) -> isize {
    loop {
        let r = f();
        if r >= 0 || errno() != libc::EINTR {
            return r;
        }
    }
}

pub fn now_f64() -> f64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

pub fn monotonic() -> f64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

pub fn process_time() -> f64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

/// (user, system, children user, children system) seconds
pub fn times() -> (f64, f64, f64, f64) {
    let mut t: libc::tms = unsafe { std::mem::zeroed() };
    unsafe { libc::times(&mut t) };
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    (t.tms_utime as f64 / hz, t.tms_stime as f64 / hz, t.tms_cutime as f64 / hz, t.tms_cstime as f64 / hz)
}

pub fn stat(path: &str, follow: bool) -> Result<libc::stat, i32> {
    let c = cstr(path);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe {
        if follow {
            libc::stat(c.as_ptr(), &mut st)
        } else {
            libc::lstat(c.as_ptr(), &mut st)
        }
    };
    if r < 0 {
        Err(errno())
    } else {
        Ok(st)
    }
}

pub fn fstat(fd: i32) -> Result<libc::stat, i32> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        Err(errno())
    } else {
        Ok(st)
    }
}

pub fn readlink(path: &str) -> Result<String, i32> {
    let c = cstr(path);
    let mut buf = vec![0u8; 4096];
    let n = unsafe { libc::readlink(c.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if n < 0 {
        return Err(errno());
    }
    buf.truncate(n as usize);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}
pub fn is_lnk(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFLNK
}
pub fn is_fifo(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFIFO
}
pub fn is_sock(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFSOCK
}
pub fn is_reg(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

pub fn exists(path: &str) -> bool {
    stat(path, true).is_ok()
}

pub fn lexists(path: &str) -> bool {
    stat(path, false).is_ok()
}

pub fn isatty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

pub fn ttyname(fd: i32) -> Option<String> {
    let mut buf = [0u8; 256];
    let r = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if r != 0 {
        return None;
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// the emulator's own messages go to a private copy of the original stderr at a high
/// descriptor (detach_stderr): an HP-UX fd *is* the host fd, so a daemon that closes 0-2
/// would otherwise close the emulator's stderr too
pub static mut ERR_FD: i32 = 2;

pub fn err_fd() -> i32 {
    unsafe { ERR_FD }
}

pub fn ewrite(s: &str) {
    let b = s.as_bytes();
    let mut off = 0;
    while off < b.len() {
        let r = unsafe { libc::write(err_fd(), b[off..].as_ptr() as *const libc::c_void, b.len() - off) };
        if r <= 0 {
            if r < 0 && errno() == libc::EINTR {
                continue;
            }
            break;
        }
        off += r as usize;
    }
}

#[macro_export]
macro_rules! emsg {
    ($($arg:tt)*) => { $crate::host::ewrite(&format!($($arg)*)) };
}

pub fn getenv(k: &str) -> Option<String> {
    std::env::var_os(k).map(|v| v.to_string_lossy().into_owned())
}

/// the user's cache directory for the emulator
pub fn cache_dir() -> String {
    let base = match getenv("XDG_CACHE_HOME") {
        Some(b) if !b.is_empty() => b,
        _ => format!("{}/.cache", getenv("HOME").unwrap_or_else(|| "/".to_string())),
    };
    format!("{}/hpuxemu", base)
}

/// "name" of errno for the trace
pub fn errno_name(e: u32) -> String {
    for &(n, s) in ERRNO_NAMES {
        if n == e {
            return s.to_string();
        }
    }
    e.to_string()
}

pub fn signal_name(s: u32) -> String {
    for &(n, nm) in SIGNAL_NAMES {
        if n == s {
            return nm.to_string();
        }
    }
    s.to_string()
}
