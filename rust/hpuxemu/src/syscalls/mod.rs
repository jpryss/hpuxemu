//! The system calls, by name; the numbers are HP-UX 10.20's or 11.00's (consts.rs), the
//! handlers the same.

pub mod files;
pub mod ioctl;
pub mod ipc;
pub mod misc;
pub mod mmap;
pub mod net;
pub mod proc;

use crate::consts::{SYSCALLS_10, SYSCALLS_11};
use crate::process::{Process, SysResult};
use std::sync::LazyLock;

pub type Handler = fn(&mut Process, &[u32; 8]) -> SysResult;

pub struct Entry {
    pub name: &'static str,
    pub f: Option<Handler>,
    /// calls that may wait: a signal that came while the program ran is handled before
    /// one of them starts (as a kernel delivers it on the way back to user mode), the
    /// call made again when the handler returns
    pub blocking: bool,
    /// the calls a thread waits in by itself when the process has several (threads.rs)
    pub thread_wait: bool,
    /// restarted after a handler with SA_RESTART returns; the ones that wait for a signal
    /// (pause, sigsuspend, sigpause) always return EINTR
    pub restartable: bool,
}

pub static UNKNOWN: Entry = Entry { name: "sys?", f: None, blocking: false, thread_wait: false, restartable: false };

const BLOCKING: &[&str] = &[
    "read", "readv", "write", "writev", "wait", "waitpid", "wait3", "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg", "accept",
    "connect", "msgsnd", "msgrcv", "semop", "select", "poll", "pause", "getmsg", "putmsg", "getpmsg", "putpmsg", "nanosleep",
    "sigtimedwait", "sigwait",
];
const THREAD_WAITS: &[&str] = &[
    "read", "readv", "recv", "recvfrom", "recvmsg", "accept", "getmsg", "getpmsg", "poll", "select", "waitpid", "wait", "wait3",
    "nanosleep", "sigtimedwait", "sigwait",
];
const RESTARTABLE: &[&str] = &[
    "read", "readv", "write", "writev", "wait", "waitpid", "wait3", "open", "ioctl", "fcntl", "lockf", "recv", "recvfrom", "recvmsg",
    "send", "sendto", "sendmsg", "accept", "connect", "msgsnd", "msgrcv", "semop",
];

fn handler(name: &str) -> Option<Handler> {
    for t in [misc::TABLE, files::TABLE, ioctl::TABLE, ipc::TABLE, mmap::TABLE, net::TABLE, proc::TABLE, crate::signals_table::TABLE, crate::streams::TABLE, crate::threads::TABLE] {
        for &(n, f) in t {
            if n == name {
                return Some(f);
            }
        }
    }
    None
}

fn build(names: &'static [(u32, &'static str)]) -> Vec<Option<Entry>> {
    let max = names.iter().map(|x| x.0).max().unwrap_or(0) as usize;
    let mut v: Vec<Option<Entry>> = (0..=max.max(139)).map(|_| None).collect();
    for &(num, name) in names {
        v[num as usize] = Some(Entry {
            name,
            f: handler(name),
            blocking: BLOCKING.contains(&name),
            thread_wait: THREAD_WAITS.contains(&name),
            restartable: RESTARTABLE.contains(&name),
        });
    }
    // syscall.h names 139 only in a comment: it is sigcleanup, the return from a handler
    if v[139].is_none() {
        v[139] = Some(Entry { name: "sigcleanup", f: handler("sigcleanup"), blocking: false, thread_wait: false, restartable: false });
    }
    v
}

/// (10.20's table, 11.00's), indexed by system call number
pub static SYSCALL_TABLE: LazyLock<(Vec<Option<Entry>>, Vec<Option<Entry>>)> = LazyLock::new(|| (build(SYSCALLS_10), build(SYSCALLS_11)));
