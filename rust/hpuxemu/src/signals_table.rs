//! the signal system calls of signals.rs, by name
use crate::process::Process;
use crate::syscalls::Handler;

pub const TABLE: &[(&str, Handler)] = &[
    ("sigaction", Process::sys_sigaction),
    ("sigvector", Process::sys_sigvector),
    ("sigcleanup", Process::sys_sigcleanup),
    ("sigstack", Process::sys_sigstack),
    ("sigaltstack", Process::sys_sigaltstack),
    ("sigsetreturn", Process::sys_sigsetreturn),
    ("sigprocmask", Process::sys_sigprocmask),
    ("siginhibit", Process::sys_siginhibit),
    ("sigenable", Process::sys_sigenable),
    ("sigsetstatemask", Process::sys_sigsetstatemask),
    ("sigpending", Process::sys_sigpending),
    ("sigblock", Process::sys_sigblock),
    ("sigsetmask", Process::sys_sigsetmask),
    ("sigsuspend", Process::sys_sigsuspend),
    ("sigpause", Process::sys_sigpause),
    ("sigtimedwait", Process::sys_sigtimedwait),
    ("sigwaitinfo", Process::sys_sigwaitinfo),
    ("sigqueue", Process::sys_sigqueue),
    ("sigwait", Process::sys_sigwait),
    ("kill", Process::sys_kill),
    ("setitimer", Process::sys_setitimer),
    ("getitimer", Process::sys_getitimer),
    ("alarm", Process::sys_alarm),
    ("pause", Process::sys_pause),
];
