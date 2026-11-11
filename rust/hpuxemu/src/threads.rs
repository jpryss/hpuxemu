//! threads.rs - HP-UX 11.00's kernel threads (LWPs), as libpthread uses them.
//!
//! A process's LWPs share the emulator's one CPU and memory: each has its saved register
//! context (the general, floating-point and control registers the program can see, its
//! thread pointer cr27) and its own signal mask, and the emulator switches between them -
//! when the running one blocks in the kernel (ksleep, lwp_wait, sched_yield ...) and, so
//! that no thread starves another spinning on a lock, every RUN_CHUNK instructions. One
//! thread runs at a time, so the kernel's atomicity (release a lock and sleep, wake and
//! requeue) comes for free. The interface is sys/lwp.h, sys/ksleep.h and sys/lwpsynch.h:
//!
//!     _lwp_create(ucontext_t *, flags, lwpid_t *, lwp_create_t *)   the context from
//!                               _lwp_makecontext: entry, argument, stack, thread pointer
//!     _lwp_exit(), _lwp_wait(lwpid, &departed), _lwp_detach, _lwp_self, _lwp_kill,
//!     _lwp_suspend/_lwp_continue/_lwp_resume
//!     ksleep(obj_flag, obj, lock, timeout)       release the lock (4 words, {1,1,1,1}
//!                                                free) and sleep on obj until a kwakeup
//!     kwakeup(obj_flag, obj, WAKEUP_ONE|ALL, &woken)
//!
//! A thread whose host call would block (read, select, waitpid, sleep ...) parks alone and
//! makes the call again when it can go ahead. A signal for the process goes to the running
//! thread, or to a waiting one that does not block it (or waits for it in sigwait);
//! _lwp_kill's goes to the thread it names. Not done: lwp_mutex_*, lwp_cond_*,
//! lwp_rwlock_* and lwp_sema_* (libpthread builds its locks on ksleep), pstat_getlwp.

use crate::consts::*;
use crate::emsg;
use crate::host::{self, host_sig};
use crate::process::*;
use crate::signals::SigSet;
use crate::syscalls::Handler;
use std::collections::BTreeMap;

pub const TABLE: &[(&str, Handler)] = &[
    ("lwp_self", Process::sys_lwp_self),
    ("lwp_getscheduler", Process::sys_lwp_getscheduler),
    ("lwp_setscheduler", Process::sys_zero),
    ("lwp_create", Process::sys_lwp_create),
    ("lwp_exit", Process::sys_lwp_exit),
    ("lwp_detached_exit", Process::sys_lwp_detached_exit),
    ("lwp_wait", Process::sys_lwp_wait),
    ("lwp_detach", Process::sys_lwp_detach),
    ("lwp_kill", Process::sys_lwp_kill),
    ("lwp_suspend", Process::sys_lwp_suspend),
    ("lwp_continue", Process::sys_lwp_continue),
    ("lwp_getstate", Process::sys_lwp_getstate),
    ("lwp_resume", Process::sys_lwp_continue),
    ("sched_yield", Process::sys_sched_yield),
    ("ksleep", Process::sys_ksleep),
    ("kwakeup", Process::sys_kwakeup),
];

// sys/ksleep.h
const RELATIVE_TIMEOUT_VALUE: u32 = 0x0200;
const WAKEUP_ALL: u32 = 0x02;
// sys/lwp.h
const LWP_SUSPENDED: u32 = 0x02;
const LWP_DETACHED: u32 = 0x04;
const LWP_INHERIT_SIGMASK: u32 = 0x10;
// sys/sched.h
const SCHED_HPUX: u32 = 2;

const ETIMEDOUT_: u32 = 238;

/// a thread's registers while it is off the CPU
#[derive(Clone)]
pub struct Ctx {
    pub gr: [u64; 32],
    pub fr: [u64; 32],
    pub sar: u64,
    pub iaoq_f: u32,
    pub iaoq_b: u32,
    pub psw_n: bool,
    pub psw_cb: u64,
    pub psw_cb_msb: u64,
    pub psw_v: u64,
    pub cr26: u64,
    pub cr27: u64,
    pub mask: SigSet,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum State {
    /// runnable
    Run,
    /// ksleep on `key`, or a sleep with only a deadline
    Sleep,
    /// lwp_wait for `key` (0 any)
    Join,
    /// a host call that would block: `conds` the conditions, the call made again when one holds
    Io,
    Yield,
    /// exited, not yet waited for
    Zombie,
}

#[derive(Clone)]
pub enum Cond {
    Fd(i32, i16),
    Sig(SigSet),
    Child(libc::idtype_t, libc::id_t),
}

/// what a wait's call returns when its deadline comes first
#[derive(Clone)]
pub enum OnTimeout {
    Default,
    Zero,
    Eagain,
    /// poll: the revents cleared
    Poll(u32, u32),
    /// select: the three sets cleared
    Select([u32; 3], u32),
}

pub struct Lwp {
    pub id: u32,
    /// None while it runs
    pub ctx: Option<Box<Ctx>>,
    pub state: State,
    pub key: Option<u32>,
    pub conds: Vec<Cond>,
    pub deadline: Option<f64>,
    pub detached: bool,
    pub departed_p: u32,
    pub suspended: bool,
    pub on_timeout: OnTimeout,
    /// signals sent to this thread (_lwp_kill), not yet taken
    pub tpending: u64,
    /// its siginhibit() masks, while it is off the CPU
    pub inhibit: Vec<SigSet>,
}

impl Lwp {
    fn new(id: u32) -> Lwp {
        Lwp { id, ctx: None, state: State::Run, key: None, conds: Vec::new(), deadline: None, detached: false, departed_p: 0, suspended: false, on_timeout: OnTimeout::Default, tpending: 0, inhibit: Vec::new() }
    }
    fn waiting(&self) -> bool {
        matches!(self.state, State::Sleep | State::Join | State::Io)
    }
}

#[derive(Default)]
pub struct Threads {
    /// {id: Lwp} once the process makes its first thread
    pub lwps: BTreeMap<u32, Lwp>,
    /// the running thread's id (it may have left `lwps`: a detached thread exiting)
    pub cur: u32,
    next_id: u32,
    /// of the pending signals: the running thread's own (from its tpending)
    tdirected: u64,
}

impl Threads {
    pub fn active(&self) -> bool {
        !self.lwps.is_empty()
    }
    pub fn multi(&self) -> bool {
        self.lwps.len() > 1
    }
}

fn sleep_s(t: f64) {
    if t > 0.0 {
        let ts = libc::timespec { tv_sec: t as libc::time_t, tv_nsec: ((t - t.floor()) * 1e9) as libc::c_long };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    }
}

fn child_ready(idtype: libc::idtype_t, id: libc::id_t) -> bool {
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::waitid(idtype, id, &mut si, libc::WEXITED | libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT) };
    // (an error: none left, the call fails at once)
    r != 0 || unsafe { si.si_pid() } != 0
}

fn mask_bits(m: &SigSet) -> u64 {
    // signals 1..63 as bits 1..63, like `pending`
    let mut b = 0u64;
    for s in 1..64 {
        if m.has(s) {
            b |= 1 << s;
        }
    }
    b
}

/// where gr1..gr31 are in 11.00's narrow save state
fn narrow_regs11() -> [usize; 31] {
    use off11::ss_narrow as N;
    [
        N::ss_gr1.0, N::ss_rp.0, N::ss_gr3.0, N::ss_gr4.0, N::ss_gr5.0, N::ss_gr6.0, N::ss_gr7.0, N::ss_gr8.0, N::ss_gr9.0, N::ss_gr10.0,
        N::ss_gr11.0, N::ss_gr12.0, N::ss_gr13.0, N::ss_gr14.0, N::ss_gr15.0, N::ss_gr16.0, N::ss_gr17.0, N::ss_gr18.0, N::ss_gr19.0,
        N::ss_gr20.0, N::ss_gr21.0, N::ss_gr22.0, N::ss_arg3.0, N::ss_arg2.0, N::ss_arg1.0, N::ss_arg0.0, N::ss_dp.0, N::ss_ret0.0,
        N::ss_ret1.0, N::ss_sp.0, N::ss_gr31.0,
    ]
}

impl Process {
    // -- contexts ------------------------------------------------------------------------
    fn lwp_setup(&mut self) {
        if self.threads.lwps.is_empty() {
            self.threads.lwps.insert(1, Lwp::new(1));
            self.threads.cur = 1;
            self.threads.next_id = 2;
        }
    }

    /// the running thread's context, as it leaves the CPU: the signals sent to it alone
    /// that are still pending go back to it
    fn ctx_save(&mut self) -> Box<Ctx> {
        let cur = self.threads.cur;
        if self.threads.tdirected != 0 {
            let mine = self.threads.tdirected & self.pending;
            if let Some(t) = self.threads.lwps.get_mut(&cur) {
                t.tpending |= mine;
            }
            self.pending &= !mine;
            self.threads.tdirected = 0;
        }
        // siginhibit/sigenable nest per thread: libpthread brackets its critical sections
        // with them, and threads switch inside them
        let inh = std::mem::take(&mut self.inhibit);
        if let Some(t) = self.threads.lwps.get_mut(&cur) {
            t.inhibit = inh;
        }
        let c = &self.cpu;
        Box::new(Ctx { gr: c.gr, fr: c.fr, sar: c.sar, iaoq_f: c.iaoq_f, iaoq_b: c.iaoq_b, psw_n: c.psw_n, psw_cb: c.psw_cb, psw_cb_msb: c.psw_cb_msb, psw_v: c.psw_v, cr26: c.cr[26], cr27: c.cr[27], mask: self.sigmask })
    }

    /// thread `id` runs: its context loaded, the signals sent to it now pending
    fn lwp_enter(&mut self, id: u32) {
        let t = self.threads.lwps.get_mut(&id).unwrap();
        let ctx = t.ctx.take().unwrap();
        let inh = std::mem::take(&mut t.inhibit);
        let tp = std::mem::take(&mut t.tpending);
        let c = &mut self.cpu;
        c.gr = ctx.gr;
        c.gr[0] = 0;
        c.fr = ctx.fr;
        c.sar = ctx.sar;
        c.iaoq_f = ctx.iaoq_f;
        c.iaoq_b = ctx.iaoq_b;
        c.psw_n = ctx.psw_n;
        c.psw_cb = ctx.psw_cb;
        c.psw_cb_msb = ctx.psw_cb_msb;
        c.psw_v = ctx.psw_v;
        c.cr[26] = ctx.cr26;
        c.cr[27] = ctx.cr27;
        self.sigmask = ctx.mask;
        self.threads.cur = id;
        self.inhibit = inh;
        if tp != 0 {
            self.threads.tdirected = tp & !self.pending;
            self.pending |= tp;
        }
        if self.trace {
            emsg!("[{}] -- lwp {} runs at {:#x} sp {:#x}\n", self.pid, id, self.cpu.iaoq_f & !3, self.gr(30));
        }
    }

    /// a new thread's context from the ucontext_t _lwp_makecontext filled (its mcontext,
    /// a __save_state: the narrow registers and the FP block)
    fn ctx_from_ucontext(&mut self, ucp: u32) -> Res<Box<Ctx>> {
        use off11::ss_narrow as N;
        let ss = off11::ucontext::uc_mcontext.0;
        let narrow = ss + off11::save_state::ss_narrow.0;
        let fpb = ss + off11::save_state::ss_fpblock.0;
        let size = off11::ucontext::uc_subcontext.0 + 48;
        let u = self.rd(ucp, size)?;
        let mut gr = [0u64; 32];
        for (i, o) in narrow_regs11().iter().enumerate() {
            gr[i + 1] = be32(&u, narrow + o) as u64;
        }
        let mut fr = [0u64; 32];
        for (i, f) in fr.iter_mut().enumerate() {
            *f = be64(&u, fpb + 8 * i);
        }
        // the thread starts as a system call returns, at r31 (_lwp_makecontext puts the
        // start routine there and leaves the pc queue alone); the thread pointer (cr27) is
        // the narrow state's last word but two, which 10.20's header leaves unnamed
        let mut head = gr[31] as u32 & !3;
        if gr[31] & 2 != 0 {
            // a function pointer: a plabel, {entry, gp}
            let (h, gp) = self.resolve_plabel(gr[31] as u32);
            head = h;
            if let Some(gp) = gp {
                gr[19] = gp as u64;
            }
        }
        let tail = head.wrapping_add(4);
        gr[28] = 0;
        gr[22] = 0;
        // the program's data pointer: _lwp_makecontext never writes r27, so the context
        // holds whatever pthread_create's stack had there (in examples/threads.c by luck
        // the data pointer, in Solid's ovdbrun garbage); it is one value for the whole
        // program, the creator's
        gr[27] = self.gr(27) as u64;
        let cr27 = be32(&u, narrow + 236) as u64;
        let sub = off11::ucontext::uc_subcontext.0 + off11::sub_ctxt::__uc_sigmask.0;
        let mask = SigSet::from_bytes(&u[sub..sub + 32]);
        // SAR is not written either: 5 bits of the residue, as mtsar would take them
        let sar = (be32(&u, narrow + N::ss_cr11.0) & 31) as u64;
        Ok(Box::new(Ctx { gr, fr, sar, iaoq_f: head | 3, iaoq_b: tail | 3, psw_n: false, psw_cb: 0, psw_cb_msb: 0, psw_v: 0, cr26: 0, cr27, mask }))
    }

    // -- scheduling ----------------------------------------------------------------------

    /// the result of a call whose deadline came first: (rv, err)
    fn timeout_result(&mut self, on: &OnTimeout, default: (u32, u32)) -> (u32, u32) {
        match on {
            OnTimeout::Default => default,
            OnTimeout::Zero => (0, 0),
            OnTimeout::Eagain => (EAGAIN, 1),
            OnTimeout::Poll(fds, nfds) => {
                for i in 0..(*nfds).min(1024) {
                    let _ = self.wr(fds + 8 * i + 6, &[0, 0]);
                }
                (0, 0)
            }
            OnTimeout::Select(sets, words) => {
                for addr in sets {
                    if *addr != 0 {
                        let _ = self.wr(*addr, &vec![0u8; 4 * *words as usize]);
                    }
                }
                (0, 0)
            }
        }
    }

    /// wake the threads whose deadline has passed or whose host call can go ahead;
    /// wait_ms: how long to wait for that when nothing else can run (-1: forever)
    fn lwp_wake_timeouts(&mut self, wait_ms: i64) {
        let now = host::now_f64();
        let due: Vec<u32> = self.threads.lwps.values().filter(|t| matches!(t.deadline, Some(d) if d <= now) && matches!(t.state, State::Sleep | State::Io)).map(|t| t.id).collect();
        for id in due {
            let (state, on) = {
                let t = self.threads.lwps.get_mut(&id).unwrap();
                (t.state, std::mem::replace(&mut t.on_timeout, OnTimeout::Default))
            };
            if state == State::Io {
                // the call is not made again: it returns, as the deadline says
                let (rv, e) = self.timeout_result(&on, (0, 0));
                if let Some(c) = self.threads.lwps.get_mut(&id).unwrap().ctx.as_mut() {
                    let ret = c.gr[31] as u32 & !3;
                    c.iaoq_f = ret | 3;
                    c.iaoq_b = ret.wrapping_add(4) | 3;
                }
                self.lwp_wake(id, rv, e);
            } else {
                // ksleep reports the timeout as its value, not as an error
                let (rv, e) = self.timeout_result(&on, (ETIMEDOUT_, 0));
                self.lwp_wake(id, rv, e);
            }
        }
        let io: Vec<u32> = self.threads.lwps.values().filter(|t| t.state == State::Io).map(|t| t.id).collect();
        if io.is_empty() {
            if wait_ms != 0 {
                sleep_s(if wait_ms < 0 { 0.5 } else { wait_ms as f64 / 1000.0 });
            }
            return;
        }
        let mut wait_ms = wait_ms;
        let mut entries: Vec<(i32, i16)> = Vec::new();
        let mut owners: Vec<u32> = Vec::new();
        let mut ready: Vec<u32> = Vec::new();
        let mut any_child = false;
        for id in &io {
            let t = &self.threads.lwps[id];
            for c in &t.conds {
                match c {
                    Cond::Fd(fd, ev) => {
                        entries.push((*fd, *ev));
                        owners.push(*id);
                    }
                    Cond::Sig(m) => {
                        if mask_bits(m) & (self.pending | t.tpending) != 0 {
                            ready.push(*id);
                        }
                    }
                    Cond::Child(ty, cid) => {
                        any_child = true;
                        if child_ready(*ty, *cid) {
                            ready.push(*id);
                        }
                    }
                }
            }
        }
        if !ready.is_empty() {
            wait_ms = 0;
        }
        if !entries.is_empty() {
            let res = self.poll_streams(&entries, if wait_ms >= 0 { wait_ms } else { 500 }).unwrap_or_else(|_| vec![0; entries.len()]);
            for (id, r) in owners.iter().zip(res.iter()) {
                if *r != 0 {
                    ready.push(*id);
                }
            }
        } else if wait_ms != 0 {
            sleep_s((if any_child { 0.05f64 } else { 0.5 }).min((if wait_ms > 0 { wait_ms } else { 500 }) as f64 / 1000.0));
        }
        for id in io {
            if ready.contains(&id) {
                // the call is made again (its context is at the gateway)
                let t = self.threads.lwps.get_mut(&id).unwrap();
                t.state = State::Run;
                t.conds.clear();
                t.key = None;
                t.deadline = None;
                t.on_timeout = OnTimeout::Default;
            }
        }
    }

    fn lwp_wake(&mut self, id: u32, rv: u32, e: u32) {
        if let Some(t) = self.threads.lwps.get_mut(&id) {
            t.state = State::Run;
            t.key = None;
            t.conds.clear();
            t.deadline = None;
            if let Some(c) = t.ctx.as_mut() {
                c.gr[28] = rv as u64;
                c.gr[22] = e as u64;
            }
        }
    }

    /// the next runnable thread after `after` in id order (round robin), or None
    fn lwp_pick(&self, after: u32) -> Option<u32> {
        let ok = |t: &&Lwp| t.state == State::Run && !t.suspended;
        if self.threads.lwps.contains_key(&after) {
            self.threads.lwps.range(after + 1..).map(|x| x.1).find(ok).or_else(|| self.threads.lwps.range(..=after).map(|x| x.1).find(ok)).map(|t| t.id)
        } else {
            self.threads.lwps.values().find(ok).map(|t| t.id)
        }
    }

    /// the time slice is over: another runnable thread, if any, runs
    pub fn lwp_preempt(&mut self) {
        if !self.threads.multi() {
            return;
        }
        self.lwp_wake_timeouts(0);
        for t in self.threads.lwps.values_mut() {
            if t.state == State::Yield {
                t.state = State::Run;
            }
        }
        let cur = self.threads.cur;
        let cur_running = self.threads.lwps.get(&cur).map(|t| t.state == State::Run).unwrap_or(false);
        if let Some(nxt) = self.lwp_pick(cur) {
            if nxt != cur && cur_running {
                let ctx = self.ctx_save();
                self.threads.lwps.get_mut(&cur).unwrap().ctx = Some(ctx);
                self.lwp_enter(nxt);
            }
        }
    }

    /// the running thread waits (its state already set): its system call returns rv when
    /// it runs again (a waker may change that); another thread runs - or, when none can,
    /// the process waits for a host call to become possible, a timeout or a signal.
    fn lwp_block(&mut self, rv: u32, e: u32) -> Stop {
        self.set_gr(28, rv);
        self.set_gr(22, e);
        self.cpu.set_pc(self.gr(31));
        let cur = self.threads.cur;
        let alive = self.threads.lwps.get(&cur).map(|t| t.state != State::Zombie).unwrap_or(false);
        let ctx = if alive { Some(self.ctx_save()) } else { None };
        self.lwp_block_saved(ctx)
    }

    /// a sleeping thread to interrupt for a pending signal: the first that does not block
    /// one of them (its ksleep returns EINTR and the signal is delivered to it)
    fn lwp_signal_target(&self) -> Option<u32> {
        for t in self.threads.lwps.values() {
            if t.waiting() {
                if let Some(c) = &t.ctx {
                    if self.pending_list().iter().any(|&s| !c.mask.has(s) && self.sigact(s).handler != 1) {
                        return Some(t.id);
                    }
                }
            }
        }
        None
    }

    /// switch away from the running thread, whose context is ctx (None: it is gone)
    fn lwp_block_saved(&mut self, ctx: Option<Box<Ctx>>) -> Stop {
        let cur = self.threads.cur;
        if let Some(t) = self.threads.lwps.get_mut(&cur) {
            t.ctx = ctx;
        }
        loop {
            self.lwp_wake_timeouts(0);
            let mut nxt = self.lwp_pick(cur);
            if nxt.is_none() {
                for t in self.threads.lwps.values_mut() {
                    if t.state == State::Yield {
                        t.state = State::Run;
                    }
                }
                nxt = self.lwp_pick(cur);
            }
            if let Some(n) = nxt {
                self.lwp_enter(n);
                return Stop::Switched;
            }
            if self.poll_signals() != 0 {
                if let Some(v) = self.lwp_signal_target() {
                    self.lwp_interrupt(v);
                    continue;
                }
            }
            let now = host::now_f64();
            let wait = self.threads.lwps.values().filter_map(|t| t.deadline).fold(0.5f64, |a, d| a.min((d - now).max(0.0)));
            self.lwp_wake_timeouts(((wait * 1000.0) as i64).max(1));
            self.poll_signals();
        }
    }

    /// a signal for the waiting thread `id`: its wait ends with EINTR (a host call it was
    /// to make again returns EINTR instead) and the signal is delivered when it runs
    fn lwp_interrupt(&mut self, id: u32) {
        let t = self.threads.lwps.get_mut(&id).unwrap();
        if t.state == State::Io {
            // a sigwait for the signal is made again, and takes it
            if t.conds.iter().any(|c| matches!(c, Cond::Sig(_))) {
                t.state = State::Run;
                t.conds.clear();
                t.key = None;
                t.deadline = None;
                t.on_timeout = OnTimeout::Default;
                return;
            }
            if let Some(c) = t.ctx.as_mut() {
                let ret = c.gr[31] as u32 & !3;
                c.iaoq_f = ret | 3;
                c.iaoq_b = ret.wrapping_add(4) | 3;
            }
        }
        self.lwp_wake(id, EINTR, 1);
    }

    /// the running thread's host call would block: it waits for one of conds or the
    /// deadline, then makes the call again - its context is left at the gateway with the
    /// call number and arguments as they are. on_timeout gives the call's result when the
    /// deadline comes first.
    fn lwp_park(&mut self, conds: Vec<Cond>, deadline: Option<f64>, on_timeout: OnTimeout) -> Stop {
        self.cpu.iaoq_f = (GATEWAY + 4) | 3;
        self.cpu.iaoq_b = (GATEWAY + 8) | 3;
        self.cpu.psw_n = false;
        let cur = self.threads.cur;
        let t = self.threads.lwps.get_mut(&cur).unwrap();
        t.state = State::Io;
        t.conds = conds;
        t.deadline = deadline;
        t.on_timeout = on_timeout;
        let ctx = self.ctx_save();
        self.lwp_block_saved(Some(ctx))
    }

    /// a descriptor whose reads never wait (O_NONBLOCK, O_NDELAY): the call goes ahead
    fn fd_nonblocking(&self, fd: u32) -> bool {
        match self.fds.get(&fd) {
            Some(f) => f.flags & (O_NONBLOCK | O_NDELAY) != 0,
            None => true,
        }
    }

    fn poll_now(&mut self, entries: &[(i32, i16)]) -> bool {
        self.poll_streams(entries, 0).map(|r| r.iter().any(|&x| x != 0)).unwrap_or(false)
    }

    /// for a call that can block the host, in a process with several threads: Ok when it
    /// can go ahead now, else the thread parks (Err(Stop::Switched)) until it can
    pub fn lwp_would_block(&mut self, name: &str, args: &[u32; 8]) -> Res<()> {
        let now = host::now_f64();
        let ts = |me: &Process, p: u32, scale: f64| -> Res<f64> {
            let d = me.rd(p, 8)?;
            Ok(be32(&d, 0) as i32 as f64 + be32(&d, 4) as i32 as f64 / scale)
        };
        match name {
            "read" | "readv" | "recv" | "recvfrom" | "recvmsg" | "accept" | "getmsg" | "getpmsg" => {
                if self.fd_nonblocking(args[0]) || self.poll_now(&[(args[0] as i32, libc::POLLIN)]) {
                    return Ok(());
                }
                Err(self.lwp_park(vec![Cond::Fd(args[0] as i32, libc::POLLIN)], None, OnTimeout::Default))
            }
            "poll" => {
                let (fds, nfds, timeout) = (args[0], args[1], args[2] as i32);
                if timeout == 0 {
                    return Ok(());
                }
                let mut conds = Vec::new();
                let mut entries = Vec::new();
                for i in 0..nfds.min(1024) {
                    let d = self.rd(fds + 8 * i, 8)?;
                    let fd = be32(&d, 0) as i32;
                    if fd >= 0 {
                        let ev = (be16(&d, 4) & 0xFF) as i16;
                        conds.push(Cond::Fd(fd, ev));
                        entries.push((fd, ev));
                    }
                }
                let deadline = if timeout > 0 { Some(now + timeout as f64 / 1000.0) } else { None };
                if !entries.is_empty() && self.poll_now(&entries) {
                    return Ok(());
                }
                Err(self.lwp_park(conds, deadline, OnTimeout::Poll(fds, nfds)))
            }
            "select" => {
                let (nfds, sets, tv) = (args[0] as i32, [args[1], args[2], args[3]], args[4]);
                let mut deadline = None;
                if tv != 0 {
                    let t = ts(self, tv, 1e6)?;
                    if t == 0.0 {
                        return Ok(());
                    }
                    deadline = Some(now + t);
                }
                let words = ((nfds.max(0) + 31) / 32) as u32;
                let mut conds = Vec::new();
                let mut entries = Vec::new();
                for (addr, ev) in [(sets[0], libc::POLLIN), (sets[1], libc::POLLOUT), (sets[2], libc::POLLPRI)] {
                    if addr == 0 {
                        continue;
                    }
                    let d = self.rd(addr, 4 * words as usize)?;
                    for i in 0..nfds.max(0) {
                        if be32(&d, 4 * (i as usize / 32)) & (1 << (i % 32)) != 0 {
                            conds.push(Cond::Fd(i, ev));
                            entries.push((i, ev));
                        }
                    }
                }
                if !entries.is_empty() && self.poll_now(&entries) {
                    return Ok(());
                }
                Err(self.lwp_park(conds, deadline, OnTimeout::Select(sets, words)))
            }
            "waitpid" | "wait" | "wait3" => {
                let pid = if name == "waitpid" { args[0] as i32 } else { -1 };
                let options = if name == "waitpid" { args[2] } else if name == "wait3" { args[1] } else { 0 };
                if options & 1 != 0 {
                    return Ok(()); // WNOHANG
                }
                let (ty, id) = if pid > 0 {
                    (libc::P_PID, pid as libc::id_t)
                } else if pid < -1 {
                    (libc::P_PGID, (-pid) as libc::id_t)
                } else {
                    (libc::P_ALL, 0)
                };
                if child_ready(ty, id) {
                    return Ok(());
                }
                Err(self.lwp_park(vec![Cond::Child(ty, id)], None, OnTimeout::Default))
            }
            "nanosleep" => {
                let t = ts(self, args[0], 1e9)?;
                let cur = self.threads.cur;
                let l = self.threads.lwps.get_mut(&cur).unwrap();
                l.state = State::Sleep;
                l.key = None;
                l.deadline = Some(now + t);
                l.on_timeout = OnTimeout::Zero;
                Err(self.lwp_block(0, 0))
            }
            "sigtimedwait" | "sigwait" => {
                let wset = SigSet::from_bytes(&self.rd(args[0], 32)?);
                if mask_bits(&wset) & self.poll_signals() != 0 {
                    return Ok(());
                }
                let mut deadline = None;
                if name == "sigtimedwait" && args[2] != 0 {
                    deadline = Some(now + ts(self, args[2], 1e9)?);
                }
                Err(self.lwp_park(vec![Cond::Sig(wset)], deadline, OnTimeout::Eagain))
            }
            _ => Ok(()),
        }
    }

    /// after fork, the child has only the thread that called it
    pub fn lwp_fork_child(&mut self) {
        if self.threads.active() {
            let cur = self.threads.cur;
            self.threads.lwps.retain(|&id, _| id == cur);
        }
    }

    // -- the system calls ----------------------------------------------------------------

    /// _lwp_self(): the running thread's id (1 for a process's first)
    pub fn sys_lwp_self(&mut self, _a: &[u32; 8]) -> SysResult {
        ok(if self.threads.active() { self.threads.cur } else { 1 })
    }

    /// _lwp_getscheduler(which, lwpid, &policy, &param): the time-sharing policy, priority 0
    pub fn sys_lwp_getscheduler(&mut self, a: &[u32; 8]) -> SysResult {
        if a[2] != 0 {
            self.wr32(a[2], SCHED_HPUX)?;
        }
        if a[3] != 0 {
            self.wr32(a[3], 0)?;
        }
        ok(0)
    }

    /// _lwp_create(ucontext, flags, &lwpid, opt): a new thread from the context
    /// _lwp_makecontext prepared; LWP_SUSPENDED leaves it stopped, LWP_DETACHED needs no
    /// _lwp_wait, LWP_INHERIT_SIGMASK gives it the creator's mask
    pub fn sys_lwp_create(&mut self, a: &[u32; 8]) -> SysResult {
        let (ucp, flags, lidp) = (a[0], a[1], a[2]);
        self.lwp_setup();
        let mut ctx = self.ctx_from_ucontext(ucp)?;
        if flags & LWP_INHERIT_SIGMASK != 0 {
            ctx.mask = self.sigmask;
        }
        let id = self.threads.next_id;
        self.threads.next_id += 1;
        let mut t = Lwp::new(id);
        if self.trace {
            emsg!(
                "[{}] -- lwp {} created: pc {:#x} sp {:#x} arg {:#x} cr27 {:#x} r27 {:#x} r19 {:#x} sar {:#x}\n",
                self.pid, id, ctx.iaoq_f & !3, ctx.gr[30], ctx.gr[26], ctx.cr27, ctx.gr[27], ctx.gr[19], ctx.sar
            );
        }
        t.ctx = Some(ctx);
        t.detached = flags & LWP_DETACHED != 0;
        t.suspended = flags & LWP_SUSPENDED != 0;
        self.threads.lwps.insert(id, t);
        if self.threads.lwps.len() == 2 {
            // now the emulator decides which thread a signal goes to: the host catches the
            // signals whose action is the default too (install_host_handler)
            for sig in 1..45 {
                if host_sig(sig) != 0 && self.sigact(sig).handler == 0 {
                    self.install_host_handler(sig, 0);
                }
            }
        }
        if lidp != 0 {
            self.wr32(lidp, id)?;
        }
        ok(0)
    }

    fn lwp_exit_current(&mut self) -> Stop {
        let cur = self.threads.cur;
        if self.threads.lwps[&cur].detached {
            self.threads.lwps.remove(&cur);
        } else {
            let t = self.threads.lwps.get_mut(&cur).unwrap();
            t.state = State::Zombie;
            t.ctx = None;
            // a thread waiting for this one (or for any) takes it
            let joiner = self.threads.lwps.values().find(|t| t.state == State::Join && (t.key == Some(cur) || t.key == Some(0))).map(|t| (t.id, t.departed_p));
            if let Some((jid, dp)) = joiner {
                if dp != 0 {
                    let _ = self.wr32(dp, cur);
                }
                self.threads.lwps.remove(&cur);
                self.lwp_wake(jid, 0, 0);
            }
        }
        if !self.threads.lwps.values().any(|t| t.state != State::Zombie) {
            self.exited = Some(Exited::Exit(0));
            return Stop::Switched;
        }
        if let Some(t) = self.threads.lwps.get_mut(&cur) {
            t.state = State::Zombie;
        }
        self.lwp_block(0, 0)
    }

    /// _lwp_exit(): the running thread ends (the process with its last thread)
    pub fn sys_lwp_exit(&mut self, _a: &[u32; 8]) -> SysResult {
        if self.threads.lwps.len() <= 1 {
            return self.sys_exit(&[0; 8]);
        }
        Err(self.lwp_exit_current())
    }

    /// _lwp_detached_exit(...): a detached thread ends (its stack is the library's)
    pub fn sys_lwp_detached_exit(&mut self, _a: &[u32; 8]) -> SysResult {
        if self.threads.lwps.len() <= 1 {
            return self.sys_exit(&[0; 8]);
        }
        let cur = self.threads.cur;
        self.threads.lwps.get_mut(&cur).unwrap().detached = true;
        Err(self.lwp_exit_current())
    }

    /// _lwp_wait(lwpid, &departed): wait for a thread (0: any) to end
    pub fn sys_lwp_wait(&mut self, a: &[u32; 8]) -> SysResult {
        let (lid, departedp) = (a[0], a[1]);
        self.lwp_setup();
        let cur = self.threads.cur;
        if lid == cur {
            return err(EDEADLK);
        }
        let z = self.threads.lwps.values().find(|t| t.state == State::Zombie && (lid == 0 || t.id == lid) && !t.detached).map(|t| t.id);
        if let Some(z) = z {
            self.threads.lwps.remove(&z);
            if departedp != 0 {
                self.wr32(departedp, z)?;
            }
            return ok(0);
        }
        if lid != 0 && self.threads.lwps.get(&lid).map(|t| t.detached).unwrap_or(true) {
            return err(ESRCH);
        }
        let t = self.threads.lwps.get_mut(&cur).unwrap();
        t.state = State::Join;
        t.key = Some(lid);
        t.departed_p = departedp;
        Err(self.lwp_block(0, 0))
    }

    /// _lwp_detach(lwpid): no _lwp_wait will be made for it
    pub fn sys_lwp_detach(&mut self, a: &[u32; 8]) -> SysResult {
        self.lwp_setup();
        let t = match self.threads.lwps.get_mut(&a[0]) {
            Some(t) => t,
            None => return err(ESRCH),
        };
        t.detached = true;
        if t.state == State::Zombie {
            self.threads.lwps.remove(&a[0]);
        }
        ok(0)
    }

    /// _lwp_kill(lwpid, sig): the signal, to that thread: its handler runs there; a wait
    /// of its (ksleep, a blocked host call) ends with EINTR unless it blocks the signal (a
    /// sigwait for it takes it)
    pub fn sys_lwp_kill(&mut self, a: &[u32; 8]) -> SysResult {
        let (lid, sig) = (a[0], a[1]);
        self.lwp_setup();
        match self.threads.lwps.get(&lid) {
            Some(t) if t.state != State::Zombie => {}
            _ => return err(ESRCH),
        }
        if sig == 0 {
            return ok(0);
        }
        if sig >= 64 {
            return err(EINVAL);
        }
        if lid == self.threads.cur {
            self.pending |= 1 << sig;
            self.threads.tdirected |= 1 << sig;
            return ok(0);
        }
        let ignored = self.sigact(sig).handler == 1;
        let t = self.threads.lwps.get_mut(&lid).unwrap();
        t.tpending |= 1 << sig;
        if t.waiting() {
            if let Some(c) = &t.ctx {
                let blocked = c.mask.has(sig);
                let waits_for = t.state == State::Io && t.conds.iter().any(|c| matches!(c, Cond::Sig(m) if m.has(sig)));
                if waits_for || (!blocked && !ignored) {
                    self.lwp_interrupt(lid);
                }
            }
        }
        ok(0)
    }

    /// _lwp_suspend(lwpid): the thread stops until _lwp_continue
    pub fn sys_lwp_suspend(&mut self, a: &[u32; 8]) -> SysResult {
        self.lwp_setup();
        match self.threads.lwps.get_mut(&a[0]) {
            Some(t) => t.suspended = true,
            None => return err(ESRCH),
        }
        if a[0] == self.threads.cur {
            return Err(self.lwp_block(0, 0));
        }
        ok(0)
    }

    /// _lwp_continue(lwpid), _lwp_resume(lwpid, flags): a suspended thread runs again
    pub fn sys_lwp_continue(&mut self, a: &[u32; 8]) -> SysResult {
        self.lwp_setup();
        match self.threads.lwps.get_mut(&a[0]) {
            Some(t) => t.suspended = false,
            None => return err(ESRCH),
        }
        ok(0)
    }

    /// _lwp_getstate(lwpid, which, &save_state): a thread's registers, as a __save_state
    /// with the narrow registers (ss_flags without SS_WIDEREGS) and the FP block;
    /// libpthread's _pthread_stack_info_np reads a suspended thread's sp there (a Java
    /// VM asks for every thread's stack)
    pub fn sys_lwp_getstate(&mut self, a: &[u32; 8]) -> SysResult {
        use off11::ss_narrow as N;
        let (lid, buf) = (a[0], a[2]);
        self.lwp_setup();
        let me = lid == self.threads.cur;
        let ctx: Box<Ctx> = match self.threads.lwps.get(&lid) {
            Some(t) if t.state != State::Zombie => {
                if me {
                    let c = &self.cpu;
                    Box::new(Ctx { gr: c.gr, fr: c.fr, sar: c.sar, iaoq_f: c.iaoq_f, iaoq_b: c.iaoq_b, psw_n: false, psw_cb: 0, psw_cb_msb: 0, psw_v: 0, cr26: 0, cr27: c.cr[27], mask: self.sigmask })
                } else {
                    match &t.ctx {
                        Some(c) => c.clone(),
                        None => return err(ESRCH),
                    }
                }
            }
            _ => return err(ESRCH),
        };
        let so = off11::save_state::ss_wide;
        let mut out = vec![0u8; so.0 + so.1];
        let narrow = off11::save_state::ss_narrow.0;
        let mut w32 = |o: usize, v: u32| out[o..o + 4].copy_from_slice(&v.to_be_bytes());
        for (i, o) in narrow_regs11().iter().enumerate() {
            w32(narrow + o, ctx.gr[i + 1] as u32);
        }
        w32(narrow + N::ss_cr11.0, ctx.sar as u32);
        w32(narrow + N::ss_pcoq_head.0, ctx.iaoq_f);
        w32(narrow + N::ss_pcoq_tail.0, ctx.iaoq_b);
        w32(narrow + 236, ctx.cr27 as u32);
        let fpb = off11::save_state::ss_fpblock.0;
        for i in 0..32 {
            out[fpb + 8 * i..fpb + 8 * i + 8].copy_from_slice(&ctx.fr[i].to_be_bytes());
        }
        self.wr(buf, &out)?;
        ok(0)
    }

    /// sched_yield(): the other runnable threads run first
    pub fn sys_sched_yield(&mut self, _a: &[u32; 8]) -> SysResult {
        if self.threads.lwps.values().filter(|t| t.state == State::Run && !t.suspended).count() < 2 {
            // no other thread of this process: the other processes, as the kernel would
            // (a JVM spins on time() and sched_yield() while it waits for another program)
            unsafe { libc::sched_yield() };
            return ok(0);
        }
        let cur = self.threads.cur;
        self.threads.lwps.get_mut(&cur).unwrap().state = State::Yield;
        Err(self.lwp_block(0, 0))
    }

    /// ksleep(obj_flag, obj, lock, timeout): release the lock (an ldcw lock of four words)
    /// and sleep on obj until a kwakeup (0), the timeout (ETIMEDOUT) or a signal (EINTR)
    pub fn sys_ksleep(&mut self, a: &[u32; 8]) -> SysResult {
        let (flags, obj, lock, tvp) = (a[0], a[1], a[2], a[3]);
        self.lwp_setup();
        let mut deadline = None;
        if tvp != 0 {
            let d = self.rd(tvp, 8)?;
            let t = be32(&d, 0) as i32 as f64 + be32(&d, 4) as i32 as f64 / 1e9;
            deadline = Some(if flags & RELATIVE_TIMEOUT_VALUE != 0 { host::now_f64() + t } else { t - self.clock_offset as f64 });
        }
        if lock != 0 {
            // the lock is four words, {1,1,1,1} when free: ldcw needs a 16-byte aligned
            // word, which is whichever of the four the library's address rounds up to
            self.wr(lock, &[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1])?;
        }
        let cur = self.threads.cur;
        let t = self.threads.lwps.get_mut(&cur).unwrap();
        t.state = State::Sleep;
        t.key = Some(obj);
        t.deadline = deadline;
        Err(self.lwp_block(0, 0))
    }

    /// kwakeup(obj_flag, obj, WAKEUP_ONE|WAKEUP_ALL, &woken): wake the sleepers on obj
    pub fn sys_kwakeup(&mut self, a: &[u32; 8]) -> SysResult {
        let (obj, wflags, wokenp) = (a[1], a[2], a[3]);
        let mut n = 0u32;
        let ids: Vec<u32> = self.threads.lwps.values().filter(|t| t.state == State::Sleep && t.key == Some(obj)).map(|t| t.id).collect();
        for id in ids {
            self.lwp_wake(id, 0, 0);
            n += 1;
            if wflags & WAKEUP_ALL == 0 {
                break;
            }
        }
        if wokenp != 0 {
            self.wr32(wokenp, n)?;
        }
        ok(0)
    }
}
