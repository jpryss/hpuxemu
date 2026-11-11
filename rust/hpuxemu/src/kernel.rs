//! kernel.rs - running the CPU and answering what it stops for: system calls (the gateway
//! page), faults, the time slice.

use crate::consts::*;
use crate::emsg;
use crate::host::{self, errno_name, signal_name};
use crate::process::*;
use crate::syscalls::{Entry, SYSCALL_TABLE};
use hppa32_jit::Exit;

/// instructions between PC samples with HPUXEMU_STATS
const STATS_CHUNK: u64 = 500_000;

impl Process {
    fn apply_hooks(&mut self) {
        // HPUXEMU_HOOKS=addr,...: log the registers when execution reaches an address
        if let Some(h) = host::getenv("HPUXEMU_HOOKS") {
            let v: Vec<u32> = h.split(',').filter_map(|x| u32::from_str_radix(x.trim().trim_start_matches("0x"), 16).ok()).collect();
            self.cpu.set_hooks(&v);
        }
    }

    pub fn run(&mut self) -> Exited {
        self.apply_hooks();
        loop {
            if let Some(e) = self.exited {
                self.stats_end("exit", false);
                return e;
            }
            if self.poll_signals() != 0 {
                self.deliver_signals(false, false);
                if self.exited.is_some() {
                    continue;
                }
            }
            let r = if self.stats.is_some() {
                let t0 = host::monotonic();
                let r = self.cpu.run(STATS_CHUNK);
                let pc = self.cpu.iaoq_f & !3;
                let st = self.stats.as_mut().unwrap();
                st.run += host::monotonic() - t0;
                st.nrun += 1;
                if r == Exit::Count {
                    // a PC sample every STATS_CHUNK instructions: where the guest's time goes
                    *st.pcs.entry(pc).or_insert(0) += 1;
                }
                r
            } else {
                self.cpu.run(RUN_CHUNK)
            };
            match r {
                Exit::Count => {
                    if self.threads.active() {
                        self.lwp_preempt();
                    }
                }
                Exit::Syscall(pc) => {
                    if pc == GATEWAY + MCAS_OFFSET {
                        self.mcas_util();
                    } else if self.stats.is_some() {
                        let num = self.gr(22);
                        let name = self.entry(num).name;
                        let t0 = host::monotonic();
                        let exec = self.syscall();
                        if let Some(st) = self.stats.as_mut() {
                            let t1 = host::monotonic();
                            let c = st.calls.entry(name).or_insert((0, 0.0));
                            c.0 += 1;
                            c.1 += t1 - t0;
                            if t1 - st.last.unwrap_or(st.t0) > 20.0 {
                                // a snapshot for a process that may never exit
                                self.stats_end("running", true);
                            }
                        }
                        if exec {
                            self.apply_hooks();
                        }
                    } else if self.syscall() {
                        self.apply_hooks();
                    }
                }
                Exit::Hook(pc) => {
                    let r: Vec<String> = (1..32).map(|i| format!("r{}={:x}", i, self.gr(i))).collect();
                    emsg!("hook {:08x}: {}\n", pc, r.join(" "));
                    for i in [26usize, 25, 24, 23] {
                        let a = self.gr(i);
                        if self.cpu.mem.is_mapped(a) {
                            if let Ok(d) = self.rd(a, 32) {
                                emsg!("    r{} -> {:?}\n", i, host::latin1(&d));
                            }
                        }
                    }
                    let _ = self.cpu.step_over();
                }
                Exit::Fault(addr, write, pc) => {
                    if addr >= STACK_BASE && addr < STACK_LIMIT && !self.cpu.mem.is_mapped(addr) {
                        // the stack grows up on demand, to its 8 MB limit
                        let page = addr & !(PAGE - 1);
                        let n = if page + 16 * PAGE <= STACK_LIMIT { 16 * PAGE } else { STACK_LIMIT - page };
                        self.cpu.mem.map(page, n, 7);
                    } else {
                        // HP-UX's trap numbers (machine/trap.h, PA-RISC 1.1): 15 data page
                        // fault (nothing mapped), 18 data memory protection (mapped, access
                        // denied)
                        let mapped = self.cpu.mem.is_mapped(addr);
                        let fault = FaultInfo { addr, write, pc, trap: if mapped { 18 } else { 15 }, mapped };
                        self.fatal(
                            &format!("memory fault at {:#x} ({}) pc {:#x}", addr, if write { "write" } else { "read" }, pc),
                            if addr < 0xC000_0000 { SIGSEGV } else { SIGBUS },
                            Some(fault),
                        );
                    }
                }
                Exit::Illegal(pc, w) => self.fatal(&format!("illegal instruction {:08x} at {:#x}", w, pc), SIGILL, None),
                Exit::Break(a, b, pc) => self.fatal(&format!("break {},{} at {:#x}", a, b, pc), SIGTRAP, None),
                Exit::Priv(pc, w) => self.fatal(&format!("privileged instruction {:08x} at {:#x}", w, pc), SIGILL, None),
                Exit::Trap(pc) | Exit::Overflow(pc) => self.fatal(&format!("conditional trap at {:#x}", pc), SIGFPE, None),
                Exit::Unaligned(addr, pc) => self.fatal(&format!("unaligned ldcw at {:#x} pc {:#x}", addr, pc), SIGBUS, None),
            }
        }
    }

    /// A fault the CPU reported: the signal goes to the program's handler if it has one
    /// (the Bourne shell grows its memory from a SIGSEGV handler), with the context's pc
    /// at the faulting instruction; otherwise the process dies with the signal and a
    /// register dump.
    pub fn fatal(&mut self, msg: &str, sig: u32, fault: Option<FaultInfo>) {
        let handler = self.sigact(sig).handler;
        if handler > 1 && !self.sigmask.has(sig) {
            if self.trace {
                emsg!("[{}] -- {}: {}\n", self.pid, signal_name(sig), msg);
            }
            self.pending |= 1u64 << sig;
            if let Some(f) = fault {
                self.fault_info.insert(sig, f);
            }
            self.deliver_signals(false, false);
            return;
        }
        emsg!("hpuxemu: {}: {}\n", self.argv0, msg);
        self.dump_regs();
        emsg!("  pc={:08x} npc={:08x} sar={:x} icount={}\n", self.cpu.iaoq_f, self.cpu.iaoq_b, self.cpu.sar, self.cpu.icount);
        self.exited = Some(Exited::Signal(sig));
    }

    pub fn entry(&self, num: u32) -> &'static Entry {
        let t = if self.is11 { &SYSCALL_TABLE.1 } else { &SYSCALL_TABLE.0 };
        match t.get(num as usize) {
            Some(Some(e)) => e,
            _ => &crate::syscalls::UNKNOWN,
        }
    }

    /// One system call: r22 the number, the arguments in r26..r23 and at sp-52..-64; the
    /// result in r28 (r29), r22 = 0 or 1 with the errno in r28. True when the call was an
    /// exec (a new image runs).
    pub fn syscall(&mut self) -> bool {
        let num = self.gr(22);
        let ent = self.entry(num);
        let name = ent.name;
        let whence = (self.gr(31), self.gr(2));
        let sp = self.gr(30);
        let mut args = [self.gr(26), self.gr(25), self.gr(24), self.gr(23), 0, 0, 0, 0];
        // the stack arguments at sp-52, -56, -60, -64
        for i in 0..4 {
            match self.cpu.mem.ld32(sp.wrapping_sub(52 + 4 * i)) {
                Ok(v) => args[4 + i as usize] = v,
                Err(_) => {
                    args[4..].fill(0);
                    break;
                }
            }
        }
        if !self.hpcache.is_empty() {
            self.hpcache.clear();
        }
        self.owners_fresh = false;
        let t0 = if self.trace { host::now_f64() } else { 0.0 };
        if ent.blocking && self.poll_signals() != 0 && self.deliver_before_call() {
            return false;
        }
        if ent.thread_wait && self.threads.multi() {
            // several threads: a call that would block the host waits in this thread only
            if let Err(Stop::Switched) = self.lwp_would_block(name, &args) {
                if self.trace {
                    emsg!("[{}] {}({}) waits\n", self.pid, name, hex4(&args));
                }
                if self.exited.is_none() && self.poll_signals() != 0 {
                    self.deliver_signals(false, false);
                }
                return false;
            }
        }
        let res = match ent.f {
            Some(f) => f(self, &args),
            None => {
                emsg!("hpuxemu: unimplemented syscall {}({}) args {}\n", name, num, args[..4].iter().map(|a| format!("{:x}", a)).collect::<Vec<_>>().join(" "));
                err(ENOSYS)
            }
        };
        let mut interrupted = false;
        let (r, e, ret2) = match res {
            Ok(Ret(r, r2)) => (r, 0, r2),
            Err(Stop::Errno(e)) => {
                if e == EAGAIN && self.nbmode.contains_key(&args[0]) {
                    let (r, e) = self.nb_result(name, args[0], e);
                    (r, e, None)
                } else {
                    (e, 1, None)
                }
            }
            Err(Stop::Interrupted) => {
                // a signal arrived during a blocking call: EINTR now; deliver_signals
                // decides whether the handler's SA_RESTART turns that into a restart
                self.poll_signals();
                interrupted = ent.restartable;
                (EINTR, 1, None)
            }
            Err(Stop::InterruptedWithMask(mask)) => {
                // sigsuspend: return EINTR with the mask restored, after the handler runs
                // with the temporary mask (the frame carries the one to restore)
                self.set_gr(28, EINTR);
                self.set_gr(22, 1);
                self.cpu.set_pc(self.gr(31));
                self.deliver_signals(false, false);
                // the frame's saved mask is the sigsuspend one; the mask after the
                // handler must be the original
                self.fix_frame_mask(mask);
                return false;
            }
            Err(Stop::NoReturn) => {
                if self.trace {
                    emsg!("[{}] {}(...)\n", self.pid, name);
                }
                return false;
            }
            Err(Stop::Switched) => {
                // the thread blocked (or ended) and another runs: its registers are loaded
                if self.trace {
                    emsg!("[{}] {}({}) blocks\n", self.pid, name, hex4(&args));
                }
                if self.exited.is_none() && self.poll_signals() != 0 {
                    self.deliver_signals(false, false);
                }
                return false;
            }
            Err(Stop::Exec) => return true,
        };
        if self.trace {
            self.trace_call(name, &args, r, e, ret2, t0, whence);
        }
        if self.exited.is_some() {
            return false;
        }
        self.set_gr(28, r);
        self.set_gr(22, e);
        if let Some(r2) = ret2 {
            self.set_gr(29, r2);
        }
        self.cpu.set_pc(self.gr(31));
        if interrupted || self.poll_signals() != 0 {
            self.deliver_signals(interrupted, false);
        }
        false
    }

    fn trace_call(&mut self, name: &str, args: &[u32; 8], r: u32, e: u32, ret2: Option<u32>, t0: f64, whence: (u32, u32)) {
        let mut shown: Vec<String> = args[..4].iter().map(|a| format!("{:#x}", a)).collect();
        // the arguments the trace shows as strings
        let paths: &[usize] = match name {
            "open" | "creat" | "stat" | "lstat" | "stat64" | "lstat64" | "access" | "chdir" | "unlink" | "execve" | "execv" | "readlink"
            | "chmod" | "chown" | "mkdir" | "rmdir" | "utime" | "truncate" | "statfs" | "statvfs" | "pathconf" | "mknod" | "lchown" => &[0],
            "link" | "symlink" | "rename" => &[0, 1],
            "write" => &[1],
            _ => &[],
        };
        for &k in paths {
            if let Ok(s) = self.rdstr_n(args[k], 200) {
                shown[k] = pyrepr(&s);
            }
        }
        if matches!(name, "connect" | "bind") {
            shown[1] = self.sockaddr_str(args[1], args[2]);
        } else if name == "sendto" {
            shown[1] = self.sockaddr_str(args[4], args[5]);
        }
        let t1 = host::now_f64();
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let tt = t1 as libc::time_t;
        unsafe { libc::localtime_r(&tt, &mut tm) };
        emsg!(
            "{:02}:{:02}:{:02}.{:03} [{}] {}({}) = {}{}{}\n",
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            (t1 * 1000.0) as u64 % 1000,
            self.pid,
            name,
            shown.join(", "),
            if e != 0 { format!("error {}", errno_name(r)) } else { format!("{:#x}", r) },
            match ret2 {
                Some(v) => format!(" r29={:#x}", v),
                None => String::new(),
            },
            if t1 - t0 >= 0.05 { format!(" <{:.3}s>", t1 - t0) } else { String::new() }
        );
        if host::getenv("HPUXEMU_TRACE_PC").map(|v| !v.is_empty()).unwrap_or(false) {
            // HPUXEMU_TRACE_PC: where the call came from - the system call stub (r31, the
            // gateway's return) and the stub's caller (r2)
            emsg!("    from {:08x}, called from {:08x}\n", whence.0, whence.1);
        }
    }
}

fn hex4(args: &[u32; 8]) -> String {
    args[..4].iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>().join(", ")
}

/// a string as Python's repr() shows it (the trace's format)
pub fn pyrepr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut o = String::new();
    o.push(q);
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if c == q => {
                o.push('\\');
                o.push(c);
            }
            c if (c as u32) < 0x20 || (c as u32) == 0x7F || ((c as u32) >= 0x80 && (c as u32) < 0xA1) || (c as u32) == 0xAD => {
                o.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => o.push(c),
        }
    }
    o.push(q);
    o
}
