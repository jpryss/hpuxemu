//! signals.rs - HP-UX signals: the mask, the handlers' frames, the calls.
//!
//! Delivery (docs/ABI.md "Signals"): the kernel pushes a struct sigcontext on the stack
//! (the stack grows up, so above sp), whose last 48 bytes are the handler's argument spill
//! area and frame marker, calls handler(sig, code, scp) with rp = the return routine libc
//! registered with sigsetreturn (libc's _sigreturn, which makes the sigcleanup system
//! call), and sigcleanup restores the context found through the frame marker's
//! previous-sp word at sp-4.

use crate::consts::*;
use crate::emsg;
use crate::host::{self, guest_sig, host_sig, signal_name};
use crate::process::*;

/// A 256-bit sigset_t: word (sig-1)/32 of the 8 words, bit (sig-1)%32 in that word.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SigSet(pub [u32; 8]);

impl SigSet {
    pub fn has(&self, sig: u32) -> bool {
        sig >= 1 && sig <= 256 && self.0[((sig - 1) / 32) as usize] & (1 << ((sig - 1) % 32)) != 0
    }
    pub fn add(&mut self, sig: u32) {
        if sig >= 1 && sig <= 256 {
            self.0[((sig - 1) / 32) as usize] |= 1 << ((sig - 1) % 32);
        }
    }
    pub fn del(&mut self, sig: u32) {
        if sig >= 1 && sig <= 256 {
            self.0[((sig - 1) / 32) as usize] &= !(1 << ((sig - 1) % 32));
        }
    }
    pub fn or(&mut self, o: &SigSet) {
        for i in 0..8 {
            self.0[i] |= o.0[i];
        }
    }
    pub fn andnot(&mut self, o: &SigSet) {
        for i in 0..8 {
            self.0[i] &= !o.0[i];
        }
    }
    pub fn full() -> SigSet {
        let mut s = SigSet([0xFFFF_FFFF; 8]);
        s.del(SIGKILL);
        s.del(SIGSTOP);
        s
    }
    pub fn from_bytes(b: &[u8]) -> SigSet {
        let mut s = SigSet::default();
        for i in 0..8 {
            s.0[i] = be32(b, 4 * i);
        }
        s
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for i in 0..8 {
            b[4 * i..4 * i + 4].copy_from_slice(&self.0[i].to_be_bytes());
        }
        b
    }
    pub fn word0(w: u32) -> SigSet {
        let mut s = SigSet::default();
        s.0[0] = w;
        s
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SigAct {
    pub handler: u32,
    pub mask: SigSet,
    pub flags: u32,
}

/// signals whose default action is to ignore them
pub fn default_ignore(sig: u32) -> bool {
    matches!(sig, SIGCHLD | SIGWINCH | SIGURG | SIGCONT | SIGPWR | SIGIO)
}
/// those that stop the process
pub fn stops(sig: u32) -> bool {
    matches!(sig, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

const SC_MASK_OFF: usize = off::siglocalx::sl_uc.0 + off::ucontext::uc_subcontext.0 + off::sub_ctxt::__uc_sigmask.0;
const SS_OFF: usize = off::siglocal::sl_ss.0;
const NARROW_OFF: usize = SS_OFF + off::save_state::ss_narrow.0;
const FP_OFF: usize = SS_OFF + off::save_state::ss_fpblock.0;
const XOR_OFF: usize = SS_OFF + off::save_state::ss_xor.0;
const SC_MAGIC: &[u8; 16] = b"hpuxemu sigctx 1";

/// where gr1..gr31 are in the narrow save state (10.20's and 11.00's layouts agree here)
pub fn narrow_regs() -> [usize; 31] {
    use off::ss_narrow as N;
    [
        N::ss_gr1.0, N::ss_rp.0, N::ss_gr3.0, N::ss_gr4.0, N::ss_gr5.0, N::ss_gr6.0, N::ss_gr7.0, N::ss_gr8.0, N::ss_gr9.0, N::ss_gr10.0,
        N::ss_gr11.0, N::ss_gr12.0, N::ss_gr13.0, N::ss_gr14.0, N::ss_gr15.0, N::ss_gr16.0, N::ss_gr17.0, N::ss_gr18.0, N::ss_gr19.0,
        N::ss_gr20.0, N::ss_gr21.0, N::ss_gr22.0, N::ss_arg3.0, N::ss_arg2.0, N::ss_arg1.0, N::ss_arg0.0, N::ss_dp.0, N::ss_ret0.0,
        N::ss_ret1.0, N::ss_sp.0, N::ss_gr31.0,
    ]
}

fn w32(f: &mut [u8], off: usize, v: u32) {
    f[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

impl Process {
    pub fn sigact(&self, sig: u32) -> SigAct {
        self.sigactions.get(&sig).copied().unwrap_or_default()
    }

    pub fn install_host_handler(&mut self, sig: u32, handler: u32) {
        let h = host_sig(sig);
        if h == 0 || h == libc::SIGKILL || h == libc::SIGSTOP {
            return;
        }
        if handler == 1 || (handler == 0 && h == libc::SIGIO) {
            // SIGPOLL's default ignores it; the host's default for SIGIO would end the
            // process when a stream's connection signals. (Not for SIGCHLD, whose SIG_IGN
            // on the host would reap the children: wait gets ECHILD.)
            host::host_signal_set(h, 1);
        } else if handler == 0 && !self.threads.multi() {
            host::host_signal_set(h, 0);
        } else {
            // (with several threads a default action is taken by deliver_signals too: the
            // thread that gets the signal is the emulator's choice, and a thread blocking
            // it - one waiting in sigwait - must not see the host act first)
            host::host_signal_set(h, 2);
        }
    }

    /// the host signals that arrived since the last look become pending guest signals
    pub fn poll_signals(&mut self) -> u64 {
        let mut hp = host::take_host_pending();
        while hp != 0 {
            let h = hp.trailing_zeros() as i32;
            hp &= hp - 1;
            if h == libc::SIGCHLD && !host::chld_is_news() {
                continue;
            }
            let g = guest_sig(h);
            if g != 0 && g < 64 {
                self.pending |= 1u64 << g;
            }
        }
        self.pending
    }

    pub fn pending_list(&self) -> Vec<u32> {
        let mut v = Vec::new();
        let mut p = self.pending;
        while p != 0 {
            v.push(p.trailing_zeros());
            p &= p - 1;
        }
        v
    }

    /// a pending signal that deliver_signals would act on now
    pub fn deliverable(&self, sig: u32) -> bool {
        if self.sigmask.has(sig) {
            return false;
        }
        let h = self.sigact(sig).handler;
        !(h == 1 || (h == 0 && default_ignore(sig)))
    }

    pub fn any_deliverable(&self) -> bool {
        self.pending != 0 && self.pending_list().iter().any(|&s| self.deliverable(s))
    }

    /// A deliverable signal pending as a blocking call begins: its handler runs first and
    /// the call is made again after it (the frame returns to the gateway with r22 and the
    /// arguments as they are now). False when no handler frame was pushed (a default
    /// action that did not end the process): the call goes ahead.
    pub fn deliver_before_call(&mut self) -> bool {
        if !self.any_deliverable() {
            return false;
        }
        let before = (self.cpu.iaoq_f, self.cpu.iaoq_b);
        self.deliver_signals(true, true);
        self.exited.is_some() || (self.cpu.iaoq_f, self.cpu.iaoq_b) != before
    }

    /// Deliver the pending signals the mask allows, one frame each (a handler runs with
    /// its signal and sa_mask blocked, and the next deliverable signal is handled when it
    /// returns). `restartable`: the CPU is at a syscall return with EINTR.
    pub fn deliver_signals(&mut self, restartable: bool, force_restart: bool) {
        self.poll_signals();
        for sig in self.pending_list() {
            if self.sigmask.has(sig) && sig != SIGKILL && sig != SIGSTOP {
                continue;
            }
            self.pending &= !(1u64 << sig);
            let act = self.sigact(sig);
            if act.handler == 1 || (act.handler == 0 && default_ignore(sig)) {
                continue;
            }
            if act.handler == 0 {
                // the default action: stop or die with the signal
                if stops(sig) {
                    let mut h = host_sig(sig);
                    if h == 0 {
                        h = libc::SIGSTOP;
                    }
                    host::host_signal_set(h, 0);
                    unsafe { libc::kill(self.pid as i32, h) };
                    continue;
                }
                self.exited = Some(Exited::Signal(sig));
                return;
            }
            let restart = (act.flags & SA_RESTART != 0 && restartable) || force_restart;
            let fault = self.fault_info.remove(&sig);
            let code = fault.map(|f| f.trap).unwrap_or(0);
            if self.push_signal_frame(sig, code, act.handler, restart, fault, act.flags & SA_SIGINFO != 0).is_err() {
                // no room for the frame (the stack pointer is wild): the process dies
                // with the signal, as HP-UX kills it when the frame cannot be written
                emsg!("hpuxemu: {}: cannot deliver {}: no stack for its frame (sp {:#x})\n", self.argv0, signal_name(sig), self.gr(30));
                self.dump_regs();
                emsg!("  pc={:08x} npc={:08x}\n", self.cpu.iaoq_f, self.cpu.iaoq_b);
                self.exited = Some(Exited::Signal(sig));
                return;
            }
            if act.flags & SA_RESETHAND != 0 {
                self.sigactions.insert(sig, SigAct::default());
                self.install_host_handler(sig, 0);
            }
            if act.flags & SA_NODEFER == 0 {
                self.sigmask.add(sig);
            }
            self.sigmask.or(&act.mask);
            return;
        }
    }

    pub fn dump_regs(&self) {
        let r: Vec<String> = (1..32).map(|i| format!("r{}={:08x}", i, self.gr(i))).collect();
        emsg!("  {}\n", r.join(" "));
    }

    /// Build the signal frame and call handler(sig, code, scp). For a CPU fault, code is
    /// HP-UX's trap number and the saved interruption registers say what faulted: iir
    /// (cr19) the instruction, isr (cr20) the space, ior (cr21) the address - what a
    /// program that pages its own memory reads to decide whether the fault
    /// is one of its own. An SA_SIGINFO handler gets a siginfo_t (si_code
    /// SEGV_MAPERR/SEGV_ACCERR, si_addr the address) in place of code.
    fn push_signal_frame(&mut self, sig: u32, code: u32, handler: u32, restart: bool, fault: Option<FaultInfo>, siginfo: bool) -> Res<()> {
        use off::siginfo_t as SI;
        use off::ss_narrow as N;
        let mut sp = self.gr(30);
        let size = off::sigcontext::SIZE;
        let mut info = vec![0u8; SI::SIZE];
        let mut sip = 0;
        if siginfo {
            // the siginfo_t first, then the frame above it (the stack grows up, and the
            // frame marker must end just below the handler's sp)
            w32(&mut info, 0, sig);
            if let Some(f) = &fault {
                let sc = if sig == SIGSEGV {
                    if f.mapped { 109 } else { 108 } // SEGV_ACCERR / SEGV_MAPERR
                } else {
                    111 // BUS_ADRERR
                };
                w32(&mut info, SI::si_code.0, sc);
                w32(&mut info, SI::si_addr.0, f.addr);
            } else if let Some(v) = self.sigvalues.remove(&sig) {
                // sigqueue's: SI_QUEUE and the value
                w32(&mut info, SI::si_code.0, -2i32 as u32);
                w32(&mut info, SI::si_value.0, v);
            } else {
                w32(&mut info, SI::si_code.0, -1i32 as u32); // SI_USER
            }
            sip = (sp + 7) & !7;
            sp = sip + info.len() as u32;
        }
        let newsp = (sp + size as u32 + 63) & !63;
        let scp = newsp - size as u32;
        if !self.cpu.mem.is_mapped(newsp - 1) {
            self.fatal(&format!("no room for a signal frame at {:#x}", sp), SIGSEGV, None);
            return Ok(());
        }
        let mut f = vec![0u8; size];
        // siglocal_misc
        use off::siglocal_misc as SM;
        if restart {
            w32(&mut f, SM::sm_syscall.0, self.gr(22));
            f[SM::sm_syscall_action.0] = SIG_RESTART as u8;
        } else {
            f[SM::sm_syscall_action.0] = SIG_RETURN as u8;
        }
        w32(&mut f, SM::sm_omask.0, self.sigmask.0[0]);
        w32(&mut f, SM::sm_rval1.0, self.gr(28));
        w32(&mut f, SM::sm_rval2.0, self.gr(29));
        // save_state: flags, the narrow registers, the FP registers
        w32(&mut f, SS_OFF, if restart { SS_INSYSCALL } else { 0 });
        let base = NARROW_OFF;
        for (i, o) in narrow_regs().iter().enumerate() {
            w32(&mut f, base + o, self.gr(i + 1));
        }
        w32(&mut f, base + N::ss_cr11.0, self.cpu.sar as u32);
        if restart {
            // back to the gateway with r22 and the arguments intact: the call is remade
            w32(&mut f, base + N::ss_pcoq_head.0, GATEWAY + 4);
            w32(&mut f, base + N::ss_pcoq_tail.0, GATEWAY + 8);
        } else {
            w32(&mut f, base + N::ss_pcoq_head.0, self.cpu.iaoq_f);
            w32(&mut f, base + N::ss_pcoq_tail.0, self.cpu.iaoq_b);
        }
        w32(&mut f, base + N::ss_cr22.0, self.ipsw());
        if let Some(fi) = &fault {
            let iir = self.cpu.mem.ld32(fi.pc & !3).unwrap_or(0);
            w32(&mut f, base + N::ss_cr19.0, iir);
            w32(&mut f, base + N::ss_cr20.0, 0);
            w32(&mut f, base + N::ss_cr21.0, fi.addr);
        }
        w32(&mut f, base + N::ss_sr7.0, 0);
        for i in 0..32 {
            f[FP_OFF + 8 * i..FP_OFF + 8 * i + 8].copy_from_slice(&self.cpu.fr[i].to_be_bytes());
        }
        // the CPU state the architected words do not hold, in the reserved area
        f[XOR_OFF..XOR_OFF + 16].copy_from_slice(SC_MAGIC);
        f[XOR_OFF + 16..XOR_OFF + 24].copy_from_slice(&self.cpu.psw_cb.to_be_bytes());
        f[XOR_OFF + 24..XOR_OFF + 32].copy_from_slice(&(self.cpu.psw_cb_msb & 1).to_be_bytes());
        f[XOR_OFF + 32..XOR_OFF + 40].copy_from_slice(&self.cpu.psw_v.to_be_bytes());
        f[XOR_OFF + 40] = self.cpu.psw_n as u8;
        // the old mask where sc_mask is (the ucontext view)
        f[SC_MASK_OFF..SC_MASK_OFF + 32].copy_from_slice(&self.sigmask.to_bytes());
        // the handler's arguments as spilled by a caller (arg3 lowest), the frame marker
        let args_off = off::sigcontext::sc_args.0;
        w32(&mut f, args_off + 12, sig);
        w32(&mut f, args_off + 8, code);
        w32(&mut f, args_off + 4, scp);
        let fm = off::sigcontext::sc_sfm.0;
        w32(&mut f, fm + off::frame_marker::fm_psp.0, scp);
        // a handler reached through an export stub returns via the frame marker's RP'
        // slot (-24(sp)) rather than r2: both hold the return routine
        w32(&mut f, fm + off::frame_marker::fm_erp.0, self.sigreturn_addr);
        w32(&mut f, fm + off::frame_marker::fm_crp.0, self.sigreturn_addr);
        let mut code = code;
        if siginfo {
            w32(&mut f, args_off + 8, sip);
            self.wr(scp, &f)?;
            self.wr(sip, &info)?;
            code = sip;
        } else {
            self.wr(scp, &f)?;
        }
        // call the handler
        let (target, gp) = self.resolve_plabel(handler);
        self.set_gr(30, newsp);
        self.set_gr(26, sig);
        self.set_gr(25, code);
        self.set_gr(24, scp);
        self.set_gr(2, self.sigreturn_addr);
        if let Some(gp) = gp {
            self.set_gr(19, gp);
        }
        self.cpu.set_pc(target);
        if self.trace {
            emsg!("[{}] -- signal {} delivered: handler {:#x} frame {:#x}{}\n", self.pid, signal_name(sig), target, scp, if restart { " (restart)" } else { "" });
        }
        Ok(())
    }

    /// After sigsuspend delivered a signal, the frame on the stack must restore the mask
    /// from before sigsuspend, not the temporary one.
    pub fn fix_frame_mask(&mut self, mask: SigSet) {
        let sp = self.gr(30);
        if let Ok(scp) = self.cpu.mem.ld32(sp.wrapping_sub(4)) {
            if let Ok(m) = self.rd(scp.wrapping_add(XOR_OFF as u32), 16) {
                if m == SC_MAGIC {
                    if self.wr(scp + SC_MASK_OFF as u32, &mask.to_bytes()).is_ok() {
                        return;
                    }
                }
            }
        }
        self.sigmask = mask;
    }

    /// A function pointer in a dynamically linked program is a plabel (bit 1 set): the
    /// address of {entry, gp}; a plain address otherwise.
    pub fn resolve_plabel(&self, addr: u32) -> (u32, Option<u32>) {
        if addr & 2 != 0 {
            if let (Ok(e), Ok(gp)) = (self.cpu.mem.ld32(addr & !3), self.cpu.mem.ld32((addr & !3).wrapping_add(4))) {
                return (e, Some(gp));
            }
        }
        (addr & !3, None)
    }

    /// The PSW as a program sees it: the carry/borrow bits 8..15 from psw_cb
    fn ipsw(&self) -> u32 {
        let cb = self.cpu.psw_cb as u32;
        let mut bits = 0u32;
        for i in 0..8 {
            // C/B bit i is the carry out of nibble i (nibble 0 the most significant)
            let carry = if i == 0 { (self.cpu.psw_cb_msb & 1) as u32 } else { (cb >> (32 - 4 * i)) & 1 };
            if carry != 0 {
                bits |= 1 << (7 - i);
            }
        }
        0x0004_000F | (bits << 16)
    }

    // ---- the calls ----

    /// sigaction(sig, act, oact): install a handler (sa_handler, sa_mask[8], sa_flags)
    pub fn sys_sigaction(&mut self, a: &[u32; 8]) -> SysResult {
        let (sig, act, oact) = (a[0], a[1], a[2]);
        if sig < 1 || sig >= 64 {
            return err(EINVAL);
        }
        let old = self.sigact(sig);
        if oact != 0 {
            let mut b = Pk::new(off::sigaction::SIZE);
            b.put(off::sigaction::sa_handler, old.handler as u64);
            b.bytes(off::sigaction::sa_mask, &old.mask.to_bytes());
            b.put(off::sigaction::sa_flags, old.flags as u64);
            self.wr(oact, &b.0)?;
        }
        if act != 0 {
            if sig == SIGKILL || sig == SIGSTOP {
                return err(EINVAL);
            }
            let d = self.rd(act, off::sigaction::SIZE)?;
            let handler = be32(&d, 0);
            let mask = SigSet::from_bytes(&d[4..36]);
            let flags = be32(&d, 36);
            if self.trace {
                emsg!("[{}]    sigaction: handler {:#x} flags {:#x}\n", self.pid, handler, flags);
            }
            self.sigactions.insert(sig, SigAct { handler, mask, flags });
            self.install_host_handler(sig, handler);
        }
        ok(0)
    }

    /// sigvector(sig, vec, ovec): the BSD-style call; sv_mask is one word, SV_RESETHAND
    /// and SV_ONSTACK map to the sigaction flags, the call is not restarted
    pub fn sys_sigvector(&mut self, a: &[u32; 8]) -> SysResult {
        let (sig, vec, ovec) = (a[0], a[1], a[2]);
        if sig < 1 || sig >= 64 {
            return err(EINVAL);
        }
        let old = self.sigact(sig);
        if ovec != 0 {
            let mut b = [0u8; 12];
            w32(&mut b, 0, old.handler);
            w32(&mut b, 4, old.mask.0[0]);
            w32(&mut b, 8, old.flags & 0xFF);
            self.wr(ovec, &b)?;
        }
        if vec != 0 {
            if sig == SIGKILL || sig == SIGSTOP {
                return err(EINVAL);
            }
            let d = self.rd(vec, 12)?;
            let (handler, mask, flags) = (be32(&d, 0), be32(&d, 4), be32(&d, 8));
            if self.trace {
                emsg!("[{}]    sigvector: handler {:#x} mask {:#x} flags {:#x}\n", self.pid, handler, mask, flags);
            }
            self.sigactions.insert(sig, SigAct { handler, mask: SigSet::word0(mask), flags: flags & 0xFF });
            self.install_host_handler(sig, handler);
        }
        ok(0)
    }

    /// sigcleanup(scp): return from a handler; the context is the sigcontext the frame
    /// marker at sp-4 points to (the argument is the caller's r28, not to be trusted)
    pub fn sys_sigcleanup(&mut self, a: &[u32; 8]) -> SysResult {
        use off::ss_narrow as N;
        let sp = self.gr(30);
        let ctx = self.cpu.mem.ld32(sp.wrapping_sub(4)).unwrap_or(a[0]);
        let f = self.rd(ctx, off::sigcontext::SIZE)?;
        if &f[XOR_OFF..XOR_OFF + 16] != SC_MAGIC {
            return err(EINVAL);
        }
        let base = NARROW_OFF;
        for (i, o) in narrow_regs().iter().enumerate() {
            self.cpu.gr[i + 1] = be32(&f, base + o) as u64;
        }
        self.cpu.sar = be32(&f, base + N::ss_cr11.0) as u64;
        for i in 0..32 {
            self.cpu.fr[i] = be64(&f, FP_OFF + 8 * i);
        }
        self.cpu.psw_cb = be64(&f, XOR_OFF + 16);
        self.cpu.psw_cb_msb = be64(&f, XOR_OFF + 24);
        self.cpu.psw_v = be64(&f, XOR_OFF + 32);
        self.sigmask = SigSet::from_bytes(&f[SC_MASK_OFF..SC_MASK_OFF + 32]);
        let (head, tail) = (be32(&f, base + N::ss_pcoq_head.0), be32(&f, base + N::ss_pcoq_tail.0));
        self.cpu.iaoq_f = head | 3;
        self.cpu.iaoq_b = tail | 3;
        self.cpu.psw_n = f[XOR_OFF + 40] == 1 && !(head >= GATEWAY && head < GATEWAY + 0x1000);
        if self.trace {
            emsg!("[{}] -- sigcleanup: back at {:#x}\n", self.pid, head);
        }
        Err(Stop::NoReturn)
    }

    /// sigstack(ss, oss): the alternate signal stack is recorded and reported back, never
    /// used - handlers run on the normal stack (portmap, rpc.* call it)
    pub fn sys_sigstack(&mut self, a: &[u32; 8]) -> SysResult {
        if a[1] != 0 {
            let mut b = [0u8; 8];
            w32(&mut b, 0, self.sigstack_rec.0);
            w32(&mut b, 4, self.sigstack_rec.1);
            self.wr(a[1], &b)?;
        }
        if a[0] != 0 {
            let d = self.rd(a[0], 8)?;
            self.sigstack_rec = (be32(&d, 0), be32(&d, 4));
        }
        ok(0)
    }

    /// sigaltstack(ss, oss): as sigstack, with stack_t {ss_sp, ss_flags, ss_size};
    /// SS_DISABLE reported when none was set
    pub fn sys_sigaltstack(&mut self, a: &[u32; 8]) -> SysResult {
        if a[1] != 0 {
            let mut b = [0u8; 12];
            w32(&mut b, 0, self.sigaltstack_rec.0);
            w32(&mut b, 4, self.sigaltstack_rec.1);
            w32(&mut b, 8, self.sigaltstack_rec.2);
            self.wr(a[1], &b)?;
        }
        if a[0] != 0 {
            let d = self.rd(a[0], 12)?;
            self.sigaltstack_rec = (be32(&d, 0), be32(&d, 4), be32(&d, 8));
        }
        ok(0)
    }

    /// sigsetreturn(addr, magic, size): libc registers its _sigreturn routine (a plabel in
    /// dynamic programs) as where signal handlers return to; size is sizeof(sigcontext)
    pub fn sys_sigsetreturn(&mut self, a: &[u32; 8]) -> SysResult {
        self.sigreturn_addr = self.resolve_plabel(a[0]).0;
        ok(0)
    }

    /// sigprocmask(how, set, oset): the mask is a 256-bit sigset_t
    pub fn sys_sigprocmask(&mut self, a: &[u32; 8]) -> SysResult {
        let (how, set, oset) = (a[0], a[1], a[2]);
        if oset != 0 {
            self.wr(oset, &self.sigmask.to_bytes())?;
        }
        if set != 0 {
            let m = SigSet::from_bytes(&self.rd(set, 32)?);
            if how == SIG_BLOCK {
                self.sigmask.or(&m);
            } else if how == SIG_UNBLOCK {
                self.sigmask.andnot(&m);
            } else if how == SIG_SETMASK {
                self.sigmask = m;
            } else {
                return err(EINVAL);
            }
            self.sigmask.del(SIGKILL);
            self.sigmask.del(SIGSTOP);
        }
        ok(0)
    }

    /// siginhibit(p) (11.00): dld.sl's cheap way to keep signals out of its critical
    /// sections; every maskable signal is held until the matching sigenable()
    pub fn sys_siginhibit(&mut self, _a: &[u32; 8]) -> SysResult {
        self.inhibit.push(self.sigmask);
        self.sigmask = SigSet::full();
        ok(0)
    }

    /// sigenable() (11.00): the mask from before the matching siginhibit() again
    pub fn sys_sigenable(&mut self, _a: &[u32; 8]) -> SysResult {
        if let Some(m) = self.inhibit.pop() {
            self.sigmask = m;
        }
        ok(0)
    }

    /// sigsetstatemask(mask): used by siglongjmp; sets the first mask word, returns the old
    pub fn sys_sigsetstatemask(&mut self, a: &[u32; 8]) -> SysResult {
        let old = self.sigmask.0[0];
        self.sigmask.0[0] = a[0];
        ok(old)
    }

    /// sigpending(set): the signals received but blocked
    pub fn sys_sigpending(&mut self, a: &[u32; 8]) -> SysResult {
        self.poll_signals();
        let mut m = SigSet::default();
        for s in self.pending_list() {
            m.add(s);
        }
        self.wr(a[0], &m.to_bytes())?;
        ok(0)
    }

    /// sigblock(mask): adds the one-word mask (signals 1-32) to the blocked set; returns
    /// the old word
    pub fn sys_sigblock(&mut self, a: &[u32; 8]) -> SysResult {
        let old = self.sigmask.0[0];
        self.sigmask.0[0] |= a[0];
        ok(old)
    }

    /// sigsetmask(mask): sets the first word of the blocked set; returns the old word
    pub fn sys_sigsetmask(&mut self, a: &[u32; 8]) -> SysResult {
        let old = self.sigmask.0[0];
        self.sigmask.0[0] = a[0];
        ok(old)
    }

    /// sigsuspend(set): wait with that mask for a signal; the mask is restored when the
    /// handler returns (it is in the frame); always EINTR
    pub fn sys_sigsuspend(&mut self, a: &[u32; 8]) -> SysResult {
        let m = SigSet::from_bytes(&self.rd(a[0], 32)?);
        self.wait_for_signal(m)
    }

    /// sigpause(mask): the one-word form of sigsuspend
    pub fn sys_sigpause(&mut self, a: &[u32; 8]) -> SysResult {
        self.wait_for_signal(SigSet::word0(a[0]))
    }

    fn wait_for_signal(&mut self, mask: SigSet) -> SysResult {
        let saved = self.sigmask;
        self.sigmask = mask;
        loop {
            self.poll_signals();
            if self.any_deliverable() {
                break;
            }
            self.host_pause();
        }
        // the frame built by deliver_signals holds the mask to restore; the EINTR return
        // is the context the handler returns to
        Err(Stop::InterruptedWithMask(saved))
    }

    /// Wait for a host signal without losing a wake-up: the host handler only records a
    /// signal, so one that arrives between "is anything pending?" and the blocking call
    /// would be slept through. The host's signals are blocked over the check, and
    /// sigsuspend unblocks them atomically.
    pub fn host_pause(&mut self) {
        let old = host::block_all();
        self.poll_signals();
        if !self.any_deliverable() {
            unsafe { libc::sigsuspend(&old) };
        }
        host::restore_mask(&old);
    }

    /// poll(2) over (fd, events); the revents (EINTR: Stop::Interrupted). timeout_ms < 0:
    /// no timeout.
    pub fn host_poll(&mut self, entries: &[(i32, i16)], timeout_ms: i64) -> Res<Vec<i16>> {
        let mut fds: Vec<libc::pollfd> = entries.iter().map(|&(fd, ev)| libc::pollfd { fd, events: ev, revents: 0 }).collect();
        let old = host::block_all();
        self.poll_signals();
        if self.any_deliverable() {
            host::restore_mask(&old);
            return Err(Stop::Interrupted);
        }
        let ts = libc::timespec { tv_sec: (timeout_ms / 1000) as libc::time_t, tv_nsec: ((timeout_ms % 1000) * 1_000_000) as libc::c_long };
        let r = unsafe { libc::ppoll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, if timeout_ms < 0 { std::ptr::null() } else { &ts }, &old) };
        let e = host::errno();
        host::restore_mask(&old);
        if r < 0 {
            if e == libc::EINTR {
                return Err(Stop::Interrupted);
            }
            return Err(herrno(e));
        }
        Ok(fds.iter().map(|f| f.revents).collect())
    }

    /// sigtimedwait(set, info, timeout): take one of the signals in set (they are blocked)
    /// when it is pending, without running a handler; returns its number and fills info.
    /// A deliverable signal outside the set interrupts (EINTR); the timeout (a timespec,
    /// none = forever) runs out with EAGAIN. 11.00's sh waits for its children this way.
    pub fn sys_sigtimedwait(&mut self, a: &[u32; 8]) -> SysResult {
        let (set, info, timeout) = (a[0], a[1], a[2]);
        let wset = SigSet::from_bytes(&self.rd(set, 32)?);
        let mut deadline = None;
        if timeout != 0 {
            let d = self.rd(timeout, 8)?;
            deadline = Some(host::now_f64() + be32(&d, 0) as i32 as f64 + be32(&d, 4) as i32 as f64 / 1e9);
        }
        loop {
            self.poll_signals();
            if let Some(g) = self.pending_list().into_iter().find(|&g| wset.has(g)) {
                self.pending &= !(1u64 << g);
                if info != 0 {
                    let mut b = Pk::new(off::siginfo_t::SIZE);
                    b.put(off::siginfo_t::si_signo, g as u64);
                    b.put(off::siginfo_t::si_code, 0); // SI_USER
                    self.wr(info, &b.0)?;
                }
                return ok(g);
            }
            if self.any_deliverable() {
                return err(EINTR);
            }
            if let Some(d) = deadline {
                let left = d - host::now_f64();
                if left <= 0.0 {
                    return err(EAGAIN);
                }
                let t = left.min(0.02);
                let ts = libc::timespec { tv_sec: 0, tv_nsec: (t * 1e9) as libc::c_long };
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
                continue;
            }
            // (a pending signal that is neither waited for nor deliverable must not make
            // this spin: wait for the next host signal)
            let old = host::block_all();
            if host::HOST_PENDING.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                unsafe { libc::sigsuspend(&old) };
            }
            host::restore_mask(&old);
        }
    }

    /// sigwaitinfo(set, info): sigtimedwait without a timeout
    pub fn sys_sigwaitinfo(&mut self, a: &[u32; 8]) -> SysResult {
        self.sys_sigtimedwait(&[a[0], a[1], 0, 0, 0, 0, 0, 0])
    }

    /// sigqueue(pid, sig, value): kill with a value; the value reaches an SA_SIGINFO
    /// handler (si_value, si_code SI_QUEUE) when the process signals itself
    pub fn sys_sigqueue(&mut self, a: &[u32; 8]) -> SysResult {
        if a[0] == self.pid && a[1] != 0 {
            self.sigvalues.insert(a[1], a[2]);
        }
        self.sys_kill(a)
    }

    /// sigwait(set, &sig): take one of the signals in set, its number in *sig
    pub fn sys_sigwait(&mut self, a: &[u32; 8]) -> SysResult {
        let g = self.sys_sigtimedwait(&[a[0], 0, 0, 0, 0, 0, 0, 0])?.0;
        if a[1] != 0 {
            self.wr32(a[1], g)?;
        }
        ok(0)
    }

    /// kill(pid, sig): emulated processes are host processes with the same pids, so the
    /// host delivers it, through the handler the target installed
    pub fn sys_kill(&mut self, a: &[u32; 8]) -> SysResult {
        let (pid, sig) = (a[0] as i32, a[1]);
        if sig >= 64 {
            return err(EINVAL);
        }
        if self.euid != 0 && pid > 0 && pid as u32 != self.pid {
            // only one's own processes (the process table says whose they are)
            let mine = self.proc_table().iter().any(|p| p.pid == pid as u32 && (p.uid == self.uid || p.uid == self.euid));
            if !mine && (sig != SIGCONT || unsafe { libc::getsid(pid) != libc::getsid(0) }) {
                return err(EPERM);
            }
        }
        let h = if sig != 0 { host_sig(sig) } else { 0 };
        if sig != 0 && h == 0 {
            return err(EINVAL);
        }
        if unsafe { libc::kill(pid, h) } < 0 {
            return Err(herr());
        }
        ok(0)
    }

    /// setitimer(which, value, ovalue): the host's timers (ITIMER_REAL/VIRTUAL/PROF)
    pub fn sys_setitimer(&mut self, a: &[u32; 8]) -> SysResult {
        let (which, val, oval) = (a[0], a[1], a[2]);
        if which > 2 {
            return err(EINVAL);
        }
        let sig = [SIGALRM, SIGVTALRM, SIGPROF][which as usize];
        self.install_host_handler(sig, self.sigact(sig).handler);
        let mut old: libc::itimerval = unsafe { std::mem::zeroed() };
        if val != 0 {
            let d = self.rd(val, 16)?;
            let mut new: libc::itimerval = unsafe { std::mem::zeroed() };
            new.it_interval.tv_sec = be32(&d, 0) as libc::time_t;
            new.it_interval.tv_usec = be32(&d, 4) as libc::suseconds_t;
            new.it_value.tv_sec = be32(&d, 8) as libc::time_t;
            new.it_value.tv_usec = be32(&d, 12) as libc::suseconds_t;
            // (a microsecond count of a second or more: carry it, as the kernel refuses)
            new.it_value.tv_sec += new.it_value.tv_usec / 1_000_000;
            new.it_value.tv_usec %= 1_000_000;
            new.it_interval.tv_sec += new.it_interval.tv_usec / 1_000_000;
            new.it_interval.tv_usec %= 1_000_000;
            unsafe { libc::setitimer(which as _, &new, &mut old) };
        } else {
            unsafe { libc::getitimer(which as _, &mut old) };
        }
        if oval != 0 {
            self.wr(oval, &itimer_bytes(&old))?;
        }
        ok(0)
    }

    /// getitimer(which, value): the host timer
    pub fn sys_getitimer(&mut self, a: &[u32; 8]) -> SysResult {
        if a[0] > 2 {
            return err(EINVAL);
        }
        let mut old: libc::itimerval = unsafe { std::mem::zeroed() };
        unsafe { libc::getitimer(a[0] as _, &mut old) };
        self.wr(a[1], &itimer_bytes(&old))?;
        ok(0)
    }

    /// alarm(secs): the host's alarm; SIGALRM comes back through the host handler
    pub fn sys_alarm(&mut self, a: &[u32; 8]) -> SysResult {
        self.install_host_handler(SIGALRM, self.sigact(SIGALRM).handler);
        ok(unsafe { libc::alarm(a[0]) })
    }

    /// pause(): wait for a signal (always EINTR)
    pub fn sys_pause(&mut self, _a: &[u32; 8]) -> SysResult {
        self.host_pause();
        Err(Stop::Interrupted)
    }
}

fn itimer_bytes(t: &libc::itimerval) -> [u8; 16] {
    let mut b = [0u8; 16];
    w32(&mut b, 0, t.it_interval.tv_sec as u32);
    w32(&mut b, 4, t.it_interval.tv_usec as u32);
    w32(&mut b, 8, t.it_value.tv_sec as u32);
    w32(&mut b, 12, t.it_value.tv_usec as u32);
    b
}
