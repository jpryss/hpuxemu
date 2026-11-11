"""lwp.py - HP-UX 11.00's kernel threads (LWPs), as libpthread uses them.

A process's LWPs share the emulator's one CPU and memory: each has its saved register
context (the general, floating-point and control registers the program can see, its
thread pointer cr27) and its own signal mask, and the emulator switches between them -
when the running one blocks in the kernel (ksleep, lwp_wait, sched_yield ...) and, so that
no thread starves another spinning on a lock, every RUN_CHUNK instructions. One thread
runs at a time, so the kernel's atomicity (release a lock and sleep, wake and requeue)
comes for free. The interface is sys/lwp.h, sys/ksleep.h and sys/lwpsynch.h:

    _lwp_create(ucontext_t *, flags, lwpid_t *, lwp_create_t *)   the context from
                              _lwp_makecontext: entry, argument, stack, thread pointer
    _lwp_exit(), _lwp_wait(lwpid, &departed), _lwp_detach, _lwp_self, _lwp_kill,
    _lwp_suspend/_lwp_continue/_lwp_resume
    ksleep(obj_flag, obj, lock, timeout)       release the lock (4 words, {1,1,1,1} free)
                                               and sleep on obj until a kwakeup
    kwakeup(obj_flag, obj, WAKEUP_ONE|ALL, &woken)

A thread whose host call would block (read, select, waitpid, sleep ...) parks alone and
makes the call again when it can go ahead. A signal for the process goes to the running
thread, or to a waiting one that does not block it (or waits for it in sigwait);
_lwp_kill's goes to the thread it names. Not done: lwp_mutex_*, lwp_cond_*, lwp_rwlock_*
and lwp_sema_* (libpthread builds its locks on ksleep), pstat_getlwp.
"""
import struct
import sys
import time

M32 = 0xFFFFFFFF

# sys/ksleep.h
RELATIVE_TIMEOUT_VALUE = 0x0200
KSLEEP_NONINTR = 0x0400
WAKEUP_ONE, WAKEUP_ALL = 0x01, 0x02
# sys/lwp.h
LWP_SUSPENDED = 0x02
LWP_DETACHED = 0x04
LWP_INHERIT_SIGMASK = 0x10
# sys/sched.h
SCHED_HPUX = 2

ETIMEDOUT = 238
EINTR = 4
ESRCH = 3
EINVAL = 22
EDEADLK = 45

NARROW_NAMES = (['ss_gr1', 'ss_rp'] + ['ss_gr%d' % i for i in range(3, 23)] +
                ['ss_arg3', 'ss_arg2', 'ss_arg1', 'ss_arg0', 'ss_dp', 'ss_ret0', 'ss_ret1', 'ss_sp', 'ss_gr31'])


class Lwp:
    """one kernel thread: its id, saved context (None while it runs), state - 'run'
    (runnable), 'sleep' (ksleep on `key`, or a sleep with only a deadline), 'join'
    (lwp_wait for `key`, 0 any), 'io' (a host call that would block: `key` the
    conditions, the call made again when one holds), 'yield', 'zombie' (exited, not yet
    waited for)"""
    __slots__ = ('id', 'ctx', 'state', 'key', 'deadline', 'detached', 'departed_p', 'suspended', 'on_timeout',
                 'tpending', 'inhibit')

    def __init__(self, lid):
        self.id = lid
        self.ctx = None
        self.state = 'run'
        self.key = None
        self.deadline = None
        self.detached = False
        self.departed_p = 0
        self.suspended = False
        self.on_timeout = None      # a wait's deadline: a function giving the call's (rv, err)
        self.tpending = set()       # signals sent to this thread (_lwp_kill), not yet taken
        self.inhibit = []           # its siginhibit() masks, while it is off the CPU

    def __repr__(self):
        return '<lwp %d %s>' % (self.id, self.state)


class _Switched(Exception):
    """the running LWP changed inside a system call: syscall() leaves the registers"""


class LwpMixin:
    """the LWP system calls and the scheduler, part of Process"""

    lwps = None             # {id: Lwp} once the process makes its first thread
    cur_lwp = None
    tdirected = frozenset()  # of self.pending: the running thread's own (from its tpending)

    # -- contexts ------------------------------------------------------------------------
    def lwp_setup(self):
        if self.lwps is None:
            main = Lwp(1)
            self.lwps = {1: main}
            self.cur_lwp = main
            self.lwp_next_id = 2

    def ctx_save(self):
        """the running thread's context, as it leaves the CPU: the signals sent to it
        alone that are still pending go back to it"""
        cpu = self.cpu
        cur = self.cur_lwp
        if self.tdirected:
            mine = set(self.tdirected) & self.pending
            if cur is not None:
                cur.tpending |= mine
            self.pending -= mine
            self.tdirected = frozenset()
        if cur is not None:
            # siginhibit/sigenable nest per thread: libpthread brackets its critical
            # sections with them, and threads switch inside them
            cur.inhibit = self.inhibit
            self.inhibit = []
        return [[cpu.gr[i] for i in range(32)], [cpu.fr[i] for i in range(32)], cpu.sar, cpu.iaoq_f, cpu.iaoq_b,
                cpu.psw_n, cpu.psw_cb, cpu.psw_cb_msb, cpu.psw_v, cpu.cr[26], cpu.cr[27], self.sigmask]

    def ctx_load(self, ctx):
        cpu = self.cpu
        gr, fr, sar, f, b, n, cb, cbm, v, cr26, cr27, mask = ctx
        for i in range(1, 32):
            cpu.gr[i] = gr[i]
        for i in range(32):
            cpu.fr[i] = fr[i]
        cpu.sar = sar
        cpu.iaoq_f = f
        cpu.iaoq_b = b
        cpu.psw_n = n
        cpu.psw_cb = cb
        cpu.psw_cb_msb = cbm
        cpu.psw_v = v
        cpu.cr[26] = cr26
        cpu.cr[27] = cr27
        self.sigmask = mask

    def lwp_enter(self, t):
        """t runs: its context loaded, the signals sent to it now pending"""
        self.ctx_load(t.ctx)
        t.ctx = None
        self.cur_lwp = t
        self.inhibit = t.inhibit
        t.inhibit = []
        if t.tpending:
            self.tdirected = frozenset(t.tpending - self.pending)
            self.pending |= t.tpending
            t.tpending = set()
        if self.trace:
            sys.stderr.write('[%d] -- lwp %d runs at %#x sp %#x\n' % (self.pid, t.id, self.cpu.iaoq_f & ~3,
                                                                     self.cpu.gr[30] & M32))

    @staticmethod
    def ctx_set_return(ctx, rv, err=0):
        ctx[0][28] = rv & M32
        ctx[0][22] = err

    def ctx_from_ucontext(self, ucp):
        """a new thread's context from the ucontext_t _lwp_makecontext filled (its
        mcontext, a __save_state: the narrow registers and the FP block)"""
        from .consts11 import OFFSET
        ss = OFFSET['__ucontext']['uc_mcontext'][0]
        narrow = ss + OFFSET['__save_state']['ss_narrow'][0]
        fpb = ss + OFFSET['__save_state']['ss_fpblock'][0]
        nr = OFFSET['__ss_narrow']
        size = OFFSET['__ucontext']['uc_subcontext'][0] + 48
        u = self.rd(ucp, size)

        def r32(off):
            return struct.unpack('>I', u[off:off + 4])[0]
        gr = [0] * 32
        for i, n in enumerate(NARROW_NAMES):
            gr[i + 1] = r32(narrow + nr[n][0])
        fr = [struct.unpack('>Q', u[fpb + 8 * i:fpb + 8 * i + 8])[0] for i in range(32)]
        # the thread starts as a system call returns, at r31 (_lwp_makecontext puts the
        # start routine there and leaves the pc queue alone); the thread pointer (cr27)
        # is the narrow state's last word but two, which 10.20's header leaves unnamed
        head = gr[31] & ~3
        if gr[31] & 2:
            # a function pointer: a plabel, {entry, gp}
            head, gp = self.resolve_plabel(gr[31])
            if gp is not None:
                gr[19] = gp
        tail = head + 4
        gr[28] = gr[22] = 0
        # the program's data pointer: _lwp_makecontext never writes r27, so the context
        # holds whatever pthread_create's stack had there (in examples/threads.c by luck
        # the data pointer, in Solid's ovdbrun garbage); it is one value for the whole
        # program, the creator's
        gr[27] = self.cpu.gr[27] & M32
        cr27 = r32(narrow + 236)
        sub = OFFSET['__ucontext']['uc_subcontext'][0] + OFFSET['__sub_ctxt']['__uc_sigmask'][0]
        mask = int.from_bytes(u[sub:sub + 32], 'big')
        # SAR is not written either: 5 bits of the residue, as mtsar would take them
        sar = r32(narrow + nr['ss_cr11'][0]) & 31
        return [gr, fr, sar, head | 3, tail | 3, False, 0, 0, 0, 0, cr27, mask]

    # -- scheduling ----------------------------------------------------------------------
    def lwp_runnable(self):
        return [t for t in self.lwps.values() if t.state == 'run' and not t.suspended]

    def lwp_wake_timeouts(self, wait_ms=0):
        """wake the threads whose deadline has passed or whose host call can go ahead;
        wait_ms: how long to wait for that when nothing else can run (-1: forever)"""
        now = time.time()
        for t in self.lwps.values():
            if t.deadline is not None and t.deadline <= now and t.state in ('sleep', 'io'):
                if t.state == 'io':
                    # the call is not made again: it returns, as the deadline says
                    rv, err = t.on_timeout() if t.on_timeout else (0, 0)
                    t.on_timeout = None
                    ret = t.ctx[0][31] & ~3
                    t.ctx[3] = ret | 3
                    t.ctx[4] = (ret + 4) | 3
                    self.lwp_wake(t, rv, err)
                else:
                    # ksleep reports the timeout as its value, not as an error
                    rv, err = t.on_timeout() if t.on_timeout else (ETIMEDOUT, 0)
                    t.on_timeout = None
                    self.lwp_wake(t, rv, err)
        io = [t for t in self.lwps.values() if t.state == 'io']
        if not io:
            if wait_ms:
                time.sleep(0.5 if wait_ms < 0 else wait_ms / 1000.0)
            return
        entries, owners = [], []
        for t in io:
            for c in t.key:
                if c[0] == 'fd':
                    entries.append((c[1], c[2]))
                    owners.append(t)
        ready = set()
        for t in io:
            for c in t.key:
                if c[0] == 'sig' and any(c[1] & self.sigbit(g) for g in self.pending | t.tpending):
                    ready.add(t.id)
                elif c[0] == 'child' and self.child_ready(c[1], c[2]):
                    ready.add(t.id)
        if ready:
            wait_ms = 0
        if entries:
            try:
                res = self.poll_streams(entries, wait_ms if wait_ms >= 0 else 500)
            except Exception:
                res = [0] * len(entries)
            for t, r in zip(owners, res):
                if r:
                    ready.add(t.id)
        elif wait_ms:
            time.sleep(min(0.05 if any(c[0] == 'child' for t in io for c in t.key) else 0.5,
                           (wait_ms if wait_ms > 0 else 500) / 1000.0))
        for t in io:
            if t.id in ready:
                # the call is made again (its context is at the gateway)
                t.state = 'run'
                t.key = None
                t.deadline = None
                t.on_timeout = None

    @staticmethod
    def sigbit(sig):
        from .emu import sigbit
        return sigbit(sig)

    @staticmethod
    def child_ready(idtype, ident):
        import os
        try:
            r = os.waitid(idtype, ident, os.WEXITED | os.WSTOPPED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return True         # none left: the call fails at once
        except OSError:
            return True
        return r is not None

    def lwp_wake(self, t, rv, err=0):
        t.state = 'run'
        t.key = None
        t.deadline = None
        if t.ctx is not None:
            self.ctx_set_return(t.ctx, rv, err)

    def lwp_pick(self, after):
        """the next runnable thread after `after` in id order (round robin), or None"""
        ids = sorted(self.lwps)
        if after in ids:
            k = ids.index(after)
            ids = ids[k + 1:] + ids[:k + 1]
        for i in ids:
            t = self.lwps[i]
            if t.state == 'run' and not t.suspended:
                return t
        return None

    def lwp_switch(self, t):
        """make t the running thread (the current one's context saved unless it is gone)"""
        cur = self.cur_lwp
        if t is cur:
            return
        if cur is not None and cur.id in self.lwps:
            cur.ctx = self.ctx_save()
        self.lwp_enter(t)

    def lwp_preempt(self):
        """the time slice is over: another runnable thread, if any, runs"""
        if not self.lwps or len(self.lwps) < 2:
            return
        self.lwp_wake_timeouts()
        for t in self.lwps.values():
            if t.state == 'yield':
                t.state = 'run'
        nxt = self.lwp_pick(self.cur_lwp.id)
        if nxt is not None and nxt is not self.cur_lwp and self.cur_lwp.state == 'run':
            self.lwp_switch(nxt)

    def lwp_block(self, rv=0, err=0):
        """the running thread waits (its state already set): its system call returns rv
        when it runs again (a waker may change that); another thread runs - or, when none
        can, the process waits for a host call to become possible, a timeout or a
        signal. Never returns."""
        cpu = self.cpu
        cpu.gr[28] = rv & M32
        cpu.gr[22] = err
        cpu.set_pc(cpu.gr[31])
        cur = self.cur_lwp
        alive = cur.id in self.lwps and cur.state != 'zombie'
        self.lwp_block_saved(self.ctx_save() if alive else None)

    def lwp_signal_target(self):
        """a sleeping thread to interrupt for a pending signal: the first that does not
        block one of them (its ksleep returns EINTR and the signal is delivered to it)"""
        from .emu import sigbit
        for t in sorted(self.lwps.values(), key=lambda t: t.id):
            if t.state in ('sleep', 'join', 'io') and t.ctx is not None:
                mask = t.ctx[11]
                if any(not (mask & sigbit(s)) and self.deliverable_any(s) for s in self.pending):
                    return t
        return None

    def deliverable_any(self, sig):
        handler = self.sigactions.get(sig, (0,))[0]
        return handler != 1

    # -- the system calls ----------------------------------------------------------------
    def sys_lwp_self(self, *a):
        """_lwp_self(): the running thread's id (1 for a process's first)"""
        return self.cur_lwp.id if self.lwps else 1

    def sys_lwp_getscheduler(self, which, lid, policyp, paramp, *a):
        """_lwp_getscheduler(which, lwpid, &policy, &param): the time-sharing policy,
        priority 0"""
        if policyp:
            self.wr(policyp, struct.pack('>i', SCHED_HPUX))
        if paramp:
            self.wr(paramp, struct.pack('>i', 0))
        return 0

    def sys_lwp_setscheduler(self, which, lid, policy, paramp, *a):
        """_lwp_setscheduler(which, lwpid, policy, &param): accepted, nothing changes"""
        return 0

    def sys_lwp_create(self, ucp, flags, lidp, optp, *a):
        """_lwp_create(ucontext, flags, &lwpid, opt): a new thread from the context
        _lwp_makecontext prepared; LWP_SUSPENDED leaves it stopped, LWP_DETACHED needs no
        _lwp_wait, LWP_INHERIT_SIGMASK gives it the creator's mask"""
        self.lwp_setup()
        ctx = self.ctx_from_ucontext(ucp)
        if flags & LWP_INHERIT_SIGMASK:
            ctx[11] = self.sigmask
        t = Lwp(self.lwp_next_id)
        self.lwp_next_id += 1
        t.ctx = ctx
        t.detached = bool(flags & LWP_DETACHED)
        t.suspended = bool(flags & LWP_SUSPENDED)
        self.lwps[t.id] = t
        if len(self.lwps) == 2:
            # now the emulator decides which thread a signal goes to: the host catches
            # the signals whose action is the default too (install_host_handler)
            from .emu import GUEST2HOST_SIG
            for sig in GUEST2HOST_SIG:
                if self.sigactions.get(sig, (0,))[0] == 0:
                    self.install_host_handler(sig, 0)
        if lidp:
            self.wr(lidp, struct.pack('>i', t.id))
        if self.trace:
            sys.stderr.write('[%d] -- lwp %d created: pc %#x sp %#x arg %#x cr27 %#x r27 %#x r19 %#x sar %#x\n' % (
                self.pid, t.id, ctx[3] & ~3, ctx[0][30], ctx[0][26], ctx[10], ctx[0][27], ctx[0][19], ctx[2]))
        return 0

    def lwp_exit_current(self):
        cur = self.cur_lwp
        if cur.detached:
            del self.lwps[cur.id]
        else:
            cur.state = 'zombie'
            cur.ctx = None
            # a thread waiting for this one (or for any) takes it
            for t in self.lwps.values():
                if t.state == 'join' and t.key in (cur.id, 0):
                    if t.departed_p:
                        self.wr(t.departed_p, struct.pack('>i', cur.id))
                    del self.lwps[cur.id]
                    self.lwp_wake(t, 0)
                    break
        live = [t for t in self.lwps.values() if t.state != 'zombie']
        if not live:
            self.exited = ('exit', 0)
            raise _Switched()
        cur.state = 'zombie'
        self.lwp_block()

    def sys_lwp_exit(self, *a):
        """_lwp_exit(): the running thread ends (the process with its last thread)"""
        if not self.lwps or len(self.lwps) == 1:
            return self.sys_exit(0)
        self.lwp_exit_current()

    def sys_lwp_detached_exit(self, *a):
        """_lwp_detached_exit(...): a detached thread ends (its stack is the library's)"""
        if not self.lwps or len(self.lwps) == 1:
            return self.sys_exit(0)
        self.cur_lwp.detached = True
        self.lwp_exit_current()

    def sys_lwp_wait(self, lid, departedp, *a):
        """_lwp_wait(lwpid, &departed): wait for a thread (0: any) to end"""
        self.lwp_setup()
        cur = self.cur_lwp
        if lid == cur.id:
            from .emu import HpuxError
            raise HpuxError(EDEADLK)
        for t in list(self.lwps.values()):
            if t.state == 'zombie' and (lid == 0 or t.id == lid) and not t.detached:
                del self.lwps[t.id]
                if departedp:
                    self.wr(departedp, struct.pack('>i', t.id))
                return 0
        if lid and (lid not in self.lwps or self.lwps[lid].detached):
            from .emu import HpuxError
            raise HpuxError(ESRCH)
        cur.state = 'join'
        cur.key = lid
        cur.departed_p = departedp
        self.lwp_block()

    def sys_lwp_detach(self, lid, *a):
        """_lwp_detach(lwpid): no _lwp_wait will be made for it"""
        self.lwp_setup()
        t = self.lwps.get(lid)
        if t is None:
            from .emu import HpuxError
            raise HpuxError(ESRCH)
        t.detached = True
        if t.state == 'zombie':
            del self.lwps[lid]
        return 0

    def lwp_interrupt(self, t):
        """a signal for the waiting thread t: its wait ends with EINTR (a host call it
        was to make again returns EINTR instead) and the signal is delivered when it runs"""
        if t.state == 'io':
            # a sigwait for the signal is made again, and takes it
            if any(c[0] == 'sig' for c in t.key or ()):
                t.state = 'run'
                t.key = t.deadline = t.on_timeout = None
                return
            ret = t.ctx[0][31] & ~3
            t.ctx[3] = ret | 3
            t.ctx[4] = (ret + 4) | 3
        self.lwp_wake(t, EINTR, 1)

    def sys_lwp_kill(self, lid, sig, *a):
        """_lwp_kill(lwpid, sig): the signal, to that thread: its handler runs there; a
        wait of its (ksleep, a blocked host call) ends with EINTR unless it blocks the
        signal (a sigwait for it takes it)"""
        self.lwp_setup()
        t = self.lwps.get(lid)
        if t is None or t.state == 'zombie':
            from .emu import HpuxError
            raise HpuxError(ESRCH)
        if not sig:
            return 0
        if t is self.cur_lwp:
            self.pending.add(sig)
            self.tdirected = frozenset(set(self.tdirected) | {sig})
            return 0
        t.tpending.add(sig)
        if t.state in ('sleep', 'join', 'io') and t.ctx is not None:
            blocked = t.ctx[11] & self.sigbit(sig)
            waits_for = t.state == 'io' and any(c[0] == 'sig' and c[1] & self.sigbit(sig) for c in t.key or ())
            if waits_for or (not blocked and self.deliverable_any(sig)):
                self.lwp_interrupt(t)
        return 0

    def sys_lwp_suspend(self, lid, *a):
        """_lwp_suspend(lwpid): the thread stops until _lwp_continue"""
        self.lwp_setup()
        t = self.lwps.get(lid)
        if t is None:
            from .emu import HpuxError
            raise HpuxError(ESRCH)
        t.suspended = True
        if t is self.cur_lwp:
            self.lwp_block()
        return 0

    def sys_lwp_continue(self, lid, *a):
        """_lwp_continue(lwpid): a suspended thread runs again"""
        self.lwp_setup()
        t = self.lwps.get(lid)
        if t is None:
            from .emu import HpuxError
            raise HpuxError(ESRCH)
        t.suspended = False
        return 0

    def sys_lwp_getstate(self, lid, which, buf, *a):
        """_lwp_getstate(lwpid, which, &save_state): a thread's registers, as a
        __save_state with the narrow registers (ss_flags without SS_WIDEREGS) and the FP
        block; libpthread's _pthread_stack_info_np reads a suspended thread's sp there
        (a Java VM asks for every thread's stack)"""
        from .consts11 import OFFSET
        self.lwp_setup()
        t = self.lwps.get(lid)
        if t is None or t.state == 'zombie' or (t is not self.cur_lwp and t.ctx is None):
            from .emu import HpuxError
            raise HpuxError(ESRCH)
        cpu = self.cpu
        if t is self.cur_lwp:
            gr = [cpu.gr[i] & M32 for i in range(32)]
            fr = [cpu.fr[i] for i in range(32)]
            sar, f, b, cr27 = cpu.sar, cpu.iaoq_f, cpu.iaoq_b, cpu.cr[27]
        else:
            gr, fr, sar, f, b = t.ctx[0], t.ctx[1], t.ctx[2], t.ctx[3], t.ctx[4]
            cr27 = t.ctx[10]
        so = OFFSET['__save_state']
        nr = OFFSET['__ss_narrow']
        out = bytearray(so['ss_wide'][0] + so['ss_wide'][1])
        narrow = so['ss_narrow'][0]

        def w32(off, v):
            struct.pack_into('>I', out, off, v & M32)
        for i, n in enumerate(NARROW_NAMES):
            w32(narrow + nr[n][0], gr[i + 1])
        w32(narrow + nr['ss_cr11'][0], sar)
        w32(narrow + nr['ss_pcoq_head'][0], f)
        w32(narrow + nr['ss_pcoq_tail'][0], b)
        w32(narrow + 236, cr27)
        fpb = so['ss_fpblock'][0]
        for i in range(32):
            struct.pack_into('>Q', out, fpb + 8 * i, fr[i] & 0xFFFFFFFFFFFFFFFF)
        self.wr(buf, bytes(out))
        return 0

    def sys_lwp_resume(self, lid, flags, *a):
        """_lwp_resume(lwpid, flags): as _lwp_continue"""
        return self.sys_lwp_continue(lid)

    def sys_sched_yield(self, *a):
        """sched_yield(): the other runnable threads run first"""
        if not self.lwps or len(self.lwp_runnable()) < 2:
            # no other thread of this process: the other processes, as the kernel would
            import os
            os.sched_yield()
            return 0
        self.cur_lwp.state = 'yield'
        self.lwp_block()

    def ksleep_deadline(self, flags, tvp):
        if not tvp:
            return None
        sec, nsec = struct.unpack('>ii', self.rd(tvp, 8))
        t = sec + nsec / 1e9
        if flags & RELATIVE_TIMEOUT_VALUE:
            return time.time() + t
        return t - getattr(self, 'clock_offset', 0)

    def sys_ksleep(self, flags, obj, lock, tvp, *a):
        """ksleep(obj_flag, obj, lock, timeout): release the lock (an ldcw lock of four
        words) and sleep on obj until a kwakeup (0), the timeout (ETIMEDOUT) or a
        signal (EINTR)"""
        self.lwp_setup()
        deadline = self.ksleep_deadline(flags, tvp)
        if lock:
            # the lock is four words, {1,1,1,1} when free: ldcw needs a 16-byte aligned
            # word, which is whichever of the four the library's address rounds up to
            self.wr(lock, struct.pack('>4I', 1, 1, 1, 1))
        cur = self.cur_lwp
        cur.state = 'sleep'
        cur.key = obj
        cur.deadline = deadline
        self.lwp_block()

    def sys_kwakeup(self, flags, obj, wflags, wokenp, *a):
        """kwakeup(obj_flag, obj, WAKEUP_ONE|WAKEUP_ALL, &woken): wake the sleepers on obj"""
        n = 0
        if self.lwps:
            for i in sorted(self.lwps):
                t = self.lwps[i]
                if t.state == 'sleep' and t.key == obj:
                    self.lwp_wake(t, 0)
                    n += 1
                    if not wflags & WAKEUP_ALL:
                        break
        if wokenp:
            self.wr(wokenp, struct.pack('>i', n))
        return 0

    def lwp_park(self, conds, deadline=None, on_timeout=None):
        """the running thread's host call would block: it waits for one of conds
        (('fd', fd, events), ('sig', mask), ('child', idtype, id)) or the deadline, then
        makes the call again - its context is left at the gateway with the call number
        and arguments as they are. on_timeout() gives the call's result when the
        deadline comes first. Never returns."""
        from .emu import GATEWAY
        cpu = self.cpu
        cur = self.cur_lwp
        cpu.iaoq_f = (GATEWAY + 4) | 3
        cpu.iaoq_b = (GATEWAY + 8) | 3
        cur.state = 'io'
        cur.key = conds
        cur.deadline = deadline
        cur.on_timeout = on_timeout
        cpu.psw_n = False
        self.lwp_block_saved(self.ctx_save())

    def lwp_block_saved(self, ctx):
        """switch away from the running thread, whose context is ctx (None: it is gone)"""
        cur = self.cur_lwp
        cur.ctx = ctx
        self.cur_lwp = None
        while True:
            self.lwp_wake_timeouts()
            nxt = self.lwp_pick(cur.id)
            if nxt is None:
                for t in self.lwps.values():
                    if t.state == 'yield':
                        t.state = 'run'
                nxt = self.lwp_pick(cur.id)
            if nxt is not None:
                self.lwp_enter(nxt)
                raise _Switched()
            if self.pending:
                victim = self.lwp_signal_target()
                if victim is not None:
                    self.lwp_interrupt(victim)
                    continue
            deadlines = [t.deadline for t in self.lwps.values() if t.deadline is not None]
            wait = min(max(0.0, min(deadlines) - time.time()) if deadlines else 0.5, 0.5)
            try:
                self.lwp_wake_timeouts(max(1, int(wait * 1000)))
            except Exception:
                pass
            self.poll_signals()

    def lwp_would_block(self, name, args):
        """for a call that can block the host, in a process with several threads: None
        when it can go ahead now, else the thread parks (lwp_park) until it can"""
        cur = self.cur_lwp
        if name in ('read', 'readv', 'recv', 'recvfrom', 'recvmsg', 'accept', 'getmsg', 'getpmsg'):
            conds = [('fd', args[0], 1)]                # POLLIN
            if self.fd_nonblocking(args[0]) or any(self.poll_streams([(args[0], 1)], 0)):
                return None
            self.lwp_park(conds)
        elif name == 'poll':
            fds, nfds, timeout = args[0], args[1], args[2]
            if timeout == 0:
                return None
            conds = []
            for i in range(min(nfds, 1024)):
                fd, ev, rev = struct.unpack('>ihh', self.rd(fds + 8 * i, 8))
                if fd >= 0:
                    conds.append(('fd', fd, ev & 0xFF))
            to = struct.unpack('>i', struct.pack('>I', timeout))[0]
            deadline = time.time() + to / 1000.0 if to > 0 else None

            def expired_poll():
                for i in range(min(nfds, 1024)):
                    self.wr(fds + 8 * i + 6, b'\0\0')
                return (0, 0)
            if conds and any(self.poll_streams([(c[1], c[2]) for c in conds], 0)):
                return None
            self.lwp_park(conds, deadline, expired_poll)
        elif name == 'select':
            nfds, rs, ws, es, tv = args[:5]
            deadline = None
            if tv:
                sec, usec = struct.unpack('>ii', self.rd(tv, 8))
                if sec == 0 and usec == 0:
                    return None
                deadline = time.time() + sec + usec / 1e6
            conds = []
            words = (nfds + 31) // 32
            for addr, ev in ((rs, 1), (ws, 4), (es, 2)):
                if not addr:
                    continue
                data = self.rd(addr, 4 * words)
                for i in range(nfds):
                    w = struct.unpack('>I', data[4 * (i // 32):4 * (i // 32) + 4])[0]
                    if w & (1 << (i % 32)):
                        conds.append(('fd', i, ev))
            if any(self.poll_streams([(c[1], c[2]) for c in conds], 0)) if conds else False:
                return None

            def expired_select():
                for addr in (rs, ws, es):
                    if addr:
                        self.wr(addr, b'\0' * (4 * words))
                return (0, 0)
            self.lwp_park(conds, deadline, expired_select)
        elif name in ('waitpid', 'wait', 'wait3'):
            import os
            pid = struct.unpack('>i', struct.pack('>I', args[0]))[0] if name == 'waitpid' else -1
            options = args[2] if name == 'waitpid' else (args[1] if name == 'wait3' else 0)
            if options & 1:                             # WNOHANG
                return None
            if pid > 0:
                c = ('child', os.P_PID, pid)
            elif pid < -1:
                c = ('child', os.P_PGID, -pid)
            else:
                c = ('child', os.P_ALL, 0)
            if self.child_ready(c[1], c[2]):
                return None
            self.lwp_park([c])
        elif name == 'nanosleep':
            sec, nsec = struct.unpack('>ii', self.rd(args[0], 8))
            cur.state = 'sleep'
            cur.key = None
            cur.deadline = time.time() + sec + nsec / 1e9
            cur.on_timeout = lambda: (0, 0)
            self.lwp_block()
        elif name in ('sigtimedwait', 'sigwait'):
            wset = int.from_bytes(self.rd(args[0], 32), 'big')
            if any(wset & self.sigbit(g) for g in self.pending):
                return None
            deadline = None
            if name == 'sigtimedwait' and args[2]:
                sec, nsec = struct.unpack('>ii', self.rd(args[2], 8))
                deadline = time.time() + sec + nsec / 1e9
            from .emu import C
            self.lwp_park([('sig', wset)], deadline, lambda: (C['EAGAIN'], 1))
        return None

    def fd_nonblocking(self, fd):
        """a descriptor whose reads never wait (O_NONBLOCK, O_NDELAY): the call goes ahead"""
        from .emu import C
        f = self.fds.get(fd)
        return f is None or bool(f.get('flags', 0) & (C['O_NONBLOCK'] | C['O_NDELAY']))

    def lwp_fork_child(self):
        """after fork, the child has only the thread that called it"""
        if self.lwps:
            cur = self.cur_lwp
            self.lwps = {cur.id: cur}
