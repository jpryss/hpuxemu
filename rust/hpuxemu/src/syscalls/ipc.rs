//! System V IPC: the host's shared memory, semaphores and message queues; keys and ids
//! are the host's, so emulated processes share them with each other. A shared memory
//! segment is attached inside the guest address space with shmat(SHM_REMAP).

use super::Handler;
use crate::consts::*;
use crate::host::{self, guest_errno};
use crate::process::*;

pub const TABLE: &[(&str, Handler)] = &[
    ("shmget", Process::sys_shmget),
    ("shmat", Process::sys_shmat),
    ("shmdt", Process::sys_shmdt),
    ("shmctl", Process::sys_shmctl),
    ("semget", Process::sys_semget),
    ("semop", Process::sys_semop),
    ("semctl", Process::sys_semctl),
    ("msgget", Process::sys_msgget),
    ("msgsnd", Process::sys_msgsnd),
    ("msgrcv", Process::sys_msgrcv),
    ("msgctl", Process::sys_msgctl),
];

const SHM_LO: u32 = 0x9000_0000;
const SHM_HI: u32 = 0xC000_0000;

/// the host's errno, EINVAL for one HP-UX has no name for
fn ipc_err() -> Stop {
    let e = host::errno();
    Stop::Errno(if HOST_ERRNO.iter().any(|x| x.0 == e) { guest_errno(e) } else { EINVAL })
}

fn perm_out(p: &libc::ipc_perm) -> Vec<u8> {
    use off::ipc_perm as P;
    let mut b = Pk::new(P::SIZE);
    b.put(P::uid, p.uid as u64);
    b.put(P::gid, p.gid as u64);
    b.put(P::cuid, p.cuid as u64);
    b.put(P::cgid, p.cgid as u64);
    b.put(P::mode, p.mode as u64);
    b.put(P::seq, p.__seq as u64);
    b.put(P::key, p.__key as u64);
    b.0
}

impl Process {
    /// shmget(key, size, flag): the host's segment (IPC_CREAT/IPC_EXCL and the mode bits
    /// are the same values)
    pub fn sys_shmget(&mut self, a: &[u32; 8]) -> SysResult {
        let r = unsafe { libc::shmget(a[0] as i32, a[1] as usize, (a[2] & 0o3777) as i32) };
        if r < 0 {
            return Err(ipc_err());
        }
        ok(r as u32)
    }

    /// shmat(shmid, addr, flag): attached in the third quadrant (0x90000000 up) when no
    /// address is given; SHM_RDONLY honoured
    pub fn sys_shmat(&mut self, a: &[u32; 8]) -> SysResult {
        let (shmid, addr, flag) = (a[0] as i32, a[1], a[2]);
        let mut ds: libc::shmid_ds = unsafe { std::mem::zeroed() };
        if unsafe { libc::shmctl(shmid, libc::IPC_STAT, &mut ds) } < 0 {
            return Err(ipc_err());
        }
        let size = ((ds.shm_segsz as u64 + PAGE as u64 - 1) & !(PAGE as u64 - 1)) as u32;
        let base = if addr != 0 {
            let b = if flag & SHM_RND != 0 { addr & !(PAGE - 1) } else { addr };
            if b & (PAGE - 1) != 0 {
                return err(EINVAL);
            }
            b
        } else {
            self.find_free(size, SHM_LO, SHM_HI, true)?
        };
        let rdonly = flag & SHM_RDONLY != 0;
        let r = unsafe { libc::shmat(shmid, self.cpu.mem.host(base) as *const libc::c_void, libc::SHM_REMAP | if rdonly { libc::SHM_RDONLY } else { 0 }) };
        if r as isize == -1 {
            let e = host::errno();
            return err(if HOST_ERRNO.iter().any(|x| x.0 == e) { guest_errno(e) } else { ENOMEM });
        }
        self.cpu.mem.mark(base, size, if rdonly { 1 } else { 3 });
        self.shm_attached.insert(base, (shmid, size, 0));
        ok(base)
    }

    /// shmdt(addr)
    pub fn sys_shmdt(&mut self, a: &[u32; 8]) -> SysResult {
        let (_, size, _) = match self.shm_attached.remove(&a[0]) {
            Some(r) => r,
            None => return err(EINVAL),
        };
        self.cpu.mem.unmap(a[0], size);
        ok(0)
    }

    /// shmctl(shmid, cmd, buf): IPC_STAT (struct shmid_ds in HP-UX layout), IPC_SET
    /// (mode), IPC_RMID
    pub fn sys_shmctl(&mut self, a: &[u32; 8]) -> SysResult {
        let (shmid, cmd, buf) = (a[0] as i32, a[1], a[2]);
        let mut ds: libc::shmid_ds = unsafe { std::mem::zeroed() };
        if cmd == IPC_RMID {
            if unsafe { libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut()) } < 0 {
                return Err(ipc_err());
            }
            return ok(0);
        }
        if cmd != IPC_STAT && cmd != IPC_SET {
            return err(EINVAL);
        }
        if unsafe { libc::shmctl(shmid, libc::IPC_STAT, &mut ds) } < 0 {
            return Err(ipc_err());
        }
        if cmd == IPC_STAT {
            use off::shmid_ds as S;
            let mut b = Pk::new(S::SIZE);
            b.bytes(S::shm_perm, &perm_out(&ds.shm_perm));
            b.put(S::shm_segsz, ds.shm_segsz as u64);
            b.put(S::shm_lpid, ds.shm_lpid as u64);
            b.put(S::shm_cpid, ds.shm_cpid as u64);
            b.put(S::shm_nattch, ds.shm_nattch as u64);
            b.put(S::shm_atime, ds.shm_atime as u64);
            b.put(S::shm_dtime, ds.shm_dtime as u64);
            b.put(S::shm_ctime, ds.shm_ctime as u64);
            self.wr(buf, &b.0)?;
            return ok(0);
        }
        let g = self.rd(buf, off::ipc_perm::SIZE)?;
        ds.shm_perm.mode = be16(&g, 16) as _;
        if unsafe { libc::shmctl(shmid, libc::IPC_SET, &mut ds) } < 0 {
            return Err(ipc_err());
        }
        ok(0)
    }

    /// semget(key, nsems, flag)
    pub fn sys_semget(&mut self, a: &[u32; 8]) -> SysResult {
        let r = unsafe { libc::semget(a[0] as i32, a[1] as i32, (a[2] & 0o3777) as i32) };
        if r < 0 {
            return Err(ipc_err());
        }
        ok(r as u32)
    }

    /// semop(semid, sops, nsops): struct sembuf has the same layout on the host; blocks on
    /// the host, interruptible
    pub fn sys_semop(&mut self, a: &[u32; 8]) -> SysResult {
        let n = a[2] as usize;
        let ops = self.rd(a[1], 6 * n)?;
        let mut hb: Vec<libc::sembuf> = Vec::with_capacity(n);
        for i in 0..n {
            hb.push(libc::sembuf { sem_num: be16(&ops, 6 * i), sem_op: be16(&ops, 6 * i + 2) as i16, sem_flg: be16(&ops, 6 * i + 4) as i16 });
        }
        if unsafe { libc::semop(a[0] as i32, hb.as_mut_ptr(), n) } < 0 {
            return Err(herr_intr());
        }
        ok(0)
    }

    /// semctl(semid, semnum, cmd, arg): the BSD command numbers mapped to the host's;
    /// GETALL/SETALL/IPC_STAT through buffers
    pub fn sys_semctl(&mut self, a: &[u32; 8]) -> SysResult {
        let (semid, semnum, cmd, arg) = (a[0] as i32, a[1] as i32, a[2], a[3]);
        // HP-UX semctl commands are the BSD numbers; Linux's differ
        let hcmd = match cmd {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 14,
            4 => 11,
            5 => 12,
            6 => 13,
            7 => 15,
            8 => 16,
            9 => 17,
            _ => return err(EINVAL),
        };
        let mut ds: libc::semid_ds = unsafe { std::mem::zeroed() };
        let r;
        if [GETVAL, GETPID, GETNCNT, GETZCNT].contains(&cmd) {
            r = unsafe { libc::semctl(semid, semnum, hcmd, 0 as libc::c_long) };
        } else if cmd == SETVAL {
            r = unsafe { libc::semctl(semid, semnum, hcmd, arg as i32 as libc::c_long) };
        } else if cmd == GETALL || cmd == SETALL {
            if unsafe { libc::semctl(semid, 0, libc::IPC_STAT, &mut ds) } < 0 {
                return Err(ipc_err());
            }
            let n = ds.sem_nsems as usize;
            let mut arr = vec![0u16; n.max(1)];
            if cmd == SETALL {
                let d = self.rd(arg, 2 * n)?;
                for i in 0..n {
                    arr[i] = be16(&d, 2 * i);
                }
            }
            r = unsafe { libc::semctl(semid, semnum, hcmd, arr.as_mut_ptr()) };
            if r >= 0 && cmd == GETALL {
                let mut out = Vec::new();
                for v in &arr[..n] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
                self.wr(arg, &out)?;
            }
        } else if cmd == IPC_STAT {
            r = unsafe { libc::semctl(semid, 0, libc::IPC_STAT, &mut ds) };
            if r >= 0 {
                use off::semid_ds as S;
                let mut b = Pk::new(S::SIZE);
                b.bytes(S::sem_perm, &perm_out(&ds.sem_perm));
                b.put(S::sem_otime, ds.sem_otime as u64);
                b.put(S::sem_ctime, ds.sem_ctime as u64);
                b.put(S::sem_nsems, ds.sem_nsems as u64);
                self.wr(arg, &b.0)?;
            }
        } else if cmd == IPC_RMID {
            r = unsafe { libc::semctl(semid, 0, libc::IPC_RMID, 0 as libc::c_long) };
        } else if cmd == IPC_SET {
            if unsafe { libc::semctl(semid, 0, libc::IPC_STAT, &mut ds) } < 0 {
                return Err(ipc_err());
            }
            let g = self.rd(arg, off::ipc_perm::SIZE)?;
            ds.sem_perm.mode = be16(&g, 16) as _;
            r = unsafe { libc::semctl(semid, 0, libc::IPC_SET, &mut ds) };
        } else {
            return err(EINVAL);
        }
        if r < 0 {
            return Err(ipc_err());
        }
        ok(r as u32)
    }

    /// msgget(key, flag)
    pub fn sys_msgget(&mut self, a: &[u32; 8]) -> SysResult {
        let r = unsafe { libc::msgget(a[0] as i32, (a[1] & 0o3777) as i32) };
        if r < 0 {
            return Err(ipc_err());
        }
        ok(r as u32)
    }

    /// msgsnd(msqid, msgp, size, flag): the 32-bit mtype becomes the host's long
    pub fn sys_msgsnd(&mut self, a: &[u32; 8]) -> SysResult {
        let mtype = self.rd32(a[1])? as i32 as libc::c_long;
        let data = self.rd(a[1].wrapping_add(4), a[2] as usize)?;
        let mut hb = mtype.to_ne_bytes().to_vec();
        hb.extend_from_slice(&data);
        if unsafe { libc::msgsnd(a[0] as i32, hb.as_ptr() as *const libc::c_void, a[2] as usize, (a[3] & IPC_NOWAIT) as i32) } < 0 {
            return Err(herr_intr());
        }
        ok(0)
    }

    /// msgrcv(msqid, msgp, size, mtype, flag)
    pub fn sys_msgrcv(&mut self, a: &[u32; 8]) -> SysResult {
        let size = a[2] as usize;
        let mut hb = vec![0u8; 8 + size];
        let hflag = (a[4] & (IPC_NOWAIT | MSG_NOERROR)) as i32; // the same values on the host
        let n = unsafe { libc::msgrcv(a[0] as i32, hb.as_mut_ptr() as *mut libc::c_void, size, a[3] as i32 as libc::c_long, hflag) };
        if n < 0 {
            return Err(herr_intr());
        }
        let t = libc::c_long::from_ne_bytes(hb[..8].try_into().unwrap());
        let mut out = (t as i32).to_be_bytes().to_vec();
        out.extend_from_slice(&hb[8..8 + n as usize]);
        self.wr(a[1], &out)?;
        ok(n as u32)
    }

    /// msgctl(msqid, cmd, buf): IPC_STAT, IPC_SET (mode, qbytes), IPC_RMID
    pub fn sys_msgctl(&mut self, a: &[u32; 8]) -> SysResult {
        let (msqid, cmd, buf) = (a[0] as i32, a[1], a[2]);
        if cmd == IPC_RMID {
            if unsafe { libc::msgctl(msqid, libc::IPC_RMID, std::ptr::null_mut()) } < 0 {
                return Err(ipc_err());
            }
            return ok(0);
        }
        if cmd != IPC_STAT && cmd != IPC_SET {
            return err(EINVAL);
        }
        let mut ds: libc::msqid_ds = unsafe { std::mem::zeroed() };
        if unsafe { libc::msgctl(msqid, libc::IPC_STAT, &mut ds) } < 0 {
            return Err(ipc_err());
        }
        if cmd == IPC_STAT {
            use off::msqid_ds as S;
            let mut b = Pk::new(S::SIZE);
            b.bytes(S::msg_perm, &perm_out(&ds.msg_perm));
            b.put(S::msg_qnum, ds.msg_qnum as u64);
            b.put(S::msg_qbytes, (ds.msg_qbytes as u64).min(0xFFFF));
            b.put(S::msg_lspid, ds.msg_lspid as u64);
            b.put(S::msg_lrpid, ds.msg_lrpid as u64);
            b.put(S::msg_stime, ds.msg_stime as u64);
            b.put(S::msg_rtime, ds.msg_rtime as u64);
            b.put(S::msg_ctime, ds.msg_ctime as u64);
            b.put(S::msg_cbytes, (ds.__msg_cbytes as u64).min(0xFFFF));
            self.wr(buf, &b.0)?;
            return ok(0);
        }
        let g = self.rd(buf, off::msqid_ds::SIZE)?;
        ds.msg_perm.mode = be16(&g, 16) as _;
        ds.msg_qbytes = be16(&g, 58) as _;
        if unsafe { libc::msgctl(msqid, libc::IPC_SET, &mut ds) } < 0 {
            return Err(ipc_err());
        }
        ok(0)
    }
}
