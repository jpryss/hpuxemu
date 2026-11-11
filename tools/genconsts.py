#!/usr/bin/env python3
"""genconsts.py - generate hpuxemu/consts.py from the HP-UX root's own headers.

    python3 tools/genconsts.py [-o MODULE] [-DNAME ...] [ROOT]

-o names the module written in hpuxemu/ (default consts); -D adds a define. The 11.00
layouts are `genconsts.py -o consts11 -D_PSTAT64 ROOT11`: 11.00's 32-bit libc asks
pstat for the _PSTAT64 structures (64-bit counters).

The host's C preprocessor and compiler are run against ROOT/usr/include (as HP-UX's cc
would see it: __hp9000s800, _HPUX_SOURCE): every numeric macro with one of the prefixes
below is evaluated, including the ioctl numbers (`_IOR('t', 107, struct winsize)` needs
sizeof), and the sizes and member offsets of the structures the system calls exchange are
printed with offsetof(). gcc -m32 lays the structures out as the PA-RISC compiler does
(ILP32, 8-byte alignment of double and long long with -malign-double) - every layout
the emulator relies on is still checked against a binary in docs/ABI.md.

The result is a plain Python module; it is committed so that the emulators run without
the root's headers (which are HP's).
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
from hpuxemu import rootdir  # noqa: E402

HEADERS = """sys/types.h sys/syscall.h sys/errno.h sys/signal.h fcntl.h sys/mman.h sys/stat.h sys/wait.h
unistd.h sys/termios.h sys/ioctl.h sys/socket.h sys/uio.h sys/resource.h sys/utsname.h sys/time.h
dirent.h sys/ipc.h sys/shm.h sys/sem.h sys/msg.h sys/pstat.h sys/stropts.h netinet/in.h sys/un.h
sys/statvfs.h sys/ttold.h sys/ptyio.h sys/sysmacros.h sys/ulimit.h ulimit.h sys/vfs.h sys/mount.h
sys/pathconf.h sys/sched.h sys/lock.h sys/poll.h sys/times.h time.h sys/param.h sys/utsname.h
sys/socket.h netinet/tcp.h sys/filio.h sys/sockio.h sys/ttyio.h sys/acl.h sys/dirent.h sys/getaccess.h
sys/fs.h sys/audit.h sys/privgrp.h sys/rtprio.h sys/mtio.h sys/strlog.h sys/timers.h
sys/timeb.h sys/ustat.h ustat.h sys/user.h sys/pstat.h sys/context.h sys/ucontext.h
sys/modem.h sys/termio.h sys/bsdtty.h net/if.h net/if_arp.h netinet/if_ether.h
sys/tiuser.h sys/tihdr.h sys/timod.h""".split()

PREFIXES = ('SYS_', 'E', 'IFF_', 'SIG', 'SA_', 'SS_', 'SIG_', 'O_', 'F_', 'FD_', 'FNDELAY', 'FAPPEND', 'FASYNC',
            'MAP_', 'PROT_', 'MS_', 'MAP', 'S_IF', 'S_I', 'W', 'R_OK', 'W_OK', 'X_OK', 'F_OK', 'SEEK_',
            'TC', 'TIOC', 'FIO', 'SIOC', 'MTIO', 'TCSA', 'B0', 'B50', 'B75', 'B110', 'B134', 'B150', 'B200',
            'B300', 'B600', 'B900', 'B1200', 'B1800', 'B2400', 'B3600', 'B4800', 'B7200', 'B9600', 'B19200',
            'B38400', 'B57600', 'B115200', 'B230400', 'EXTA', 'EXTB', 'IGNBRK', 'BRKINT', 'IGNPAR', 'PARMRK',
            'INPCK', 'ISTRIP', 'INLCR', 'IGNCR', 'ICRNL', 'IUCLC', 'IXON', 'IXANY', 'IXOFF', 'IMAXBEL',
            'OPOST', 'OLCUC', 'ONLCR', 'OCRNL', 'ONOCR', 'ONLRET', 'OFILL', 'OFDEL', 'NLDLY', 'CRDLY',
            'TABDLY', 'BSDLY', 'VTDLY', 'FFDLY', 'CBAUD', 'CSIZE', 'CS5', 'CS6', 'CS7', 'CS8', 'CSTOPB',
            'CREAD', 'PARENB', 'PARODD', 'HUPCL', 'CLOCAL', 'LOBLK', 'CRTS', 'ISIG', 'ICANON', 'XCASE',
            'ECHO', 'ECHOE', 'ECHOK', 'ECHONL', 'NOFLSH', 'TOSTOP', 'IEXTEN', 'FLUSHO', 'PENDIN', 'ECHOCTL',
            'ECHOPRT', 'ECHOKE', 'VINTR', 'VQUIT', 'VERASE', 'VKILL', 'VEOF', 'VEOL', 'VEOL2', 'VMIN',
            'VTIME', 'VSUSP', 'VSTART', 'VSTOP', 'VSWTCH', 'VDSUSP', 'VWERASE', 'VLNEXT', 'NCCS', 'NCC',
            'SOL_', 'SO_', 'AF_', 'PF_', 'SOCK_', 'MSG_', 'IPPROTO_', 'IP_', 'TCP_', 'INADDR_', 'SHUT_',
            'IPC_', 'SHM_', 'SEM_', 'GETVAL', 'SETVAL', 'GETPID', 'GETNCNT', 'GETZCNT', 'GETALL', 'SETALL',
            'MSG_', 'RLIMIT_', 'RLIM_', 'RUSAGE_', 'ITIMER_', 'PRIO_', 'POLL', 'I_', 'FLUSH', 'PSTAT_',
            'PS_', '_SC_', '_PC_', '_CS_', 'UL_', 'ST_', 'MNT', 'FS_', 'PATH_MAX', 'NAME_MAX', 'MAXPATHLEN',
            'MAXNAMLEN', 'NOFILE', 'OPEN_MAX', 'NBBY', 'CLK_TCK', 'HZ', 'MINSIGSTKSZ', 'SIGSTKSZ', 'NSIG',
            '_NSIG', 'MAXSIG', 'NUMBER_OF', 'ACL_', 'SCHED_', 'PST_', 'NGROUPS', 'MAXUPRC', 'LOCK_',
            'MADV_', 'MCL_', 'UTSLEN', 'SNLEN', 'DIRSIZ', 'MAXHOSTNAMELEN', 'TTY', 'TIOCM_', 'MODEM', 'MCGETA',
            'MCSETA', 'MCGETT', 'MCSETT', 'UIO_', 'IOV_MAX', 'PF_', 'FIONREAD', 'FIONBIO', 'FIOASYNC', 'FIOSETOWN',
            'FIOGETOWN', 'SIOCGIFCONF', 'MINSIGSTKSZ', 'CLOCK_', 'TIMER_', 'FFSYNC', 'ACCESS_', 'ACCESSX',
            'SIGEV_', 'LWP_', '_POSIX_', 'STREAM', 'SAVE', 'TCOOFF', 'TCOON', 'TCIOFF', 'TCION', 'TCIFLUSH',
            'TCOFLUSH', 'TCIOFLUSH', 'TCSANOW', 'TCSADRAIN', 'TCSAFLUSH', 'FD_SETSIZE', 'NFDBITS', 'MNTTYPE',
            'MNTOPT', 'NAME_', 'LINK_MAX', 'PIPE_BUF', 'CHILD_MAX', 'ARG_MAX', 'NZERO', 'SIGPOLL', 'SIGXCPU',
            'FNONBLOCK', 'FNONBIO', 'FSYNC', 'FCREAT', 'FEXCL', 'FNOCTTY', 'FTRUNC', 'FREAD', 'FWRITE',
            'T_', 'TS_', 'TI_', 'TBAD', 'TNO', 'TOUTSTATE', 'TACCES', 'TSYSERR', 'TLOOK', 'TBUFOVFLW', 'TFLOW',
            'TSTATECHNG', 'TADDRBUSY', 'TINDOUT', 'TPROVMISMATCH', 'TRESQLEN', 'TRESADDR', 'TQFULL', 'TPROTO',
            'RNORM', 'RMSGD', 'RMSGN', 'RPROT', 'MORECTL', 'MOREDATA', 'RS_')

STRUCTS = """stat stat64 termios termio sgttyb winsize sigaction sigcontext sigvec sigstack sigaltstack
dirent __dirent64 utsname rusage timeval timezone timespec itimerval rlimit rlimit64 flock flock64 statvfs
statvfs64 statfs sockaddr sockaddr_in sockaddr_un msghdr iovec linger tms timeb ipc_perm shmid_ds semid_ds
msqid_ds sembuf pst_status pst_static pst_dynamic pst_vminfo pst_processor pollfd strbuf ustat utimbuf
sigset_t siginfo_t ucontext mcontext_t pst_filedetails pst_fileinfo mtget mtop sched_param group passwd
__save_state __ss_narrow __fp_dbl_block siglocal_misc siglocal frame_marker __ucontext __sub_ctxt siglocalx ifreq ifconf strioctl
T_info_ack T_bind_req T_bind_ack T_ok_ack T_error_ack T_conn_req T_conn_con T_conn_ind T_discon_ind T_optmgmt_req""".split()

MEMBERS = {
    'stat': 'st_dev st_ino st_mode st_nlink st_rdev st_size st_atime st_mtime st_ctime st_blksize st_blocks st_uid st_gid st_basemode st_fstype st_realdev st_netdev st_netino',
    'stat64': 'st_dev st_ino st_mode st_nlink st_rdev st_size st_atime st_mtime st_ctime st_blksize st_blocks st_uid st_gid st_basemode st_fstype st_realdev',
    'termios': 'c_iflag c_oflag c_cflag c_lflag c_reserved c_cc',
    'termio': 'c_iflag c_oflag c_cflag c_lflag c_line c_cc',
    'sgttyb': 'sg_ispeed sg_ospeed sg_erase sg_kill sg_flags',
    'winsize': 'ws_row ws_col ws_xpixel ws_ypixel',
    'sigaction': 'sa_handler sa_mask sa_flags',
    'sigcontext': 'sc_syscall sc_syscall_action sc_pad1 sc_pad2 sc_ctxt sc_sl sc_args sc_sfm',
    '__save_state': 'ss_flags ss_narrow ss_pad ss_fpblock ss_xor ss_wide',
    '__ss_narrow': 'ss_gr1 ss_rp ss_gr3 ss_gr4 ss_gr5 ss_gr6 ss_gr7 ss_gr8 ss_gr9 ss_gr10 ss_gr11 ss_gr12 ss_gr13 ss_gr14 ss_gr15 ss_gr16 ss_gr17 ss_gr18 ss_gr19 ss_gr20 ss_gr21 ss_gr22 ss_arg3 ss_arg2 ss_arg1 ss_arg0 ss_dp ss_ret0 ss_ret1 ss_sp ss_gr31 ss_cr11 ss_pcoq_head ss_pcsq_head ss_pcoq_tail ss_pcsq_tail ss_cr15 ss_cr19 ss_cr20 ss_cr21 ss_cr22 ss_cpustate ss_sr4 ss_sr0 ss_sr1 ss_sr2 ss_sr3 ss_sr5 ss_sr6 ss_sr7 ss_cr0 ss_cr8 ss_cr9 ss_cr10 ss_cr12 ss_cr13 ss_cr24 ss_cr25 ss_cr26 ss_mpsfu_high ss_mpsfu_low ss_mpsfu_ovflo',
    '__fp_dbl_block': 'ss_fp0 ss_fp1 ss_fp31',
    'siglocal_misc': 'sm_syscall sm_onstack sm_omask sm_syscall_action sm_eosys sm_error sm_rval1 sm_rval2 sm_arg',
    'siglocal': 'sl_misc sl_ss',
    '__ucontext': 'uc_mcontext uc_spares uc_subcontext',
    '__sub_ctxt': '__uc_link __uc_sigmask __uc_stack',
    'siglocalx': 'sl_misc sl_uc sl_si',
    'ifreq': 'ifr_name ifr_ifru',
    'ifconf': 'ifc_len ifc_ifcu',
    'frame_marker': 'fm_edp fm_esr4 fm_erp fm_crp fm_sl fm_clup fm_ep fm_psp',
    'sigvec': 'sv_handler sv_mask sv_flags',
    'sigstack': 'ss_sp ss_onstack',
    'sigaltstack': 'ss_sp ss_size ss_flags',
    'dirent': 'd_ino d_reclen d_namlen d_name',
    '__dirent64': 'd_ino d_reclen d_namlen d_name',
    'utsname': 'sysname nodename release version machine __idnumber',
    'rusage': 'ru_utime ru_stime ru_maxrss ru_ixrss ru_idrss ru_isrss ru_minflt ru_majflt ru_nswap ru_inblock ru_oublock ru_msgsnd ru_msgrcv ru_nsignals ru_nvcsw ru_nivcsw',
    'timeval': 'tv_sec tv_usec',
    'timezone': 'tz_minuteswest tz_dsttime',
    'timespec': 'tv_sec tv_nsec',
    'itimerval': 'it_interval it_value',
    'rlimit': 'rlim_cur rlim_max',
    'rlimit64': 'rlim_cur rlim_max',
    'flock': 'l_type l_whence l_start l_len l_pid',
    'flock64': 'l_type l_whence l_start l_len l_pid',
    'statvfs': 'f_bsize f_frsize f_blocks f_bfree f_bavail f_files f_ffree f_favail f_basetype f_namemax f_fsid f_flag',
    'statvfs64': 'f_bsize f_frsize f_blocks f_bfree f_bavail f_files f_ffree f_favail f_basetype f_namemax f_fsid f_flag',
    'statfs': 'f_type f_bsize f_blocks f_bfree f_bavail f_files f_ffree f_fsid f_magic f_featurebits f_cnode',
    'sockaddr': 'sa_family sa_data',
    'sockaddr_in': 'sin_family sin_port sin_addr sin_zero',
    'sockaddr_un': 'sun_family sun_path',
    'msghdr': 'msg_name msg_namelen msg_iov msg_iovlen msg_accrights msg_accrightslen',
    'iovec': 'iov_base iov_len',
    'linger': 'l_onoff l_linger',
    'tms': 'tms_utime tms_stime tms_cutime tms_cstime',
    'timeb': 'time millitm timezone dstflag',
    'ipc_perm': 'uid gid cuid cgid mode seq key',
    'shmid_ds': 'shm_perm shm_segsz shm_lpid shm_cpid shm_nattch shm_atime shm_dtime shm_ctime',
    'semid_ds': 'sem_perm sem_base sem_nsems sem_otime sem_ctime',
    'msqid_ds': 'msg_perm msg_first msg_last msg_cbytes msg_qnum msg_qbytes msg_lspid msg_lrpid msg_stime msg_rtime msg_ctime',
    'sembuf': 'sem_num sem_op sem_flg',
    'pst_status': 'pst_idx pst_uid pst_pid pst_ppid pst_dsize pst_tsize pst_ssize pst_nice pst_ttydev pst_pgrp pst_pri pst_addr pst_cpu pst_utime pst_stime pst_start pst_flag pst_stat pst_wchan pst_procnum pst_cmd pst_time pst_cpticks pst_cptickstotal pst_fss pst_pctcpu pst_rssize pst_suid pst_shmsize pst_mmsize pst_usize pst_iosize pst_vtsize pst_vdsize pst_vssize pst_vshmsize pst_vmmsize pst_vusize pst_viosize pst_minorfaults pst_majorfaults pst_nswap pst_nsignals pst_msgrcv pst_msgsnd pst_maxrss pst_sid pst_schedpolicy pst_ticksleft pst_euid pst_egid pst_highestfd pst_ioch pst_uname pst_ucomm pst_gid pst_rssize pst_inblock pst_oublock pst_term',
    'pst_static': 'max_proc page_size boot_time pst_maxmem physical_memory cpu_states',
    'pst_dynamic': 'psd_proc_cnt psd_max_proc_cnt psd_last_pid psd_rq psd_dw psd_pw psd_sl psd_sw psd_avg_1_min psd_avg_5_min psd_avg_15_min psd_cpu_time psd_activecpu',
    'pst_vminfo': 'psv_sswtch psv_sintr psv_ssyscall psv_cpu psv_sxbrd psv_rfree',
    'pollfd': 'fd events revents',
    'strbuf': 'maxlen len buf',
    'ustat': 'f_tfree f_tinode f_fname f_fpack f_blksize',
    'utimbuf': 'actime modtime',
    'siginfo_t': 'si_signo si_errno si_code si_pid si_uid si_addr si_status si_value',
    'ucontext': 'uc_link uc_sigmask uc_stack uc_mcontext',
    'mtget': 'mt_type mt_dsreg mt_gstat mt_erreg mt_resid mt_fileno mt_blkno',
    'mtop': 'mt_op mt_count',
    'sched_param': 'sched_priority',
    'pst_fileinfo': 'psf_idx psf_fd psf_ftype psf_offset psf_flag',
}


def main(argv):
    modname = 'consts'
    extra = []
    args = []
    i = 1
    while i < len(argv):
        if argv[i] == '-o':
            modname = argv[i + 1]
            i += 2
            continue
        if argv[i].startswith('-D'):
            extra.append(argv[i])
        else:
            args.append(argv[i])
        i += 1
    root = args[0] if args else rootdir.default_root()
    inc = os.path.join(root, 'usr/include')
    defs = ['-D__hp9000s800', '-D__hppa', '-D_HPUX_SOURCE', '-D_LARGEFILE64_SOURCE', '-D_PROTOTYPES', '-D_INCLUDE_HPUX_SOURCE',
            '-D_INCLUDE_XOPEN_SOURCE', '-D_INCLUDE_XOPEN_SOURCE_EXTENDED', '-D_INCLUDE_POSIX_SOURCE', '-D_INCLUDE_AES_SOURCE',
            '-D_INCLUDE_POSIX4_SOURCE', '-D_INCLUDE_POSIX2_SOURCE', '-D__STDC_EXT__'] + extra
    with tempfile.TemporaryDirectory() as tmp:
        allh = os.path.join(tmp, 'all.h')
        present = [h for h in HEADERS if os.path.exists(os.path.join(inc, h))]
        with open(allh, 'w') as f:
            for h in present:
                f.write('#include <%s>\n' % h)
        out = subprocess.run(['cpp', '-P', '-dM', '-nostdinc', '-I' + inc] + defs + [allh], capture_output=True, text=True)
        macros = {}
        for line in out.stdout.split('\n'):
            m = re.match(r'#define (\w+) (.*)', line)
            if m and '(' not in m.group(1):
                macros[m.group(1)] = m.group(2)
        cands = sorted(n for n in macros if any(n.startswith(p) for p in PREFIXES) and n != 'SIG_DFL' and n != 'SIG_IGN' and n != 'SIG_ERR' and n != 'SIG_HOLD')
        cands = [n for n in cands if not re.match(r'^E$', n)]
        # evaluate with the compiler: one constant per line, so failing lines can be dropped
        keep = cands
        struct_members = {s: MEMBERS.get(s, '').split() for s in STRUCTS}
        for attempt in range(12):
            src = os.path.join(tmp, 'c.c')
            with open(src, 'w') as f:
                f.write('#include <stddef.h>\n')
                for h in present:
                    f.write('#include <%s>\n' % h)
                for n in keep:
                    f.write('long long M_%s = (long long)(%s);\n' % (n, n))
                for s, mems in struct_members.items():
                    kw = '' if s.endswith('_t') else 'struct '
                    f.write('int S_%s = (int)sizeof(%s%s);\n' % (s, kw, s))
                    for mm in mems:
                        f.write('int O_%s_Z_%s[2] = {(int)offsetof(%s%s, %s), (int)sizeof(((%s%s*)0)->%s)};\n' % (s, mm, kw, s, mm, kw, s, mm))
            asm = os.path.join(tmp, 'c.s')
            # no 32-bit libgcc is needed: only the assembly is read (gcc -S)
            r = subprocess.run(['gcc', '-m32', '-malign-double', '-w', '-S', '-nostdinc', '-I' + inc,
                                '-I/usr/lib/gcc/x86_64-linux-gnu/13/include'] + defs + ['-o', asm, src], capture_output=True, text=True)
            if r.returncode == 0:
                break
            bad_lines = set()
            for m in re.finditer(r'c\.c:(\d+):', r.stderr):
                bad_lines.add(int(m.group(1)))
            if not bad_lines:
                print(r.stderr[:4000])
                return 1
            lines = open(src).read().split('\n')
            dropped = 0
            for ln in sorted(bad_lines):
                text = lines[ln - 1]
                mm = re.match(r'long long M_(\w+) ', text)
                if mm and mm.group(1) in keep:
                    keep.remove(mm.group(1))
                    dropped += 1
                mo = re.match(r'int O_(\w+)_Z_(\w+)\[', text)
                if mo and mo.group(1) in struct_members:
                    struct_members[mo.group(1)] = [x for x in struct_members[mo.group(1)] if x != mo.group(2)]
                    dropped += 1
                ms = re.match(r'int S_(\w+) ', text)
                if ms and ms.group(1) in struct_members:
                    del struct_members[ms.group(1)]
                    dropped += 1
            if not dropped:
                print(r.stderr[:4000])
                return 1
        else:
            print('could not compile')
            return 1
        # read the initialised values back from the assembly
        res = []
        cur = None
        vals = []
        for line in open(asm):
            m = re.match(r'^(M_\w+|S_\w+|O_\w+):', line)
            if m:
                if cur:
                    res.append((cur, vals))
                cur = m.group(1)
                vals = []
                continue
            m = re.match(r'^\s+\.(long|quad)\s+(-?\d+)', line)
            if m and cur:
                vals.append((m.group(1), int(m.group(2))))
            m = re.match(r'^\s+\.zero\s+(\d+)', line)
            if m and cur:
                # a zero-initialised object: as many zero words
                for _ in range(int(m.group(1)) // 4):
                    vals.append(('long', 0))
        if cur:
            res.append((cur, vals))
    consts = {}
    sizes = {}
    offsets = {}
    for name, vals in res:
        if name.startswith('M_'):
            # a long long: two .long (low, high) or one .quad
            if len(vals) == 2 and vals[0][0] == 'long':
                v = (vals[0][1] & 0xFFFFFFFF) | ((vals[1][1] & 0xFFFFFFFF) << 32)
            elif vals:
                v = vals[0][1] & 0xFFFFFFFFFFFFFFFF
            else:
                continue
            if v >= 1 << 63:
                v -= 1 << 64
            consts[name[2:]] = v
        elif name.startswith('S_'):
            sizes[name[2:]] = vals[0][1] if vals else 0
        elif name.startswith('O_'):
            s_, m_ = name[2:].split('_Z_', 1)
            if len(vals) >= 2:
                offsets.setdefault(s_, {})[m_] = (vals[0][1], vals[1][1])
    out = os.path.join(HERE, '..', 'hpuxemu', modname + '.py')
    release = open(os.path.join(root, 'etc/hpuxemu/release')).read().strip()
    with open(out, 'w') as f:
        f.write('"""%s.py - constants and structure layouts of HP-UX %s, generated by\n' % (modname, release[2:]))
        f.write('tools/genconsts.py %sfrom the root\'s /usr/include (do not edit).' % ''.join(e + ' ' for e in extra))
        f.write(' Values are what the C\n'
                'headers define; `SIZEOF[struct]` and `OFFSET[struct][member] = (offset, size)` come\n'
                'from gcc -m32 -malign-double over the same headers (docs/ABI.md checks them against\n'
                'what the binaries do)."""\n\n')
        f.write('# release the headers came from\nRELEASE = %r\n\n' % open(os.path.join(root, 'etc/hpuxemu/release')).read().strip())
        f.write('C = {\n')
        for n in sorted(consts):
            f.write('    %r: %d,\n' % (n, consts[n]))
        f.write('}\n\n')
        f.write('SYSCALL_NAMES = {\n')
        for n in sorted(consts):
            if n.startswith('SYS_') and n[4:].islower():
                f.write('    %d: %r,\n' % (consts[n], n[4:]))
        f.write('}\n\n')
        f.write('ERRNO_NAMES = {\n')
        seen = set()
        for n in sorted(consts, key=lambda x: (consts[x], x)):
            if n.startswith('E') and n[1:].isalnum() and n[1:].isupper() and consts[n] > 0 and consts[n] not in seen and n not in ('EXTA', 'EXTB', 'ECHO', 'ECHOE', 'ECHOK', 'ECHONL', 'ECHOCTL', 'ECHOPRT', 'ECHOKE'):
                seen.add(consts[n])
                f.write('    %d: %r,\n' % (consts[n], n))
        f.write('}\n\n')
        f.write('SIGNAL_NAMES = {\n')
        seen = set()
        for n in sorted(consts, key=lambda x: (consts[x], x)):
            if re.match(r'^SIG[A-Z0-9]+$', n) and n not in ('SIGSTKSZ', 'SIGRTMAX', 'SIGRTMIN') and 0 < consts[n] < 64 and consts[n] not in seen:
                seen.add(consts[n])
                f.write('    %d: %r,\n' % (consts[n], n))
        f.write('}\n\n')
        f.write('SIZEOF = {\n')
        for s in sorted(sizes):
            f.write('    %r: %d,\n' % (s, sizes[s]))
        f.write('}\n\n')
        f.write('OFFSET = {\n')
        for s in sorted(offsets):
            f.write('    %r: {\n' % s)
            for mname, (o, sz) in sorted(offsets[s].items(), key=lambda kv: kv[1]):
                f.write('        %r: (%d, %d),\n' % (mname, o, sz))
            f.write('    },\n')
        f.write('}\n')
    print('%s: %d constants, %d structures' % (out, len(consts), len(sizes)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
