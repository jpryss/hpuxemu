//! hpuxemu - user-mode emulator for 32-bit HP-UX 10.20/11.00 PA-RISC programs (Rust
//! implementation; hpuxemu/emu.py is the reference, docs/DESIGN.md explains the design,
//! docs/ABI.md the interface).
//!
//!     hpuxemu [-r ROOT] [-t] [-e VAR=VAL] [-0 ARGV0] [-C DIR] [-u USER] PROGRAM [ARGS...]

mod consts;
mod host;
mod kernel;
mod loader;
mod netman;
mod owners;
mod process;
mod sha256;
mod signals;
mod signals_table;
mod som;
mod stats;
mod streams;
mod syscalls;
mod threads;

use consts::ENOEXEC;
use process::{Exited, Process, Stop};

const USAGE: &str = "hpuxemu - the HP-UX emulator: loader, process, system calls

    hpuxemu [-r ROOT] [-t] [-e VAR=VAL] [-0 ARGV0] [-C DIR] [-u USER] PROGRAM [ARGS...]

PROGRAM is a path inside the root (or a name looked up on the guest's PATH). -0 sets its
argv[0] (a login shell is started as \"-sh\"), -C the working directory (/), -u the user
it runs as (a name or uid from the root's /etc/passwd; root by default). -t traces
system calls like HP-UX's `tusc`. The root is $HPUX_ROOT, ./hpuxroot or ../hpuxroot when
-r does not name it.
";

/// where the HP-UX root is when none is given: $HPUX_ROOT, else ./hpuxroot, else
/// ../hpuxroot, else `hpuxroot` next to the repository the program was built in
fn default_root() -> String {
    if let Some(e) = host::getenv("HPUX_ROOT").filter(|e| !e.is_empty()) {
        return e;
    }
    for cand in ["hpuxroot", "../hpuxroot"] {
        if std::path::Path::new(cand).is_dir() {
            if let Ok(p) = std::fs::canonicalize(cand) {
                return p.to_string_lossy().into_owned();
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        for dir in exe.ancestors().skip(1) {
            let c = dir.join("hpuxroot");
            if c.is_dir() {
                return c.to_string_lossy().into_owned();
            }
        }
    }
    "hpuxroot".to_string()
}

/// (uid, gid, groups) of a user in the root's /etc/passwd and /etc/group
fn lookup_user(root: &str, who: &str) -> (u32, u32, Vec<u32>) {
    let digits = !who.is_empty() && who.bytes().all(|c| c.is_ascii_digit());
    let mut found: Option<(String, u32, u32)> = None;
    if let Ok(b) = std::fs::read(format!("{}/etc/passwd", root)) {
        for line in host::latin1(&b).lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 4 && (f[0] == who || (digits && f[2] == who)) {
                if let (Ok(u), Ok(g)) = (f[2].parse(), f[3].parse()) {
                    found = Some((f[0].to_string(), u, g));
                    break;
                }
            }
        }
    }
    let (name, uid, gid) = match found {
        Some(x) => x,
        None => {
            if digits {
                let n = who.parse().unwrap_or(0);
                return (n, n, Vec::new());
            }
            emsg!("hpuxemu: no such user in the root: {}\n", who);
            std::process::exit(2);
        }
    };
    let mut groups = Vec::new();
    if let Ok(b) = std::fs::read(format!("{}/etc/group", root)) {
        for line in host::latin1(&b).lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 4 && f[3].split(',').any(|m| m == name) {
                match f[2].parse::<u32>() {
                    Ok(g) if g != gid => groups.push(g),
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }
    (uid, gid, groups)
}

/// The host's process ids are the guest's, and HP-UX 10.20's are at most 30000 (MAXPID):
/// csh loses track of a child with a larger id and waits for it for ever (its job table
/// keeps the id in 16 bits, as old code did). Linux's kernel.pid_max is often 4194304:
/// say so, once.
fn warn_pid_max() {
    if host::getenv("HPUXEMU_PID_MAX_OK").map(|v| !v.is_empty()).unwrap_or(false) {
        return;
    }
    std::env::set_var("HPUXEMU_PID_MAX_OK", "1");
    if let Some(n) = std::fs::read_to_string("/proc/sys/kernel/pid_max").ok().and_then(|s| s.trim().parse::<u64>().ok()) {
        if n > 30000 {
            emsg!(
                "hpuxemu: warning: kernel.pid_max is {}; HP-UX programs need process ids up to 30000 (csh hangs otherwise):\n    sudo sysctl -w kernel.pid_max=30000\n",
                n
            );
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    // The emulator's own messages (traces, faults, unimplemented calls) go to a private
    // copy of the original stderr at a high descriptor: an HP-UX fd *is* the host fd, so a
    // daemon that closes 0-2 (portmap, ttsession) would otherwise close the emulator's
    // stderr too.
    unsafe {
        let fd = libc::fcntl(2, libc::F_DUPFD, 900);
        if fd >= 0 {
            host::ERR_FD = fd;
        }
        // a program that writes to a pipe nobody reads dies of SIGPIPE unless it says
        // otherwise (Rust's start-up ignores the signal)
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let (mut root, mut trace, mut user, mut argv0, mut cwd) = (None::<String>, false, None::<String>, None::<String>, "/".to_string());
    let mut env: Vec<(String, String)> = Vec::new();
    let mut i = 1;
    while i < argv.len() && argv[i].starts_with('-') && argv[i] != "-" {
        let a = argv[i].as_str();
        if matches!(a, "-r" | "-e" | "--cpu" | "-0" | "-C" | "-u") && i + 1 >= argv.len() {
            emsg!("hpuxemu: {} needs a value\n", a);
            std::process::exit(2);
        }
        match a {
            "-r" => {
                i += 1;
                root = Some(argv[i].clone());
            }
            "-t" => trace = true,
            "-e" => {
                i += 1;
                let (k, v) = argv[i].split_once('=').unwrap_or((&argv[i], ""));
                env.push((k.to_string(), v.to_string()));
            }
            // (the Python emulator's choice of CPU: there is one here)
            "--cpu" => i += 1,
            // argv[0] for the program (a login shell is started as "-sh")
            "-0" => {
                i += 1;
                argv0 = Some(argv[i].clone());
            }
            "-C" => {
                i += 1;
                cwd = argv[i].clone();
            }
            // start as a user of the root's /etc/passwd (name or uid), with its groups
            "-u" => {
                i += 1;
                user = Some(argv[i].clone());
            }
            _ => {
                print!("{}", USAGE);
                std::process::exit(2);
            }
        }
        i += 1;
    }
    if i >= argv.len() {
        print!("{}", USAGE);
        std::process::exit(2);
    }
    let root = root.unwrap_or_else(default_root);
    let user = user.map(|u| lookup_user(&root, &u));
    warn_pid_max();
    let mut envd: Vec<(String, String)> = vec![
        ("PATH".into(), "/usr/bin:/usr/ccs/bin:/usr/contrib/bin:/opt/langtools/bin:/sbin".into()),
        ("HOME".into(), "/".into()),
        ("TERM".into(), host::getenv("TERM").unwrap_or_else(|| "vt100".to_string())),
        ("LOGNAME".into(), "root".into()),
        ("SHELL".into(), "/usr/bin/sh".into()),
        ("TZ".into(), "MET-1METDST".into()),
    ];
    for (k, v) in env {
        match envd.iter_mut().find(|e| e.0 == k) {
            Some(e) => e.1 = v,
            None => envd.push((k, v)),
        }
    }
    let envp: Vec<String> = envd.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
    let mut p = Process::new(&root, trace, envd);
    p.cwd = cwd;
    if let Some((uid, gid, groups)) = user {
        p.uid = uid;
        p.euid = uid;
        p.suid = uid;
        p.gid = gid;
        p.egid = gid;
        p.sgid = gid;
        p.groups = groups;
    }
    for fd in 0..3 {
        p.newfd(fd, "/dev/tty", 0);
    }
    let prog = p.find_program(&argv[i]);
    let mut args = vec![argv0.unwrap_or_else(|| argv[i].clone())];
    args.extend(argv[i + 1..].iter().cloned());
    p.stats_begin("start", &prog);
    let t0 = host::monotonic();
    let mut r = p.load(&prog, args.clone(), envp.clone());
    if let Err(Stop::Errno(ENOEXEC)) = r {
        // not a SOM file and no #! line: a shell script, as execvp would run it
        let mut sh = vec!["sh".to_string(), prog.clone()];
        sh.extend(args[1..].iter().cloned());
        r = p.load("/usr/bin/sh", sh, envp);
    }
    if let Err(e) = r {
        let what = match e {
            Stop::Errno(n) => host::errno_name(n),
            _ => "cannot load".to_string(),
        };
        emsg!("hpuxemu: {}: {}\n", argv[i], what);
        std::process::exit(127);
    }
    if let Some(s) = p.stats.as_mut() {
        s.load = host::monotonic() - t0;
    }
    let r = p.run();
    p.unpublish();
    let code = match r {
        Exited::Exit(c) => c as i32,
        Exited::Signal(s) => 128 + s as i32,
    };
    if host::getenv("HPPA_JIT_TRACE").is_some() {
        drop(p); // the JIT's trace prints when the CPU is freed
    }
    // (the kernel frees the rest: unmapping the CPU's 4 GB reservation by hand costs more
    // than a short program's whole run)
    unsafe { libc::_exit(code) }
}
