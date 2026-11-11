//! loader.rs - loading a SOM executable, the initial stack, and the routines of dld.sl and
//! libc the CPU runs natively.

use crate::consts::*;
use crate::host::{self, to_latin1};
use crate::process::*;
use crate::sha256::{hex, sha256};
use crate::som::Som;

impl Process {
    pub fn find_program(&mut self, name: &str) -> String {
        if name.contains('/') {
            return name.to_string();
        }
        let path = self.env_get("PATH").unwrap_or("/usr/bin:/bin:/usr/ccs/bin:/sbin").to_string();
        for d in path.split(':') {
            let cand = format!("{}/{}", if d.is_empty() { "." } else { d }, name);
            if let Ok(hp) = self.hostpath(&cand) {
                if host::stat(&hp, true).map(|s| host::is_reg(&s)).unwrap_or(false)
                    && unsafe { libc::access(host::cstr(&hp).as_ptr(), libc::X_OK) } == 0
                {
                    return cand;
                }
            }
        }
        name.to_string()
    }

    /// Load a SOM executable the way the HP-UX 10.20 kernel does (binfmt-som style: text
    /// and data mapped from the file at their link addresses, bss zeroed, the stack at
    /// STACK_BASE with argc/argv/envp in r26/r25/r24 and the kernel's process-info block
    /// in r23), then start at the entry point.
    pub fn load(&mut self, path: &str, argv: Vec<String>, envp: Vec<String>) -> Res<()> {
        let hp = self.hostpath(path)?;
        // a missing program or #! interpreter: exec fails with ENOENT and the old image
        // goes on, as on HP-UX
        let data = match std::fs::read(&hp) {
            Ok(d) => d,
            Err(e) => return Err(herrno(e.raw_os_error().unwrap_or(libc::EIO))),
        };
        if data.starts_with(b"#!") {
            // an interpreter script
            let line = data[2..].split(|&c| c == b'\n').next().unwrap_or(&[]);
            let line = host::latin1(line);
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.is_empty() {
                return err(ENOEXEC);
            }
            let mut nargv: Vec<String> = words.iter().map(|s| s.to_string()).collect();
            nargv.push(path.to_string());
            nargv.extend(argv.into_iter().skip(1));
            let interp = words[0].to_string();
            return self.load(&interp, nargv, envp);
        }
        let s = match Som::new(&data) {
            Some(s) => s,
            None => return err(ENOEXEC),
        };
        let e = match s.exec {
            Some(e) if matches!(s.magic, 0x107 | 0x108 | 0x10b) => e,
            _ => return err(ENOEXEC),
        };
        let file = |off: u32, n: u32| -> &[u8] {
            let a = (off as usize).min(data.len());
            let b = (off as usize + n as usize).min(data.len());
            &data[a..b]
        };
        if !self.cpu_fresh {
            self.cpu = new_cpu();
        }
        self.cpu_fresh = false;
        self.native_list.clear();
        self.argv0 = path.to_string();
        self.argv = argv.clone();
        self.start_time = self.now() as i64;
        self.publish();
        // text: the file from tfile at tmem (for SHARE_MAGIC programs tfile is 0, so the
        // SOM header and the dictionaries are mapped too, at 0x1000: dld and crt0 read them)
        let tstart = e.tmem & !(PAGE - 1);
        let tlen = (e.tmem + e.tsize + PAGE - 1) & !(PAGE - 1);
        self.text_base = e.tmem;
        self.text_size = e.tsize;
        let mem = &mut self.cpu.mem;
        mem.map(tstart, tlen - tstart, 7);
        let _ = mem.write(e.tmem, file(e.tfile, e.tsize));
        mem.protect(tstart, tlen - tstart, 5);
        let dstart = e.dmem & !(PAGE - 1);
        let dend = (e.dmem + e.dsize + e.bsize + PAGE - 1) & !(PAGE - 1);
        // data, bss, the heap and the stack are executable, as on PA-RISC HP-UX: HP's Java VM
        // runs the code its JIT writes into malloc'd memory
        mem.map(dstart, dend - dstart, 7);
        let _ = mem.write(e.dmem, file(e.dfile, e.dsize));
        self.brk = dend;
        self.brk_base = dend;
        mem.map(self.brk, PAGE, 7); // the page beyond the break (sys_brk)
        if e.flags & 1 == 0 {
            // exec_flags bit 0 (ld -z) makes nil-pointer dereferences an error; without
            // it HP-UX lets a program read page 0 as zeros (head -3 reads argv past its end)
            mem.map(0, PAGE, 1);
        }
        // the stack
        mem.map(STACK_BASE, 256 * 1024, 7);
        self.stack_mapped_end = STACK_BASE + 256 * 1024;
        let presumed_dp = s.presumed_dp;
        let sp = self.build_stack(&argv, &envp);
        self.set_gr(30, sp);
        self.set_gr(27, presumed_dp);
        self.cpu.cr[27] = 0;
        self.cpu.set_pc(e.entry);
        self.set_gr(31, self.cpu.iaoq_f);
        Ok(())
    }

    /// argv/envp strings and vectors at the bottom of the stack, then the kernel's
    /// process-info block (what crt0 reads through r23), then sp (64-byte aligned, with
    /// the argument slots -36..-48(sp) filled as the calling convention has them).
    fn build_stack(&mut self, argv: &[String], envp: &[String]) -> u32 {
        // (the stack is mapped 256 KB at first: more arguments than that need more)
        let need: usize = argv.iter().chain(envp.iter()).map(|a| a.len() + 5).sum::<usize>() + 4096;
        if need > 256 * 1024 - 65536 {
            let size = ((need + 65536 + PAGE as usize - 1) & !(PAGE as usize - 1)) as u32;
            self.cpu.mem.map(STACK_BASE + 256 * 1024, size - 256 * 1024, 7);
            self.stack_mapped_end = STACK_BASE + size;
        }
        let mem = &mut self.cpu.mem;
        let mut p = STACK_BASE + 16;
        let mut strs = Vec::new();
        for a in argv.iter().chain(envp.iter()) {
            strs.push(p);
            let mut b = to_latin1(a);
            b.push(0);
            let _ = mem.write(p, &b);
            p += b.len() as u32;
        }
        p = (p + 7) & !7;
        let argvp = p;
        for i in 0..argv.len() {
            let _ = mem.st32(p, strs[i]);
            p += 4;
        }
        let _ = mem.st32(p, 0);
        p += 4;
        let envpp = p;
        for i in 0..envp.len() {
            let _ = mem.st32(p, strs[argv.len() + i]);
            p += 4;
        }
        let _ = mem.st32(p, 0);
        p += 4;
        p = (p + 7) & !7;
        // the process-info block: crt0 copies word 0 to _CPU_REVISION, word 1's bits to
        // _FPU_MODEL/_FPU_REVISION, word 3 to _CPU_KEYBITS_1. Word 0 is the CPU version
        // sysconf(_SC_CPU_VERSION) gives: HP's Java VM checks
        // _CPU_REVISION for PA-RISC 1.0/1.1/2.0 and its JIT gives up - with a longjmp to a
        // buffer nothing has set - when it is none of them
        let info = p;
        let _ = mem.st32(p, CPU_PA_RISC1_1);
        let _ = mem.write(p + 4, &[0u8; 12]);
        p += 16;
        let sp = (p + 64 + 63) & !63;
        let _ = mem.st32(sp - 36, argv.len() as u32);
        let _ = mem.st32(sp - 40, argvp);
        let _ = mem.st32(sp - 44, envpp);
        let _ = mem.st32(sp - 48, info);
        self.set_gr(26, argv.len() as u32);
        self.set_gr(25, argvp);
        self.set_gr(24, envpp);
        self.set_gr(23, info);
        sp
    }

    /// the CPU's native routines are those of `native_list`
    pub fn set_natives(&mut self) {
        let l: Vec<(u32, hppa32_jit::NativeFn)> = self.native_list.iter().filter_map(|&(a, k)| hppa32_jit::hpux::routine(k).map(|f| (a, f))).collect();
        self.cpu.set_natives(&l);
    }

    /// dld.sl's or libc's text mapped executable: the CPU runs the routines of it that it
    /// knows natively from now on. Every executable file mapping is noted for
    /// HPUXEMU_STATS's PC samples.
    pub fn install_natives(&mut self, fd: u32, base: u32, off: u64, size: u32, prot: u32, anon: bool) {
        if anon || prot & PROT_EXEC == 0 {
            return;
        }
        let hp = match host::readlink(&format!("/proc/self/fd/{}", fd)) {
            Ok(h) => h,
            Err(_) => return,
        };
        if let Some(st) = self.stats.as_mut() {
            st.maps.push((base, size, hp.clone(), off));
        }
        let name = hp.rsplit('/').next().unwrap_or("");
        if !(name.starts_with("dld") || name.starts_with("libc.")) {
            return;
        }
        let found = natives_for(&hp, base, off, size);
        if !found.is_empty() {
            self.native_list.retain(|e| !(base <= e.0 && e.0 < base.wrapping_add(size)));
            self.native_list.extend(found);
            self.set_natives();
        }
    }
}

// ---- which routines of a mapped library the CPU may run natively -------------------------
//
// dld.sl resolves a large program's symbols with three small routines it calls millions of
// times, and a loop over each library's export hash chain (findlibsym): `$$remU` (millicode
// remainder: PA-RISC 1.1 divides a bit per step), `hash_string` and `strcmp`. When a process
// maps dld.sl's text executable, natives_for finds them by the library's symbol table,
// checks each routine's code against the versions whose native equivalent
// (rust/hppa32-jit/src/hpux.rs) was compared with the real code instruction for instruction
// (tools/nativetest.py), and gives their run-time addresses. Unknown code - another dld.sl,
// a patch that changed one - is left to run as it is.
//
// HPUXEMU_NATIVE=0 turns it off; HPUXEMU_NATIVE=calls leaves findlibsym's loop to the real
// code (the three called routines stay native).

const REMU_A: u8 = 1;
const HASH_A: u8 = 2;
const STRCMP: u8 = 3;
const REMU_B: u8 = 4;
const HASH_B: u8 = 5;
const HASH_C: u8 = 6;
const WALK_A: u8 = 7;
const WALK_B: u8 = 8;
const WALK_C: u8 = 9;
const LSTRCMP_A: u8 = 10;
const LSTRCMP_B: u8 = 11;
const LSTRCMP_C: u8 = 12;

/// (symbol, length of its code, sha256 of it: first 24 hex digits, kind, the entry's
/// offset in the routine): each routine from its symbol to its last return, compared
/// register for register with native.rs by tools/nativetest.py. findlibsym's loop over an
/// export hash chain is entered at its head, inside the routine; the whole routine is
/// fingerprinted, since the native walk resumes in it and relies on its register use.
const FINGERPRINTS: &[(&str, usize, &str, u8, u32)] = &[
    // dld.sl of 10.20 with patches and of 11.00
    ("$$remU", 0x140, "dc785fc0ebe228b42c343dcb", REMU_A, 0),
    ("hash_string", 0x28, "9160ee50e9b95ee657fb33fb", HASH_A, 0),
    ("strcmp", 0x2a8, "fd185bf6b6b68566ea51621c", STRCMP, 0),
    ("hash_string", 0x28, "c804963defb33f9c5c35b0c8", HASH_B, 0),
    ("strcmp", 0x2a8, "fe31f76e0efae02e735695fc", STRCMP, 0),
    // 10.20's original dld.sl
    ("$$remU", 0x12c, "ea578e76a942f8d8c57789e6", REMU_B, 0),
    ("hash_string", 0x30, "706375441247db5a5ab08f9f", HASH_C, 0),
    // libc.1's strcmp (the routine itself, after its export stub), up to its multibyte path
    ("strcmp", 0x2b8, "ddadeccaa731866040d5e199", LSTRCMP_A, 0), // 10.20
    ("strcmp", 0x2b8, "a47ae4a2794ddfa72355b2ca", LSTRCMP_B, 0), // 11.00's libc.1
    ("strcmp", 0x2b8, "705e0b7a002dda303f33885e", LSTRCMP_C, 0), // 11.00's libc.2
    ("findlibsym", 0x298, "939b8cba4a24876b29b750c2", WALK_A, 0x90), // 10.20 with patches
    ("findlibsym", 0x308, "5c1500d9665472b05c67f12a", WALK_B, 0x94), // 11.00
    ("findlibsym", 0x2b0, "3cd9b29dcd98154bcd368b18", WALK_C, 0x90), // 10.20
];
const NAMES: [&[u8]; 4] = [b"$$remU", b"hash_string", b"strcmp", b"findlibsym"];
/// bumped when FINGERPRINTS changes: the cached tables are for one version
const TABLE_VERSION: u32 = 1;

/// [(file offset of the entry, kind, file offset and length of the code it relies on)] for
/// the known routines of the library at host `path`. Reading a library's symbols and
/// fingerprinting takes milliseconds, which every process start would pay for libc: the
/// table is kept in the user's cache directory, for the file's path, mtime and size.
fn table(path: &str) -> Vec<(u64, u8, u64, u64)> {
    let st = match host::stat(path, true) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let real = std::fs::canonicalize(path).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| path.to_string());
    let key = format!("{} {} {} {} v{}", real, st.st_mtime, st.st_mtime_nsec, st.st_size, TABLE_VERSION);
    let cache = format!("{}/natives-{}.txt", host::cache_dir(), &hex(&sha256(key.as_bytes()))[..24]);
    if let Ok(txt) = std::fs::read_to_string(&cache) {
        let mut out = Vec::new();
        let mut good = txt.ends_with("end\n");
        for line in txt.lines() {
            if line == "end" {
                break;
            }
            let v: Vec<u64> = line.split(' ').filter_map(|x| x.parse().ok()).collect();
            if v.len() != 4 {
                good = false;
                break;
            }
            out.push((v[0], v[1] as u8, v[2], v[3]));
        }
        if good {
            return out;
        }
    }
    let mut out = Vec::new();
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return out,
    };
    if let Some(s) = Som::new(&data) {
        let subs = s.subspaces();
        let mut seen: Vec<(String, u64)> = Vec::new();
        for (name, value) in s.symbols(&|n| NAMES.contains(&n)) {
            if value == 0 {
                continue;
            }
            let v = value & !3;
            for ss in &subs {
                if ss.length != 0 && ss.start <= v && (v as u64) < ss.start as u64 + ss.length as u64 {
                    let f = (v - ss.start) as u64 + ss.file_loc as u64;
                    if !seen.iter().any(|x| x.0 == name && x.1 == f) {
                        seen.push((name.clone(), f));
                    }
                    break;
                }
            }
        }
        for (name, foff) in seen {
            for &(n, length, fp, kind, head) in FINGERPRINTS {
                let f = foff as usize;
                if n == name && f + length <= data.len() && &hex(&sha256(&data[f..f + length]))[..24] == fp {
                    out.push((foff + head as u64, kind, foff, length as u64));
                    break;
                }
            }
        }
    }
    let _ = std::fs::create_dir_all(host::cache_dir());
    let tmp = format!("{}.{}", cache, unsafe { libc::getpid() });
    let mut txt = String::new();
    for e in &out {
        txt.push_str(&format!("{} {} {} {}\n", e.0, e.1, e.2, e.3));
    }
    txt.push_str("end\n");
    if std::fs::write(&tmp, txt).is_ok() {
        let _ = std::fs::rename(&tmp, &cache);
    }
    out
}

/// [(run-time address, kind)] for the known routines of the library at host `path`, whose
/// file bytes from `off` are mapped at `base` for `size` bytes
fn natives_for(path: &str, base: u32, off: u64, size: u32) -> Vec<(u32, u8)> {
    let mode = host::getenv("HPUXEMU_NATIVE").unwrap_or_else(|| "1".to_string());
    if mode == "0" {
        return Vec::new();
    }
    let mut found = Vec::new();
    for (entry, kind, foff, length) in table(path) {
        if mode == "calls" && matches!(kind, WALK_A | WALK_B | WALK_C) {
            continue;
        }
        if off <= foff && foff + length <= off + size as u64 {
            found.push(((base as u64 + entry - off) as u32, kind));
        }
    }
    found
}
