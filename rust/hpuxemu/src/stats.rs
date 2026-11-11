//! stats.rs - HPUXEMU_STATS=FILE: where each program image's time goes. One JSON line per
//! image (exit, exec) - wall and host CPU seconds, the seconds in the CPU, the image's
//! load, each system call's count and wall seconds, PC samples by mapped file
//! (tools/stats.py reads them).

use crate::host;
use crate::process::Process;
use std::collections::HashMap;

pub struct Stats {
    pub how: &'static str,
    pub prog: String,
    pub pid: u32,
    pub t0: f64,
    u0: f64,
    s0: f64,
    pub run: f64,
    pub nrun: u64,
    pub load: f64,
    pub calls: HashMap<&'static str, (u64, f64)>,
    pub pcs: HashMap<u32, u64>,
    /// executable file mappings: (base, size, host path, file offset)
    pub maps: Vec<(u32, u32, String, u64)>,
    pub last: Option<f64>,
}

fn jstr(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

impl Process {
    /// a new program image (exec, the first load) or a forked copy starts its account
    pub fn stats_begin(&mut self, how: &'static str, path: &str) {
        if host::getenv("HPUXEMU_STATS").map(|f| f.is_empty()).unwrap_or(true) {
            return;
        }
        let t = host::times();
        self.stats = Some(Box::new(Stats {
            how,
            prog: path.to_string(),
            pid: unsafe { libc::getpid() } as u32,
            t0: host::monotonic(),
            u0: t.0,
            s0: t.1,
            run: 0.0,
            nrun: 0,
            load: 0.0,
            calls: HashMap::new(),
            pcs: HashMap::new(),
            maps: Vec::new(),
            last: None,
        }));
    }

    /// 'file+0xoffset' for a PC in a mapped file (the program's text: its own path)
    fn stats_where(&self, pc: u32, st: &Stats) -> String {
        for (base, size, path, off) in &st.maps {
            if *base <= pc && (pc as u64) < *base as u64 + *size as u64 {
                let pre = format!("{}/", self.root);
                let p = if path.starts_with(&pre) { &path[self.root.len()..] } else { path.as_str() };
                return format!("{}+{:#x}", p, (pc - base) as u64 + off);
            }
        }
        for m in &self.mappings {
            if let Some(path) = &m.path {
                if m.base <= pc && (pc as u64) < m.base as u64 + m.size as u64 {
                    return format!("{}+{:#x}", path, (pc - m.base) as u64 + m.off);
                }
            }
        }
        if self.text_base <= pc && (pc as u64) < self.text_base as u64 + self.text_size as u64 {
            return format!("{}+{:#x}", st.prog, pc);
        }
        format!("?+{:#x}", pc)
    }

    /// the image ends (exit, exec), or a snapshot of one still running (keep)
    pub fn stats_end(&mut self, why: &str, keep: bool) {
        let mut st = match self.stats.take() {
            Some(s) => s,
            None => return,
        };
        let now = host::monotonic();
        st.last = Some(now);
        let t = host::times();
        let mut calls: Vec<(&&str, &(u64, f64))> = st.calls.iter().collect();
        calls.sort_by(|a, b| b.1 .1.partial_cmp(&a.1 .1).unwrap_or(std::cmp::Ordering::Equal));
        let mut rec = format!(
            "{{\"id\": \"{}-{:.6}\", \"pid\": {}, \"how\": {}, \"prog\": {}, \"end\": {}, \"wall\": {:.4}, \"user\": {:.3}, \"sys\": {:.3}, \"cpu_run\": {:.4}, \"nrun\": {}, \"load\": {:.4}, \"ncalls\": {}, \"call_wall\": {:.4}, \"calls\": {{",
            st.pid,
            st.t0,
            st.pid,
            jstr(st.how),
            jstr(&st.prog),
            jstr(why),
            now - st.t0,
            t.0 - st.u0,
            t.1 - st.s0,
            st.run,
            st.nrun,
            st.load,
            st.calls.values().map(|c| c.0).sum::<u64>(),
            st.calls.values().map(|c| c.1).sum::<f64>()
        );
        let parts: Vec<String> = calls.iter().take(25).map(|(k, v)| format!("{}: [{}, {:.4}]", jstr(k), v.0, v.1)).collect();
        rec.push_str(&parts.join(", "));
        rec.push('}');
        if let Some(a) = self.cpu.jit_stats() {
            rec.push_str(&format!(
                ", \"jit\": {{\"compiled\": {}, \"dropped\": {}, \"refused\": {}, \"flushes\": {}, \"insns\": {}, \"compile_s\": {:.4}, \"blocks_run\": {}, \"block_insns\": {}, \"steps\": {}, \"handovers\": {}}}",
                a[0], a[1], a[2], a[3], a[4], a[5] as f64 / 1e9, a[6], a[7], a[8], a[9]
            ));
        }
        if !st.pcs.is_empty() {
            // the samples by mapped file and offset (the program's own text by its path)
            let mut whr: HashMap<String, u64> = HashMap::new();
            for (pc, n) in &st.pcs {
                *whr.entry(self.stats_where(*pc, &st)).or_insert(0) += n;
            }
            let parts: Vec<String> = whr.iter().map(|(k, v)| format!("{}: {}", jstr(k), v)).collect();
            rec.push_str(&format!(", \"pcs\": {{{}}}", parts.join(", ")));
        }
        rec.push_str("}\n");
        if let Some(f) = host::getenv("HPUXEMU_STATS") {
            unsafe {
                let fd = libc::open(host::cstr(&f).as_ptr(), libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC, 0o644);
                if fd >= 0 {
                    libc::write(fd, rec.as_ptr() as *const libc::c_void, rec.len());
                    libc::close(fd);
                }
            }
        }
        if keep {
            self.stats = Some(st);
        }
    }
}
