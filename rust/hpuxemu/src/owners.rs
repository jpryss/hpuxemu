//! owners.rs - the root's owners table (etc/hpuxemu/owners: the HP-UX mode, owner, group
//! and type of every file the depots delivered, by guest path; one line each, "mode uid
//! gid type path", written in path order).
//!
//! Every emulated process consults the table at its first stat, and parsing its 20,000
//! lines takes longer than many a program's run: a table in path order is searched as it
//! is, by bisection over the file's bytes. That the file is in order is checked once per
//! version of it (the check's result is kept in the user's cache directory); one that is
//! not is parsed into a map.

use crate::host;
use crate::sha256::{hex, sha256};
use std::collections::HashMap;

/// (mode, uid, gid, type)
pub type Owner = (u32, i64, i64, String);

pub enum Owners {
    Sorted(FileMap),
    Map(HashMap<String, Owner>),
}

/// a file mapped read-only (the table is a megabyte, a lookup touches a few pages of it)
pub struct FileMap {
    ptr: *mut libc::c_void,
    len: usize,
}

impl FileMap {
    fn open(path: &str) -> Option<FileMap> {
        unsafe {
            let fd = libc::open(host::cstr(path).as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return None;
            }
            let len = host::fstat(fd).map(|s| s.st_size as usize).unwrap_or(0);
            let ptr = if len == 0 { libc::MAP_FAILED } else { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_PRIVATE, fd, 0) };
            libc::close(fd);
            if ptr == libc::MAP_FAILED {
                return if len == 0 { Some(FileMap { ptr: std::ptr::null_mut(), len: 0 }) } else { None };
            }
            Some(FileMap { ptr, len })
        }
    }
    fn bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for FileMap {
    fn drop(&mut self) {
        if self.len != 0 {
            unsafe { libc::munmap(self.ptr, self.len) };
        }
    }
}

fn parse_line(line: &[u8]) -> Option<(&[u8], Owner)> {
    let mut it = line.splitn(5, |&c| c == b' ');
    let (m, u, g, t, path) = (it.next()?, it.next()?, it.next()?, it.next()?, it.next()?);
    let num = |b: &[u8], radix| i64::from_str_radix(std::str::from_utf8(b).ok()?, radix).ok();
    Some((path, (num(m, 8)? as u32, num(u, 10)?, num(g, 10)?, String::from_utf8_lossy(t).into_owned())))
}

fn path_of(line: &[u8]) -> Option<&[u8]> {
    line.splitn(5, |&c| c == b' ').nth(4)
}

fn is_sorted(data: &[u8]) -> bool {
    let mut prev: &[u8] = b"";
    for line in data.split(|&c| c == b'\n') {
        if line.is_empty() {
            continue;
        }
        match path_of(line) {
            Some(p) if p > prev => prev = p,
            _ => return false,
        }
    }
    true
}

fn parse_all(data: &[u8]) -> HashMap<String, Owner> {
    let mut m = HashMap::with_capacity(data.len() / 40);
    for line in data.split(|&c| c == b'\n') {
        if let Some((p, o)) = parse_line(line) {
            m.insert(String::from_utf8_lossy(p).into_owned(), o);
        }
    }
    m
}

/// the line containing byte `pos`: (start, end without the newline)
fn line_at(data: &[u8], pos: usize) -> (usize, usize) {
    let start = data[..pos].iter().rposition(|&c| c == b'\n').map(|i| i + 1).unwrap_or(0);
    let end = data[pos..].iter().position(|&c| c == b'\n').map(|i| pos + i).unwrap_or(data.len());
    (start, end)
}

/// where the first line whose path is not less than `key` starts
fn lower_bound(data: &[u8], key: &[u8]) -> usize {
    let (mut lo, mut hi) = (0usize, data.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (s, e) = line_at(data, mid);
        let less = match path_of(&data[s..e]) {
            Some(p) => p < key,
            None => true,
        };
        if less {
            lo = (e + 1).min(data.len());
        } else {
            hi = s;
        }
    }
    lo
}

impl Owners {
    /// the table of the file at `path` with the stamp (mtime in ns, size) `stamp`
    pub fn load(path: &str, stamp: Option<(i64, i64)>) -> Owners {
        let data = match FileMap::open(path) {
            Some(d) => d,
            None => return Owners::Map(HashMap::new()),
        };
        let real = std::fs::canonicalize(path).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| path.to_string());
        let mark = format!("{}/owners-{}.sorted", host::cache_dir(), &hex(&sha256(real.as_bytes()))[..16]);
        let want = match stamp {
            Some((m, s)) => format!("{} {}", m, s),
            None => String::new(),
        };
        if !want.is_empty() && std::fs::read_to_string(&mark).map(|s| s == want).unwrap_or(false) {
            return Owners::Sorted(data);
        }
        if is_sorted(data.bytes()) {
            if !want.is_empty() {
                let _ = std::fs::create_dir_all(host::cache_dir());
                let tmp = format!("{}.{}", mark, unsafe { libc::getpid() });
                if std::fs::write(&tmp, &want).is_ok() {
                    let _ = std::fs::rename(&tmp, &mark);
                }
            }
            return Owners::Sorted(data);
        }
        Owners::Map(parse_all(data.bytes()))
    }

    pub fn get(&self, gpath: &str) -> Option<Owner> {
        match self {
            Owners::Map(m) => m.get(gpath).cloned(),
            Owners::Sorted(data) => {
                let data = data.bytes();
                let at = lower_bound(data, gpath.as_bytes());
                if at >= data.len() {
                    return None;
                }
                let (s, e) = line_at(data, at);
                match parse_line(&data[s..e]) {
                    Some((p, o)) if p == gpath.as_bytes() => Some(o),
                    _ => None,
                }
            }
        }
    }

    /// the paths of the table that start with `pre`
    pub fn with_prefix(&self, pre: &str) -> Vec<String> {
        match self {
            Owners::Map(m) => m.keys().filter(|p| p.starts_with(pre)).cloned().collect(),
            Owners::Sorted(data) => {
                let data = data.bytes();
                let mut out = Vec::new();
                let mut at = lower_bound(data, pre.as_bytes());
                while at < data.len() {
                    let (s, e) = line_at(data, at);
                    match path_of(&data[s..e]) {
                        Some(p) if p.starts_with(pre.as_bytes()) => out.push(String::from_utf8_lossy(p).into_owned()),
                        _ => break,
                    }
                    at = e + 1;
                }
                out
            }
        }
    }

    /// the table as a map, to change it
    pub fn map(&mut self) -> &mut HashMap<String, Owner> {
        if let Owners::Sorted(data) = self {
            *self = Owners::Map(parse_all(data.bytes()));
        }
        match self {
            Owners::Map(m) => m,
            Owners::Sorted(_) => unreachable!(),
        }
    }
}
