//! som.rs - SOM object files (HP-UX PA-RISC a.out and shared libraries): what the loader
//! and the native-routine table need. The layouts are those of the root's
//! /usr/include/filehdr.h, aouthdr.h, scnhdr.h and syms.h; all fields big-endian.
//! (hpuxemu/som.py describes whole files: `python3 -m hpuxemu.som FILE`.)

use crate::process::{be16, be32};

const HPUX_AUX_ID: u32 = 4;

/// the HP-UX exec auxiliary header
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct Exec {
    pub tsize: u32,
    pub tmem: u32,
    pub tfile: u32,
    pub dsize: u32,
    pub dmem: u32,
    pub dfile: u32,
    pub bsize: u32,
    pub entry: u32,
    pub flags: u32,
    pub bfill: u32,
}

pub struct Subspace {
    pub file_loc: u32,
    pub start: u32,
    pub length: u32,
}

pub struct Som<'a> {
    pub data: &'a [u8],
    pub magic: u16,
    pub presumed_dp: u32,
    pub exec: Option<Exec>,
    hdr: [u32; 28],
}

fn in_range(b: &[u8], o: usize, n: usize) -> bool {
    o.checked_add(n).map(|e| e <= b.len()).unwrap_or(false)
}

impl<'a> Som<'a> {
    pub fn new(b: &'a [u8]) -> Option<Som<'a>> {
        if b.len() < 128 {
            return None;
        }
        let magic = be16(b, 2);
        if !matches!(magic, 0x104 | 0x106 | 0x107 | 0x108 | 0x109 | 0x10b | 0x10d | 0x10e) {
            return None;
        }
        let mut hdr = [0u32; 28];
        for (i, h) in hdr.iter_mut().enumerate() {
            *h = be32(b, 16 + 4 * i);
        }
        let mut s = Som { data: b, magic, presumed_dp: hdr[6], exec: None, hdr };
        // aux headers
        let mut off = hdr[3] as usize;
        let end = off.saturating_add(hdr[4] as usize);
        while off + 8 <= end && in_range(b, off, 8) {
            let flags = be32(b, off);
            let length = be32(b, off + 4) as usize;
            if flags & 0xFFFF == HPUX_AUX_ID && in_range(b, off + 8, 40) {
                let v: Vec<u32> = (0..10).map(|i| be32(b, off + 8 + 4 * i)).collect();
                s.exec = Some(Exec { tsize: v[0], tmem: v[1], tfile: v[2], dsize: v[3], dmem: v[4], dfile: v[5], bsize: v[6], entry: v[7], flags: v[8], bfill: v[9] });
            }
            off += 8 + length;
        }
        Some(s)
    }

    pub fn subspaces(&self) -> Vec<Subspace> {
        let b = self.data;
        let (loc, total) = (self.hdr[9] as usize, self.hdr[10] as usize);
        let mut v = Vec::new();
        for i in 0..total {
            let o = loc + i * 40;
            if !in_range(b, o, 40) {
                break;
            }
            v.push(Subspace { file_loc: be32(b, o + 8), start: be32(b, o + 16), length: be32(b, o + 20) });
        }
        v
    }

    /// (name, value) of every symbol whose name `want` accepts
    pub fn symbols(&self, want: &dyn Fn(&[u8]) -> bool) -> Vec<(String, u32)> {
        let b = self.data;
        let (loc, total, strs) = (self.hdr[19] as usize, self.hdr[20] as usize, self.hdr[23] as usize);
        let mut v = Vec::new();
        for i in 0..total {
            let o = loc + i * 20;
            if !in_range(b, o, 20) {
                break;
            }
            let n = strs + be32(b, o + 4) as usize;
            if n >= b.len() {
                continue;
            }
            let e = b[n..].iter().position(|&c| c == 0).map(|p| n + p).unwrap_or(b.len());
            if want(&b[n..e]) {
                v.push((String::from_utf8_lossy(&b[n..e]).into_owned(), be32(b, o + 16)));
            }
        }
        v
    }
}
