//! netman.rs - HP-UX 10's network management driver, /dev/netman, from the host's tables,
//! and 11.00's MIB-2 streams (/dev/ip, /dev/nuls, /dev/dlpi, /dev/lanN).
//!
//!     fd = open("/dev/netman", O_RDWR);
//!     struct nmparms p = { ID_ifTable, buf, &len };
//!     ioctl(fd, NMIOGET, &p);            /* len in: the buffer's size; out: bytes filled */
//!
//! The SNMP agent's MIB-2 subagent (mib2agt) reads every MIB-2 table this way: interfaces,
//! the address translation and IP-to-media (ARP) tables, IP addresses and routes, the TCP
//! connections and UDP listeners, the IP/ICMP/TCP/UDP counters. Object ids are
//! OBJID(group, index) = group << 16 | index (sys/mib.h): index 0 of a counter group is all
//! its counters, 1..n one of them; the tables are NumEnt (a count), Table (an array of
//! entries) and Entry (one entry, chosen by the key the caller puts in the buffer).
//!
//! The answers come from Linux's /proc/net (dev, route, arp, snmp, tcp, udp) and the
//! emulator's interface list (lo0 and lan0, the host's default-route interface - the same
//! names and addresses SIOCGIFCONF gives). Structures are sys/mib.h's, big-endian, 32-bit
//! (mib_ifEntry 152 bytes, mib_ipAdEnt 20, mib_ipRouteEnt 44 ...; 11.00's physical
//! addresses are 36-byte mib_physaddr_t, so its mib_ifEntry is 180). NMIOSET and the other
//! writes fail with EPERM: the host's tables are not the guest's to change.

use crate::host;
use crate::streams::{Msg, M_PCPROTO, M_PROTO, RQ_CLOSE, RQ_IOCTL, RQ_PUTMSG};
use crate::syscalls::net::inet_aton;
use std::collections::{HashMap, VecDeque};

pub const NMIOGET: u32 = 0xC00C_6D01; // _IOWR('m', 1, struct nmparms)
pub const NMIOSET: u32 = 0x800C_6D02; // _IOW('m', 2, struct nmparms)
pub const NMIODEL: u32 = 0x800C_6D03;
pub const NMIOCRE: u32 = 0x800C_6D04;

const GP_SYS: u32 = 1;
const GP_IF: u32 = 2;
const GP_AT: u32 = 3;
const GP_IP: u32 = 4;
const GP_ICMP: u32 = 5;
const GP_TCP: u32 = 6;
const GP_UDP: u32 = 7;

// the counters of each group in sys/mib.h's order, by /proc/net/snmp's names
const IP_COUNTERS: &str = "Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates";
const ICMP_COUNTERS: &str = "InMsgs InErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps";
const TCP_COUNTERS: &str = "RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts";
const UDP_COUNTERS: &str = "InDatagrams NoPorts InErrors OutDatagrams";

fn group_counters(g: u32) -> Option<(&'static str, &'static str)> {
    match g {
        GP_IP => Some(("Ip", IP_COUNTERS)),
        GP_ICMP => Some(("Icmp", ICMP_COUNTERS)),
        GP_TCP => Some(("Tcp", TCP_COUNTERS)),
        GP_UDP => Some(("Udp", UDP_COUNTERS)),
        _ => None,
    }
}

/// Linux tcp states (/proc/net/tcp, hex) -> tcpConnState (RFC 1213)
fn tcp_state(s: u32) -> i32 {
    match s {
        1 => 5,
        2 => 3,
        3 => 4,
        4 => 6,
        5 => 7,
        6 => 11,
        7 => 1,
        8 => 8,
        9 => 9,
        10 => 2,
        11 => 10,
        _ => 1,
    }
}

fn aton(a: &str) -> u32 {
    u32::from_be_bytes(inet_aton(a))
}

/// an address from /proc/net (host-order hex) as an int in network order
fn hexaddr(h: &str) -> u32 {
    u32::from_str_radix(h, 16).unwrap_or(0).swap_bytes()
}

fn p32(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_be_bytes());
}

fn padded(b: &[u8], n: usize) -> Vec<u8> {
    let mut v = b[..b.len().min(n)].to_vec();
    v.resize(n, 0);
    v
}

fn port16(p: u32) -> i32 {
    if p > 32767 { p as i32 - 65536 } else { p as i32 }
}

pub type Iface = (String, String, String, String, u32);

pub struct Netman {
    v11: bool,
    pub ifs: Vec<Iface>,
    boot_time: f64,
    /// guest name -> host name, for counters and MAC
    pub hostif: HashMap<String, String>,
}

impl Netman {
    /// interfaces: [(name, address, netmask, broadcast, flags)] (Process::interfaces);
    /// boot_time: the guest's boot time, for sysUpTime; v11: 11.00's structures;
    /// lan_first: the loopback numbered after the LAN interfaces, as 11.00's agent numbers
    /// them (the DLPI PPAs first) - ifIndex is the position in self.ifs
    pub fn new(interfaces: Vec<Iface>, boot_time: f64, v11: bool, lan_first: bool) -> Netman {
        let ifs: Vec<Iface> = if lan_first {
            let mut v: Vec<Iface> = interfaces.iter().filter(|i| i.0 != "lo0").cloned().collect();
            v.extend(interfaces.iter().filter(|i| i.0 == "lo0").cloned());
            v
        } else {
            interfaces
        };
        let mut hostif = HashMap::new();
        for i in &ifs {
            hostif.insert(i.0.clone(), if i.0 == "lo0" { "lo".to_string() } else { host_name(&i.1) });
        }
        Netman { v11, ifs, boot_time, hostif }
    }

    // -- the host's tables ---------------------------------------------------------------
    fn snmp(&self) -> HashMap<String, HashMap<String, i64>> {
        let mut out = HashMap::new();
        let txt = match std::fs::read_to_string("/proc/net/snmp") {
            Ok(t) => t,
            Err(_) => return out,
        };
        let lines: Vec<&str> = txt.lines().collect();
        let mut i = 0;
        while i + 1 < lines.len() {
            if let (Some((k, names)), Some((_, vals))) = (lines[i].split_once(':'), lines[i + 1].split_once(':')) {
                let m: HashMap<String, i64> = names.split_whitespace().zip(vals.split_whitespace()).map(|(n, v)| (n.to_string(), v.parse().unwrap_or(0))).collect();
                out.insert(k.to_string(), m);
            }
            i += 2;
        }
        out
    }

    fn devstats(&self) -> HashMap<String, Vec<u64>> {
        let mut st = HashMap::new();
        if let Ok(txt) = std::fs::read_to_string("/proc/net/dev") {
            for line in txt.lines().skip(2) {
                if let Some((n, rest)) = line.split_once(':') {
                    st.insert(n.trim().to_string(), rest.split_whitespace().map(|x| x.parse().unwrap_or(0)).collect());
                }
            }
        }
        st
    }

    pub fn mac(&self, hname: &str) -> Vec<u8> {
        match std::fs::read_to_string(format!("/sys/class/net/{}/address", hname)) {
            Ok(s) => {
                let v: Option<Vec<u8>> = s.trim().split(':').map(|x| u8::from_str_radix(x, 16).ok()).collect();
                v.unwrap_or_default()
            }
            Err(_) => Vec::new(),
        }
    }

    pub fn mtu(&self, hname: &str, default: u32) -> u32 {
        std::fs::read_to_string(format!("/sys/class/net/{}/mtu", hname)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(default)
    }

    fn index(&self, hname: &str) -> u32 {
        for (i, e) in self.ifs.iter().enumerate() {
            if self.hostif.get(&e.0).map(|h| h == hname).unwrap_or(false) {
                return i as u32 + 1;
            }
        }
        0
    }

    /// a physical address field: 8 bytes (10.20), or mib_physaddr_t (11.00)
    fn phys(&self, mac: &[u8]) -> Vec<u8> {
        if self.v11 {
            let mut v = (mac.len() as u32).to_be_bytes().to_vec();
            v.extend(padded(mac, 32));
            v
        } else {
            padded(mac, 8)
        }
    }

    /// mib_ifEntry: 152 bytes, 180 on 11.00
    pub fn if_entries(&self) -> Vec<Vec<u8>> {
        let stats = self.devstats();
        let zero = vec![0u64; 16];
        let mut out = Vec::new();
        for (i, e) in self.ifs.iter().enumerate() {
            let h = self.hostif.get(&e.0).cloned().unwrap_or_default();
            let v = stats.get(&h).filter(|v| v.len() >= 12).unwrap_or(&zero);
            // /proc/net/dev: rx bytes packets errs drop fifo frame compressed multicast,
            //                tx bytes packets errs drop fifo colls carrier compressed
            let lo = e.0 == "lo0";
            // (11.00's kernel keeps 32 bytes of a description)
            let descr = if lo {
                if self.v11 { format!("{} Software Loopback", e.0) } else { format!("{} Hewlett-Packard Software Loopback", e.0) }
            } else {
                format!("{} Hewlett-Packard LAN Interface", e.0)
            };
            let mac = if lo { Vec::new() } else { self.mac(&h) };
            let mut o = Vec::new();
            p32(&mut o, i as u32 + 1);
            o.extend(padded(&descr.as_bytes()[..descr.len().min(63)], 64));
            p32(&mut o, if lo { 24 } else { 6 });
            p32(&mut o, if lo { 4136 } else { self.mtu(&h, 1500) });
            p32(&mut o, if lo { 0 } else { 10_000_000 });
            o.extend(self.phys(&mac));
            for x in [1u32, 1, 0] {
                p32(&mut o, x);
            }
            for x in [v[0], v[1].wrapping_sub(v[7]), v[7], v[3], v[2], 0, v[8], v[9], 0, v[11], v[10], 0, 0] {
                p32(&mut o, x as u32);
            }
            out.push(o);
        }
        out
    }

    /// mib_ipAdEnt, 20 bytes
    pub fn ipad_entries(&self) -> Vec<Vec<u8>> {
        // BcastAddr is the MIB's ipAdEntBcastAddr, the low bit of the broadcast address
        // (1: all ones) - HP's agent passes the field through as that integer
        self.ifs
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let mut o = Vec::new();
                for x in [aton(&e.1), i as u32 + 1, aton(&e.2), aton(&e.3) & 1, 65535] {
                    p32(&mut o, x);
                }
                o
            })
            .collect()
    }

    /// mib_ipRouteEnt, 44 bytes
    pub fn route_entries(&self) -> Vec<Vec<u8>> {
        let row = |v: [u32; 11]| {
            let mut o = Vec::new();
            for x in v {
                p32(&mut o, x);
            }
            o
        };
        let m1 = -1i32 as u32;
        let mut out = Vec::new();
        // the loopback network, which HP-UX has as a route through lo0
        let lo = self.index("lo");
        out.push(row([aton("127.0.0.0"), if lo != 0 { lo } else { 1 }, 0, m1, m1, m1, aton("127.0.0.1"), 3, 2, 0, aton("255.0.0.0")]));
        if let Ok(txt) = std::fs::read_to_string("/proc/net/route") {
            for line in txt.lines().skip(1) {
                let p: Vec<&str> = line.split_whitespace().collect();
                if p.len() < 8 {
                    continue;
                }
                let idx = self.index(p[0]);
                if idx == 0 {
                    continue;
                }
                let (dest, gw, flags, metric, mask) = (hexaddr(p[1]), hexaddr(p[2]), u32::from_str_radix(p[3], 16).unwrap_or(0), p[6].parse::<u32>().unwrap_or(0), hexaddr(p[7]));
                if flags & 1 == 0 {
                    continue; // RTF_UP
                }
                let remote = flags & 2 != 0; // RTF_GATEWAY
                let nexthop = if remote { gw } else { aton(&self.ifs[idx as usize - 1].1) };
                out.push(row([dest, idx, if remote { metric } else { 0 }, m1, m1, m1, nexthop, if remote { 4 } else { 3 }, 2, 0, mask]));
            }
        }
        out
    }

    /// (ifIndex, mac, address, type)
    fn arp(&self) -> Vec<(u32, Vec<u8>, u32, u32)> {
        let mut out = Vec::new();
        if let Ok(txt) = std::fs::read_to_string("/proc/net/arp") {
            for line in txt.lines().skip(1) {
                let p: Vec<&str> = line.split_whitespace().collect();
                if p.len() < 6 || p[3] == "00:00:00:00:00:00" {
                    continue;
                }
                let idx = self.index(p[5]);
                if idx == 0 {
                    continue;
                }
                let mac: Vec<u8> = p[3].split(':').map(|x| u8::from_str_radix(x, 16).unwrap_or(0)).collect();
                let flags = u32::from_str_radix(p[2].trim_start_matches("0x"), 16).unwrap_or(0);
                out.push((idx, mac, aton(p[0]), if flags & 4 != 0 { 4 } else { 3 })); // ATF_PERM: static
            }
        }
        out
    }

    /// mib_ipNetToMediaEnt
    pub fn ntm_entries(&self) -> Vec<Vec<u8>> {
        self.arp()
            .iter()
            .map(|(idx, mac, a, t)| {
                let mut o = idx.to_be_bytes().to_vec();
                o.extend(self.phys(mac));
                p32(&mut o, *a);
                p32(&mut o, *t);
                o
            })
            .collect()
    }

    /// mib_AtEntry
    fn at_entries(&self) -> Vec<Vec<u8>> {
        self.arp()
            .iter()
            .map(|(idx, mac, a, _)| {
                let mut o = idx.to_be_bytes().to_vec();
                o.extend(self.phys(mac));
                p32(&mut o, *a);
                o
            })
            .collect()
    }

    /// (local address, port, remote address, port, state) of /proc/net/tcp or udp
    fn sockets(&self, name: &str) -> Vec<(u32, u32, u32, u32, u32)> {
        let mut out = Vec::new();
        if let Ok(txt) = std::fs::read_to_string(format!("/proc/net/{}", name)) {
            for line in txt.lines().skip(1) {
                let p: Vec<&str> = line.split_whitespace().collect();
                if p.len() < 4 {
                    continue;
                }
                if let (Some((la, lp)), Some((ra, rp))) = (p[1].split_once(':'), p[2].split_once(':')) {
                    let h = |x: &str| u32::from_str_radix(x, 16).unwrap_or(0);
                    out.push((hexaddr(la), h(lp), hexaddr(ra), h(rp), h(p[3])));
                }
            }
        }
        out
    }

    /// (state, local address, local port, remote address, remote port), sorted
    fn tcp_conns(&self) -> Vec<(i32, u32, u32, u32, u32)> {
        let mut c = self.sockets("tcp");
        c.sort();
        c.dedup();
        c.sort_by_key(|c| (c.0, c.1, c.2, c.3));
        c.into_iter().map(|(la, lp, ra, rp, s)| (tcp_state(s), la, lp, ra, rp)).collect()
    }

    /// mib_tcpConnEnt, 20 bytes
    fn tcp_entries(&self) -> Vec<Vec<u8>> {
        self.tcp_conns()
            .into_iter()
            .map(|(st, la, lp, ra, rp)| {
                let mut o = Vec::new();
                p32(&mut o, st as u32);
                p32(&mut o, la);
                o.extend_from_slice(&(port16(lp) as i16).to_be_bytes());
                o.extend_from_slice(&[0, 0]);
                p32(&mut o, ra);
                o.extend_from_slice(&(port16(rp) as i16).to_be_bytes());
                o.extend_from_slice(&[0, 0]);
                o
            })
            .collect()
    }

    fn udp_listeners(&self) -> Vec<(u32, u32)> {
        let mut l: Vec<(u32, u32)> = self.sockets("udp").into_iter().map(|s| (s.0, s.1)).collect();
        l.sort();
        l.dedup();
        l
    }

    /// mib_udpLsnEnt, 8 bytes
    fn udp_entries(&self) -> Vec<Vec<u8>> {
        self.udp_listeners()
            .into_iter()
            .map(|(la, lp)| {
                let mut o = la.to_be_bytes().to_vec();
                o.extend_from_slice(&(port16(lp) as i16).to_be_bytes());
                o.extend_from_slice(&[0, 0]);
                o
            })
            .collect()
    }

    pub fn counters(&self, group: u32) -> Vec<u32> {
        let (sec, names) = match group_counters(group) {
            Some(x) => x,
            None => return Vec::new(),
        };
        let snmp = self.snmp();
        let empty = HashMap::new();
        let sec = snmp.get(sec).unwrap_or(&empty);
        names
            .split(' ')
            .map(|n| {
                let v = if group == GP_TCP && n == "MaxConn" { -1 } else { sec.get(n).copied().unwrap_or(0) };
                v as u32
            })
            .collect()
    }

    // -- the request -----------------------------------------------------------------------

    /// the bytes for an object id (key: the caller's buffer, for an Entry); Err: the
    /// errno's name
    pub fn get(&self, objid: u32, key: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (g, i) = (objid >> 16, objid & 0xFFFF);
        let pa = if self.v11 { 40 } else { 12 }; // where NetAddr follows the physical address
        // (kind 0 count, 1 table, 2 entry; rows; the key's offset and length)
        let table: Option<(u32, Vec<Vec<u8>>, usize, usize)> = match (g, i) {
            (GP_IF, 1..=3) => Some((i - 1, self.if_entries(), 0, 4)),
            (GP_AT, 1..=3) => Some((i - 1, self.at_entries(), pa, 4)),
            (GP_IP, 1025..=1027) => Some((i - 1025, self.ipad_entries(), 0, 4)),
            (GP_IP, 1028..=1030) => Some((i - 1028, self.route_entries(), 0, 4)),
            (GP_IP, 1031..=1033) => Some((i - 1031, self.ntm_entries(), pa, 4)),
            (GP_TCP, 1025..=1027) => Some((i - 1025, self.tcp_entries(), 4, 16)),
            (GP_UDP, 1025..=1027) => Some((i - 1025, self.udp_entries(), 0, 6)),
            _ => None,
        };
        if let Some((kind, rows, off, ln)) = table {
            return match kind {
                0 => Ok((rows.len() as u32).to_be_bytes().to_vec()),
                1 => Ok(rows.concat()),
                _ => {
                    let want = &key[off.min(key.len())..(off + ln).min(key.len())];
                    for r in rows {
                        if r.len() >= off + ln && &r[off..off + ln] == want {
                            return Ok(r);
                        }
                    }
                    Err("ENOENT")
                }
            };
        }
        if self.v11 && (g, i) == (GP_IP, 23) {
            return Ok(vec![0; 4]); // ipRoutingDiscards (11.00): Linux does not count them
        }
        if group_counters(g).is_some() {
            let vals = self.counters(g);
            if i == 0 {
                let mut o = Vec::new();
                for v in &vals {
                    p32(&mut o, *v);
                }
                return Ok(o);
            }
            if i >= 1 && i as usize <= vals.len() {
                return Ok(vals[i as usize - 1].to_be_bytes().to_vec());
            }
        }
        if g == GP_SYS {
            if i == 1 {
                return Ok(b"Hewlett-Packard HP-UX\0".to_vec());
            }
            if i == 3 {
                return Ok((((host::now_f64() - self.boot_time) * 100.0) as i64 as u32).to_be_bytes().to_vec());
            }
        }
        Err("EINVAL")
    }
}

/// the host interface that has this address (the default-route one)
fn host_name(addr: &str) -> String {
    let sk = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sk < 0 {
        return String::new();
    }
    let mut found = String::new();
    if let Ok(txt) = std::fs::read_to_string("/proc/net/dev") {
        for line in txt.lines().skip(2) {
            let n = line.split(':').next().unwrap_or("").trim();
            let mut ifr = [0u8; 40];
            let b = n.as_bytes();
            ifr[..b.len().min(15)].copy_from_slice(&b[..b.len().min(15)]);
            if unsafe { libc::ioctl(sk, 0x8915, ifr.as_mut_ptr()) } < 0 {
                continue;
            }
            if format!("{}.{}.{}.{}", ifr[20], ifr[21], ifr[22], ifr[23]) == addr {
                found = n.to_string();
                break;
            }
        }
    }
    unsafe { libc::close(sk) };
    found
}

// -- HP-UX 11.00: MIB-2 from /dev/ip ---------------------------------------------------------
//
// 11.00 has no /dev/netman. libnm.1 (mibget) reads MIB-2 the SVR4 way: open /dev/ip (or
// /dev/nuls with tcpm/udpm pushed, or /dev/ip with arpm), putmsg a T_OPTMGMT_REQ
// (MGMT_flags 0x80) carrying one XTI t_opthdr {len 16, level MIB2_IP, name 0}, then getmsg
// replies until the end: each a T_OPTMGMT_ACK (prim 29, MGMT_flags 0x20) whose t_opthdr
// {len = 16 + data, level, name} announces one table, its bytes the message's data part
// (so the first getmsg, ctl only, returns MOREDATA); the last has len 16 and no data. The
// levels are 256 + the MIB group; the names are 0 (the group's scalars) and the tables'
// Solaris numbers. libnm.1 copies the records into sys/mib.h's structures.

const MIB2_IF: u32 = 258;
const MIB2_IP: u32 = 260;
const MIB2_ICMP: u32 = 261;
const MIB2_TCP: u32 = 262;
const MIB2_UDP: u32 = 263;
const T_OPTMGMT_ACK: u32 = 29;
const T_ERROR_ACK: u32 = 25;
const T_SUCCESS: u32 = 0x20;
const T_CURRENT: u32 = 0x80;
const DL_ATTACH_REQ: u32 = 0x0b;
const DL_DETACH_REQ: u32 = 0x0c;
const DL_OK_ACK: u32 = 0x06;
const DL_ERROR_ACK: u32 = 0x05;
const DL_HP_PPA_REQ: u32 = 0xe2;
const DL_HP_PPA_ACK: u32 = 0xe1;
/// libnm's setup_mci_get_req: {526, 1, 0x7fffffff, 1, 28, ...}
const DL_HP_MIB_REQ: u32 = 526;
// the kernel's record sizes (libnm divides the table lengths by them)
const IPADDR_REC: usize = 88;
const ROUTE_REC: usize = 116;
const MEDIA_REC: usize = 92;
const TCPCONN_REC: usize = 56;
const UDP_REC: usize = 20;

fn words(v: &[u32]) -> Vec<u8> {
    let mut o = Vec::new();
    for x in v {
        p32(&mut o, *x);
    }
    o
}

fn rd32(b: &[u8], o: usize) -> u32 {
    if o + 4 <= b.len() {
        u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    } else {
        0
    }
}

/// [(level, name, bytes)]: what /dev/ip reports, as the 11.00 kernel lays it out
fn mib2_tables(nm: &Netman) -> Vec<(u32, u32, Vec<u8>)> {
    let mut out = Vec::new();
    let ifs = nm.if_entries(); // 11.00 mib_ifEntry, 180 bytes each
    out.push((MIB2_IF, 1, (ifs.len() as u32).to_be_bytes().to_vec()));
    for (e, u) in nm.ifs.iter().zip(ifs.iter()) {
        if e.0 != "lo0" || u.len() < 180 {
            continue;
        }
        // IP's own interface, the loopback (the LAN interfaces come from DLPI); the
        // kernel's record: index, a word, a 32-byte description, type mtu speed and the
        // physical address length, the address, then the status words and counters
        let d = &u[4..68];
        let d = &d[..d.iter().position(|&c| c == 0).unwrap_or(d.len())];
        let mut r = u[0..4].to_vec();
        r.extend_from_slice(&[0; 4]);
        r.extend(padded(&d[..d.len().min(31)], 32));
        r.extend_from_slice(&u[68..180]);
        out.push((MIB2_IF, 2, r));
    }
    let ip = nm.counters(GP_IP);
    let tcp = nm.counters(GP_TCP);
    let udp = nm.counters(GP_UDP);
    // mib2_ip: the 19 counters, the entry sizes, ipRoutingDiscards, then tcpInErrs and
    // udpNoPorts (libnm reads those two here), checksum and overflow counts
    let mut ipw = ip.clone();
    ipw.extend_from_slice(&[IPADDR_REC as u32, ROUTE_REC as u32, MEDIA_REC as u32, 0, tcp[12], udp[1], 0, 0, 0, 0, 0, 0, 0]);
    out.push((MIB2_IP, 0, words(&ipw)));
    let mut t = Vec::new();
    for r in nm.ipad_entries() {
        let mut rec = r[..12].to_vec();
        p32(&mut rec, 1);
        rec.extend_from_slice(&r[16..20]);
        t.extend(padded(&rec, IPADDR_REC));
    }
    out.push((MIB2_IP, 20, t));
    out.push((MIB2_IP, 21, nm.route_entries().iter().flat_map(|r| padded(r, ROUTE_REC)).collect()));
    out.push((MIB2_IP, 22, nm.ntm_entries().iter().flat_map(|r| padded(r, MEDIA_REC)).collect()));
    out.push((MIB2_ICMP, 0, words(&nm.counters(GP_ICMP))));
    let mut tw = tcp.clone();
    tw.extend_from_slice(&[0; 10]);
    out.push((MIB2_TCP, 0, words(&tw)));
    let mut conns = Vec::new();
    for (st, la, lp, ra, rp) in nm.tcp_conns() {
        conns.extend(padded(&words(&[st as u32, la, lp & 0xFFFF, ra, rp & 0xFFFF]), TCPCONN_REC));
    }
    out.push((MIB2_TCP, 13, conns));
    // mib2_udp: InDatagrams, InErrors, OutDatagrams
    out.push((MIB2_UDP, 0, padded(&words(&[udp[0], udp[2], udp[3]]), 20)));
    let mut lsn = Vec::new();
    for (la, lp) in nm.udp_listeners() {
        lsn.extend(padded(&words(&[la, lp & 0xFFFF]), UDP_REC));
    }
    out.push((MIB2_UDP, 5, lsn));
    out
}

/// /dev/ip and /dev/nuls of an 11.00 root: a stream the emulator answers itself, with what
/// a Stream (streams.rs) offers the stream calls - the messages waiting, and call() for
/// putmsg and the ioctls. A T_OPTMGMT_REQ for MIB-2 queues mib2_tables()' replies; modules
/// can be pushed and popped (libnm pushes arpm, tcpm, udpm) and change nothing.
pub struct Mib {
    pub driver: String,
    modules: Vec<Vec<u8>>,
}

fn first_word(b: &[u8]) -> Vec<u8> {
    b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())].to_vec()
}

impl Mib {
    pub fn new(driver: &str) -> Mib {
        Mib { driver: driver.to_string(), modules: Vec::new() }
    }

    fn optmgmt(&mut self, nm: &Netman, ctl: &[u8], msgs: &mut VecDeque<Msg>) {
        let (prim, olen, ooff, flags) = (rd32(ctl, 0), rd32(ctl, 4) as i32, rd32(ctl, 8) as usize, rd32(ctl, 12));
        let level = if olen >= 16 && ctl.len() >= ooff + 16 { rd32(ctl, ooff + 4) } else { 0 };
        if flags & T_CURRENT == 0 || !(MIB2_IF..=MIB2_UDP).contains(&level) {
            msgs.push_back(Msg { typ: M_PCPROTO, band: 0, ctl: Some(words(&[T_ERROR_ACK, prim, 3, 0])), data: None }); // TBADOPT
            return;
        }
        for (lvl, name, data) in mib2_tables(nm) {
            let hdr = words(&[T_OPTMGMT_ACK, 16, 16, T_SUCCESS, 16 + data.len() as u32, lvl, name, 0]);
            msgs.push_back(Msg { typ: M_PROTO, band: 0, ctl: Some(hdr), data: Some(data) });
        }
        msgs.push_back(Msg { typ: M_PROTO, band: 0, ctl: Some(words(&[T_OPTMGMT_ACK, 16, 16, T_SUCCESS, 16, 0, 0, 0])), data: None });
    }

    /// /dev/dlpi and /dev/lanN: the LAN interfaces as libnm sees them - DL_HP_PPA_REQ lists
    /// them (each with its ifIndex as dl_nmid and its device, /dev/ + dl_module_id_1),
    /// DL_ATTACH_REQ picks one, and HP's network management request (526) answers an
    /// ifEntry with the 11.00 mib_ifEntry in the data part (reply word 2: 0 for success)
    fn dlpi(&mut self, nm: &Netman, ctl: &[u8], msgs: &mut VecDeque<Msg>) {
        let prim = rd32(ctl, 0);
        let lans: Vec<(usize, &Iface)> = nm.ifs.iter().enumerate().filter(|(_, e)| e.0 != "lo0").collect();
        let pc = |ctl: Vec<u8>, data: Option<Vec<u8>>| Msg { typ: M_PCPROTO, band: 0, ctl: Some(ctl), data };
        if prim == DL_HP_PPA_REQ {
            let mut data = Vec::new();
            for (ppa, (i, e)) in lans.iter().enumerate() {
                let h = nm.hostif.get(&e.0).cloned().unwrap_or_default();
                let mac = nm.mac(&h);
                // '>II100sI20sII64sIII64s64s64sIII'
                p32(&mut data, 0);
                p32(&mut data, ppa as u32);
                data.extend(padded(format!("0/0/0/{}", ppa).as_bytes(), 100));
                p32(&mut data, 4);
                data.extend(padded(&mac, 20));
                p32(&mut data, mac.len() as u32);
                p32(&mut data, 52);
                data.extend(padded(b"btlan", 64));
                p32(&mut data, ppa as u32);
                p32(&mut data, nm.mtu(&h, 1500));
                p32(&mut data, 0);
                data.extend(padded(e.0.as_bytes(), 64));
                data.extend(padded(b"", 64));
                data.extend(padded(b"arpm", 64));
                p32(&mut data, *i as u32 + 1);
                p32(&mut data, 0);
                p32(&mut data, 0);
            }
            let mut c = words(&[DL_HP_PPA_ACK, data.len() as u32, lans.len() as u32, 16]);
            c.extend(data);
            msgs.push_back(pc(c, None));
        } else if prim == DL_ATTACH_REQ {
            if (rd32(ctl, 4) as usize) < lans.len() && ctl.len() >= 8 {
                msgs.push_back(pc(words(&[DL_OK_ACK, prim]), None));
            } else {
                msgs.push_back(pc(words(&[DL_ERROR_ACK, prim, 8, 0]), None)); // DL_BADPPA
            }
        } else if prim == DL_DETACH_REQ {
            msgs.push_back(pc(words(&[DL_OK_ACK, prim]), None));
        } else if prim == DL_HP_MIB_REQ && ctl.len() >= 68 {
            // {526, 1, 0x7fffffff, 1, 28, OID length, ?, the OID 1.3.6.1.2.1.group.table.entry.key}
            let group = rd32(ctl, 52);
            let key = rd32(ctl, 64) as i32;
            let ifs = nm.if_entries();
            let okv = group == GP_IF && key >= 1 && key as usize <= ifs.len();
            let mut reply = ctl[..8].to_vec();
            p32(&mut reply, if okv { 0 } else { 22 });
            reply.extend_from_slice(&ctl[12..28]);
            msgs.push_back(pc(reply, if okv { Some(ifs[key as usize - 1].clone()) } else { None }));
        } else {
            msgs.push_back(pc(words(&[DL_ERROR_ACK, prim, 3, 0]), None)); // DL_BADPRIM
        }
    }

    /// a request as the STREAMS daemon would get it: (rval, errno, data)
    pub fn call(&mut self, nm: &dyn Fn() -> std::rc::Rc<Netman>, op: u32, payload: &[u8], msgs: &mut VecDeque<Msg>) -> (i32, u32, Vec<u8>) {
        if op == RQ_PUTMSG {
            let nc = rd32(payload, 8) as i32;
            if nc < 4 || payload.len() < 16 + nc as usize {
                return (-1, 71, Vec::new()); // EPROTO
            }
            let ctl = &payload[16..16 + nc as usize];
            if self.driver != "ip" && self.driver != "nuls" {
                self.dlpi(&nm(), ctl, msgs);
                return (0, 0, Vec::new());
            }
            if ctl.len() >= 16 && rd32(ctl, 0) == 8 {
                self.optmgmt(&nm(), ctl, msgs);
                return (0, 0, Vec::new());
            }
            return (-1, 71, Vec::new());
        }
        if op == RQ_IOCTL {
            let (req, arg, ln) = (rd32(payload, 0), rd32(payload, 4), rd32(payload, 8) as usize);
            let body = &payload[12.min(payload.len())..(12 + ln).min(payload.len())];
            let name9 = |n: &[u8]| padded(&n[..n.len().min(8)], 9);
            return match req & 0xFFFF {
                0x5302 => {
                    // I_PUSH
                    self.modules.insert(0, first_word(body));
                    (0, 0, Vec::new())
                }
                0x5303 => {
                    // I_POP
                    if self.modules.is_empty() {
                        return (-1, 22, Vec::new());
                    }
                    self.modules.remove(0);
                    (0, 0, Vec::new())
                }
                0x530b => (self.modules.contains(&first_word(body)) as i32, 0, Vec::new()), // I_FIND
                0x5316 => {
                    // I_LIST
                    let mut names = self.modules.clone();
                    names.push(self.driver.as_bytes().to_vec());
                    (names.len() as i32, 0, names.iter().flat_map(|n| name9(n)).collect())
                }
                0x5304 => {
                    // I_LOOK
                    if self.modules.is_empty() {
                        return (-1, 22, Vec::new());
                    }
                    (0, 0, name9(&self.modules[0]))
                }
                0x5305 => {
                    // I_FLUSH
                    if arg & 1 != 0 {
                        msgs.clear();
                    }
                    (0, 0, Vec::new())
                }
                _ => (-1, 22, Vec::new()),
            };
        }
        if op == RQ_CLOSE {
            return (0, 0, Vec::new());
        }
        (-1, 22, Vec::new())
    }
}
