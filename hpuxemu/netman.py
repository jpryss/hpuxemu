"""netman.py - HP-UX 10's network management driver, /dev/netman, from the host's tables.

    fd = open("/dev/netman", O_RDWR);
    struct nmparms p = { ID_ifTable, buf, &len };
    ioctl(fd, NMIOGET, &p);            /* len in: the buffer's size; out: bytes filled */

The SNMP agent's MIB-2 subagent (mib2agt) reads every MIB-2 table this way: interfaces,
the address translation and IP-to-media (ARP) tables, IP addresses and routes, the
TCP connections and UDP listeners, the IP/ICMP/TCP/UDP counters. Object ids are
OBJID(group, index) = group << 16 | index (sys/mib.h): index 0 of a counter group is all
its counters, 1..n one of them; the tables are NumEnt (a count), Table (an array of
entries) and Entry (one entry, chosen by the key the caller puts in the buffer).

The answers come from Linux's /proc/net (dev, route, arp, snmp, tcp, udp) and the
emulator's interface list (lo0 and lan0, the host's default-route interface - the same
names and addresses SIOCGIFCONF gives). Structures are sys/mib.h's, big-endian, 32-bit
(mib_ifEntry 152 bytes, mib_ipAdEnt 20, mib_ipRouteEnt 44 ...; 11.00's physical
addresses are 36-byte mib_physaddr_t, so its mib_ifEntry is 180). NMIOSET and the other
writes fail with EPERM: the host's tables are not the guest's to change.
"""
import os
import socket
import struct
import time

NMIOGET = 0xC00C6D01      # _IOWR('m', 1, struct nmparms)
NMIOSET = 0x800C6D02      # _IOW('m', 2, struct nmparms)
NMIODEL = 0x800C6D03
NMIOCRE = 0x800C6D04

GP_sys, GP_if, GP_at, GP_ip, GP_icmp, GP_tcp, GP_udp, GP_trans = 1, 2, 3, 4, 5, 6, 7, 10


def OBJID(g, i):
    return (g << 16) + i


# the counters of each group in sys/mib.h's order, by /proc/net/snmp's names
COUNTERS = {
    GP_ip: ('Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos '
            'InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs '
            'ReasmFails FragOKs FragFails FragCreates').split(),
    GP_icmp: ('InMsgs InErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos '
              'InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors '
              'OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps '
              'OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps').split(),
    GP_tcp: ('RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets '
             'CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts').split(),
    GP_udp: 'InDatagrams NoPorts InErrors OutDatagrams'.split(),
}
SNMP_SECTION = {GP_ip: 'Ip', GP_icmp: 'Icmp', GP_tcp: 'Tcp', GP_udp: 'Udp'}

# Linux tcp states (/proc/net/tcp, hex) -> tcpConnState (RFC 1213)
TCP_STATE = {1: 5, 2: 3, 3: 4, 4: 6, 5: 7, 6: 11, 7: 1, 8: 8, 9: 9, 10: 2, 11: 10}

IF_ENTRY = '>i64siiI8siiI' + 'I' * 11 + 'Ii'          # mib_ifEntry, 152 bytes
AT_ENTRY = '>i8sI'                                     # mib_AtEntry, 16
IPAD_ENTRY = '>IiIIi'                                  # mib_ipAdEnt, 20
NTM_ENTRY = '>i8sIi'                                   # mib_ipNetToMediaEnt, 20
ROUTE_ENTRY = '>IiiiiiIiiiI'                           # mib_ipRouteEnt, 44
TCPCONN_ENTRY = '>iIh2xIh2x'                           # mib_tcpConnEnt, 20
UDPLSN_ENTRY = '>Ih2x'                                 # mib_udpLsnEnt, 8

# HP-UX 11.00's sys/mib.h made the physical addresses a mib_physaddr_t {int o_length;
# unsigned char o_bytes[32]} (36 bytes) where 10.20 has unsigned char [8]: mib_ifEntry
# is 180 bytes, mib_AtEntry 44, mib_ipNetToMediaEnt 48. The rest is the same.
IF_ENTRY_11 = '>i64siiI36siiI' + 'I' * 11 + 'Ii'
AT_ENTRY_11 = '>i36sI'
NTM_ENTRY_11 = '>i36sIi'


class NetmanError(Exception):
    def __init__(self, errno):
        Exception.__init__(self, errno)
        self.errno = errno


def _aton(a):
    return struct.unpack('>I', socket.inet_aton(a))[0]


def _hexaddr(h):
    """an address from /proc/net (host-order hex) as an int in network order"""
    return struct.unpack('>I', struct.pack('<I', int(h, 16)))[0]


class Netman:
    def __init__(self, interfaces, boot_time, release='B.10.20', lan_first=False):
        """interfaces: [(name, address, netmask, broadcast, flags)] (Process.interfaces);
        boot_time: the guest's boot time, for sysUpTime; release: B.11.* for 11.00's
        structures; lan_first: the loopback numbered after the LAN interfaces, as 11.00's
        agent numbers them (the DLPI PPAs first) - ifIndex is the position in self.ifs"""
        self.v11 = release.startswith('B.11')
        self.ifs = [i for i in interfaces if i[0] != 'lo0'] + [i for i in interfaces if i[0] == 'lo0'] \
            if lan_first else interfaces
        self.boot_time = boot_time
        self.hostif = {}          # guest name -> host name, for counters and MAC
        for name, addr, *_ in self.ifs:
            self.hostif[name] = 'lo' if name == 'lo0' else self._host_name(addr)

    @staticmethod
    def _host_name(addr):
        """the host interface that has this address (the default-route one)"""
        try:
            import fcntl
            sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for line in open('/proc/net/dev').read().splitlines()[2:]:
                n = line.split(':')[0].strip()
                try:
                    a = socket.inet_ntoa(fcntl.ioctl(sk.fileno(), 0x8915, struct.pack('16s16x', n.encode()))[20:24])
                except OSError:
                    continue
                if a == addr:
                    sk.close()
                    return n
            sk.close()
        except OSError:
            pass
        return ''

    # -- the host's tables -------------------------------------------------------------
    def _snmp(self):
        out = {}
        try:
            lines = open('/proc/net/snmp').read().splitlines()
        except OSError:
            return out
        for i in range(0, len(lines) - 1, 2):
            k, names = lines[i].split(':', 1)
            _, vals = lines[i + 1].split(':', 1)
            out[k] = dict(zip(names.split(), (int(v) for v in vals.split())))
        return out

    def _devstats(self):
        st = {}
        try:
            for line in open('/proc/net/dev').read().splitlines()[2:]:
                n, rest = line.split(':', 1)
                v = [int(x) for x in rest.split()]
                st[n.strip()] = v
        except OSError:
            pass
        return st

    def _mac(self, hname):
        try:
            return bytes(int(x, 16) for x in open('/sys/class/net/%s/address' % hname).read().strip().split(':'))
        except (OSError, ValueError):
            return b''

    def _mtu(self, hname, default):
        try:
            return int(open('/sys/class/net/%s/mtu' % hname).read())
        except (OSError, ValueError):
            return default

    def _index(self, hname):
        for i, (name, *_r) in enumerate(self.ifs):
            if self.hostif.get(name) == hname:
                return i + 1
        return 0

    def if_entries(self):
        stats = self._devstats()
        out = []
        for i, (name, addr, mask, bcast, flags) in enumerate(self.ifs):
            h = self.hostif.get(name, '')
            v = stats.get(h, [0] * 16)
            # /proc/net/dev: rx bytes packets errs drop fifo frame compressed multicast,
            #                tx bytes packets errs drop fifo colls carrier compressed
            loop = name == 'lo0'
            # (11.00's kernel keeps 32 bytes of a description)
            descr = ('%s Software Loopback' if self.v11 else '%s Hewlett-Packard Software Loopback') if loop \
                else '%s Hewlett-Packard LAN Interface'
            descr %= name
            mac = b'' if loop else self._mac(h)
            out.append(struct.pack(IF_ENTRY_11 if self.v11 else IF_ENTRY, i + 1, descr.encode()[:63], 24 if loop else 6,
                                   4136 if loop else self._mtu(h, 1500), 0 if loop else 10000000,
                                   self._phys(mac), 1, 1, 0,
                                   v[0] & 0xFFFFFFFF, (v[1] - v[7]) & 0xFFFFFFFF, v[7] & 0xFFFFFFFF, v[3] & 0xFFFFFFFF,
                                   v[2] & 0xFFFFFFFF, 0,
                                   v[8] & 0xFFFFFFFF, v[9] & 0xFFFFFFFF, 0, v[11] & 0xFFFFFFFF, v[10] & 0xFFFFFFFF,
                                   0, 0))
        return out

    def ipad_entries(self):
        # BcastAddr is the MIB's ipAdEntBcastAddr, the low bit of the broadcast address
        # (1: all ones) - HP's agent passes the field through as that integer
        return [struct.pack(IPAD_ENTRY, _aton(addr), i + 1, _aton(mask), _aton(bcast) & 1, 65535)
                for i, (name, addr, mask, bcast, flags) in enumerate(self.ifs)]

    def route_entries(self):
        out = []
        # the loopback network, which HP-UX has as a route through lo0
        out.append(struct.pack(ROUTE_ENTRY, _aton('127.0.0.0'), self._index('lo') or 1, 0, -1, -1, -1, _aton('127.0.0.1'), 3, 2, 0,
                               _aton('255.0.0.0')))
        try:
            lines = open('/proc/net/route').read().splitlines()[1:]
        except OSError:
            lines = []
        for line in lines:
            p = line.split()
            if len(p) < 8:
                continue
            idx = self._index(p[0])
            if not idx:
                continue
            dest, gw, flags, metric, mask = _hexaddr(p[1]), _hexaddr(p[2]), int(p[3], 16), int(p[6]), _hexaddr(p[7])
            if not flags & 1:          # RTF_UP
                continue
            remote = bool(flags & 2)   # RTF_GATEWAY
            nexthop = gw if remote else _aton(self.ifs[idx - 1][1])
            out.append(struct.pack(ROUTE_ENTRY, dest, idx, metric if remote else 0, -1, -1, -1, nexthop,
                                   4 if remote else 3, 2, 0, mask))
        return out

    def arp(self):
        out = []
        try:
            lines = open('/proc/net/arp').read().splitlines()[1:]
        except OSError:
            return out
        for line in lines:
            p = line.split()
            if len(p) < 6 or p[3] == '00:00:00:00:00:00':
                continue
            idx = self._index(p[5])
            if not idx:
                continue
            mac = bytes(int(x, 16) for x in p[3].split(':'))
            flags = int(p[2], 16)
            out.append((idx, mac, _aton(p[0]), 4 if flags & 4 else 3))    # ATF_PERM: static
        return out

    def ntm_entries(self):
        return [struct.pack(NTM_ENTRY_11 if self.v11 else NTM_ENTRY, idx, self._phys(mac), a, t)
                for idx, mac, a, t in self.arp()]

    def at_entries(self):
        return [struct.pack(AT_ENTRY_11 if self.v11 else AT_ENTRY, idx, self._phys(mac), a)
                for idx, mac, a, t in self.arp()]

    def _phys(self, mac):
        """a physical address field: 8 bytes (10.20), or mib_physaddr_t (11.00)"""
        if self.v11:
            return struct.pack('>i', len(mac)) + mac.ljust(32, b'\0')
        return mac.ljust(8, b'\0')

    def _sockets(self, name):
        out = []
        try:
            lines = open('/proc/net/' + name).read().splitlines()[1:]
        except OSError:
            return out
        for line in lines:
            p = line.split()
            la, lp = p[1].split(':')
            ra, rp = p[2].split(':')
            out.append((_hexaddr(la), int(lp, 16), _hexaddr(ra), int(rp, 16), int(p[3], 16)))
        return out

    def tcp_entries(self):
        conns = sorted(set(self._sockets('tcp')), key=lambda c: (c[0], c[1], c[2], c[3]))
        return [struct.pack(TCPCONN_ENTRY, TCP_STATE.get(s, 1), la, lp - 65536 if lp > 32767 else lp,
                            ra, rp - 65536 if rp > 32767 else rp)
                for la, lp, ra, rp, s in conns]

    def udp_entries(self):
        lsn = sorted({(la, lp) for la, lp, ra, rp, s in self._sockets('udp')})
        return [struct.pack(UDPLSN_ENTRY, la, lp - 65536 if lp > 32767 else lp) for la, lp in lsn]

    def counters(self, group):
        sec = self._snmp().get(SNMP_SECTION[group], {})
        vals = []
        for n in COUNTERS[group]:
            v = sec.get(n, 0)
            if group == GP_tcp and n == 'MaxConn':
                v = -1
            vals.append(v & 0xFFFFFFFF)
        return vals

    # -- the request ---------------------------------------------------------------------
    def get(self, objid, key=b''):
        """the bytes for an object id (key: the caller's buffer, for an Entry)"""
        g, i = objid >> 16, objid & 0xFFFF
        pa = 40 if self.v11 else 12          # where NetAddr follows the physical address
        tables = {
            (GP_if, 1): ('count', self.if_entries), (GP_if, 2): ('table', self.if_entries), (GP_if, 3): ('entry', self.if_entries, 0, 4),
            (GP_at, 1): ('count', self.at_entries), (GP_at, 2): ('table', self.at_entries), (GP_at, 3): ('entry', self.at_entries, pa, 4),
            (GP_ip, 1025): ('count', self.ipad_entries), (GP_ip, 1026): ('table', self.ipad_entries), (GP_ip, 1027): ('entry', self.ipad_entries, 0, 4),
            (GP_ip, 1028): ('count', self.route_entries), (GP_ip, 1029): ('table', self.route_entries), (GP_ip, 1030): ('entry', self.route_entries, 0, 4),
            (GP_ip, 1031): ('count', self.ntm_entries), (GP_ip, 1032): ('table', self.ntm_entries), (GP_ip, 1033): ('entry', self.ntm_entries, pa, 4),
            (GP_tcp, 1025): ('count', self.tcp_entries), (GP_tcp, 1026): ('table', self.tcp_entries), (GP_tcp, 1027): ('entry', self.tcp_entries, 4, 16),
            (GP_udp, 1025): ('count', self.udp_entries), (GP_udp, 1026): ('table', self.udp_entries), (GP_udp, 1027): ('entry', self.udp_entries, 0, 6),
        }
        if (g, i) in tables:
            kind, fn = tables[(g, i)][:2]
            rows = fn()
            if kind == 'count':
                return struct.pack('>i', len(rows))
            if kind == 'table':
                return b''.join(rows)
            off, ln = tables[(g, i)][2:]
            want = key[off:off + ln]
            for r in rows:
                if r[off:off + ln] == want:
                    return r
            raise NetmanError('ENOENT')
        if self.v11 and (g, i) == (GP_ip, 23):
            return struct.pack('>I', 0)      # ipRoutingDiscards (11.00): Linux does not count them
        if g in COUNTERS:
            vals = self.counters(g)
            if i == 0:
                return struct.pack('>%dI' % len(vals), *vals)
            if 1 <= i <= len(vals):
                return struct.pack('>I', vals[i - 1])
        if g == GP_sys:
            if i == 1:
                return b'Hewlett-Packard HP-UX\0'
            if i == 3:
                return struct.pack('>I', int((time.time() - self.boot_time) * 100) & 0xFFFFFFFF)
        raise NetmanError('EINVAL')


# -- HP-UX 11.00: MIB-2 from /dev/ip -------------------------------------------------------
#
# 11.00 has no /dev/netman. libnm.1 (mibget) reads MIB-2 the SVR4 way: open /dev/ip (or
# /dev/nuls with tcpm/udpm pushed, or /dev/ip with arpm), putmsg a T_OPTMGMT_REQ
# (MGMT_flags 0x80) carrying one XTI t_opthdr {len 16, level MIB2_IP, name 0}, then
# getmsg replies until the end: each a T_OPTMGMT_ACK (prim 29, MGMT_flags 0x20) whose
# t_opthdr {len = 16 + data, level, name} announces one table, its bytes the message's
# data part (so the first getmsg, ctl only, returns MOREDATA); the last has len 16 and no
# data. The levels are 256 + the MIB group; the names are 0 (the group's scalars) and
# the tables' Solaris numbers. libnm.1 copies the records into sys/mib.h's structures.

MIB2_IF, MIB2_IP, MIB2_ICMP, MIB2_TCP, MIB2_UDP = 258, 260, 261, 262, 263
MIB2_IP_ADDR, MIB2_IP_ROUTE, MIB2_IP_MEDIA, MIB2_TCP_CONN, MIB2_UDP_ENTRY = 20, 21, 22, 13, 5
T_OPTMGMT_ACK, T_ERROR_ACK, T_SUCCESS, T_CURRENT = 29, 25, 0x20, 0x80
DL_ATTACH_REQ, DL_DETACH_REQ, DL_OK_ACK, DL_ERROR_ACK, DL_HP_PPA_REQ, DL_HP_PPA_ACK = 0x0b, 0x0c, 0x06, 0x05, 0xe2, 0xe1
DL_HP_MIB_REQ = 526             # libnm's setup_mci_get_req: {526, 1, 0x7fffffff, 1, 28, ...}
# the kernel's record sizes (libnm divides the table lengths by them)
IPADDR_REC, ROUTE_REC, MEDIA_REC, TCPCONN_REC, UDP_REC, IF_REC = 88, 116, 92, 56, 20, 152


def _pad(b, n):
    return b + b'\0' * (n - len(b))


def mib2_tables(nm):
    """[(level, name, bytes)]: what /dev/ip reports, as the 11.00 kernel lays it out"""
    out = []
    ifs = nm.if_entries()                  # 11.00 mib_ifEntry, 180 bytes each
    out.append((MIB2_IF, 1, struct.pack('>i', len(ifs))))
    for u in [u for (e, u) in zip(nm.ifs, ifs) if e[0] == 'lo0']:
        # IP's own interface, the loopback (the LAN interfaces come from DLPI: MibStream); the
        # kernel's record: index, a word, a 32-byte description, type mtu speed and
        # the physical address length, the address, then the status words and counters
        descr = u[4:68].split(b'\0')[0][:31]
        out.append((MIB2_IF, 2, u[0:4] + b'\0' * 4 + descr.ljust(32, b'\0') + u[68:84] + u[84:116] + u[116:180]))
    ip = nm.counters(GP_ip)
    tcp = nm.counters(GP_tcp)
    udp = nm.counters(GP_udp)
    # mib2_ip: the 19 counters, the entry sizes, ipRoutingDiscards, then tcpInErrs and
    # udpNoPorts (libnm reads those two here), checksum and overflow counts
    ipw = ip + [IPADDR_REC, ROUTE_REC, MEDIA_REC, 0, tcp[12], udp[1], 0, 0, 0, 0, 0, 0, 0]
    out.append((MIB2_IP, 0, struct.pack('>%dI' % len(ipw), *ipw)))
    out.append((MIB2_IP, MIB2_IP_ADDR, b''.join(
        _pad(struct.pack('>IiII', *struct.unpack('>IiII', r[:16])[:3], 1) + r[16:20], IPADDR_REC)
        for r in nm.ipad_entries())))
    out.append((MIB2_IP, MIB2_IP_ROUTE, b''.join(_pad(r, ROUTE_REC) for r in nm.route_entries())))
    out.append((MIB2_IP, MIB2_IP_MEDIA, b''.join(_pad(r, MEDIA_REC) for r in nm.ntm_entries())))
    icmp = nm.counters(GP_icmp)
    out.append((MIB2_ICMP, 0, struct.pack('>%dI' % len(icmp), *icmp)))
    tw = tcp + [0] * 10
    out.append((MIB2_TCP, 0, struct.pack('>%dI' % len(tw), *tw)))
    conns = []
    for r in nm.tcp_entries():
        st, la, lp, ra, rp = struct.unpack(TCPCONN_ENTRY, r)
        conns.append(_pad(struct.pack('>iIiIi', st, la, lp & 0xFFFF, ra, rp & 0xFFFF), TCPCONN_REC))
    out.append((MIB2_TCP, MIB2_TCP_CONN, b''.join(conns)))
    # mib2_udp: InDatagrams, InErrors, OutDatagrams
    out.append((MIB2_UDP, 0, struct.pack('>3I8x', udp[0], udp[2], udp[3])))
    lsn = []
    for r in nm.udp_entries():
        la, lp = struct.unpack(UDPLSN_ENTRY, r)
        lsn.append(_pad(struct.pack('>Ii', la, lp & 0xFFFF), UDP_REC))
    out.append((MIB2_UDP, MIB2_UDP_ENTRY, b''.join(lsn)))
    return out


class MibStream:
    """/dev/ip and /dev/nuls of an 11.00 root: a stream the emulator answers itself, with
    what Stream (streams.py) offers the stream calls - the messages waiting, and call()
    for putmsg and the ioctls. A T_OPTMGMT_REQ for MIB-2 queues mib2_tables()' replies;
    modules can be pushed and popped (libnm pushes arpm, tcpm, udpm) and change nothing."""

    def __init__(self, driver, netman_fn):
        import collections
        self.driver = driver
        self.netman_fn = netman_fn
        self.sid = 0
        self.fd = -1
        self.msgs = collections.deque()
        self.rerror = self.werror = 0
        self.hangup = False
        self.rdopt = 0x11
        self.wropt = 0
        self.sigs = []
        self.sigevents = 0
        self.modules = []

    def ready(self):
        import select
        if not self.msgs:
            return 0
        return select.POLLPRI if self.msgs[0].type == 0x83 else select.POLLIN

    def pending(self):
        return False

    def wait_msg(self, nonblock, wait, pred=lambda m: True):
        from .streams import StreamError
        for m in self.msgs:
            if pred(m):
                return m
        raise StreamError(11)      # nothing will come: EAGAIN rather than a wait forever

    def _optmgmt(self, ctl):
        from .streams import Msg, M_PCPROTO, M_PROTO
        prim, olen, ooff, flags = struct.unpack('>iiii', ctl[:16])
        level = struct.unpack('>i', ctl[ooff + 4:ooff + 8])[0] if olen >= 16 and len(ctl) >= ooff + 16 else 0
        if not flags & T_CURRENT or not MIB2_IF <= level <= MIB2_UDP:
            self.msgs.append(Msg(M_PCPROTO, 0, struct.pack('>iiii', T_ERROR_ACK, prim, 3, 0), None))   # TBADOPT
            return
        for lvl, name, data in mib2_tables(self.netman_fn()):
            hdr = struct.pack('>iiii', T_OPTMGMT_ACK, 16, 16, T_SUCCESS) + struct.pack('>iiii', 16 + len(data), lvl, name, 0)
            self.msgs.append(Msg(M_PROTO, 0, hdr, data))
        self.msgs.append(Msg(M_PROTO, 0, struct.pack('>iiii', T_OPTMGMT_ACK, 16, 16, T_SUCCESS) +
                             struct.pack('>iiii', 16, 0, 0, 0), None))

    def _dlpi(self, ctl):
        """/dev/dlpi and /dev/lanN: the LAN interfaces as libnm sees them - DL_HP_PPA_REQ
        lists them (each with its ifIndex as dl_nmid and its device, /dev/ + dl_module_id_1),
        DL_ATTACH_REQ picks one, and HP's network management request (526) answers an
        ifEntry with the 11.00 mib_ifEntry in the data part (reply word 2: 0 for success)"""
        from .streams import Msg, M_PCPROTO, M_PROTO
        prim = struct.unpack('>I', ctl[:4])[0]
        nm = self.netman_fn()
        lans = [(i, e) for i, e in enumerate(nm.ifs) if e[0] != 'lo0']
        if prim == DL_HP_PPA_REQ:
            infos = []
            for ppa, (i, (name, addr, mask, bcast, flags)) in enumerate(lans):
                mac = nm._mac(nm.hostif.get(name, ''))
                infos.append(struct.pack('>II100sI20sII64sIII64s64s64sIII', 0, ppa, b'0/0/0/%d' % ppa, 4, mac, len(mac),
                                         52, b'btlan', ppa, nm._mtu(nm.hostif.get(name, ''), 1500), 0,
                                         name.encode(), b'', b'arpm', i + 1, 0, 0))
            data = b''.join(infos)
            self.msgs.append(Msg(M_PCPROTO, 0, struct.pack('>IIII', DL_HP_PPA_ACK, len(data), len(infos), 16) + data, None))
        elif prim == DL_ATTACH_REQ:
            ppa = struct.unpack('>I', ctl[4:8])[0]
            if ppa < len(lans):
                self.ppa = ppa
                self.msgs.append(Msg(M_PCPROTO, 0, struct.pack('>II', DL_OK_ACK, prim), None))
            else:
                self.msgs.append(Msg(M_PCPROTO, 0, struct.pack('>IIII', DL_ERROR_ACK, prim, 8, 0), None))   # DL_BADPPA
        elif prim == DL_DETACH_REQ:
            self.msgs.append(Msg(M_PCPROTO, 0, struct.pack('>II', DL_OK_ACK, prim), None))
        elif prim == DL_HP_MIB_REQ and len(ctl) >= 68:
            # {526, 1, 0x7fffffff, 1, 28, OID length, ?, the OID 1.3.6.1.2.1.group.table.entry.key}
            group, = struct.unpack('>I', ctl[52:56])
            key, = struct.unpack('>i', ctl[64:68])
            ifs = nm.if_entries()
            ok = group == GP_if and 1 <= key <= len(ifs)
            reply = ctl[:8] + struct.pack('>I', 0 if ok else 22) + ctl[12:28]
            self.msgs.append(Msg(M_PCPROTO, 0, reply, ifs[key - 1] if ok else None))
        else:
            self.msgs.append(Msg(M_PCPROTO, 0, struct.pack('>IIII', DL_ERROR_ACK, prim, 3, 0), None))     # DL_BADPRIM

    def call(self, op, payload, copyin=None, copyout=None, wait=None):
        from . import streams
        if op == streams.RQ_PUTMSG:
            hipri, band, nc, nd = struct.unpack('>iiii', payload[:16])
            ctl = payload[16:16 + nc] if nc >= 0 else None
            if ctl is None or len(ctl) < 4:
                return -1, 71, b''              # EPROTO
            if self.driver != 'ip' and self.driver != 'nuls':
                self._dlpi(ctl)
                return 0, 0, b''
            if len(ctl) >= 16 and struct.unpack('>i', ctl[:4])[0] == 8:
                self._optmgmt(ctl)
                return 0, 0, b''
            return -1, 71, b''
        if op == streams.RQ_IOCTL:
            req, arg, ln = struct.unpack('>iiI', payload[:12])
            body = payload[12:12 + ln]
            I_PUSH, I_POP, I_LOOK, I_FLUSH, I_FIND, I_LIST = 0x5302, 0x5303, 0x5304, 0x5305, 0x530b, 0x5316
            low = req & 0xFFFF
            if low == I_PUSH:
                self.modules.insert(0, body.split(b'\0')[0])
                return 0, 0, b''
            if low == I_POP:
                if not self.modules:
                    return -1, 22, b''
                self.modules.pop(0)
                return 0, 0, b''
            if low == I_FIND:
                return int(body.split(b'\0')[0] in self.modules), 0, b''
            if low == I_LIST:
                names = self.modules + [self.driver.encode()]
                return len(names), 0, b''.join(n[:8].ljust(9, b'\0') for n in names)
            if low == I_LOOK:
                if not self.modules:
                    return -1, 22, b''
                return 0, 0, self.modules[0][:8].ljust(9, b'\0')
            if low == I_FLUSH:
                if arg & 1:
                    self.msgs.clear()
                return 0, 0, b''
            return -1, 22, b''
        if op == streams.RQ_CLOSE:
            return 0, 0, b''
        return -1, 22, b''
