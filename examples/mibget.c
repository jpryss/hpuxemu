/* MIB-2 through libnm, HP's network management library, as the SNMP agent (mib2agt)
   reads it: open_mib() and get_mib_info() - on 11.00 a T_OPTMGMT_REQ to /dev/ip and the
   tables in getmsg replies, the LAN interfaces' entries from DLPI (/dev/dlpi, /dev/lan0);
   11.00 only (10.20's agent reads /dev/netman: netman.c). K&R C for HP's bundled cc:
   cc -o mibget mibget.c -lnm. A LAN interface's entry is read through its own device,
   open_mib("/dev/lan0", O_RDWR, ppa, 0); IP's (/dev/ip) has the loopback and the rest.
   Prints:   ifs 2 lan0 lo0  loop 127.0.0.1 rto 1 udp 1 icmp 1 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int get(fd, id, buf, len) int fd; int id; char *buf; int *len; {
    struct nmparms p;
    p.objid = id; p.buffer = buf; p.len = (unsigned int *)len;
    return get_mib_info(fd, &p);
}

/* the description of interface i, read through the stream fd */
void descr(fd, i) int fd; int i; {
    mib_ifEntry e;
    int len;
    e.ifIndex = i;
    len = sizeof e;
    if (get(fd, ID_ifEntry, (char *)&e, &len) < 0)
        printf(" ?");
    else
        printf(" %.4s", e.ifDescr);
}

main() {
    int fd, lan, n, len, i, v, lo;
    mib_ipAdEnt ads[8];
    struct in_addr a;

    fd = open_mib("/dev/ip", O_RDWR, 0, 0);
    if (fd < 0) { perror("open_mib"); return 1; }
    len = sizeof n;
    if (get(fd, ID_ifNumber, (char *)&n, &len) < 0) { perror("ifNumber"); return 1; }
    printf("ifs %d", n);
    lan = open_mib("/dev/lan0", O_RDWR, 0, 0);
    if (lan < 0) { perror("open_mib /dev/lan0"); return 1; }
    descr(lan, 1);              /* 11.00 numbers the LAN interfaces first */
    close_mib(lan);
    descr(fd, n);
    len = sizeof ads;
    if (get(fd, ID_ipAddrTable, (char *)ads, &len) < 0) { perror("ipAddrTable"); return 1; }
    lo = 0;
    for (i = 0; i < len / sizeof ads[0]; i++)
        if (ads[i].Addr == htonl(INADDR_LOOPBACK)) { a.s_addr = ads[i].Addr; lo = 1; }
    printf(" loop %s", lo ? inet_ntoa(a) : "-");
    len = sizeof v;
    if (get(fd, ID_tcpRtoMin, (char *)&v, &len) < 0) { perror("tcpRtoMin"); return 1; }
    printf(" rto %d", v > 0);
    len = sizeof v;
    if (get(fd, ID_udpInDatagrams, (char *)&v, &len) < 0) { perror("udpInDatagrams"); return 1; }
    printf(" udp %d", len == 4);
    len = sizeof v;
    if (get(fd, ID_icmpInMsgs, (char *)&v, &len) < 0) { perror("icmpInMsgs"); return 1; }
    printf(" icmp %d\n", len == 4);
    close_mib(fd);
    return 0;
}
