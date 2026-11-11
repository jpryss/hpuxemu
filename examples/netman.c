/* /dev/netman, HP-UX's network management driver, as mib2agt reads it: the interface
   count and table, the IP address table, one interface entry by index, a counter, and
   a write refused. K&R C for HP's bundled cc. Prints:
       ifs N lo0 1 lan0 ADDRS N loop 127.0.0.1 entry 2 ttl T set refused */
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int get(fd, id, buf, len) int fd; int id; char *buf; int *len; {
    struct nmparms p;
    p.objid = id; p.buffer = buf; p.len = len;
    return ioctl(fd, NMIOGET, &p);
}

main() {
    int fd, n, len, i, ttl;
    mib_ifEntry ifs[8];
    mib_ipAdEnt ads[8];
    mib_ifEntry one;
    struct in_addr a;
    struct nmparms p;

    fd = open("/dev/netman", O_RDWR);
    if (fd < 0) { perror("/dev/netman"); return 1; }
    len = sizeof n;
    if (get(fd, ID_ifNumber, (char *)&n, &len) < 0) { perror("ifNumber"); return 1; }
    printf("ifs %d", n);
    len = sizeof ifs;
    if (get(fd, ID_ifTable, (char *)ifs, &len) < 0) { perror("ifTable"); return 1; }
    for (i = 0; i < len / sizeof ifs[0]; i++)
        printf(" %.4s %d", ifs[i].ifDescr, ifs[i].ifType == 24 ? 1 : 0);
    len = sizeof ads;
    if (get(fd, ID_ipAddrTable, (char *)ads, &len) < 0) { perror("ipAddrTable"); return 1; }
    a.s_addr = ads[0].Addr;
    printf(" ADDRS %d loop %s", len / sizeof ads[0], inet_ntoa(a));
    one.ifIndex = 2;
    len = sizeof one;
    if (get(fd, ID_ifEntry, (char *)&one, &len) < 0) { perror("ifEntry"); return 1; }
    printf(" entry %d", one.ifIndex);
    len = sizeof ttl;
    if (get(fd, ID_ipDefaultTTL, (char *)&ttl, &len) < 0) { perror("ipDefaultTTL"); return 1; }
    printf(" ttl %d", ttl > 0 ? 1 : 0);
    p.objid = ID_ipForwarding; p.buffer = (char *)&ttl; len = sizeof ttl; p.len = &len;
    printf(" set %s\n", ioctl(fd, NMIOSET, &p) < 0 ? "refused" : "allowed");
    return 0;
}
