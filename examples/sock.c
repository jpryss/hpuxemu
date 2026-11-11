/* A socket test: a TCP server on the loopback interface and a client in a child,
   then the same over a Unix-domain socket. K&R C for HP's bundled cc. */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int talk(s) int s; {
    char buf[64]; int n;
    n = recv(s, buf, sizeof buf, 0);
    if (n <= 0) { perror("recv"); return 1; }
    buf[n] = 0;
    printf("server got: %s\n", buf);
    send(s, "pong", 4, 0);
    return 0;
}

int main(argc, argv) int argc; char **argv; {
    int ls, s, c, n, one = 1, len; struct sockaddr_in sin, peer; struct sockaddr_un sun;
    char buf[64];
    ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof one);
    memset((char *) &sin, 0, sizeof sin);
    sin.sin_family = AF_INET; sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sin.sin_port = 0;
    if (bind(ls, (struct sockaddr *) &sin, sizeof sin) < 0) { perror("bind"); return 1; }
    len = sizeof sin;
    getsockname(ls, (struct sockaddr *) &sin, &len);
    printf("listening on %s port %d\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    listen(ls, 5);
    if (fork() == 0) {
        c = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(c, (struct sockaddr *) &sin, sizeof sin) < 0) { perror("connect"); _exit(1); }
        send(c, "ping", 4, 0);
        n = recv(c, buf, sizeof buf, 0); buf[n > 0 ? n : 0] = 0;
        write(1, "client got: ", 12); write(1, buf, n > 0 ? n : 0); write(1, "\n", 1);
        _exit(0);
    }
    len = sizeof peer;
    s = accept(ls, (struct sockaddr *) &peer, &len);
    if (s < 0) { perror("accept"); return 1; }
    printf("accepted from %s\n", inet_ntoa(peer.sin_addr));
    talk(s); close(s); wait(0); close(ls);

    unlink("/tmp/sock.test");
    ls = socket(AF_UNIX, SOCK_STREAM, 0);
    memset((char *) &sun, 0, sizeof sun);
    sun.sun_family = AF_UNIX; strcpy(sun.sun_path, "/tmp/sock.test");
    if (bind(ls, (struct sockaddr *) &sun, sizeof sun) < 0) { perror("bind unix"); return 1; }
    listen(ls, 5);
    if (fork() == 0) {
        c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(c, (struct sockaddr *) &sun, sizeof sun) < 0) { perror("connect unix"); _exit(1); }
        send(c, "unix ping", 9, 0);
        n = recv(c, buf, sizeof buf, 0); buf[n > 0 ? n : 0] = 0;
        write(1, "client got: ", 12); write(1, buf, n > 0 ? n : 0); write(1, "\n", 1);
        _exit(0);
    }
    len = sizeof sun;
    s = accept(ls, (struct sockaddr *) &sun, &len);
    talk(s); close(s); wait(0);
    unlink("/tmp/sock.test");
    printf("done\n");
    return 0;
}
