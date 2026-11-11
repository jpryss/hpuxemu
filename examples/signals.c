/* signals.c - fork, pipes, wait, stop/continue, SIGUSR1 bursts, alarm interrupting a read, blocked signals: the expected output ends with "chld>=51 1" (run by tools/sweep.txt) */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
int chld = 0, usr = 0, alrm = 0;
void onchld() { chld++; }
void onusr() { usr++; }
void onalrm() { alrm++; }
void handle(sig, fn) int sig; void (*fn)(); { struct sigaction sa; sa.sa_handler = fn; sigemptyset(&sa.sa_mask); sa.sa_flags = 0; sigaction(sig, &sa, (struct sigaction *) 0); }
main() {
    int i, n, fd[2], st, pid, sum = 0, got = 0; char buf[32];
    handle(SIGCHLD, onchld); handle(SIGUSR1, onusr); handle(SIGALRM, onalrm);
    /* 50 children, each writes its number through a pipe and exits with it */
    for (i = 1; i <= 50; i++) {
        pipe(fd);
        pid = fork();
        if (pid == 0) { close(fd[0]); sprintf(buf, "%d\n", i * i); write(fd[1], buf, strlen(buf)); _exit(i % 100); }
        close(fd[1]);
        n = read(fd[0], buf, sizeof buf); buf[n] = 0; sum += atoi(buf); close(fd[0]);
        while (wait(&st) != pid) ;
        got += (st >> 8) & 0xff;
    }
    printf("pipes %d exits %d\n", sum, got);
    /* a child that we stop, continue, signal and kill */
    pid = fork();
    if (pid == 0) { for (;;) pause(); }
    kill(pid, SIGSTOP); waitpid(pid, &st, 2 /* WUNTRACED */); printf("stopped %d\n", (st & 0xff) == 0177 && ((st >> 8) & 0xff) == SIGSTOP);
    kill(pid, SIGCONT); kill(pid, SIGTERM); waitpid(pid, &st, 0); printf("termsig %d\n", st & 0x7f);
    /* signals to ourselves */
    for (i = 0; i < 100; i++) kill(getpid(), SIGUSR1);
    printf("usr1 %d\n", usr);
    /* alarm interrupts a read on an empty pipe; the read fails with EINTR */
    pipe(fd); alarm(1); errno = 0; n = read(fd[0], buf, 1); printf("alarm %d read %d eintr %d\n", alrm, n, errno == EINTR);
    /* a blocked signal is delivered after unblocking */
    sigblock(sigmask(SIGUSR1)); kill(getpid(), SIGUSR1); printf("blocked %d ", usr); sigsetmask(0); printf("unblocked %d\n", usr);
    printf("chld>=51 %d\n", chld >= 51);
    return 0;
}
