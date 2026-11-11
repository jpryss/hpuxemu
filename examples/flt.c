/* flt.c - loads and stores the program may not make, and SIGSEGV from outside: what the
   emulator's fault handler (unchecked loads in compiled code) must get right */
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
jmp_buf jb; int got;
void h(sig) int sig; { got = sig; signal(sig, h); longjmp(jb, 1); }
int rd(p) volatile char *p; { int i, s = 0; for (i = 0; i < 2000; i++) s += p[0] + i; return s; }
main()
{
    char *p; int i, n = 0, pid, st;
    signal(SIGSEGV, h); signal(SIGBUS, h);
    /* unmapped */
    for (i = 0; i < 50; i++) { got = 0; if (!setjmp(jb)) { rd((char *)0x60000000 + i * 4096); printf("no fault!\n"); } else n++; sigsetmask(0); }
    printf("unmapped: %d faults, last signal %d\n", n, got);
    /* a page with no access, then readable again */
    p = mmap(0, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    p[0] = 7; p[4096] = 9;
    printf("readable: %d\n", rd(p) > 0);
    mprotect(p, 4096, PROT_NONE);
    got = 0; if (!setjmp(jb)) { rd(p); printf("no fault!\n"); } else printf("PROT_NONE: signal %d\n", got); sigsetmask(0);
    printf("next page still readable: %d\n", p[4096]);
    mprotect(p, 4096, PROT_READ);
    printf("PROT_READ again: %d\n", p[0]);
    got = 0; if (!setjmp(jb)) { p[0] = 1; printf("no fault on write!\n"); } else printf("write to read-only: signal %d\n", got); sigsetmask(0);
    /* a deep stack: grows on demand */
    { volatile char big[3000000]; big[0] = 1; big[2999999] = 2; printf("stack: %d\n", big[0] + big[2999999]); }
    /* SIGSEGV sent by another process: the handler, then the default action */
    got = 0; if (!setjmp(jb)) { kill(getpid(), SIGSEGV); for (i = 0; i < 100000000; i++) ; printf("not delivered\n"); } else printf("kill: signal %d\n", got); sigsetmask(0);
    fflush(stdout);
    if ((pid = fork()) == 0) { signal(SIGSEGV, SIG_DFL); for (;;) rd(p + 4096); }
    sleep(1); kill(pid, SIGSEGV); wait(&st); printf("child: status %#x\n", st); fflush(stdout);
    if ((pid = fork()) == 0) { signal(SIGSEGV, SIG_IGN); kill(getpid(), SIGSEGV); printf("ignored\n"); fflush(stdout); signal(SIGSEGV, SIG_DFL); rd((char *)0x60000000); _exit(3); }
    wait(&st); printf("child: status %#x\n", st);
    return 0;
}
