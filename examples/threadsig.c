/* signals in a threaded HP-UX 11.00 program: every thread blocks SIGTERM and one waits
   for it in sigwait (the daemon's way); pthread_kill runs another thread's handler.
   cc -o threadsig threadsig.c -lpthread. Prints:   sigwait got 15 usr1 handled 1 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
volatile int got_usr1 = 0;
void h(s) int s; { got_usr1++; }
void *sigthread(arg) void *arg; {
    sigset_t s; int sig = 0;
    sigemptyset(&s); sigaddset(&s, SIGTERM);
    sigwait(&s, &sig);
    printf("sigwait got %d", sig); fflush(stdout);
    return 0;
}
void *worker(arg) void *arg; {
    int i;
    for (i = 0; i < 50 && !got_usr1; i++) usleep(20000);
    return (void *)got_usr1;
}
main() {
    pthread_t a, b; sigset_t s; void *r;
    struct sigaction sa;
    sigemptyset(&s); sigaddset(&s, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &s, 0);
    sa.sa_handler = h; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, 0);
    pthread_create(&a, 0, sigthread, 0);
    pthread_create(&b, 0, worker, 0);
    sleep(1);
    kill(getpid(), SIGTERM);
    pthread_join(a, 0);
    pthread_kill(b, SIGUSR1);
    pthread_join(b, &r);
    printf(" usr1 handled %d\n", (int)r > 0);
    return 0;
}
