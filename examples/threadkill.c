/* HP-UX 11.00: pthread_kill aims at one thread - the handler runs in that thread, whether
   it is busy, waiting on a condition or blocked in read - and a thread in sigwait takes a
   signal sent to it. cc -o threadkill threadkill.c -lpthread.
   Prints:   busy 1 cond 1 read 1 wait 17 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
pthread_t busy_t, cond_t, read_t, wait_t;
volatile int busy_hit = 0, cond_hit = 0, read_hit = 0, stop = 0;
pthread_mutex_t m; pthread_cond_t c;
int fds[2];
void h(s) int s; {
    pthread_t me = pthread_self();
    if (pthread_equal(me, busy_t)) busy_hit++;
    if (pthread_equal(me, cond_t)) cond_hit++;
    if (pthread_equal(me, read_t)) read_hit++;
}
void *busy(a) void *a; { while (!stop) ; return 0; }
void *condw(a) void *a; {
    pthread_mutex_lock(&m);
    while (!stop) pthread_cond_wait(&c, &m);
    pthread_mutex_unlock(&m);
    return 0;
}
void *reader(a) void *a; { char b[4]; int n = read(fds[0], b, 1); return (void *)n; }
void *waiter(a) void *a; {
    sigset_t s; int sig = 0;
    sigemptyset(&s); sigaddset(&s, SIGUSR2);
    sigwait(&s, &sig);
    return (void *)sig;
}
main() {
    struct sigaction sa; sigset_t s; void *rr, *rw;
    sa.sa_handler = h; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, 0);
    sigemptyset(&s); sigaddset(&s, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &s, 0);
    pthread_mutex_init(&m, 0); pthread_cond_init(&c, 0);
    pipe(fds);
    pthread_create(&busy_t, 0, busy, 0);
    pthread_create(&cond_t, 0, condw, 0);
    pthread_create(&read_t, 0, reader, 0);
    pthread_create(&wait_t, 0, waiter, 0);
    sleep(1);
    pthread_kill(busy_t, SIGUSR1);
    pthread_kill(cond_t, SIGUSR1);
    pthread_kill(read_t, SIGUSR1);
    pthread_kill(wait_t, SIGUSR2);
    sleep(1);
    pthread_join(wait_t, &rw);
    write(fds[1], "x", 1);
    pthread_join(read_t, &rr);
    pthread_mutex_lock(&m); stop = 1; pthread_cond_broadcast(&c); pthread_mutex_unlock(&m);
    pthread_join(busy_t, 0); pthread_join(cond_t, 0);
    printf("busy %d cond %d read %d wait %d\n", busy_hit, cond_hit, read_hit, (int)rw);
    return 0;
}
