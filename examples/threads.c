/* POSIX threads on HP-UX 11.00 (libpthread over kernel threads: _lwp_create, ksleep,
   kwakeup ...): a mutex, condition variables with a producer and two consumers, a timed
   wait that runs out, two busy threads that only preemption lets share the CPU, and
   threads that block in the kernel - read of a pipe, select with a timeout, waitpid -
   while the others go on. K&R C for HP's bundled cc: cc -o threads threads.c -lpthread.
   Prints:   count 4000 pc 200 20100 timedwait ETIMEDOUT spin 1 read hello 1 select 0 child 3 */
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pthread.h>

pthread_mutex_t m;
pthread_cond_t c;
int counter = 0, queue[16], head = 0, tail = 0, done = 0, consumed = 0;
volatile int spin_a = 0, spin_b = 0, stop = 0, work = 0;
int fds[2];
char got[16];
int selected = -1, status = -1;

void *counting(arg) void *arg; {
    int i;
    for (i = 0; i < 1000; i++) { pthread_mutex_lock(&m); counter++; pthread_mutex_unlock(&m); }
    return arg;
}
void *producer(arg) void *arg; {
    int i;
    for (i = 1; i <= 200; i++) {
        pthread_mutex_lock(&m);
        while ((tail + 1) % 16 == head) pthread_cond_wait(&c, &m);
        queue[tail] = i; tail = (tail + 1) % 16;
        pthread_cond_broadcast(&c);
        pthread_mutex_unlock(&m);
    }
    pthread_mutex_lock(&m); done = 1; pthread_cond_broadcast(&c); pthread_mutex_unlock(&m);
    return 0;
}
void *consumer(arg) void *arg; {
    int sum = 0;
    for (;;) {
        pthread_mutex_lock(&m);
        while (head == tail && !done) pthread_cond_wait(&c, &m);
        if (head == tail && done) { pthread_mutex_unlock(&m); break; }
        sum += queue[head]; head = (head + 1) % 16; consumed++;
        pthread_cond_broadcast(&c);
        pthread_mutex_unlock(&m);
    }
    return (void *)sum;
}
void *spinner(arg) void *arg; {
    while (!stop) { if (arg) spin_a++; else spin_b++; }
    return 0;
}
void *reader(arg) void *arg; {
    int n = read(fds[0], got, sizeof got - 1);
    got[n > 0 ? n : 0] = 0;
    return (void *)(work >= 300000);
}
void *selector(arg) void *arg; {
    fd_set r; struct timeval tv; int p[2];
    pipe(p);
    FD_ZERO(&r); FD_SET(p[0], &r);
    tv.tv_sec = 0; tv.tv_usec = 300000;
    selected = select(p[0] + 1, &r, 0, 0, &tv);
    return 0;
}
void *waiter(arg) void *arg; {
    int pid, st;
    pid = fork();
    if (pid == 0) { sleep(1); _exit(3); }
    waitpid(pid, &st, 0);
    status = WEXITSTATUS(st);
    return 0;
}

main() {
    pthread_t t[4], p, c1, c2, s1, s2, a, b, w;
    void *r1, *r2, *ra;
    struct timespec ts;
    int i, rc;

    pthread_mutex_init(&m, 0); pthread_cond_init(&c, 0);
    for (i = 0; i < 4; i++) pthread_create(&t[i], 0, counting, 0);
    for (i = 0; i < 4; i++) pthread_join(t[i], 0);
    printf("count %d", counter);

    pthread_create(&c1, 0, consumer, 0); pthread_create(&c2, 0, consumer, 0);
    pthread_create(&p, 0, producer, 0);
    pthread_join(p, 0); pthread_join(c1, &r1); pthread_join(c2, &r2);
    printf(" pc %d %d", consumed, (int)r1 + (int)r2);

    pthread_mutex_lock(&m);
    ts.tv_sec = time(0) + 1; ts.tv_nsec = 0;
    rc = pthread_cond_timedwait(&c, &m, &ts);
    pthread_mutex_unlock(&m);
    printf(" timedwait %s", rc == ETIMEDOUT ? "ETIMEDOUT" : "?");

    pthread_create(&s1, 0, spinner, (void *)1); pthread_create(&s2, 0, spinner, 0);
    sleep(1);
    stop = 1;
    pthread_join(s1, 0); pthread_join(s2, 0);
    printf(" spin %d", spin_a > 0 && spin_b > 0);

    pipe(fds);
    pthread_create(&a, 0, reader, 0);
    pthread_create(&b, 0, selector, 0);
    pthread_create(&w, 0, waiter, 0);
    for (i = 0; i < 300000; i++) work++;
    write(fds[1], "hello", 5);
    pthread_join(a, &ra); pthread_join(b, 0); pthread_join(w, 0);
    printf(" read %s %d select %d child %d\n", got, (int)ra, selected, status);
    return 0;
}
