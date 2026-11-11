/* HP-UX 11.00 realtime signals (37..44, SIGRTMIN from sysconf): sigaction with SA_SIGINFO
   and sigqueue, whose value arrives in si_value. cc -o rtsig rtsig.c. Prints: rt 38 got 38 val 42 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
int got = 0, val = 0;
void h(s, si, uc) int s; siginfo_t *si; void *uc; { got = s; val = si ? si->si_value.sival_int : -1; }
main() {
    struct sigaction sa; union sigval v;
    sa.sa_sigaction = h; sigemptyset(&sa.sa_mask); sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGRTMIN + 1, &sa, 0) < 0) { perror("sigaction"); return 1; }
    v.sival_int = 42;
    if (sigqueue(getpid(), SIGRTMIN + 1, v) < 0) { perror("sigqueue"); return 1; }
    printf("rt %d got %d val %d\n", SIGRTMIN + 1, got, val);
    return 0;
}
