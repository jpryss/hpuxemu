#include <stdio.h>
/* a mixed integer/FP loop: the instruction mix of ordinary C code */
unsigned int lcg(s) unsigned int s; { return s * (unsigned)1103515245 + (unsigned)12345; }
int main(argc, argv) int argc; char **argv; {
    unsigned int s = 1; int i; double x = 0; long sum = 0; char buf[4096];
    int n = argc > 1 ? atoi(argv[1]) : 20000000;
    for (i = 0; i < 4096; i++) buf[i] = i;
    for (i = 0; i < n; i++) {
        s = lcg(s);
        sum += buf[s >> 20] ^ (s & 0xff);
        if ((i & 7) == 0) x += (double) (s & 0xffff) / 65536.0;
    }
    printf("%lu %.3f\n", sum, x);
    return 0;
}
