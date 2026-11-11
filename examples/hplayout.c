/* hplayout.c - what a program sees of HP-UX's process layout (tools/sweep.txt, sweep11.txt).
 * K&R C, for the bundled cc.
 *
 * - _CPU_REVISION, which crt0 copies from the kernel's process-info block, is the CPU
 *   version sysconf(_SC_CPU_VERSION) gives (HP's Java VM checks it before using its JIT);
 * - shared-library text lies in the fourth quadrant (0xC0000000 up), program text below
 *   (the JIT tells library code from the program's by that);
 * - code written into malloc'd memory runs (the data segment is executable on PA-RISC
 *   HP-UX; the JIT puts its code there). The code includes a single-precision fcmp of a
 *   right-half register (fr4R), the form Solid's ovdbrun uses.
 */
#include <stdio.h>
#include <unistd.h>

extern int _CPU_REVISION;
extern char *malloc();

static unsigned code[] = {
    0x38840484,     /* fcmp,sgl,? fr4R,fr4 - the single-precision compare, right half */
    0xe840c000,     /* bv r0(r2) */
    0x341c0054      /* ldi 42,r28 (in the delay slot) */
};

static unsigned
entry(p)
    unsigned p;
{
    if (p & 2)                      /* a plabel: {entry, linkage pointer} */
        return *(unsigned *) (p & ~3);
    return p & ~3;
}

main()
{
    unsigned *heap = (unsigned *) malloc(sizeof code);
    unsigned plabel[2];
    int (*fn)();
    int i;
    unsigned libc_text = entry((unsigned) printf), prog_text = entry((unsigned) main);

    printf("cpu revision %s\n", _CPU_REVISION == sysconf(_SC_CPU_VERSION) ? "ok" : "WRONG");
    printf("library text %s\n", libc_text >= 0xC0000000 ? "in Q4" : "NOT IN Q4");
    printf("program text %s\n", prog_text < 0x40000000 ? "in Q1" : "NOT IN Q1");
    for (i = 0; i < 3; i++)
        heap[i] = code[i];
    /* call it through a plabel of its own, {entry, r19}: what $$dyncall expects */
    plabel[0] = (unsigned) heap;
    plabel[1] = 0;
    fn = (int (*)()) ((unsigned) plabel | 2);
    printf("heap code returns %d\n", (*fn)());
    return 0;
}
