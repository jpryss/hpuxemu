; ksubr.s - the kernel's setjmp and longjmp for the STREAMS daemon (see strd.c).
; Kernel code saves its context in a label_t (sys/types.h: rp, sp, 17 general
; registers ...), 112 bytes, smaller than the C library's jmp_buf: libc's setjmp
; would write past it. Saved: rp, sp, the callee-saved r3-r18 and dp (r27).
; setjmp returns 0, longjmp makes it return 1.

	.SPACE	$TEXT$
	.SUBSPA	$CODE$

	.EXPORT	setjmp,ENTRY,PRIV_LEV=3,ARGW0=GR,RTNVAL=GR
setjmp
	.PROC
	.CALLINFO	FRAME=0,NO_CALLS
	.ENTRY
	stw	%r2,0(%r26)
	stw	%r30,4(%r26)
	stw	%r3,8(%r26)
	stw	%r4,12(%r26)
	stw	%r5,16(%r26)
	stw	%r6,20(%r26)
	stw	%r7,24(%r26)
	stw	%r8,28(%r26)
	stw	%r9,32(%r26)
	stw	%r10,36(%r26)
	stw	%r11,40(%r26)
	stw	%r12,44(%r26)
	stw	%r13,48(%r26)
	stw	%r14,52(%r26)
	stw	%r15,56(%r26)
	stw	%r16,60(%r26)
	stw	%r17,64(%r26)
	stw	%r18,68(%r26)
	stw	%r27,72(%r26)
	bv	%r0(%r2)
	ldi	0,%r28
	.EXIT
	.PROCEND

	.EXPORT	longjmp,ENTRY,PRIV_LEV=3,ARGW0=GR,RTNVAL=GR
longjmp
	.PROC
	.CALLINFO	FRAME=0,NO_CALLS
	.ENTRY
	ldw	0(%r26),%r2
	ldw	4(%r26),%r30
	ldw	8(%r26),%r3
	ldw	12(%r26),%r4
	ldw	16(%r26),%r5
	ldw	20(%r26),%r6
	ldw	24(%r26),%r7
	ldw	28(%r26),%r8
	ldw	32(%r26),%r9
	ldw	36(%r26),%r10
	ldw	40(%r26),%r11
	ldw	44(%r26),%r12
	ldw	48(%r26),%r13
	ldw	52(%r26),%r14
	ldw	56(%r26),%r15
	ldw	60(%r26),%r16
	ldw	64(%r26),%r17
	ldw	68(%r26),%r18
	ldw	72(%r26),%r27
	bv	%r0(%r2)
	ldi	1,%r28
	.EXIT
	.PROCEND

	.END
