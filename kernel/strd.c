/*
 * strd.c - a STREAMS framework for HP-UX 10.20 kernel STREAMS drivers and modules, run
 * as an ordinary process in hpuxemu (the "STREAMS daemon").
 *
 * A third-party kernel protocol stack (a driver library linked into the kernel by
 * config(1M)) is relocatable PA-RISC code that calls the kernel's STREAMS services:
 * allocb, putq, putnext, qenable, timeout ... This file provides those services, written
 * to the SVR4 STREAMS rules with HP-UX's structure layouts (sys/stream.h), and is linked
 * with the stack's own object files by HP's linker (tools/mkstrd.py), so the stack runs
 * unchanged, as it did in the kernel. The services needing privileged code are trivial
 * here: one process, one thread, no interrupts (spl* do nothing).
 *
 * Processes of the emulator open a STREAMS device (/dev/tcp ...) by connecting to this
 * daemon's socket; each connection is one stream with its stream head here. The
 * emulator turns putmsg/getmsg/read/write/ioctl on such a descriptor into the requests
 * below, and gets the messages that reach the stream head back. The wire format is the
 * guest's (big-endian words).
 *
 *   request  (emulator -> daemon): word op, word length, payload
 *   message  (daemon -> emulator): word kind, word length, payload
 *
 * Written for the bundled (K&R) C compiler of HP-UX 10.20.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include "strd.h"

/* ---- requests and messages (hpuxemu/streams.py has the same numbers) ---- */
#define RQ_OPEN		1	/* flags uid gid pid name -> REPLY rval errno sid */
#define RQ_PUTMSG	2	/* flags band ctllen datalen ctl data -> REPLY */
#define RQ_IOCTL	3	/* cmd arg len data -> COPYIN/COPYOUT ... REPLY rval errno data */
#define RQ_COPYDATA	4	/* errno data: answers COPYIN/COPYOUT */
#define RQ_CLOSE	5
#define RQ_DEBUG	6	/* level: the stack's own debug variables */

#define MS_REPLY	1
#define MS_MSG		2	/* type band ctllen datalen ctl data */
#define MS_FLUSH	3	/* flags */
#define MS_ERROR	4	/* rerror werror */
#define MS_HANGUP	5
#define MS_SIG		6	/* signal */
#define MS_COPYIN	7	/* addr len */
#define MS_COPYOUT	8	/* addr len data */

int lbolt;			/* clock ticks since the daemon started (HZ 100) */
int strmsgsz = 65535;		/* the HP-UX tunables' defaults */
int strctlsz = 1024;
int strd_trace = 0;		/* -t: every message at a stream head */

static struct timeval t0;
static char cred0[64];		/* a struct ucred: root */

/* ======================================================================= */
/* messages                                                                  */
/* ======================================================================= */
#define MBSZ	96		/* msgb plus room for MSG_KERNEL_FIELDS */
#define DBSZ	64		/* datab, padded */

static int nmblk, ndblk;

mblk_t *
allocb(size, pri)
int size;
unsigned int pri;
{
	mblk_t *mp;
	dblk_t *dp;
	unsigned char *buf;

	if (size < 0)
		size = 0;
	mp = (mblk_t *) calloc(1, MBSZ);
	dp = (dblk_t *) calloc(1, DBSZ + size + 8);
	if (mp == 0 || dp == 0)
		return 0;
	buf = (unsigned char *) dp + DBSZ;
	dp->db_base = buf;
	dp->db_lim = buf + size;
	dp->db_ref = 1;
	dp->db_type = M_DATA;
	dp->db_size = size;
	mp->b_datap = dp;
	mp->b_rptr = mp->b_wptr = buf;
	nmblk++;
	ndblk++;
	return mp;
}

mblk_t *
esballoc(base, size, pri, fr)
unsigned char *base;
int size, pri;
frtn_t *fr;
{
	/* the caller's buffer, freed by its free routine */
	mblk_t *mp = (mblk_t *) calloc(1, MBSZ);
	dblk_t *dp = (dblk_t *) calloc(1, DBSZ + sizeof(frtn_t));

	dp->db_base = base;
	dp->db_lim = base + size;
	dp->db_ref = 1;
	dp->db_type = M_DATA;
	dp->db_flag = 1;
	memcpy((char *) dp + DBSZ, (char *) fr, sizeof(frtn_t));
	mp->b_datap = dp;
	mp->b_rptr = mp->b_wptr = base;
	nmblk++;
	ndblk++;
	return mp;
}

int
testb(size, pri)
int size;
unsigned int pri;
{
	return 1;
}

void
freeb(bp)
mblk_t *bp;
{
	dblk_t *dp;

	if (bp == 0)
		return;
	dp = bp->b_datap;
	if (--dp->db_ref == 0) {
		if (dp->db_flag == 1) {
			frtn_t *fr = (frtn_t *) ((char *) dp + DBSZ);
			(*fr->free_func) (fr->free_arg);
		}
		free((char *) dp);
		ndblk--;
	}
	bp->b_datap = 0;
	free((char *) bp);
	nmblk--;
}

void
freemsg(mp)
mblk_t *mp;
{
	mblk_t *n;

	while (mp) {
		n = mp->b_cont;
		freeb(mp);
		mp = n;
	}
}

mblk_t *
dupb(bp)
mblk_t *bp;
{
	mblk_t *nb = (mblk_t *) calloc(1, MBSZ);

	if (nb == 0)
		return 0;
	nb->b_rptr = bp->b_rptr;
	nb->b_wptr = bp->b_wptr;
	nb->b_datap = bp->b_datap;
	nb->b_band = bp->b_band;
	nb->b_flag = bp->b_flag;
	bp->b_datap->db_ref++;
	nmblk++;
	return nb;
}

mblk_t *
dupmsg(mp)
mblk_t *mp;
{
	mblk_t *head = 0, **pp = &head;

	for (; mp; mp = mp->b_cont) {
		if ((*pp = dupb(mp)) == 0) {
			freemsg(head);
			return 0;
		}
		pp = &(*pp)->b_cont;
	}
	return head;
}

mblk_t *
copyb(bp)
mblk_t *bp;
{
	int n = bp->b_wptr - bp->b_rptr;
	mblk_t *nb = allocb(n, 0);

	if (nb == 0)
		return 0;
	nb->b_datap->db_type = bp->b_datap->db_type;
	nb->b_band = bp->b_band;
	nb->b_flag = bp->b_flag;
	memcpy((char *) nb->b_wptr, (char *) bp->b_rptr, n);
	nb->b_wptr += n;
	return nb;
}

mblk_t *
copymsg(mp)
mblk_t *mp;
{
	mblk_t *head = 0, **pp = &head;

	for (; mp; mp = mp->b_cont) {
		if ((*pp = copyb(mp)) == 0) {
			freemsg(head);
			return 0;
		}
		pp = &(*pp)->b_cont;
	}
	return head;
}

void
linkb(mp, bp)
mblk_t *mp, *bp;
{
	while (mp->b_cont)
		mp = mp->b_cont;
	mp->b_cont = bp;
}

mblk_t *
unlinkb(mp)
mblk_t *mp;
{
	mblk_t *bp = mp->b_cont;

	mp->b_cont = 0;
	return bp;
}

mblk_t *
rmvb(mp, bp)
mblk_t *mp, *bp;
{
	mblk_t *head = mp, *prev = 0;

	for (; mp; prev = mp, mp = mp->b_cont)
		if (mp == bp) {
			if (prev)
				prev->b_cont = bp->b_cont;
			else
				head = bp->b_cont;
			bp->b_cont = 0;
			return head;
		}
	return (mblk_t *) -1;
}

int
msgdsize(mp)
mblk_t *mp;
{
	int n = 0;

	for (; mp; mp = mp->b_cont)
		if (mp->b_datap->db_type == M_DATA)
			n += mp->b_wptr - mp->b_rptr;
	return n;
}

static int
msgsize(mp)
mblk_t *mp;
{
	int n = 0;

	for (; mp; mp = mp->b_cont)
		n += mp->b_wptr - mp->b_rptr;
	return n;
}

int
adjmsg(mp, len)
mblk_t *mp;
int len;
{
	mblk_t *bp, *last;
	int type = mp->b_datap->db_type, total = 0, n;

	for (bp = mp; bp && bp->b_datap->db_type == type; bp = bp->b_cont)
		total += bp->b_wptr - bp->b_rptr;
	if ((len < 0 ? -len : len) > total)
		return 0;
	if (len >= 0) {
		for (bp = mp; len > 0 && bp; bp = bp->b_cont) {
			n = bp->b_wptr - bp->b_rptr;
			if (n > len)
				n = len;
			bp->b_rptr += n;
			len -= n;
		}
	} else {
		len = -len;
		while (len > 0) {
			last = 0;
			for (bp = mp; bp && bp->b_datap->db_type == type; bp = bp->b_cont)
				if (bp->b_wptr > bp->b_rptr)
					last = bp;
			if (last == 0)
				break;
			n = last->b_wptr - last->b_rptr;
			if (n > len)
				n = len;
			last->b_wptr -= n;
			len -= n;
		}
	}
	return 1;
}

int
pullupmsg(mp, len)
mblk_t *mp;
int len;
{
	mblk_t *bp, *nb, **pp;
	int type = mp->b_datap->db_type, total = 0, k;
	unsigned char *p, *orp, *owp;
	dblk_t *od;

	for (bp = mp; bp && bp->b_datap->db_type == type; bp = bp->b_cont)
		total += bp->b_wptr - bp->b_rptr;
	if (len == -1)
		len = total;
	if (len > total)
		return 0;
	if (mp->b_wptr - mp->b_rptr >= len && ((long) mp->b_rptr & 3) == 0)
		return 1;
	if ((nb = allocb(len, 0)) == 0)
		return 0;
	p = nb->b_wptr;
	for (bp = mp; len > 0; bp = bp->b_cont) {
		k = bp->b_wptr - bp->b_rptr;
		if (k > len)
			k = len;
		memcpy((char *) p, (char *) bp->b_rptr, k);
		p += k;
		bp->b_rptr += k;
		len -= k;
	}
	/* mp takes the new data block; the old one (what is left of it) follows it */
	od = mp->b_datap;
	orp = mp->b_rptr;
	owp = mp->b_wptr;
	mp->b_datap = nb->b_datap;
	mp->b_rptr = nb->b_rptr;
	mp->b_wptr = p;
	mp->b_datap->db_type = type;
	nb->b_datap = od;
	nb->b_rptr = orp;
	nb->b_wptr = owp;
	nb->b_cont = mp->b_cont;
	mp->b_cont = nb;
	for (pp = &mp->b_cont; *pp && (*pp)->b_datap->db_type == type && (*pp)->b_rptr == (*pp)->b_wptr;) {
		bp = *pp;
		*pp = bp->b_cont;
		freeb(bp);
	}
	return 1;
}

/* ======================================================================= */
/* queues                                                                    */
/* ======================================================================= */
#define QSZ	128		/* queue_t plus room for QUEUE_KERNEL_FIELDS */

struct qrec {			/* every queue, to find a queue's predecessor */
	queue_t *q;
	struct qrec *next;
};
static struct qrec *allq;
static queue_t *runq_head, *runq_tail;

static void
setq(q, qi)
queue_t *q;
struct qinit *qi;
{
	q->q_qinfo = qi;
	if (qi && qi->qi_minfo) {
		q->q_minpsz = qi->qi_minfo->mi_minpsz;
		q->q_maxpsz = qi->qi_minfo->mi_maxpsz;
		q->q_hiwat = qi->qi_minfo->mi_hiwat;
		q->q_lowat = qi->qi_minfo->mi_lowat;
	}
}

/* a queue pair; returns the read queue */
queue_t *
allocqp(rinit, winit)
struct qinit *rinit, *winit;
{
	queue_t *rq = (queue_t *) calloc(1, QSZ), *wq = (queue_t *) calloc(1, QSZ);
	struct qrec *a = (struct qrec *) malloc(sizeof *a), *b = (struct qrec *) malloc(sizeof *b);

	rq->q_flag = QREADR | QUSE | QWANTR;
	wq->q_flag = QUSE | QWANTR;
	rq->q_other = wq;
	wq->q_other = rq;
	setq(rq, rinit);
	setq(wq, winit);
	a->q = rq;
	b->q = wq;
	a->next = b;
	b->next = allq;
	allq = a;
	return rq;
}

void
freeqp(rq)
queue_t *rq;
{
	queue_t *wq = rq->q_other, *q, *pq;
	struct qrec **pp, *r;

	flushq(rq, FLUSHALL);
	flushq(wq, FLUSHALL);
	/* off the run list */
	for (pq = 0, q = runq_head; q; pq = q, q = q->q_link)
		if (q == rq || q == wq) {
			if (pq)
				pq->q_link = q->q_link;
			else
				runq_head = q->q_link;
			if (runq_tail == q)
				runq_tail = pq;
		}
	for (pp = &allq; (r = *pp) != 0;)
		if (r->q == rq || r->q == wq) {
			*pp = r->next;
			free((char *) r);
		} else
			pp = &r->next;
	free((char *) rq);
	free((char *) wq);
}

queue_t *
backq(q)
queue_t *q;
{
	struct qrec *r;

	for (r = allq; r; r = r->next)
		if (r->q->q_next == q)
			return r->q;
	return 0;
}

void
qenable(q)
queue_t *q;
{
	if (q->q_qinfo == 0 || q->q_qinfo->qi_srvp == 0)
		return;
	if (q->q_flag & QENAB)
		return;
	q->q_flag |= QENAB;
	q->q_link = 0;
	if (runq_tail)
		runq_tail->q_link = q;
	else
		runq_head = q;
	runq_tail = q;
}

void
noenable(q)
queue_t *q;
{
	q->q_flag |= QNOENB;
}

void
enableok(q)
queue_t *q;
{
	q->q_flag &= ~QNOENB;
}

static void
backenable(q)
queue_t *q;
{
	while ((q = backq(q)) != 0)
		if (q->q_qinfo && q->q_qinfo->qi_srvp) {
			qenable(q);
			return;
		}
}

/* run the scheduled service procedures */
void
runqueues()
{
	queue_t *q;

	while ((q = runq_head) != 0) {
		runq_head = q->q_link;
		if (runq_head == 0)
			runq_tail = 0;
		q->q_link = 0;
		q->q_flag &= ~QENAB;
		if (q->q_qinfo && q->q_qinfo->qi_srvp)
			(*q->q_qinfo->qi_srvp) (q);
	}
}

static void
qcount(q, mp, sign)
queue_t *q;
mblk_t *mp;
int sign;
{
	if (mp->b_datap->db_type >= QPCTL || mp->b_band)
		return;
	q->q_count += sign * msgsize(mp);
	if (q->q_count >= q->q_hiwat)
		q->q_flag |= QFULL;
	else if (sign < 0)
		q->q_flag &= ~QFULL;
}

/* insert mp before emp (at the end when emp is 0) */
int
insq(q, emp, mp)
queue_t *q;
mblk_t *emp, *mp;
{
	if (emp == 0) {
		mp->b_prev = q->q_last;
		mp->b_next = 0;
		if (q->q_last)
			q->q_last->b_next = mp;
		else
			q->q_first = mp;
		q->q_last = mp;
	} else {
		mp->b_next = emp;
		mp->b_prev = emp->b_prev;
		if (emp->b_prev)
			emp->b_prev->b_next = mp;
		else
			q->q_first = mp;
		emp->b_prev = mp;
	}
	qcount(q, mp, 1);
	return 1;
}

void
rmvq(q, mp)
queue_t *q;
mblk_t *mp;
{
	if (mp->b_prev)
		mp->b_prev->b_next = mp->b_next;
	else
		q->q_first = mp->b_next;
	if (mp->b_next)
		mp->b_next->b_prev = mp->b_prev;
	else
		q->q_last = mp->b_prev;
	mp->b_next = mp->b_prev = 0;
	qcount(q, mp, -1);
	if (q->q_count <= q->q_lowat && (q->q_flag & QWANTW)) {
		q->q_flag &= ~QWANTW;
		backenable(q);
	}
}

/* where a message of this priority and band goes */
static mblk_t *
qplace(q, mp)
queue_t *q;
mblk_t *mp;
{
	mblk_t *bp;

	if (mp->b_datap->db_type >= QPCTL) {
		for (bp = q->q_first; bp && bp->b_datap->db_type >= QPCTL; bp = bp->b_next);
		return bp;
	}
	if (mp->b_band) {
		for (bp = q->q_first; bp && (bp->b_datap->db_type >= QPCTL || bp->b_band >= mp->b_band); bp = bp->b_next);
		return bp;
	}
	return 0;
}

int
putq(q, mp)
queue_t *q;
mblk_t *mp;
{
	int pri = mp->b_datap->db_type >= QPCTL;
	int was_empty = q->q_first == 0;

	insq(q, qplace(q, mp), mp);
	if (pri || ((q->q_flag & QWANTR) && !(q->q_flag & QNOENB)) || (was_empty && !(q->q_flag & QNOENB)))
		qenable(q);
	return 1;
}

int
putbq(q, mp)
queue_t *q;
mblk_t *mp;
{
	mblk_t *bp;

	/* in front of the messages of its own class */
	if (mp->b_datap->db_type >= QPCTL)
		bp = q->q_first;
	else if (mp->b_band)
		for (bp = q->q_first; bp && (bp->b_datap->db_type >= QPCTL || bp->b_band > mp->b_band); bp = bp->b_next);
	else
		for (bp = q->q_first; bp && (bp->b_datap->db_type >= QPCTL || bp->b_band); bp = bp->b_next);
	insq(q, bp, mp);
	if (mp->b_datap->db_type >= QPCTL)
		qenable(q);
	return 1;
}

mblk_t *
getq(q)
queue_t *q;
{
	mblk_t *bp = q->q_first;

	if (bp == 0) {
		q->q_flag |= QWANTR;
		return 0;
	}
	q->q_flag &= ~QWANTR;
	rmvq(q, bp);
	if (q->q_first == 0 && (q->q_flag & QWANTW)) {
		q->q_flag &= ~QWANTW;
		backenable(q);
	}
	return bp;
}

void
flushq(q, flag)
queue_t *q;
int flag;
{
	mblk_t *bp = q->q_first, *nb;

	q->q_first = q->q_last = 0;
	q->q_count = 0;
	q->q_flag &= ~QFULL;
	while (bp) {
		nb = bp->b_next;
		bp->b_next = bp->b_prev = 0;
		if (flag == FLUSHALL || datamsg(bp->b_datap->db_type))
			freemsg(bp);
		else
			insq(q, 0, bp);
		bp = nb;
	}
	if (q->q_flag & QWANTW) {
		q->q_flag &= ~QWANTW;
		backenable(q);
	}
}

void
flushband(q, band, flag)
queue_t *q;
int band, flag;
{
	mblk_t *bp, *nb;

	if (band == 0) {
		flushq(q, flag);
		return;
	}
	for (bp = q->q_first; bp; bp = nb) {
		nb = bp->b_next;
		if (bp->b_band == band && (flag == FLUSHALL || datamsg(bp->b_datap->db_type))) {
			rmvq(q, bp);
			freemsg(bp);
		}
	}
}

int
qsize(q)
queue_t *q;
{
	int n = 0;
	mblk_t *bp;

	for (bp = q->q_first; bp; bp = bp->b_next)
		n++;
	return n;
}

int
canput(q)
queue_t *q;
{
	if (q == 0)
		return 0;
	while (q->q_next && !(q->q_qinfo && q->q_qinfo->qi_srvp))
		q = q->q_next;
	if (q->q_flag & QFULL) {
		q->q_flag |= QWANTW;
		return 0;
	}
	return 1;
}

int
bcanput(q, band)
queue_t *q;
int band;
{
	return canput(q);
}

int
canputnext(q)
queue_t *q;
{
	return canput(q->q_next);
}

/* HP-UX's put(): the queue's own put procedure */
int
puthere(q, mp)
queue_t *q;
mblk_t *mp;
{
	if (q == 0) {
		fprintf(stderr, "strd: message type %#x to no queue, dropped\n", mp->b_datap->db_type);
		freemsg(mp);
		return 0;
	}
	if (q->q_qinfo && q->q_qinfo->qi_putp)
		(*q->q_qinfo->qi_putp) (q, mp);
	else
		putq(q, mp);
	return 0;
}

int
put(q, mp)
queue_t *q;
mblk_t *mp;
{
	return puthere(q, mp);
}

int
putnext(q, mp)
queue_t *q;
mblk_t *mp;
{
	return puthere(q->q_next, mp);
}

void
qreply_(q, mp)
queue_t *q;
mblk_t *mp;
{
	puthere(OTHERQ(q)->q_next, mp);
}

int
putctl(q, type)
queue_t *q;
int type;
{
	mblk_t *mp = allocb(0, 0);

	if (mp == 0)
		return 0;
	mp->b_datap->db_type = type;
	puthere(q, mp);
	return 1;
}

int
putctl1(q, type, param)
queue_t *q;
int type, param;
{
	mblk_t *mp = allocb(1, 0);

	if (mp == 0)
		return 0;
	mp->b_datap->db_type = type;
	*mp->b_wptr++ = param;
	puthere(q, mp);
	return 1;
}

/* ======================================================================= */
/* time                                                                      */
/* ======================================================================= */
struct tmo {
	int id;
	int when;
	int (*fn) ();
	char *arg;
	struct tmo *next;
};
static struct tmo *timeouts;
static int tmo_ids;

static void
tick()
{
	struct timeval tv;

	gettimeofday(&tv, (struct timezone *) 0);
	lbolt = (tv.tv_sec - t0.tv_sec) * HZ + (tv.tv_usec - t0.tv_usec) / (1000000 / HZ);
}

int
timeout(fn, arg, ticks)
int (*fn) ();
char *arg;
int ticks;
{
	struct tmo *t = (struct tmo *) malloc(sizeof *t), **pp;

	tick();
	t->id = ++tmo_ids;
	if (tmo_ids > 0x7ffffff0)
		tmo_ids = 1;
	t->when = lbolt + (ticks > 0 ? ticks : 1);
	t->fn = fn;
	t->arg = arg;
	for (pp = &timeouts; *pp && (*pp)->when <= t->when; pp = &(*pp)->next);
	t->next = *pp;
	*pp = t;
	return t->id;
}

int
untimeout(id)
int id;
{
	struct tmo **pp, *t;

	for (pp = &timeouts; (t = *pp) != 0; pp = &t->next)
		if (t->id == id) {
			*pp = t->next;
			free((char *) t);
			return 0;
		}
	return -1;
}

static void
run_timeouts()
{
	struct tmo *t;

	tick();
	while ((t = timeouts) != 0 && t->when <= lbolt) {
		timeouts = t->next;
		(*t->fn) (t->arg);
		free((char *) t);
		runqueues();
	}
}

/* ======================================================================= */
/* the rest of the kernel interface                                          */
/* ======================================================================= */
int spl5() { return 0; }
int spl6() { return 0; }

int splx(s) int s; { return 0; }

int
strlog(mid, sid, level, flags, fmt, a1, a2, a3, a4, a5)
short mid, sid;
char level;
unsigned short flags;
char *fmt;
int a1, a2, a3, a4, a5;
{
	fprintf(stderr, "strlog %d/%d level %d: ", mid, sid, level);
	fprintf(stderr, fmt, a1, a2, a3, a4, a5);
	fprintf(stderr, "\n");
	return 0;
}

/* drivers and modules: str_install's table */
#define NDEV 32
static struct {
	char name[FMNAMESZ + 1];
	streams_info_t *si;
	int major;
} devsw[NDEV];
static int ndev;
static int next_major = 200;

int
str_install(si)
streams_info_t *si;
{
	int i;

	if (ndev >= NDEV)
		return ENOMEM;
	for (i = 0; i < ndev; i++)
		if (strcmp(devsw[i].name, si->name) == 0)
			return EEXIST;
	strncpy(devsw[ndev].name, si->name, FMNAMESZ);
	devsw[ndev].si = si;
	devsw[ndev].major = si->inst_major >= 0 ? si->inst_major : next_major++;
	fprintf(stderr, "strd: %s %s installed (major %d)\n", si->inst_flags & STR_IS_MODULE ? "module" : "driver",
		si->name, devsw[ndev].major);
	ndev++;
	return 0;
}

int
str_uninstall(si)
streams_info_t *si;
{
	return 0;
}

int install_driver(d, ops) char *d, *ops; { return 0; }
int uninstall_driver(d) char *d; { return 0; }

static int
findsw(name, module)
char *name;
int module;
{
	int i;

	for (i = 0; i < ndev; i++)
		if (strcmp(devsw[i].name, name) == 0 &&
		    ((devsw[i].si->inst_flags & STR_IS_MODULE) != 0) == module)
			return i;
	return -1;
}

/* open and close of a driver or module, V.4 or old style */
static int
qopen(sw, rq, devp, flag, sflag)
int sw;
queue_t *rq;
dev_t *devp;
int flag, sflag;
{
	streams_info_t *si = devsw[sw].si;
	int r;

	if (rq->q_qinfo->qi_qopen == 0)
		return 0;
	if (si->inst_flags & STR_SYSV4_OPEN)
		r = (*rq->q_qinfo->qi_qopen) (rq, devp, flag, sflag, (cred_t *) cred0);
	else {
		r = (*rq->q_qinfo->qi_qopen) (rq, *devp, flag, sflag);
		if (r == OPENFAIL)
			return ENXIO;
		if (sflag == CLONEOPEN)
			*devp = makedev(major(*devp), r);
		r = 0;
	}
	runqueues();
	return r;
}

static void
qclose(sw, rq, flag)
int sw;
queue_t *rq;
int flag;
{
	streams_info_t *si = devsw[sw].si;

	if (rq->q_qinfo->qi_qclose == 0)
		return;
	if (si->inst_flags & STR_SYSV4_OPEN)
		(*rq->q_qinfo->qi_qclose) (rq, flag, (cred_t *) cred0);
	else
		(*rq->q_qinfo->qi_qclose) (rq);
	runqueues();
}

/* ======================================================================= */
/* stream heads                                                              */
/* ======================================================================= */
#define NPUSH 9
struct sth {
	int fd;			/* the emulator's connection; -1 when closed */
	int id;
	int pid;		/* the process that opened it (for the trace) */
	queue_t *rq, *wq;	/* the stream head's queues */
	int drv;		/* devsw index of the driver */
	dev_t dev;
	int npush;		/* modules pushed, sw indices from the top */
	int mods[NPUSH];
	int flag;		/* open flags */
	/* the ioctl waiting for its acknowledgement */
	int ioc_id, ioc_cmd, ioc_kind, ioc_tmo, ioc_len;
	int ioc_link;		/* I_LINK: the lower stream's sth id */
	/* multiplexing */
	struct sth *upper;	/* linked below this stream */
	int lindex, lpersist;
	int rerror, werror, hangup;
	struct sth *next;
};
static struct sth *streams;
static int sth_ids, ioc_ids, link_ids;

#define IOC_STR		1
#define IOC_TRANS	2
#define IOC_LINK	3
#define IOC_UNLINK	4

static int sth_rput();
static int sth_wput();
static struct module_info sth_minfo = { 0, "strhead", 0, INFPSZ, 65536, 8192 };
static struct qinit sth_rinit = { sth_rput, 0, 0, 0, 0, &sth_minfo, 0 };
static struct qinit sth_winit = { sth_wput, 0, 0, 0, 0, &sth_minfo, 0 };

static struct sth *
sth_find(id)
int id;
{
	struct sth *sp;

	for (sp = streams; sp; sp = sp->next)
		if (sp->id == id)
			return sp;
	return 0;
}

/* the guest's words */
static void
put32(p, v)
unsigned char *p;
unsigned int v;
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static unsigned int
get32(p)
unsigned char *p;
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static int
writen(fd, p, n)
int fd;
char *p;
int n;
{
	int k;

	while (n > 0) {
		k = write(fd, p, n);
		if (k < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += k;
		n -= k;
	}
	return 0;
}

static int
readn(fd, p, n)
int fd;
char *p;
int n;
{
	int k;

	while (n > 0) {
		k = read(fd, p, n);
		if (k < 0 && errno == EINTR)
			continue;
		if (k <= 0)
			return -1;
		p += k;
		n -= k;
	}
	return 0;
}

/* one message to the emulator: kind, then the words, then the bytes */
static void
sendmsg_(sp, kind, words, nw, bytes, nb)
struct sth *sp;
int kind;
int *words;
int nw;
char *bytes;
int nb;
{
	unsigned char *buf;
	int i, len = 4 * nw + nb;

	if (sp->fd < 0)
		return;
	buf = (unsigned char *) malloc(8 + len);
	put32(buf, kind);
	put32(buf + 4, len);
	for (i = 0; i < nw; i++)
		put32(buf + 8 + 4 * i, words[i]);
	if (nb > 0)
		memcpy((char *) buf + 8 + 4 * nw, bytes, nb);
	if (writen(sp->fd, (char *) buf, 8 + len) < 0)
		fprintf(stderr, "strd: stream %d: write to the emulator failed (errno %d)\n", sp->id, errno);
	free((char *) buf);
}

static void
reply(sp, rval, err, data, n)
struct sth *sp;
int rval, err;
char *data;
int n;
{
	int w[2];

	w[0] = rval;
	w[1] = err;
	sendmsg_(sp, MS_REPLY, w, 2, data, n);
}

/* the bytes of a message's blocks (of one kind: ctl or data), malloc'ed */
static char *
gather(mp, np)
mblk_t *mp;
int *np;
{
	int n = msgsize(mp);
	char *buf = (char *) malloc(n + 1), *p = buf;

	for (; mp; mp = mp->b_cont) {
		memcpy(p, (char *) mp->b_rptr, mp->b_wptr - mp->b_rptr);
		p += mp->b_wptr - mp->b_rptr;
	}
	*np = n;
	return buf;
}

static void trace_msg();

static void
deliver(sp, mp)
struct sth *sp;
mblk_t *mp;
{
	/* M_PROTO/M_PCPROTO: the first block(s) of that type are the control part */
	mblk_t *bp, *data = mp;
	int type = mp->b_datap->db_type, w[4], nc = -1, nd = -1;
	char *ctl = 0, *dat = 0, *both;

	if (type != M_DATA) {
		for (bp = mp; bp->b_cont && bp->b_cont->b_datap->db_type == type; bp = bp->b_cont);
		data = bp->b_cont;
		bp->b_cont = 0;
		ctl = gather(mp, &nc);
		bp->b_cont = data;
	}
	if (data)
		dat = gather(data, &nd);
	else if (type == M_DATA)
		dat = gather(mp, &nd);
	w[0] = type;
	w[1] = mp->b_band;
	w[2] = nc;
	w[3] = nd;
	both = (char *) malloc((nc > 0 ? nc : 0) + (nd > 0 ? nd : 0) + 1);
	if (nc > 0)
		memcpy(both, ctl, nc);
	if (nd > 0)
		memcpy(both + (nc > 0 ? nc : 0), dat, nd);
	sendmsg_(sp, MS_MSG, w, 4, both, (nc > 0 ? nc : 0) + (nd > 0 ? nd : 0));
	free(both);
	if (ctl)
		free(ctl);
	if (dat)
		free(dat);
	freemsg(mp);
}

static void
ioc_done(sp)
struct sth *sp;
{
	if (sp->ioc_tmo)
		untimeout(sp->ioc_tmo);
	sp->ioc_id = sp->ioc_tmo = 0;
	sp->ioc_kind = 0;
}

static void finish_link();

/* an acknowledgement of the ioctl in progress */
static void
ioc_ack(sp, mp)
struct sth *sp;
mblk_t *mp;
{
	struct iocblk *ioc = (struct iocblk *) mp->b_rptr;
	int kind = sp->ioc_kind, n = 0, rval, err;
	char *data = 0;

	if (mp->b_datap->db_type == M_IOCACK) {
		rval = ioc->ioc_rval;
		err = ioc->ioc_error;
		if (mp->b_cont && ioc->ioc_count > 0 && ioc->ioc_count != TRANSPARENT && kind == IOC_STR) {
			data = gather(mp->b_cont, &n);
			if (n > (int) ioc->ioc_count)
				n = ioc->ioc_count;
		}
	} else {
		rval = -1;
		err = ioc->ioc_error ? ioc->ioc_error : EINVAL;
	}
	if (err)
		rval = -1;
	ioc_done(sp);
	if (kind == IOC_LINK || kind == IOC_UNLINK)
		finish_link(sp, kind, rval, err);
	else
		reply(sp, rval, err, data, n);
	if (data)
		free(data);
	freemsg(mp);
}

static int
ioc_timeout(arg)
char *arg;
{
	struct sth *sp = sth_find((int) arg);

	if (sp && sp->ioc_id) {
		sp->ioc_tmo = 0;
		if (sp->ioc_kind == IOC_LINK || sp->ioc_kind == IOC_UNLINK) {
			int kind = sp->ioc_kind;
			ioc_done(sp);
			finish_link(sp, kind, -1, ETIME);
		} else {
			ioc_done(sp);
			reply(sp, -1, ETIME, (char *) 0, 0);
		}
	}
	return 0;
}

/* M_COPYIN/M_COPYOUT of a transparent ioctl: the emulator copies, RQ_COPYDATA answers */
static mblk_t *ioc_copy_mp;

static void
ioc_copy(sp, mp)
struct sth *sp;
mblk_t *mp;
{
	struct copyreq *cq = (struct copyreq *) mp->b_rptr;
	int w[2], n = 0;
	char *data = 0;

	w[0] = (int) cq->cq_addr;
	w[1] = cq->cq_size;
	if (mp->b_datap->db_type == M_COPYOUT && mp->b_cont)
		data = gather(mp->b_cont, &n);
	if (n > (int) cq->cq_size)
		n = cq->cq_size;
	sendmsg_(sp, mp->b_datap->db_type == M_COPYIN ? MS_COPYIN : MS_COPYOUT, w, 2, data, n);
	if (data)
		free(data);
	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = 0;
	}
	/* kept to become the M_IOCDATA */
	if (ioc_copy_mp)
		freemsg(ioc_copy_mp);
	ioc_copy_mp = mp;
}

static void
copydata(sp, err, data, n)
struct sth *sp;
int err;
char *data;
int n;
{
	mblk_t *mp = ioc_copy_mp;
	struct copyresp *cp;
	int wasin;

	if (mp == 0 || sp->ioc_id == 0)
		return;
	ioc_copy_mp = 0;
	wasin = mp->b_datap->db_type == M_COPYIN;
	mp->b_datap->db_type = M_IOCDATA;
	cp = (struct copyresp *) mp->b_rptr;
	cp->cp_rval = (caddr_t) err;
	mp->b_wptr = mp->b_rptr + sizeof(struct copyresp);
	if (wasin && !err) {
		mp->b_cont = allocb(n, 0);
		memcpy((char *) mp->b_cont->b_wptr, data, n);
		mp->b_cont->b_wptr += n;
	}
	putnext(sp->wq, mp);
	if (err) {
		/* the module frees its state; the ioctl fails */
		ioc_done(sp);
		reply(sp, -1, err, (char *) 0, 0);
	}
}

static int
sth_rput(q, mp)
queue_t *q;
mblk_t *mp;
{
	struct sth *sp = (struct sth *) q->q_ptr;
	int type = mp->b_datap->db_type, w[2];

	if (strd_trace)
		trace_msg(sp, "up", mp);
	switch (type) {
	case M_DATA:
	case M_PROTO:
	case M_PCPROTO:
		if (sp->fd < 0 || sp->rerror)
			freemsg(mp);
		else
			deliver(sp, mp);
		return 0;
	case M_IOCACK:
	case M_IOCNAK:
		if (sp->ioc_id && ((struct iocblk *) mp->b_rptr)->ioc_id == sp->ioc_id)
			ioc_ack(sp, mp);
		else
			freemsg(mp);
		return 0;
	case M_COPYIN:
	case M_COPYOUT:
		if (sp->ioc_id && ((struct copyreq *) mp->b_rptr)->cq_id == sp->ioc_id && sp->ioc_kind == IOC_TRANS)
			ioc_copy(sp, mp);
		else
			freemsg(mp);
		return 0;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR) {
			flushq(q, FLUSHALL);
			w[0] = *mp->b_rptr;
			sendmsg_(sp, MS_FLUSH, w, 1, (char *) 0, 0);
		}
		if (*mp->b_rptr & FLUSHW) {
			*mp->b_rptr &= ~FLUSHR;
			flushq(WR(q), FLUSHALL);
			qreply_(q, mp);
		} else
			freemsg(mp);
		return 0;
	case M_ERROR:
		if (mp->b_wptr - mp->b_rptr >= 2) {
			sp->rerror = mp->b_rptr[0];
			sp->werror = mp->b_rptr[1];
		} else
			sp->rerror = sp->werror = mp->b_rptr[0];
		w[0] = sp->rerror;
		w[1] = sp->werror;
		sendmsg_(sp, MS_ERROR, w, 2, (char *) 0, 0);
		freemsg(mp);
		return 0;
	case M_HANGUP:
		sp->hangup = 1;
		sendmsg_(sp, MS_HANGUP, w, 0, (char *) 0, 0);
		freemsg(mp);
		return 0;
	case M_SIG:
	case M_PCSIG:
		w[0] = *mp->b_rptr;
		sendmsg_(sp, MS_SIG, w, 1, (char *) 0, 0);
		freemsg(mp);
		return 0;
	default:		/* M_SETOPTS ... */
		freemsg(mp);
		return 0;
	}
}

static int
sth_wput(q, mp)
queue_t *q;
mblk_t *mp;
{
	putnext(q, mp);
	return 0;
}

static void
trace_msg(sp, dir, mp)
struct sth *sp;
char *dir;
mblk_t *mp;
{
	/* -t: the first 48 bytes of each block; -tt: all of them */
	int i, n, max = strd_trace > 1 ? 1 << 20 : 48;
	mblk_t *bp;

	fprintf(stderr, "strd: stream %d %s type %#x band %d:", sp ? sp->id : -1, dir,
		mp->b_datap->db_type, mp->b_band);
	for (bp = mp; bp; bp = bp->b_cont) {
		n = bp->b_wptr - bp->b_rptr;
		fprintf(stderr, " [%s%d]", bp->b_datap->db_type == M_DATA ? "data " : "", n);
		for (i = 0; i < n && i < max; i++)
			fprintf(stderr, " %02x", bp->b_rptr[i]);
		if (n > max)
			fprintf(stderr, " ...");
	}
	fprintf(stderr, "\n");
}

/* ---- open, push, pop, close ---- */
static struct sth *
sth_alloc(fd)
int fd;
{
	struct sth *sp = (struct sth *) calloc(1, sizeof *sp);

	sp->fd = fd;
	sp->id = ++sth_ids;
	sp->rq = allocqp(&sth_rinit, &sth_winit);
	sp->wq = sp->rq->q_other;
	sp->rq->q_ptr = sp->wq->q_ptr = (char *) sp;
	sp->next = streams;
	streams = sp;
	return sp;
}

static void
sth_free(sp)
struct sth *sp;
{
	struct sth **pp;

	for (pp = &streams; *pp; pp = &(*pp)->next)
		if (*pp == sp) {
			*pp = sp->next;
			break;
		}
	if (sp->rq)
		freeqp(sp->rq);
	free((char *) sp);
}

static int
do_open(sp, name, flag)
struct sth *sp;
char *name;
int flag;
{
	int sw = findsw(name, 0), err;
	streams_info_t *si;
	queue_t *rq;

	if (sw < 0)
		return ENXIO;
	si = devsw[sw].si;
	rq = allocqp(si->inst_str_tab.st_rdinit, si->inst_str_tab.st_wrinit);
	sp->wq->q_next = rq->q_other;
	rq->q_next = sp->rq;
	sp->drv = sw;
	sp->flag = flag;
	sp->dev = makedev(devsw[sw].major, 0);
	err = qopen(sw, rq, &sp->dev, flag, CLONEOPEN);
	if (err) {
		sp->wq->q_next = 0;
		freeqp(rq);
		return err;
	}
	return 0;
}

static int
do_push(sp, name)
struct sth *sp;
char *name;
{
	int sw = findsw(name, 1), err;
	streams_info_t *si;
	queue_t *rq, *below;

	if (sw < 0)
		return EINVAL;
	if (sp->npush >= NPUSH)
		return EINVAL;
	si = devsw[sw].si;
	rq = allocqp(si->inst_str_tab.st_rdinit, si->inst_str_tab.st_wrinit);
	below = sp->wq->q_next;
	rq->q_other->q_next = below;
	rq->q_next = sp->rq;
	OTHERQ(below)->q_next = rq;
	sp->wq->q_next = rq->q_other;
	err = qopen(sw, rq, &sp->dev, sp->flag, MODOPEN);
	if (err) {
		sp->wq->q_next = below;
		OTHERQ(below)->q_next = sp->rq;
		freeqp(rq);
		return err;
	}
	memmove((char *) &sp->mods[1], (char *) &sp->mods[0], sp->npush * sizeof(int));
	sp->mods[0] = sw;
	sp->npush++;
	return 0;
}

static int
do_pop(sp)
struct sth *sp;
{
	queue_t *wq = sp->wq->q_next, *rq = OTHERQ(wq);

	if (sp->npush == 0)
		return EINVAL;
	qclose(sp->mods[0], rq, sp->flag);
	sp->wq->q_next = wq->q_next;
	OTHERQ(wq->q_next)->q_next = sp->rq;
	freeqp(rq);
	sp->npush--;
	memmove((char *) &sp->mods[0], (char *) &sp->mods[1], sp->npush * sizeof(int));
	return 0;
}

static void do_unlink_all();

static void
dismantle(sp)
struct sth *sp;
{
	queue_t *wq;

	while (sp->npush)
		do_pop(sp);
	wq = sp->wq->q_next;
	if (wq) {
		qclose(sp->drv, OTHERQ(wq), sp->flag);
		freeqp(OTHERQ(wq));
		sp->wq->q_next = 0;
	}
	sth_free(sp);
}

static void
do_close(sp)
struct sth *sp;
{
	if (sp->fd >= 0) {
		close(sp->fd);
		sp->fd = -1;
	}
	if (sp->upper)		/* linked below a multiplexor: it stays until unlinked */
		return;
	do_unlink_all(sp, 0);
	dismantle(sp);
}

/* ---- ioctls ---- */
static void
send_ioctl(sp, cmd, kind, data, n, tmo)
struct sth *sp;
int cmd, kind;
char *data;
int n, tmo;
{
	mblk_t *mp = allocb(sizeof(struct iocblk), 0);
	struct iocblk *ioc = (struct iocblk *) mp->b_wptr;

	memset((char *) ioc, 0, sizeof *ioc);
	mp->b_datap->db_type = M_IOCTL;
	mp->b_wptr += sizeof *ioc;
	ioc->ioc_cmd = cmd;
	ioc->ioc_cr = (cred_t *) cred0;
	ioc->ioc_id = ++ioc_ids;
	ioc->ioc_count = kind == IOC_TRANS ? TRANSPARENT : n;
	if (n > 0 || kind == IOC_TRANS) {
		mp->b_cont = allocb(n, 0);
		memcpy((char *) mp->b_cont->b_wptr, data, n);
		mp->b_cont->b_wptr += n;
	}
	sp->ioc_id = ioc->ioc_id;
	sp->ioc_cmd = cmd;
	sp->ioc_kind = kind;
	sp->ioc_tmo = tmo >= 0 ? timeout(ioc_timeout, (char *) sp->id, (tmo ? tmo : 15) * HZ) : 0;
	if (strd_trace)
		trace_msg(sp, "down", mp);
	putnext(sp->wq, mp);
}

/* I_LINK: the lower stream's head becomes the multiplexor's lower queue pair */
static int
start_link(sp, lower, persist)
struct sth *sp, *lower;
int persist;
{
	streams_info_t *si = devsw[sp->drv].si;
	struct linkblk lb;

	if (lower == 0 || lower == sp || lower->upper || si->inst_str_tab.st_muxwinit == 0)
		return EINVAL;
	lower->upper = sp;
	lower->lindex = ++link_ids;
	lower->lpersist = persist;
	setq(lower->rq, si->inst_str_tab.st_muxrinit);
	setq(lower->wq, si->inst_str_tab.st_muxwinit);
	lower->rq->q_ptr = lower->wq->q_ptr = 0;
	memset((char *) &lb, 0, sizeof lb);
	lb.l_qtop = sp->wq;	/* fixed below: the driver's own write queue */
	{
		queue_t *q = sp->wq;
		while (q->q_next)
			q = q->q_next;
		lb.l_qtop = q;
	}
	lb.l_qbot = lower->wq;
	lb.l_index = lower->lindex;
	sp->ioc_link = lower->id;
	send_ioctl(sp, persist ? I_PLINK : I_LINK, IOC_LINK, (char *) &lb, sizeof lb, 0);
	return 0;
}

static void
relink_head(lower)
struct sth *lower;
{
	setq(lower->rq, &sth_rinit);
	setq(lower->wq, &sth_winit);
	lower->rq->q_ptr = lower->wq->q_ptr = (char *) lower;
	lower->upper = 0;
	lower->lindex = 0;
}

static void
finish_link(sp, kind, rval, err)
struct sth *sp;
int kind, rval, err;
{
	struct sth *lower = sth_find(sp->ioc_link);

	if (kind == IOC_LINK) {
		if (err && lower)
			relink_head(lower);
		reply(sp, err ? -1 : lower->lindex, err, (char *) 0, 0);
	} else {
		if (lower) {
			relink_head(lower);
			if (lower->fd < 0)	/* its descriptor was closed meanwhile */
				dismantle(lower);
		}
		if (sp->fd >= 0)
			reply(sp, err ? -1 : 0, err, (char *) 0, 0);
	}
}

static int
start_unlink(sp, lower)
struct sth *sp, *lower;
{
	struct linkblk lb;
	queue_t *q = sp->wq;

	while (q->q_next)
		q = q->q_next;
	memset((char *) &lb, 0, sizeof lb);
	lb.l_qtop = q;
	lb.l_qbot = lower->wq;
	lb.l_index = lower->lindex;
	sp->ioc_link = lower->id;
	send_ioctl(sp, lower->lpersist ? I_PUNLINK : I_UNLINK, IOC_UNLINK, (char *) &lb, sizeof lb, 0);
	return 0;
}

/* on close: the links of this stream (not the persistent ones) go, one at a time */
static void
do_unlink_all(sp, persist)
struct sth *sp;
int persist;
{
	struct sth *l;
	int again = 1;

	while (again) {
		again = 0;
		for (l = streams; l; l = l->next)
			if (l->upper == sp && l->lpersist == persist) {
				int fd = sp->fd;
				sp->fd = -1;	/* no replies */
				start_unlink(sp, l);
				runqueues();
				if (sp->ioc_id) {	/* not acknowledged: undo it ourselves */
					ioc_done(sp);
					relink_head(l);
					if (l->fd < 0)
						dismantle(l);
				}
				sp->fd = fd;
				again = 1;
				break;
			}
	}
}

static void
do_ioctl(sp, cmd, arg, data, n)
struct sth *sp;
int cmd, arg;
char *data;
int n;
{
	int i, err = 0, rval = 0;
	char name[FMNAMESZ + 1];
	struct sth *l;

	if (sp->upper) {
		reply(sp, -1, EINVAL, (char *) 0, 0);
		return;
	}
	if (sp->ioc_id) {
		reply(sp, -1, EBUSY, (char *) 0, 0);
		return;
	}
	switch (cmd) {
	case I_STR:		/* data: ic_cmd ic_timout ic_len, then ic_len bytes */
		if (n < 12) {
			err = EINVAL;
			break;
		}
		if (sp->hangup) {
			err = ENXIO;
			break;
		}
		send_ioctl(sp, get32((unsigned char *) data), IOC_STR, data + 12, n - 12,
			   (int) get32((unsigned char *) data + 4));
		return;
	case I_PUSH:
		memset(name, 0, sizeof name);
		strncpy(name, data, n < FMNAMESZ ? n : FMNAMESZ);
		err = do_push(sp, name);
		break;
	case I_POP:
		err = do_pop(sp);
		break;
	case I_LOOK:
		if (sp->npush == 0) {
			err = EINVAL;
			break;
		}
		reply(sp, 0, 0, devsw[sp->mods[0]].name, strlen(devsw[sp->mods[0]].name) + 1);
		return;
	case I_FIND:
		memset(name, 0, sizeof name);
		strncpy(name, data, n < FMNAMESZ ? n : FMNAMESZ);
		if (findsw(name, 1) < 0) {
			err = EINVAL;
			break;
		}
		for (i = 0; i < sp->npush; i++)
			if (strcmp(devsw[sp->mods[i]].name, name) == 0)
				rval = 1;
		break;
	case I_FDINSERT:	/* data: flags, the other stream, offset, ctl length, data length, ctl, data */
		{
			unsigned char *p = (unsigned char *) data;
			int flags, off, nc, nd;
			struct sth *other;
			mblk_t *mp, *dp = 0;
			queue_t *qp;

			if (n < 20) {
				err = EINVAL;
				break;
			}
			flags = get32(p);
			other = sth_find(get32(p + 4));
			off = get32(p + 8);
			nc = get32(p + 12);
			nd = get32(p + 16);
			if (other == 0 || other->upper || nc < (int) sizeof(queue_t *) || off < 0 ||
			    off > nc - (int) sizeof(queue_t *) || (off & 3) || n < 20 + nc + (nd > 0 ? nd : 0)) {
				err = EINVAL;
				break;
			}
			/* the read queue of the other stream's driver: the queue it knows as its own */
			for (qp = other->wq; qp->q_next; qp = qp->q_next);
			qp = OTHERQ(qp);
			mp = allocb(nc, 0);
			memcpy((char *) mp->b_wptr, (char *) p + 20, nc);
			memcpy((char *) mp->b_wptr + off, (char *) &qp, sizeof qp);
			mp->b_wptr += nc;
			mp->b_datap->db_type = (flags & RS_HIPRI) ? M_PCPROTO : M_PROTO;
			if (nd >= 0) {
				dp = allocb(nd, 0);
				memcpy((char *) dp->b_wptr, (char *) p + 20 + nc, nd);
				dp->b_wptr += nd;
				mp->b_cont = dp;
			}
			if (strd_trace)
				trace_msg(sp, "down", mp);
			putnext(sp->wq, mp);
			break;
		}
	case I_LIST:
		{
			char buf[(NPUSH + 1) * (FMNAMESZ + 1)];
			memset(buf, 0, sizeof buf);
			for (i = 0; i < sp->npush; i++)
				strcpy(buf + i * (FMNAMESZ + 1), devsw[sp->mods[i]].name);
			strcpy(buf + i * (FMNAMESZ + 1), devsw[sp->drv].name);
			reply(sp, sp->npush + 1, 0, buf, (sp->npush + 1) * (FMNAMESZ + 1));
			return;
		}
	case I_FLUSH:
		if (arg & ~FLUSHRW) {
			err = EINVAL;
			break;
		}
		if (arg & FLUSHW)
			flushq(sp->wq, FLUSHALL);
		if (arg & FLUSHR)
			flushq(sp->rq, FLUSHALL);
		putctl1(sp->wq->q_next, M_FLUSH, arg);
		break;
	case I_CANPUT:
		rval = canput(sp->wq->q_next);
		break;
	case I_LINK:
	case I_PLINK:
		err = start_link(sp, sth_find(arg), cmd == I_PLINK);
		if (err)
			break;
		return;
	case I_UNLINK:
	case I_PUNLINK:
		for (l = streams; l; l = l->next)
			if (l->upper == sp && (arg == -1 || l->lindex == arg) && l->lpersist == (cmd == I_PUNLINK))
				break;
		if (l == 0) {
			err = EINVAL;
			break;
		}
		if (arg == -1) {
			do_unlink_all(sp, cmd == I_PUNLINK);
			break;
		}
		start_unlink(sp, l);
		return;
	case I_SETCLTIME:
	case I_GETCLTIME:
		break;
	default:		/* a transparent ioctl: the argument is the word sent */
		send_ioctl(sp, cmd, IOC_TRANS, (char *) &arg, 4, 0);
		return;
	}
	reply(sp, err ? -1 : rval, err, (char *) 0, 0);
}

/* putmsg/write */
static void
do_putmsg(sp, flags, band, nc, nd, ctl, dat)
struct sth *sp;
int flags, band, nc, nd;
char *ctl, *dat;
{
	mblk_t *mp = 0, *dp = 0;

	if (sp->upper || sp->hangup || sp->werror) {
		reply(sp, -1, sp->upper ? EINVAL : sp->hangup ? ENXIO : sp->werror, (char *) 0, 0);
		return;
	}
	if (nc >= 0 && !(nc == 0 && (flags & RS_HIPRI) == 0 && nd >= 0)) {
		mp = allocb(nc, 0);
		memcpy((char *) mp->b_wptr, ctl, nc);
		mp->b_wptr += nc;
		mp->b_datap->db_type = (flags & RS_HIPRI) ? M_PCPROTO : M_PROTO;
		mp->b_band = band;
	}
	if (nd >= 0 && (nd > 0 || mp == 0)) {
		dp = allocb(nd, 0);
		memcpy((char *) dp->b_wptr, dat, nd);
		dp->b_wptr += nd;
		dp->b_band = band;
	}
	if (mp)
		mp->b_cont = dp;
	else
		mp = dp;
	if (mp == 0) {
		reply(sp, 0, 0, (char *) 0, 0);
		return;
	}
	if (strd_trace)
		trace_msg(sp, "down", mp);
	putnext(sp->wq, mp);
	/* the service procedures the message scheduled run before putmsg returns, as
	 * HP-UX runs them on the way out of the system call: what they send up (TLI's
	 * T_OK_ACK for a T_CONN_REQ) is at the stream head when the program looks -
	 * t_connect on a non-blocking endpoint reads it with no waiting */
	runqueues();
	reply(sp, 0, 0, (char *) 0, 0);
}

/* one request of a connection; -1 when the connection is gone */
static int
request(sp)
struct sth *sp;
{
	unsigned char hdr[8], *p;
	int op, len, flags;
	char *buf;

	if (readn(sp->fd, (char *) hdr, 8) < 0)
		return -1;
	op = get32(hdr);
	len = get32(hdr + 4);
	if (len < 0 || len > 1 << 20)
		return -1;
	buf = (char *) malloc(len + 1);
	if (readn(sp->fd, buf, len) < 0) {
		free(buf);
		return -1;
	}
	buf[len] = 0;
	p = (unsigned char *) buf;
	switch (op) {
	case RQ_OPEN:		/* flags uid gid pid name */
		flags = get32(p);
		sp->pid = get32(p + 12);
		{
			int err = do_open(sp, buf + 16, flags);
			int w[3];
			w[0] = err ? -1 : 0;
			w[1] = err;
			w[2] = sp->id;
			sendmsg_(sp, MS_REPLY, w, 3, (char *) 0, 0);
			if (strd_trace || err)
				fprintf(stderr, "strd: stream %d: open %s by process %d = %d\n", sp->id, buf + 16, sp->pid, err);
			if (err) {
				free(buf);
				return -1;
			}
		}
		break;
	case RQ_PUTMSG:		/* flags band ctllen datalen bytes */
		{
			int nc = get32(p + 8), nd = get32(p + 12);
			do_putmsg(sp, get32(p), get32(p + 4), nc, nd, buf + 16, buf + 16 + (nc > 0 ? nc : 0));
		}
		break;
	case RQ_IOCTL:		/* cmd arg len bytes */
		do_ioctl(sp, get32(p), get32(p + 4), buf + 12, get32(p + 8));
		break;
	case RQ_COPYDATA:	/* errno bytes */
		copydata(sp, get32(p), buf + 4, len - 4);
		break;
	case RQ_DEBUG:
		strd_trace = get32(p);
		reply(sp, 0, 0, (char *) 0, 0);
		break;
	case RQ_CLOSE:
	default:
		free(buf);
		return -1;
	}
	free(buf);
	runqueues();
	return 0;
}

/* ======================================================================= */
/* main                                                                      */
/* ======================================================================= */
extern void strd_drivers();
extern char *dl_wire_path;
extern int dl_nmid;
extern unsigned char dl_mac[6];

static void
usage()
{
	fprintf(stderr, "usage: strd [-t|-tt] [-e wire] [-m station-address] [-n nmid] [socket]\n");
	exit(2);
}

int
main(argc, argv)
int argc;
char **argv;
{
	char *path = "/var/spool/sockets/streams";
	struct sockaddr_un sa;
	int ls, i, n, maxfd;
	fd_set rs;
	struct timeval tv, *tvp;
	struct sth *sp, *nsp;

	for (i = 1; i < argc; i++)
		if (strcmp(argv[i], "-t") == 0)
			strd_trace = 1;
		else if (strcmp(argv[i], "-tt") == 0)
			strd_trace = 2;
		else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
			dl_nmid = atoi(argv[++i]);
		else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc)
			dl_wire_path = argv[++i];
		else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
			int a[6], k;
			if (sscanf(argv[++i], "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) != 6)
				usage();
			for (k = 0; k < 6; k++)
				dl_mac[k] = a[k];
		} else if (argv[i][0] == '-')
			usage();
		else
			path = argv[i];
	setvbuf(stdout, (char *) 0, _IONBF, 0);
	setvbuf(stderr, (char *) 0, _IONBF, 0);
	signal(SIGPIPE, SIG_IGN);
	gettimeofday(&t0, (struct timezone *) 0);
	tick();

	/* what the kernel's driver install table would call */
	strd_modules();
	strd_drivers();

	ls = socket(AF_UNIX, SOCK_STREAM, 0);
	memset((char *) &sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
	unlink(path);
	if (ls < 0 || bind(ls, (struct sockaddr *) &sa, sizeof sa) < 0 || listen(ls, 16) < 0) {
		perror(path);
		exit(1);
	}
	chmod(path, 0666);
	fprintf(stderr, "strd: ready on %s\n", path);

	for (;;) {
		FD_ZERO(&rs);
		FD_SET(ls, &rs);
		maxfd = ls;
		for (sp = streams; sp; sp = sp->next)
			if (sp->fd >= 0) {
				FD_SET(sp->fd, &rs);
				if (sp->fd > maxfd)
					maxfd = sp->fd;
			}
		strd_fds(&rs, &maxfd);
		tvp = 0;
		if (timeouts) {
			tick();
			n = timeouts->when - lbolt;
			if (n < 0)
				n = 0;
			tv.tv_sec = n / HZ;
			tv.tv_usec = (n % HZ) * (1000000 / HZ);
			tvp = &tv;
		}
		n = select(maxfd + 1, (int *) &rs, (int *) 0, (int *) 0, tvp);
		if (n < 0 && errno != EINTR) {
			perror("select");
			sleep(1);
		}
		run_timeouts();
		if (n <= 0)
			continue;
		strd_io(&rs);
		runqueues();
		if (FD_ISSET(ls, &rs)) {
			int fd = accept(ls, (struct sockaddr *) 0, (int *) 0);
			if (fd >= 0) {
				fcntl(fd, F_SETFD, 1);
				sth_alloc(fd);
			}
		}
		for (sp = streams; sp; sp = nsp) {
			nsp = sp->next;
			if (sp->fd >= 0 && FD_ISSET(sp->fd, &rs) && request(sp) < 0) {
				if (strd_trace)
					fprintf(stderr, "strd: stream %d closed\n", sp->id);
				do_close(sp);
				runqueues();
				nsp = streams;	/* the list may have changed */
				FD_ZERO(&rs);
			}
		}
	}
}
