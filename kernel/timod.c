/*
 * timod.c - the TLI module (timod) for the STREAMS daemon, written to the SVR4 rules:
 * the TLI library's TI_* ioctls (I_STR) become TPI requests to the transport
 * provider below, and the provider's acknowledgement goes back as the ioctl's answer.
 * An error acknowledgement answers with TLI_error | UNIX_error << 8, which the library
 * turns into t_errno and errno. HP-UX's own additions: TI_XTI_HELLO and the XTI/TLI
 * modes are accepted, TI_XTI_GET_STATE gives the qlen of the last TI_BIND,
 * TI_GET_TUNABLES the stream limits.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include "strd.h"

#ifndef TI_XTI_HELLO
#define TI_XTI_HELLO		(('T'<<8)|7)
#define TI_XTI_GET_STATE	(('T'<<8)|8)
#define TI_XTI_CLEAR_EVENT	(('T'<<8)|9)
#define TI_XTI_MODE		(('T'<<8)|10)
#define TI_TLI_MODE		(('T'<<8)|11)
#endif
#ifndef TI_GET_TUNABLES
#define TI_GET_TUNABLES		(('T'<<8)|12)
#endif

extern int strmsgsz, strctlsz;

struct tim {
	mblk_t *ioc;		/* the M_IOCTL waiting for the provider */
	int expect;		/* the primitive it was turned into */
	unsigned long qlen;
};

static int tim_open(), tim_close(), tim_wput(), tim_rput();
static struct module_info tim_minfo = { 0, "timod", 0, INFPSZ, 4096, 1024 };
static struct qinit tim_rinit = { tim_rput, 0, tim_open, tim_close, 0, &tim_minfo, 0 };
static struct qinit tim_winit = { tim_wput, 0, 0, 0, 0, &tim_minfo, 0 };
static streams_info_t tim_info = { "timod", -1, { &tim_rinit, &tim_winit, 0, 0 }, STR_IS_MODULE | STR_SYSV4_OPEN, 0, "" };

void
timod_install()
{
	str_install(&tim_info);
}

static int
tim_open(q, devp, flag, sflag, cr)
queue_t *q;
dev_t *devp;
int flag, sflag;
char *cr;
{
	struct tim *t;

	if (q->q_ptr)
		return 0;
	t = (struct tim *) calloc(1, sizeof *t);
	q->q_ptr = WR(q)->q_ptr = (char *) t;
	return 0;
}

static int
tim_close(q, flag, cr)
queue_t *q;
int flag;
char *cr;
{
	struct tim *t = (struct tim *) q->q_ptr;

	if (t) {
		if (t->ioc)
			freemsg(t->ioc);
		free((char *) t);
	}
	q->q_ptr = WR(q)->q_ptr = 0;
	return 0;
}

/* answer the ioctl mp (an M_IOCTL) at once */
static void
iocans(q, mp, type, rval, err, data)
queue_t *q;
mblk_t *mp;
int type, rval, err;
mblk_t *data;
{
	struct iocblk *ioc = (struct iocblk *) mp->b_rptr;

	mp->b_datap->db_type = type;
	ioc->ioc_rval = rval;
	ioc->ioc_error = err;
	if (mp->b_cont)
		freemsg(mp->b_cont);
	mp->b_cont = data;
	ioc->ioc_count = data ? msgdsize(data) : 0;
	qreply_(q, mp);
}

static int
tim_wput(q, mp)
queue_t *q;
mblk_t *mp;
{
	struct tim *t = (struct tim *) q->q_ptr;
	struct iocblk *ioc;
	mblk_t *bp;
	int prim, need;

	if (mp->b_datap->db_type == M_FLUSH) {
		putnext(q, mp);
		return 0;
	}
	if (mp->b_datap->db_type != M_IOCTL) {
		putnext(q, mp);
		return 0;
	}
	ioc = (struct iocblk *) mp->b_rptr;
	switch (ioc->ioc_cmd) {
	case TI_GETINFO:
		prim = T_INFO_REQ;
		need = sizeof(struct T_info_req);
		break;
	case TI_OPTMGMT:
		prim = T_OPTMGMT_REQ;
		need = sizeof(struct T_optmgmt_req);
		break;
	case TI_BIND:
		prim = T_BIND_REQ;
		need = sizeof(struct T_bind_req);
		break;
	case TI_UNBIND:
		prim = T_UNBIND_REQ;
		need = sizeof(struct T_unbind_req);
		break;
	case TI_XTI_HELLO:
	case TI_XTI_CLEAR_EVENT:
	case TI_XTI_MODE:
	case TI_TLI_MODE:
		iocans(q, mp, M_IOCACK, 0, 0, (mblk_t *) 0);
		return 0;
	case TI_XTI_GET_STATE:
		bp = allocb(sizeof(unsigned int), 0);
		*(unsigned int *) bp->b_wptr = t->qlen;
		bp->b_wptr += sizeof(unsigned int);
		iocans(q, mp, M_IOCACK, 0, 0, bp);
		return 0;
	case TI_GET_TUNABLES:
		bp = allocb(2 * sizeof(int), 0);
		((int *) bp->b_wptr)[0] = strmsgsz;
		((int *) bp->b_wptr)[1] = strctlsz;
		bp->b_wptr += 2 * sizeof(int);
		iocans(q, mp, M_IOCACK, 0, 0, bp);
		return 0;
	default:		/* TI_GETMYNAME, the provider's own: its business */
		putnext(q, mp);
		return 0;
	}
	if (t->ioc) {
		iocans(q, mp, M_IOCNAK, 0, EBUSY, (mblk_t *) 0);
		return 0;
	}
	if (mp->b_cont == 0 || msgdsize(mp->b_cont) < need || !pullupmsg(mp->b_cont, -1)) {
		iocans(q, mp, M_IOCNAK, 0, EINVAL, (mblk_t *) 0);
		return 0;
	}
	bp = mp->b_cont;
	mp->b_cont = 0;
	bp->b_datap->db_type = prim == T_INFO_REQ ? M_PCPROTO : M_PROTO;
	*(long *) bp->b_rptr = prim;
	if (prim == T_BIND_REQ)
		t->qlen = ((struct T_bind_req *) bp->b_rptr)->CONIND_number;
	t->ioc = mp;
	t->expect = prim;
	putnext(q, bp);
	return 0;
}

static int
tim_rput(q, mp)
queue_t *q;
mblk_t *mp;
{
	struct tim *t = (struct tim *) q->q_ptr;
	union T_primitives *p;
	mblk_t *ioc;
	int prim, ack = -1;

	if ((mp->b_datap->db_type != M_PROTO && mp->b_datap->db_type != M_PCPROTO) || t->ioc == 0 ||
	    mp->b_wptr - mp->b_rptr < sizeof(long)) {
		putnext(q, mp);
		return 0;
	}
	p = (union T_primitives *) mp->b_rptr;
	prim = p->type;
	switch (prim) {
	case T_ERROR_ACK:
		if (p->error_ack.ERROR_prim == t->expect)
			ack = 0;
		break;
	case T_OK_ACK:
		if (p->ok_ack.CORRECT_prim == t->expect && t->expect == T_UNBIND_REQ)
			ack = 1;
		break;
	case T_BIND_ACK:
		if (t->expect == T_BIND_REQ)
			ack = 1;
		break;
	case T_INFO_ACK:
		if (t->expect == T_INFO_REQ)
			ack = 1;
		break;
	case T_OPTMGMT_ACK:
		if (t->expect == T_OPTMGMT_REQ)
			ack = 1;
		break;
	}
	if (ack < 0) {
		putnext(q, mp);
		return 0;
	}
	ioc = t->ioc;
	t->ioc = 0;
	t->expect = 0;
	if (ack == 0) {
		int rval = p->error_ack.TLI_error | (p->error_ack.UNIX_error << 8);
		freemsg(mp);
		mp = 0;
		((struct iocblk *) ioc->b_rptr)->ioc_rval = rval;
		ioc->b_datap->db_type = M_IOCACK;
		((struct iocblk *) ioc->b_rptr)->ioc_error = 0;
		((struct iocblk *) ioc->b_rptr)->ioc_count = 0;
		putnext(q, ioc);
		return 0;
	}
	mp->b_datap->db_type = M_DATA;
	ioc->b_datap->db_type = M_IOCACK;
	((struct iocblk *) ioc->b_rptr)->ioc_rval = 0;
	((struct iocblk *) ioc->b_rptr)->ioc_error = 0;
	((struct iocblk *) ioc->b_rptr)->ioc_count = msgdsize(mp);
	ioc->b_cont = mp;
	putnext(q, ioc);
	return 0;
}
