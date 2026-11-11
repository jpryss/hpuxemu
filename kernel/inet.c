/*
 * inet.c - TCP and UDP as TPI transport providers for the STREAMS daemon: /dev/tcp
 * (T_COTS_ORD) and /dev/udp (T_CLTS) over the sockets of the system the daemon runs on
 * (the emulator's, so the host's).
 *
 * HP-UX 11.00's TLI/XTI users reach TCP and UDP through these devices, not through
 * sockets: rpcbind (/etc/netconfig names /dev/udp and /dev/tcp), the RPC library,
 * ToolTalk. Each stream has one socket. The TPI requests (sys/tihdr.h) become socket
 * calls; what arrives on the socket goes up as indications: T_CONN_IND for a
 * connection waiting on a listener, T_DATA_IND or T_UNITDATA_IND for data, T_ORDREL_IND
 * at end of file, T_DISCON_IND for an error. The daemon's main loop asks for the
 * sockets to watch (inet_fds) and hands over the readable ones (inet_io); a socket is
 * not read while its stream head is full. A connect in progress is checked from a
 * timeout, as the loop watches readability only. Sending blocks, briefly: the peers are
 * mostly on the same machine.
 *
 * Addresses are struct sockaddr_in, as HP-UX's inet transports have them. Options
 * (T_OPTMGMT_REQ) are acknowledged as given: the providers have none of their own.
 *
 * Written for the bundled (K&R) C compiler; compiled with the root's own headers, so
 * the structures are 10.20's or 11.00's.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/tihdr.h>
#include <sys/tiuser.h>
#include "strd.h"

#define NPEND	8		/* connections waiting on one listener */

struct pend {
	int fd;			/* the accepted socket, -1: free slot */
	long seq;
	struct sockaddr_in from;
};

struct in {
	queue_t *rq;
	int tcp;		/* 1: /dev/tcp, 0: /dev/udp */
	int fd;			/* the socket, -1 before T_BIND_REQ */
	int state;		/* TS_* */
	int qlen;		/* listener: CONIND_number */
	int connecting;		/* a non-blocking connect is pending */
	int eof;		/* T_ORDREL_IND sent */
	long tmo;		/* the connect poll's timeout */
	struct sockaddr_in local, peer;
	struct pend pend[NPEND];
	struct in *next;
};

static struct in *ins;
static long seqno;

static int in_open(), in_close(), in_wput();
static struct module_info tcp_minfo = { 0, "tcp", 0, INFPSZ, 65536, 8192 };
static struct module_info udp_minfo = { 0, "udp", 0, INFPSZ, 65536, 8192 };
static struct qinit tcp_rinit = { 0, 0, in_open, in_close, 0, &tcp_minfo, 0 };
static struct qinit tcp_winit = { in_wput, 0, 0, 0, 0, &tcp_minfo, 0 };
static struct qinit udp_rinit = { 0, 0, in_open, in_close, 0, &udp_minfo, 0 };
static struct qinit udp_winit = { in_wput, 0, 0, 0, 0, &udp_minfo, 0 };
static streams_info_t tcp_info = { "tcp", -1, { &tcp_rinit, &tcp_winit, 0, 0 }, STR_IS_DEVICE | STR_SYSV4_OPEN, 0, "" };
static streams_info_t udp_info = { "udp", -1, { &udp_rinit, &udp_winit, 0, 0 }, STR_IS_DEVICE | STR_SYSV4_OPEN, 0, "" };

void
inet_install()
{
	str_install(&tcp_info);
	str_install(&udp_info);
}

static int
in_open(q, devp, flag, sflag, cr)
queue_t *q;
dev_t *devp;
int flag, sflag;
char *cr;
{
	struct in *s = (struct in *) calloc(1, sizeof *s);
	int i;

	s->rq = q;
	s->tcp = q->q_qinfo == &tcp_rinit;
	s->fd = -1;
	s->state = TS_UNBND;
	for (i = 0; i < NPEND; i++)
		s->pend[i].fd = -1;
	s->next = ins;
	ins = s;
	q->q_ptr = WR(q)->q_ptr = (char *) s;
	return 0;
}

static void
drop_socket(s)
struct in *s;
{
	int i;

	if (s->tmo) {
		untimeout(s->tmo);
		s->tmo = 0;
	}
	if (s->fd >= 0)
		close(s->fd);
	s->fd = -1;
	s->connecting = 0;
	for (i = 0; i < NPEND; i++)
		if (s->pend[i].fd >= 0) {
			close(s->pend[i].fd);
			s->pend[i].fd = -1;
		}
}

static int
in_close(q, flag, cr)
queue_t *q;
int flag;
char *cr;
{
	struct in *s = (struct in *) q->q_ptr, **pp;

	drop_socket(s);
	for (pp = &ins; *pp; pp = &(*pp)->next)
		if (*pp == s) {
			*pp = s->next;
			break;
		}
	free((char *) s);
	q->q_ptr = WR(q)->q_ptr = 0;
	return 0;
}

/* ---- building the messages that go up ---- */

/* a message of size bytes of type with the primitive prim, mp reused when it can be */
static mblk_t *
reuse(mp, size, type, prim)
mblk_t *mp;
int size, type;
long prim;
{
	if (mp && mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = 0;
	}
	if (!mp || mp->b_datap->db_lim - mp->b_datap->db_base < size || mp->b_datap->db_ref > 1) {
		if (mp)
			freemsg(mp);
		mp = allocb(size < 64 ? 64 : size, 0);
	}
	mp->b_rptr = mp->b_datap->db_base;
	mp->b_wptr = mp->b_rptr + size;
	memset((char *) mp->b_rptr, 0, size);
	mp->b_datap->db_type = type;
	*(long *) mp->b_rptr = prim;
	return mp;
}

static void
ok_ack(q, mp, prim)
queue_t *q;
mblk_t *mp;
long prim;
{
	mp = reuse(mp, sizeof(struct T_ok_ack), M_PCPROTO, (long) T_OK_ACK);
	((struct T_ok_ack *) mp->b_rptr)->CORRECT_prim = prim;
	qreply_(q, mp);
}

static void
error_ack(q, mp, prim, terr, uerr)
queue_t *q;
mblk_t *mp;
long prim;
int terr, uerr;
{
	struct T_error_ack *e;

	if (strd_trace)
		fprintf(stderr, "inet: primitive %ld refused: t_errno %d errno %d\n", prim, terr, uerr);
	mp = reuse(mp, sizeof(struct T_error_ack), M_PCPROTO, (long) T_ERROR_ACK);
	e = (struct T_error_ack *) mp->b_rptr;
	e->ERROR_prim = prim;
	e->TLI_error = terr;
	e->UNIX_error = uerr;
	qreply_(q, mp);
}

/* an indication with an address (at the end of the control part) and data */
static mblk_t *
addr_msg(size, prim, sin, lenoff, data, n)
int size;
long prim;
struct sockaddr_in *sin;
int lenoff;		/* where the address's length and offset words are */
char *data;
int n;
{
	mblk_t *mp = reuse((mblk_t *) 0, size + (sin ? sizeof *sin : 0), M_PROTO, prim);
	long *w = (long *) (mp->b_rptr + lenoff);

	if (sin) {
		w[0] = sizeof *sin;
		w[1] = size;
		memcpy((char *) mp->b_rptr + size, (char *) sin, sizeof *sin);
	}
	if (n > 0) {
		mblk_t *dp = allocb(n, 0);
		memcpy((char *) dp->b_wptr, data, n);
		dp->b_wptr += n;
		mp->b_cont = dp;
	}
	return mp;
}

static void
discon_ind(s, err, seq)
struct in *s;
int err;
long seq;
{
	mblk_t *mp = reuse((mblk_t *) 0, sizeof(struct T_discon_ind), M_PROTO, (long) T_DISCON_IND);

	((struct T_discon_ind *) mp->b_rptr)->DISCON_reason = err;
	((struct T_discon_ind *) mp->b_rptr)->SEQ_number = seq;
	putnext(s->rq, mp);
}

/* ---- the requests ---- */

static void
info_ack(q, mp, s)
queue_t *q;
mblk_t *mp;
struct in *s;
{
	struct T_info_ack *ia;

	mp = reuse(mp, sizeof(struct T_info_ack), M_PCPROTO, (long) T_INFO_ACK);
	ia = (struct T_info_ack *) mp->b_rptr;
	ia->TSDU_size = s->tcp ? 0 : 65508;
	ia->ETSDU_size = s->tcp ? -1 : -2;
	ia->CDATA_size = -2;
	ia->DDATA_size = -2;
	ia->ADDR_size = sizeof(struct sockaddr_in);
	ia->OPT_size = 1024;
	ia->TIDU_size = 65536;
	ia->SERV_type = s->tcp ? T_COTS_ORD : T_CLTS;
	ia->CURRENT_state = s->state;
	ia->PROVIDER_flag = 0;
	qreply_(q, mp);
}

static int
new_socket(s)
struct in *s;
{
	int on = 1;

	s->fd = socket(AF_INET, s->tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (s->fd < 0)
		return -1;
	fcntl(s->fd, F_SETFD, 1);
	setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof on);
	return 0;
}

static void
do_bind(q, mp, s)
queue_t *q;
mblk_t *mp;
struct in *s;
{
	struct T_bind_req *br = (struct T_bind_req *) mp->b_rptr;
	struct T_bind_ack *ba;
	struct sockaddr_in sin;
	int len = sizeof sin, qlen = br->CONIND_number;

	if (s->state != TS_UNBND) {
		error_ack(q, mp, (long) T_BIND_REQ, TOUTSTATE, 0);
		return;
	}
	memset((char *) &sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	if (br->ADDR_length > 0) {
		if (br->ADDR_length < 8 || br->ADDR_offset + br->ADDR_length > mp->b_wptr - mp->b_rptr) {
			error_ack(q, mp, (long) T_BIND_REQ, TBADADDR, 0);
			return;
		}
		memcpy((char *) &sin, (char *) mp->b_rptr + br->ADDR_offset,
		       br->ADDR_length < (long) sizeof sin ? br->ADDR_length : sizeof sin);
		sin.sin_family = AF_INET;
	}
	if (new_socket(s) < 0) {
		error_ack(q, mp, (long) T_BIND_REQ, TSYSERR, errno);
		return;
	}
	if (bind(s->fd, (struct sockaddr *) &sin, sizeof sin) < 0) {
		int e = errno;
		drop_socket(s);
		error_ack(q, mp, (long) T_BIND_REQ, e == EADDRINUSE ? TADDRBUSY : e == EACCES ? TACCES : TSYSERR, e);
		return;
	}
	getsockname(s->fd, (struct sockaddr *) &s->local, &len);
	if (s->tcp && qlen > 0) {
		if (qlen > NPEND)
			qlen = NPEND;
		listen(s->fd, qlen);
		s->qlen = qlen;
	} else
		qlen = 0;
	s->state = TS_IDLE;
	mp = reuse(mp, sizeof(struct T_bind_ack) + sizeof s->local, M_PCPROTO, (long) T_BIND_ACK);
	ba = (struct T_bind_ack *) mp->b_rptr;
	ba->ADDR_length = sizeof s->local;
	ba->ADDR_offset = sizeof(struct T_bind_ack);
	ba->CONIND_number = qlen;
	memcpy((char *) mp->b_rptr + ba->ADDR_offset, (char *) &s->local, sizeof s->local);
	if (strd_trace)
		fprintf(stderr, "inet: %s bound to port %d (qlen %d)\n", s->tcp ? "tcp" : "udp", ntohs(s->local.sin_port), qlen);
	qreply_(q, mp);
}

static void
addr_ack(q, mp, s)
queue_t *q;
mblk_t *mp;
struct in *s;
{
	struct T_addr_ack *aa;
	int sz = sizeof(struct T_addr_ack), connected = s->state == TS_DATA_XFER || s->state == TS_WIND_ORDREL ||
		s->state == TS_WREQ_ORDREL;

	mp = reuse(mp, sz + 2 * sizeof(struct sockaddr_in), M_PCPROTO, (long) T_ADDR_ACK);
	aa = (struct T_addr_ack *) mp->b_rptr;
	if (s->state != TS_UNBND) {
		aa->LOCADDR_length = sizeof s->local;
		aa->LOCADDR_offset = sz;
		memcpy((char *) mp->b_rptr + sz, (char *) &s->local, sizeof s->local);
	}
	if (connected) {
		aa->REMADDR_length = sizeof s->peer;
		aa->REMADDR_offset = sz + sizeof s->local;
		memcpy((char *) mp->b_rptr + sz + sizeof s->local, (char *) &s->peer, sizeof s->peer);
	}
	qreply_(q, mp);
}

static void
optmgmt(q, mp)
queue_t *q;
mblk_t *mp;
{
	/* the options as given, as if all were applied: T_SUCCESS (XTI) where asked */
	mp->b_datap->db_type = M_PCPROTO;
	((struct T_optmgmt_ack *) mp->b_rptr)->PRIM_type = T_OPTMGMT_ACK;
	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = 0;
	}
	qreply_(q, mp);
}

static void connect_poll();

/* the end of a connect: T_CONN_CON, or T_DISCON_IND with the error */
static void
connect_done(s, err)
struct in *s;
int err;
{
	int len = sizeof s->local;

	s->connecting = 0;
	if (err) {
		if (strd_trace)
			fprintf(stderr, "inet: connect to port %d failed: errno %d\n", ntohs(s->peer.sin_port), err);
		close(s->fd);
		s->fd = -1;
		if (new_socket(s) == 0)
			bind(s->fd, (struct sockaddr *) &s->local, sizeof s->local);
		s->state = TS_IDLE;
		discon_ind(s, err, -1L);
		return;
	}
	fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL, 0) & ~O_NONBLOCK);
	getsockname(s->fd, (struct sockaddr *) &s->local, &len);
	s->state = TS_DATA_XFER;
	putnext(s->rq, addr_msg(sizeof(struct T_conn_con), (long) T_CONN_CON, &s->peer, 4, (char *) 0, 0));
}

static void
connect_poll(arg)
caddr_t arg;
{
	struct in *s = (struct in *) arg;
	fd_set ws;
	struct timeval tv;
	int err = 0, len = sizeof err;

	s->tmo = 0;
	if (!s->connecting || s->fd < 0)
		return;
	FD_ZERO(&ws);
	FD_SET(s->fd, &ws);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	if (select(s->fd + 1, (int *) 0, (int *) &ws, (int *) 0, &tv) <= 0) {
		s->tmo = timeout(connect_poll, (caddr_t) s, HZ / 20);
		return;
	}
	if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len) < 0)
		err = errno;
	connect_done(s, err);
}

static void
do_connect(q, mp, s)
queue_t *q;
mblk_t *mp;
struct in *s;
{
	struct T_conn_req *cr = (struct T_conn_req *) mp->b_rptr;

	if (!s->tcp) {
		error_ack(q, mp, (long) T_CONN_REQ, TNOTSUPPORT, 0);
		return;
	}
	if (s->state != TS_IDLE || s->qlen > 0) {
		error_ack(q, mp, (long) T_CONN_REQ, TOUTSTATE, 0);
		return;
	}
	if (cr->DEST_length < 8 || cr->DEST_offset + cr->DEST_length > mp->b_wptr - mp->b_rptr) {
		error_ack(q, mp, (long) T_CONN_REQ, TBADADDR, 0);
		return;
	}
	memset((char *) &s->peer, 0, sizeof s->peer);
	memcpy((char *) &s->peer, (char *) mp->b_rptr + cr->DEST_offset,
	       cr->DEST_length < (long) sizeof s->peer ? cr->DEST_length : sizeof s->peer);
	s->peer.sin_family = AF_INET;
	fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL, 0) | O_NONBLOCK);
	ok_ack(q, mp, (long) T_CONN_REQ);
	s->state = TS_WCON_CREQ;
	s->connecting = 1;
	if (connect(s->fd, (struct sockaddr *) &s->peer, sizeof s->peer) == 0)
		connect_done(s, 0);
	else if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK)
		s->tmo = timeout(connect_poll, (caddr_t) s, HZ / 50);
	else
		connect_done(s, errno);
}

/* the T_CONN_RES of a listener: the accepted socket goes to the acceptor's stream */
static void
do_accept(q, mp, s)
queue_t *q;
mblk_t *mp;
struct in *s;
{
	struct T_conn_res *cr = (struct T_conn_res *) mp->b_rptr;
	queue_t *aq = cr->QUEUE_ptr;
	struct in *a = aq ? (struct in *) aq->q_ptr : 0;
	int i;

	for (i = 0; i < NPEND; i++)
		if (s->pend[i].fd >= 0 && s->pend[i].seq == cr->SEQ_number)
			break;
	if (i == NPEND) {
		error_ack(q, mp, (long) T_CONN_RES, TBADSEQ, 0);
		return;
	}
	if (a == 0)
		a = s;
	if (a != s && a->state != TS_IDLE && a->state != TS_UNBND) {
		error_ack(q, mp, (long) T_CONN_RES, TOUTSTATE, 0);
		return;
	}
	if (a == s) {
		/* accepting on the listener itself: it stops listening */
		close(s->fd);
		s->qlen = 0;
	} else if (a->fd >= 0)
		close(a->fd);
	a->fd = s->pend[i].fd;
	a->peer = s->pend[i].from;
	{
		int len = sizeof a->local;
		getsockname(a->fd, (struct sockaddr *) &a->local, &len);
	}
	a->state = TS_DATA_XFER;
	a->eof = 0;
	s->pend[i].fd = -1;
	if (s != a) {
		for (i = 0; i < NPEND && s->pend[i].fd < 0; i++);
		s->state = i < NPEND ? TS_WRES_CIND : TS_IDLE;
	}
	ok_ack(q, mp, (long) T_CONN_RES);
}

static void
do_discon(q, mp, s)
queue_t *q;
mblk_t *mp;
struct in *s;
{
	long seq = ((struct T_discon_req *) mp->b_rptr)->SEQ_number;
	int i;

	if (s->qlen > 0) {
		/* a listener refuses a waiting connection */
		for (i = 0; i < NPEND; i++)
			if (s->pend[i].fd >= 0 && s->pend[i].seq == seq) {
				close(s->pend[i].fd);
				s->pend[i].fd = -1;
				break;
			}
		if (i == NPEND) {
			error_ack(q, mp, (long) T_DISCON_REQ, TBADSEQ, 0);
			return;
		}
		for (i = 0; i < NPEND && s->pend[i].fd < 0; i++);
		s->state = i < NPEND ? TS_WRES_CIND : TS_IDLE;
		ok_ack(q, mp, (long) T_DISCON_REQ);
		return;
	}
	if (s->fd >= 0) {
		struct sockaddr_in local;
		local = s->local;
		drop_socket(s);
		if (new_socket(s) == 0) {
			local.sin_port = 0;
			bind(s->fd, (struct sockaddr *) &local, sizeof local);
		}
	}
	s->state = TS_IDLE;
	flushq(RD(q), FLUSHDATA);
	ok_ack(q, mp, (long) T_DISCON_REQ);
}

static void
send_data(q, s, mp)
queue_t *q;
struct in *s;
mblk_t *mp;
{
	mblk_t *bp;

	for (bp = mp; bp; bp = bp->b_cont) {
		char *p = (char *) bp->b_rptr;
		int n = bp->b_wptr - bp->b_rptr, k;
		if (bp->b_datap->db_type != M_DATA)
			continue;
		while (n > 0) {
			k = send(s->fd, p, n, 0);
			if (k < 0 && errno == EINTR)
				continue;
			if (k <= 0) {
				int e = errno;
				drop_socket(s);
				s->state = TS_IDLE;
				discon_ind(s, e, -1L);
				freemsg(mp);
				return;
			}
			p += k;
			n -= k;
		}
	}
	freemsg(mp);
}

static void
unitdata(q, mp, s)
queue_t *q;
mblk_t *mp;
struct in *s;
{
	struct T_unitdata_req *ur = (struct T_unitdata_req *) mp->b_rptr;
	struct sockaddr_in to;
	mblk_t *bp;
	char buf[65536];
	int n = 0;

	if (s->tcp || s->fd < 0 || ur->DEST_length < 8 ||
	    ur->DEST_offset + ur->DEST_length > mp->b_wptr - mp->b_rptr) {
		freemsg(mp);
		return;
	}
	memset((char *) &to, 0, sizeof to);
	memcpy((char *) &to, (char *) mp->b_rptr + ur->DEST_offset,
	       ur->DEST_length < (long) sizeof to ? ur->DEST_length : sizeof to);
	to.sin_family = AF_INET;
	for (bp = mp->b_cont; bp && n < (int) sizeof buf; bp = bp->b_cont) {
		int k = bp->b_wptr - bp->b_rptr;
		if (k > (int) sizeof buf - n)
			k = sizeof buf - n;
		memcpy(buf + n, (char *) bp->b_rptr, k);
		n += k;
	}
	if (sendto(s->fd, buf, n, 0, (struct sockaddr *) &to, sizeof to) < 0 && strd_trace)
		fprintf(stderr, "inet: udp sendto port %d: errno %d\n", ntohs(to.sin_port), errno);
	freemsg(mp);
}

static int
in_wput(q, mp)
queue_t *q;
mblk_t *mp;
{
	struct in *s = (struct in *) q->q_ptr;
	long prim;

	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(q, FLUSHALL);
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), FLUSHALL);
			*mp->b_rptr &= ~FLUSHW;
			qreply_(q, mp);
		} else
			freemsg(mp);
		return 0;
	case M_IOCTL:
		mp->b_datap->db_type = M_IOCNAK;
		((struct iocblk *) mp->b_rptr)->ioc_error = EINVAL;
		qreply_(q, mp);
		return 0;
	case M_DATA:
		if (s->tcp && s->fd >= 0 && (s->state == TS_DATA_XFER || s->state == TS_WIND_ORDREL))
			send_data(q, s, mp);
		else
			freemsg(mp);
		return 0;
	case M_PROTO:
	case M_PCPROTO:
		break;
	default:
		freemsg(mp);
		return 0;
	}
	if (mp->b_wptr - mp->b_rptr < (int) sizeof(long)) {
		freemsg(mp);
		return 0;
	}
	prim = *(long *) mp->b_rptr;
	if (strd_trace > 1)
		fprintf(stderr, "inet: %s request %ld in state %d\n", s->tcp ? "tcp" : "udp", prim, s->state);
	switch (prim) {
	case T_INFO_REQ:
		info_ack(q, mp, s);
		break;
	case T_BIND_REQ:
		do_bind(q, mp, s);
		break;
	case T_UNBIND_REQ:
		if (s->state != TS_IDLE) {
			error_ack(q, mp, prim, TOUTSTATE, 0);
			break;
		}
		drop_socket(s);
		s->qlen = 0;
		s->state = TS_UNBND;
		ok_ack(q, mp, prim);
		break;
	case T_OPTMGMT_REQ:
		optmgmt(q, mp);
		break;
	case T_ADDR_REQ:
		addr_ack(q, mp, s);
		break;
	case T_CONN_REQ:
		do_connect(q, mp, s);
		break;
	case T_CONN_RES:
		do_accept(q, mp, s);
		break;
	case T_DISCON_REQ:
		do_discon(q, mp, s);
		break;
	case T_DATA_REQ:
	case T_EXDATA_REQ:
		if (s->tcp && s->fd >= 0 && (s->state == TS_DATA_XFER || s->state == TS_WIND_ORDREL))
			send_data(q, s, mp);
		else
			freemsg(mp);
		break;
	case T_ORDREL_REQ:
		if (s->fd >= 0)
			shutdown(s->fd, 1);
		if (s->state == TS_WREQ_ORDREL) {
			/* both sides have released: back to idle, with a fresh socket */
			struct sockaddr_in local;
			local = s->local;
			drop_socket(s);
			if (new_socket(s) == 0) {
				local.sin_port = 0;
				bind(s->fd, (struct sockaddr *) &local, sizeof local);
			}
			s->state = TS_IDLE;
		} else
			s->state = TS_WIND_ORDREL;
		freemsg(mp);
		break;
	case T_UNITDATA_REQ:
		unitdata(q, mp, s);
		break;
	default:
		error_ack(q, mp, prim, TNOTSUPPORT, 0);
		break;
	}
	return 0;
}

/* ---- the sockets in the daemon's main loop ---- */

void
inet_fds(rs, maxfd)
fd_set *rs;
int *maxfd;
{
	struct in *s;

	for (s = ins; s; s = s->next) {
		if (s->fd < 0 || s->connecting || s->eof || !canput(s->rq->q_next ? s->rq->q_next : s->rq))
			continue;
		if (s->tcp && s->state != TS_DATA_XFER && s->state != TS_WIND_ORDREL && s->qlen == 0)
			continue;
		FD_SET(s->fd, rs);
		if (s->fd > *maxfd)
			*maxfd = s->fd;
	}
}

static void
listener_ready(s)
struct in *s;
{
	struct sockaddr_in from;
	int len = sizeof from, fd, i;

	fd = accept(s->fd, (struct sockaddr *) &from, &len);
	if (fd < 0)
		return;
	for (i = 0; i < NPEND && s->pend[i].fd >= 0; i++);
	if (i == NPEND) {
		close(fd);
		return;
	}
	fcntl(fd, F_SETFD, 1);
	s->pend[i].fd = fd;
	s->pend[i].seq = ++seqno;
	s->pend[i].from = from;
	s->state = TS_WRES_CIND;
	{
		mblk_t *mp = addr_msg(sizeof(struct T_conn_ind), (long) T_CONN_IND, &from, 4, (char *) 0, 0);
		((struct T_conn_ind *) mp->b_rptr)->SEQ_number = s->pend[i].seq;
		putnext(s->rq, mp);
	}
}

void
inet_io(rs)
fd_set *rs;
{
	static char buf[65536];
	struct in *s, *next;
	int n;

	for (s = ins; s; s = next) {
		next = s->next;
		if (s->fd < 0 || !FD_ISSET(s->fd, rs))
			continue;
		FD_CLR(s->fd, rs);
		if (s->tcp && s->qlen > 0) {
			listener_ready(s);
			continue;
		}
		if (!s->tcp) {
			struct sockaddr_in from;
			int len = sizeof from;
			n = recvfrom(s->fd, buf, sizeof buf, 0, (struct sockaddr *) &from, &len);
			if (n >= 0)
				putnext(s->rq, addr_msg(sizeof(struct T_unitdata_ind), (long) T_UNITDATA_IND, &from, 4, buf, n));
			continue;
		}
		n = recv(s->fd, buf, sizeof buf, 0);
		if (n > 0) {
			mblk_t *mp = reuse((mblk_t *) 0, sizeof(struct T_data_ind), M_PROTO, (long) T_DATA_IND);
			mblk_t *dp = allocb(n, 0);
			memcpy((char *) dp->b_wptr, buf, n);
			dp->b_wptr += n;
			mp->b_cont = dp;
			putnext(s->rq, mp);
		} else if (n == 0) {
			/* the peer released its side */
			s->eof = 1;
			s->state = s->state == TS_WIND_ORDREL ? TS_IDLE : TS_WREQ_ORDREL;
			putnext(s->rq, reuse((mblk_t *) 0, sizeof(struct T_ordrel_ind), M_PROTO, (long) T_ORDREL_IND));
			if (s->state == TS_IDLE) {
				struct sockaddr_in local;
				local = s->local;
				drop_socket(s);
				if (new_socket(s) == 0) {
					local.sin_port = 0;
					bind(s->fd, (struct sockaddr *) &local, sizeof local);
				}
				s->eof = 0;
			}
		} else if (errno != EINTR && errno != EAGAIN) {
			int e = errno;
			drop_socket(s);
			s->state = TS_IDLE;
			discon_ind(s, e, -1L);
		}
	}
}
