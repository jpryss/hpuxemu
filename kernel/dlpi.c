/*
 * dlpi.c - the LAN's DLPI driver (/dev/dlpi) for the STREAMS daemon: a DLPI version 2,
 * style 2 provider for 802.3 with LLC type 1, as HP-UX's own is to the protocols that
 * use it (a protocol stack binds its LLC SAP and links the stream below itself).
 *
 * The frames go to and come from a host program over a socket (strd -e PATH, a stream
 * socket; each frame is a word of length and the frame): that program is the wire. With
 * no wire, what is sent is counted and dropped, and nothing arrives, as on a LAN
 * interface with no cable.
 *
 * PPA 0 is lan0; it is also attached by its network management ID (NMID, lanscan's
 * "NM ID"), as programs written for HP-UX 9 do: strd -n NMID, 4 by default, what
 * lan0 has on a workstation. Its station address is strd -m xx:xx:xx:xx:xx:xx (by default the
 * locally administered 0a:00:09:00:00:01).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/dlpi.h>
#include "strd.h"

#define NMULTI 16
#define LLC_UI 0x03
#define LLC_XID 0xaf
#define LLC_TEST 0xe3

struct dl {
	queue_t *rq;
	int state;
	int ppa;
	int sap;
	int nmulti;
	unsigned char multi[NMULTI][6];
	int promisc;
	struct dl *next;
};
static struct dl *dls;

unsigned char dl_mac[6] = { 0x0a, 0x00, 0x09, 0x00, 0x00, 0x01 };
static unsigned char bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
char *dl_wire_path;
int dl_nmid = 4;
static int wire = -1;
static int tx_frames, tx_dropped, rx_frames;

static int dl_open(), dl_close(), dl_wput();
static struct module_info dl_minfo = { 0, "dlpi", 0, INFPSZ, 65536, 8192 };
static struct qinit dl_rinit = { 0, 0, dl_open, dl_close, 0, &dl_minfo, 0 };
static struct qinit dl_winit = { dl_wput, 0, 0, 0, 0, &dl_minfo, 0 };
static streams_info_t dl_info = { "dlpi", -1, { &dl_rinit, &dl_winit, 0, 0 }, STR_IS_DEVICE | STR_SYSV4_OPEN, 0, "" };

void
dlpi_install()
{
	str_install(&dl_info);
}

static int
dl_open(q, devp, flag, sflag, cr)
queue_t *q;
dev_t *devp;
int flag, sflag;
char *cr;
{
	struct dl *d = (struct dl *) calloc(1, sizeof *d);

	d->rq = q;
	d->state = DL_UNATTACHED;
	d->sap = -1;
	d->next = dls;
	dls = d;
	q->q_ptr = WR(q)->q_ptr = (char *) d;
	return 0;
}

static int
dl_close(q, flag, cr)
queue_t *q;
int flag;
char *cr;
{
	struct dl *d = (struct dl *) q->q_ptr, **pp;

	for (pp = &dls; *pp; pp = &(*pp)->next)
		if (*pp == d) {
			*pp = d->next;
			break;
		}
	free((char *) d);
	q->q_ptr = WR(q)->q_ptr = 0;
	return 0;
}

/* an acknowledgement in place of the request mp */
static mblk_t *
reuse(mp, size, type, prim)
mblk_t *mp;
int size, type;
u_long prim;
{
	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = 0;
	}
	if (mp->b_datap->db_lim - mp->b_datap->db_base < size || mp->b_datap->db_ref > 1) {
		freemsg(mp);
		mp = allocb(size, 0);
	}
	mp->b_rptr = mp->b_datap->db_base;
	mp->b_wptr = mp->b_rptr + size;
	memset((char *) mp->b_rptr, 0, size);
	mp->b_datap->db_type = type;
	*(u_long *) mp->b_rptr = prim;
	return mp;
}

static void
ok_ack(q, mp, prim)
queue_t *q;
mblk_t *mp;
u_long prim;
{
	mp = reuse(mp, sizeof(dl_ok_ack_t), M_PCPROTO, DL_OK_ACK);
	((dl_ok_ack_t *) mp->b_rptr)->dl_correct_primitive = prim;
	qreply_(q, mp);
}

static void
error_ack(q, mp, prim, err, uerr)
queue_t *q;
mblk_t *mp;
u_long prim;
int err, uerr;
{
	fprintf(stderr, "dlpi: primitive %#x refused: DLPI error %d\n", prim, err);
	mp = reuse(mp, sizeof(dl_error_ack_t), M_PCPROTO, DL_ERROR_ACK);
	((dl_error_ack_t *) mp->b_rptr)->dl_error_primitive = prim;
	((dl_error_ack_t *) mp->b_rptr)->dl_errno = err;
	((dl_error_ack_t *) mp->b_rptr)->dl_unix_errno = uerr;
	qreply_(q, mp);
}

static void
info_ack(q, mp, d)
queue_t *q;
mblk_t *mp;
struct dl *d;
{
	dl_info_ack_t *ia;
	int size = sizeof(dl_info_ack_t) + 7 + 6 + 1;

	mp = reuse(mp, size, M_PCPROTO, DL_INFO_ACK);
	ia = (dl_info_ack_t *) mp->b_rptr;
	ia->dl_max_sdu = 1497;
	ia->dl_min_sdu = 1;
	ia->dl_addr_length = 7;
	ia->dl_mac_type = DL_CSMACD;
	ia->dl_current_state = d->state;
	ia->dl_sap_length = -1;
	ia->dl_service_mode = DL_CLDLS;
	ia->dl_provider_style = DL_STYLE2;
	ia->dl_version = DL_VERSION_2;
	ia->dl_brdcst_addr_length = 6;
	if (d->state != DL_UNATTACHED) {
		ia->dl_addr_offset = sizeof(dl_info_ack_t);
		memcpy((char *) mp->b_rptr + ia->dl_addr_offset, (char *) dl_mac, 6);
		mp->b_rptr[ia->dl_addr_offset + 6] = d->sap < 0 ? 0 : d->sap;
	}
	ia->dl_brdcst_addr_offset = sizeof(dl_info_ack_t) + 7;
	memcpy((char *) mp->b_rptr + ia->dl_brdcst_addr_offset, (char *) bcast, 6);
	qreply_(q, mp);
}

/* a frame to the wire: 802.3 header, LLC, data */
static void
wire_send(frame, n)
unsigned char *frame;
int n;
{
	unsigned char len[4];

	tx_frames++;
	if (strd_trace) {
		int i;
		fprintf(stderr, "dlpi: tx %d:", n);
		for (i = 0; i < n && i < 40; i++)
			fprintf(stderr, " %02x", frame[i]);
		fprintf(stderr, "\n");
	}
	if (wire < 0) {
		tx_dropped++;
		return;
	}
	len[0] = n >> 24;
	len[1] = n >> 16;
	len[2] = n >> 8;
	len[3] = n;
	if (write(wire, (char *) len, 4) != 4 || write(wire, (char *) frame, n) != n) {
		fprintf(stderr, "dlpi: the wire went away\n");
		close(wire);
		wire = -1;
	}
}

static void
unitdata_req(q, mp, d)
queue_t *q;
mblk_t *mp;
struct dl *d;
{
	dl_unitdata_req_t *ur = (dl_unitdata_req_t *) mp->b_rptr;
	unsigned char *dst, frame[1600];
	int n = 0, dsap, k;
	mblk_t *bp;

	if (d->state != DL_IDLE) {
		freemsg(mp);
		return;
	}
	if (ur->dl_dest_addr_length < 6) {
		freemsg(mp);
		return;
	}
	dst = mp->b_rptr + ur->dl_dest_addr_offset;
	dsap = ur->dl_dest_addr_length >= 7 ? dst[6] : d->sap;
	memcpy((char *) frame, (char *) dst, 6);
	memcpy((char *) frame + 6, (char *) dl_mac, 6);
	frame[14] = dsap;
	frame[15] = d->sap;
	frame[16] = LLC_UI;
	n = 17;
	for (bp = mp->b_cont; bp; bp = bp->b_cont) {
		k = bp->b_wptr - bp->b_rptr;
		if (n + k > 1514)
			k = 1514 - n;
		memcpy((char *) frame + n, (char *) bp->b_rptr, k);
		n += k;
	}
	frame[12] = (n - 14) >> 8;
	frame[13] = n - 14;
	while (n < 60)
		frame[n++] = 0;
	freemsg(mp);
	wire_send(frame, n);
}

static int
dl_wput(q, mp)
queue_t *q;
mblk_t *mp;
{
	struct dl *d = (struct dl *) q->q_ptr;
	u_long prim;
	int i;

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
		fprintf(stderr, "dlpi: ioctl %#x refused\n", ((struct iocblk *) mp->b_rptr)->ioc_cmd);
		qreply_(q, mp);
		return 0;
	case M_PROTO:
	case M_PCPROTO:
		break;
	default:
		freemsg(mp);
		return 0;
	}
	if (mp->b_wptr - mp->b_rptr < sizeof(u_long)) {
		freemsg(mp);
		return 0;
	}
	prim = *(u_long *) mp->b_rptr;
	if (strd_trace && prim != DL_UNITDATA_REQ)
		fprintf(stderr, "dlpi: primitive %#x state %d arg %ld\n", prim, d->state,
			mp->b_wptr - mp->b_rptr >= 8 ? ((long *) mp->b_rptr)[1] : -1L);
	switch (prim) {
	case DL_INFO_REQ:
		info_ack(q, mp, d);
		break;
	case DL_ATTACH_REQ:
		if (d->state != DL_UNATTACHED)
			error_ack(q, mp, prim, DL_OUTSTATE, 0);
		else if (((dl_attach_req_t *) mp->b_rptr)->dl_ppa != 0 &&
			 ((dl_attach_req_t *) mp->b_rptr)->dl_ppa != dl_nmid)
			error_ack(q, mp, prim, DL_BADPPA, 0);
		else {
			d->ppa = 0;
			d->state = DL_UNBOUND;
			ok_ack(q, mp, prim);
		}
		break;
	case DL_DETACH_REQ:
		if (d->state != DL_UNBOUND)
			error_ack(q, mp, prim, DL_OUTSTATE, 0);
		else {
			d->state = DL_UNATTACHED;
			ok_ack(q, mp, prim);
		}
		break;
	case DL_BIND_REQ:
		{
			dl_bind_req_t *br = (dl_bind_req_t *) mp->b_rptr;
			dl_bind_ack_t *ba;
			int sap = br->dl_sap;
			if (d->state != DL_UNBOUND) {
				error_ack(q, mp, prim, DL_OUTSTATE, 0);
				break;
			}
			if (sap > 0xff || (sap & 1)) {
				error_ack(q, mp, prim, DL_BADSAP, 0);
				break;
			}
			d->sap = sap;
			d->state = DL_IDLE;
			mp = reuse(mp, sizeof(dl_bind_ack_t) + 7, M_PCPROTO, DL_BIND_ACK);
			ba = (dl_bind_ack_t *) mp->b_rptr;
			ba->dl_sap = sap;
			ba->dl_addr_length = 7;
			ba->dl_addr_offset = sizeof(dl_bind_ack_t);
			memcpy((char *) mp->b_rptr + ba->dl_addr_offset, (char *) dl_mac, 6);
			mp->b_rptr[ba->dl_addr_offset + 6] = sap;
			qreply_(q, mp);
		}
		break;
	case DL_UNBIND_REQ:
		if (d->state != DL_IDLE)
			error_ack(q, mp, prim, DL_OUTSTATE, 0);
		else {
			d->state = DL_UNBOUND;
			d->sap = -1;
			flushq(q, FLUSHALL);
			flushq(RD(q), FLUSHALL);
			ok_ack(q, mp, prim);
		}
		break;
	case DL_ENABMULTI_REQ:
	case DL_DISABMULTI_REQ:
		{
			dl_enabmulti_req_t *er = (dl_enabmulti_req_t *) mp->b_rptr;
			unsigned char *a = mp->b_rptr + er->dl_addr_offset;
			if (d->state == DL_UNATTACHED) {
				error_ack(q, mp, prim, DL_OUTSTATE, 0);
				break;
			}
			if (er->dl_addr_length != 6 || !(a[0] & 1)) {
				error_ack(q, mp, prim, DL_BADADDR, 0);
				break;
			}
			for (i = 0; i < d->nmulti; i++)
				if (memcmp((char *) d->multi[i], (char *) a, 6) == 0)
					break;
			if (prim == DL_ENABMULTI_REQ) {
				if (i == d->nmulti) {
					if (d->nmulti == NMULTI) {
						error_ack(q, mp, prim, DL_TOOMANY, 0);
						break;
					}
					memcpy((char *) d->multi[d->nmulti++], (char *) a, 6);
				}
			} else {
				if (i == d->nmulti) {
					error_ack(q, mp, prim, DL_NOTENAB, 0);
					break;
				}
				memcpy((char *) d->multi[i], (char *) d->multi[--d->nmulti], 6);
			}
			ok_ack(q, mp, prim);
		}
		break;
	case DL_PROMISCON_REQ:
		d->promisc = 1;
		ok_ack(q, mp, prim);
		break;
	case DL_PROMISCOFF_REQ:
		d->promisc = 0;
		ok_ack(q, mp, prim);
		break;
	case DL_PHYS_ADDR_REQ:
		{
			dl_phys_addr_ack_t *pa;
			mp = reuse(mp, sizeof(dl_phys_addr_ack_t) + 6, M_PCPROTO, DL_PHYS_ADDR_ACK);
			pa = (dl_phys_addr_ack_t *) mp->b_rptr;
			pa->dl_addr_length = 6;
			pa->dl_addr_offset = sizeof(dl_phys_addr_ack_t);
			memcpy((char *) mp->b_rptr + pa->dl_addr_offset, (char *) dl_mac, 6);
			qreply_(q, mp);
		}
		break;
	case DL_UNITDATA_REQ:
		unitdata_req(q, mp, d);
		break;
	default:
		fprintf(stderr, "dlpi: primitive %#x not supported\n", prim);
		error_ack(q, mp, prim, DL_NOTSUPPORTED, 0);
		break;
	}
	return 0;
}

/* a frame from the wire: to each stream bound to its SAP that the address reaches */
static void
wire_recv(f, n)
unsigned char *f;
int n;
{
	struct dl *d;
	int i, len, group;
	mblk_t *mp, *dp;
	dl_unitdata_ind_t *ui;

	rx_frames++;
	if (n < 17)
		return;
	len = (f[12] << 8) | f[13];
	if (len > 1500)		/* Ethernet II: not ours */
		return;
	if (len + 14 < n)
		n = len + 14;
	if (f[16] != LLC_UI)
		return;
	group = f[0] & 1;
	for (d = dls; d; d = d->next) {
		if (d->state != DL_IDLE || d->sap != f[14])
			continue;
		if (!d->promisc) {
			if (group) {
				if (memcmp((char *) f, (char *) bcast, 6) != 0) {
					for (i = 0; i < d->nmulti; i++)
						if (memcmp((char *) d->multi[i], (char *) f, 6) == 0)
							break;
					if (i == d->nmulti)
						continue;
				}
			} else if (memcmp((char *) f, (char *) dl_mac, 6) != 0)
				continue;
		}
		if (!canput(d->rq->q_next))
			continue;
		mp = allocb(sizeof(dl_unitdata_ind_t) + 14, 0);
		dp = allocb(n - 17, 0);
		if (mp == 0 || dp == 0) {
			freemsg(mp);
			freemsg(dp);
			continue;
		}
		mp->b_datap->db_type = M_PROTO;
		ui = (dl_unitdata_ind_t *) mp->b_wptr;
		memset((char *) ui, 0, sizeof *ui);
		ui->dl_primitive = DL_UNITDATA_IND;
		ui->dl_dest_addr_length = 7;
		ui->dl_dest_addr_offset = sizeof *ui;
		ui->dl_src_addr_length = 7;
		ui->dl_src_addr_offset = sizeof *ui + 7;
		ui->dl_group_address = group;
		memcpy((char *) mp->b_wptr + sizeof *ui, (char *) f, 6);
		mp->b_wptr[sizeof *ui + 6] = f[14];
		memcpy((char *) mp->b_wptr + sizeof *ui + 7, (char *) f + 6, 6);
		mp->b_wptr[sizeof *ui + 13] = f[15];
		mp->b_wptr += sizeof *ui + 14;
		memcpy((char *) dp->b_wptr, (char *) f + 17, n - 17);
		dp->b_wptr += n - 17;
		mp->b_cont = dp;
		putnext(d->rq, mp);
	}
}

/* the daemon's main loop asks for the wire's descriptor and hands over its input */
extern void inet_fds(), inet_io(), inet_install();

void
strd_fds(rs, maxfd)
fd_set *rs;
int *maxfd;
{
	inet_fds(rs, maxfd);
	if (wire < 0 && dl_wire_path) {
		struct sockaddr_un sa;
		static int warned;
		wire = socket(AF_UNIX, SOCK_STREAM, 0);
		memset((char *) &sa, 0, sizeof sa);
		sa.sun_family = AF_UNIX;
		strncpy(sa.sun_path, dl_wire_path, sizeof sa.sun_path - 1);
		if (connect(wire, (struct sockaddr *) &sa, sizeof sa) < 0) {
			if (!warned++)
				fprintf(stderr, "dlpi: no wire at %s yet\n", dl_wire_path);
			close(wire);
			wire = -1;
		} else
			fprintf(stderr, "dlpi: wire %s connected\n", dl_wire_path);
	}
	if (wire >= 0) {
		FD_SET(wire, rs);
		if (wire > *maxfd)
			*maxfd = wire;
	}
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

void
strd_io(rs)
fd_set *rs;
{
	unsigned char hdr[4], frame[1600];
	int n;

	inet_io(rs);

	if (wire < 0 || !FD_ISSET(wire, rs))
		return;
	if (readn(wire, (char *) hdr, 4) < 0)
		goto gone;
	n = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
	if (n < 0 || n > (int) sizeof frame)
		goto gone;
	if (readn(wire, (char *) frame, n) < 0)
		goto gone;
	wire_recv(frame, n);
	return;
gone:
	fprintf(stderr, "dlpi: the wire went away\n");
	close(wire);
	wire = -1;
}

extern void timod_install();

void
strd_modules()
{
	timod_install();
	dlpi_install();
	inet_install();
}
