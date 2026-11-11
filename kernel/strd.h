/* strd.h - what the STREAMS daemon's parts share (see strd.c) */
#ifndef HZ
#define HZ 100
#endif
#ifndef OPENFAIL
#define OPENFAIL (-1)
#endif
#ifndef datamsg
#define datamsg(type) ((type) == M_DATA || (type) == M_PROTO || (type) == M_PCPROTO || (type) == M_DELAY)
#endif
#ifndef major
#define major(d) (((unsigned) (d) >> 24) & 0xff)
#define minor(d) ((d) & 0xffffff)
#define makedev(ma, mi) ((dev_t) (((ma) << 24) | ((mi) & 0xffffff)))
#endif
#ifndef STR_IS_MODULE
#define STR_IS_DEVICE	0x00000001
#define STR_IS_MODULE	0x00000002
#define STR_SYSV4_OPEN	0x00000100
#endif
#ifndef ETIME
#define ETIME 62
#endif

/* the kernel's streams_info_t (sys/stream.h has it for _KERNEL only) */
typedef struct stream_inst {
	char *name;
	int inst_major;
	struct streamtab inst_str_tab;
	unsigned int inst_flags;
	int inst_sync_level;
	char inst_sync_info[FMNAMESZ + 1];
} streams_info_t;

extern mblk_t *allocb(), *dupmsg(), *copymsg(), *getq(), *unlinkb();
extern void freemsg(), freeb(), flushq(), qenable(), qreply_(), linkb();
extern int putq(), putbq(), putnext(), puthere(), canput(), putctl1(), str_install();
extern int strd_trace;

/* the modules and drivers of the daemon itself (timod, dlpi) and the LAN */
extern void strd_modules();
extern void strd_fds();
extern void strd_io();
