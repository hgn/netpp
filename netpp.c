/*
** Copyright (C) 2009 - Hagen Paul Pfeifer <hagen@jauu.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <assert.h>
#include <inttypes.h>
#include <getopt.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/sendfile.h>

#include <limits.h>
#include <netdb.h>

#ifdef HAVE_RDTSCLL
# include <linux/timex.h>

#ifndef rdtscll
# define rdtscll(val) \
     __asm__ __volatile__("rdtsc" : "=A" (val))
#endif
#endif /* HAVE_RDTSCLL */

#undef __always_inline
#if __GNUC_PREREQ (3,2)
# define __always_inline __inline __attribute__ ((__always_inline__))
#else
# define __always_inline __inline
#endif

/*
 * See if our compiler is known to support flexible array members.
 */
#ifndef FLEX_ARRAY
#if defined(__STDC_VERSION__) && \
	(__STDC_VERSION__ >= 199901L) && \
	(!defined(__SUNPRO_C) || (__SUNPRO_C > 0x580))
# define FLEX_ARRAY /* empty */
#elif defined(__GNUC__)
# if (__GNUC__ >= 3)
#  define FLEX_ARRAY /* empty */
# else
#  define FLEX_ARRAY 0 /* older GNU extension */
# endif
#endif

/*
 * Otherwise, default to safer but a bit wasteful traditional style
 */
#ifndef FLEX_ARRAY
# define FLEX_ARRAY 1
#endif
#endif

#ifndef ULLONG_MAX
# define ULLONG_MAX 18446744073709551615ULL
#endif

#define min(x,y) ({                     \
        typeof(x) _x = (x);             \
        typeof(y) _y = (y);             \
        (void) (&_x == &_y);    \
        _x < _y ? _x : _y; })

#define max(x,y) ({                     \
        typeof(x) _x = (x);             \
        typeof(y) _y = (y);             \
        (void) (&_x == &_y);    \
        _x > _y ? _x : _y; })

#define TIME_GT(x,y) (x->tv_sec > y->tv_sec || (x->tv_sec == y->tv_sec && x->tv_usec > y->tv_usec))
#define TIME_LT(x,y) (x->tv_sec < y->tv_sec || (x->tv_sec == y->tv_sec && x->tv_usec < y->tv_usec))

#if !defined likely && !defined unlikely
# define likely(x)   __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifdef DEBUG
static const int debug_enabled = 1;
#else
static const int debug_enabled = 0;
#endif

#define err_msg(format, args...) \
        do { \
                x_err_ret(__FILE__, __LINE__,  format , ## args); \
        } while (0)

#define err_sys(format, args...) \
        do { \
                x_err_sys(__FILE__, __LINE__,  format , ## args); \
        } while (0)

#define err_sys_die(exitcode, format, args...) \
        do { \
                x_err_sys(__FILE__, __LINE__, format , ## args); \
                exit( exitcode ); \
        } while (0)

#define err_msg_die(exitcode, format, args...) \
        do { \
                x_err_ret(__FILE__, __LINE__,  format , ## args); \
				exit( exitcode ); \
        } while (0)

#define pr_debug(format, args...) \
        do { \
                if (debug_enabled) \
                        msg(format, ##args); \
		} while (0)

/* determine the size of an array */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BITSIZEOF(x)  (CHAR_BIT * sizeof(x))

#define EXIT_OK         EXIT_SUCCESS
#define EXIT_FAILMEM    1
#define EXIT_FAILOPT    2
#define EXIT_FAILMISC   3
#define EXIT_FAILNET    4
#define EXIT_FAILHEADER 6
#define EXIT_FAILEVENT  7
#define EXIT_FAILFILE   8
#define EXIT_FAILINT    9 /* INTernal error */

#define SUCCESS 0
#define FAILURE -1

#define RANDPOOLSRC "/dev/urandom"

#define MAXERRMSG 1024

#define	DEFAULT_RX_BUF_SIZE 2048

#define	DEFAULT_V4_MULT_ADDR "224.110.99.112"
#define DEFAULT_LISTEN_PORT "6666"

enum {
	MODE_SERVER = 1,
	MODE_CLIENT
};

struct opts {
	int wanted_af_family;
	int rx_buf_size;
	char *me;
	char *port;
	char *filename;
	char *outfilename;
};

#define	OFFER_PDU_MAGIC 0x2323
#define	OFFER_PDU_VERSION 0x01

struct offer_pdu_hdr {
	uint16_t magic;
	uint16_t cookie;
	uint16_t opcode;
	uint16_t len;
	/* tlv's follows */
} __attribute__((packed));

#define	OFFER_TLV_FILE 0x01
#define	OFFER_TLV_SHA1 0x02

struct offer_pdu_tlv_file {
	uint16_t type;
	uint16_t len;
	uint32_t filesize;
	uint32_t filename_len;
	char filename[FLEX_ARRAY]; /* must end on a 4 byte boundary */
} __attribute__((packed));

/* this message is sent from the client to the
 * server and signals that the client received
 * correctly a offer PDU, opens a passive TCP socket
 * on port port and is now ready to receive the file */
struct request_pdu_hdr {
	uint16_t port;
} __attribute__((packed));

struct cl_offer_info {
	uint32_t file_size;
	uint32_t filename_len;
	char *filename;
};

struct cl_srv_addr_info {
	struct sockaddr_storage ss;
	socklen_t ss_len;
};

struct cl_file_hndl {
	int fd;
};

struct srv_cl_request_info {
	uint16_t port;
};

struct srv_cl_addr_info {
	struct sockaddr_storage ss;
	socklen_t ss_len;
};

struct srv_file_hndl {
	int fd;
	char *name; /* pointer to opts.filename */
	off_t filesize;
};

struct srv_state {
	uint16_t cookie;
};

struct ctx {
	int mode;
	struct opts *opts;
	/* client bookkeeping */
	struct cl_offer_info cl_offer_info;
	struct cl_srv_addr_info cl_srv_addr_info;
	struct cl_file_hndl cl_file_hndl;
	/* server stuff */
	struct srv_state srv_state;
	struct srv_cl_request_info srv_cl_request_info;
	struct srv_cl_addr_info srv_cl_addr_info;
	struct srv_file_hndl srv_file_hndl;
};

int subtime(struct timeval *op1, struct timeval *op2,
				   struct timeval *result)
{
	int borrow = 0, sign = 0;
	struct timeval *temp_time;

	if (TIME_LT(op1, op2)) {
		temp_time = op1;
		op1  = op2;
		op2  = temp_time;
		sign = 1;
	}

	if (op1->tv_usec >= op2->tv_usec) {
		result->tv_usec = op1->tv_usec-op2->tv_usec;
	} else {
		result->tv_usec = (op1->tv_usec + 1000000) - op2->tv_usec;
		borrow = 1;
	}
	result->tv_sec = (op1->tv_sec-op2->tv_sec) - borrow;

	return sign;
}

double tv_to_sec(struct timeval *tv)
{
	return (double)tv->tv_sec + (double)tv->tv_usec * 1000000;
}


void msg(const char *format, ...)
{
	va_list ap;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	fprintf(stderr, "[%ld.%06ld] ", tv.tv_sec, tv.tv_usec);

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

	fputs("\n", stderr);
}


static void err_doit(int sys_error, const char *file,
		const int line_no, const char *fmt, va_list ap)
{
	int errno_save;
	char buf[MAXERRMSG];

	errno_save = errno;

	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	if (sys_error) {
		size_t len = strlen(buf);
		snprintf(buf + len,  sizeof buf - len, " (%s)",
				strerror(errno_save));
	}

	fprintf(stderr, "ERROR [%s:%d]: %s\n", file, line_no, buf);
	fflush(NULL);

	errno = errno_save;
}


void x_err_ret(const char *file, int line_no, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(0, file, line_no, fmt, ap);
	va_end(ap);
	return;
}


void x_err_sys(const char *file, int line_no, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(1, file, line_no, fmt, ap);
	va_end(ap);
}


static void * xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (!ptr)
		err_sys_die(EXIT_FAILMEM, "failure in malloc!\n");
	return ptr;
}


static void* xzalloc(size_t size)
{
	void *ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}


static void xsetsockopt(int s, int level, int optname,
		const void *optval, socklen_t optlen, const char *str)
{
	int ret = setsockopt(s, level, optname, optval, optlen);
	if (ret)
		err_sys_die(EXIT_FAILNET, "Can't set socketoption %s", str);
}


void xfstat(int filedes, struct stat *buf, const char *s)
{
	if (fstat(filedes, buf))
		err_sys_die(EXIT_FAILMISC, "Can't fstat file %s", s);
}

unsigned long long xstrtoull(const char *str)
{
	char *endptr;
	long long val;

	errno = 0;
	val = strtoll(str, &endptr, 10);
	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
			|| (errno != 0 && val == 0)) {
		err_sys_die(EXIT_FAILURE, "strtoll failure");
	}

	if (endptr == str) {
		err_msg_die(EXIT_FAILURE, "No digits found in commandline");
	}

	return val;
}

static int xatoi(const char *str)
{
	long val;
	char *endptr;

	val = strtol(str, &endptr, 10);
	if ((val == LONG_MIN || val == LONG_MAX) && errno != 0)
		err_sys_die(EXIT_FAILURE, "strtoll failure");

	if (endptr == str)
		err_msg_die(EXIT_FAILURE, "No digits found in commandline");

	if (val > INT_MAX)
		return INT_MAX;

	if (val < INT_MIN)
		return INT_MIN;

	if ('\0' != *endptr)
		err_msg_die(EXIT_FAILURE,
				"To many characters on input: \"%s\"", str);

	return val;
}


/*******/

#define TP_IDX_MAX      8

struct throughput {
	off_t curr_total;
	off_t prev_total;
	struct timeval prev_tv;
	unsigned int avg_bytes;
	unsigned int avg_misecs;
	unsigned int last_bytes[TP_IDX_MAX];
	unsigned int last_misecs[TP_IDX_MAX];
	unsigned int idx;
	char display[32];
};

struct progress {
	const char *title;
	int last_value;
	unsigned total;
	unsigned last_percent;
	unsigned delay;
	unsigned delayed_percent_treshold;
	struct throughput *throughput;
};

static struct progress *progress;
static volatile int progress_update;

static void progress_interval(int signum __attribute__((unused)))
{
	progress_update = 1;
}

static void set_progress_signal(void)
{
	struct sigaction sa;
	struct itimerval v;

	progress_update = 0;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = progress_interval;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGALRM, &sa, NULL);

	v.it_interval.tv_sec = 1;
	v.it_interval.tv_usec = 0;
	v.it_value = v.it_interval;
	setitimer(ITIMER_REAL, &v, NULL);
}

static void clear_progress_signal(void)
{
	struct itimerval v;

	memset(&v, 0, sizeof(v));

	setitimer(ITIMER_REAL, &v, NULL);
	signal(SIGALRM, SIG_IGN);

	progress_update = 0;
}

static int display(struct progress *progress, unsigned n, const char *done)
{
	const char *eol, *tp;

	if (progress->delay) {
		if (!progress_update || --progress->delay)
			return 0;
		if (progress->total) {
			unsigned percent = n * 100 / progress->total;
			if (percent > progress->delayed_percent_treshold) {
				/* inhibit this progress report entirely */
				clear_progress_signal();
				progress->delay = -1;
				progress->total = 0;
				return 0;
			}
		}
	}

	progress->last_value = n;
	tp = (progress->throughput) ? progress->throughput->display : "";
	eol = done ? done : "   \r";
	if (progress->total) {
		unsigned percent = n * 100 / progress->total;
		if (percent != progress->last_percent || progress_update) {
			progress->last_percent = percent;
			fprintf(stderr, "%s: %3u%% (%u/%u)%s%s",
				progress->title, percent, n,
				progress->total, tp, eol);
			fflush(stderr);
			progress_update = 0;
			return 1;
		}
	} else if (progress_update) {
		fprintf(stderr, "%s: %u%s%s", progress->title, n, tp, eol);
		fflush(stderr);
		progress_update = 0;
		return 1;
	}

	return 0;
}

static void throughput_string(struct throughput *tp, off_t total,
			      unsigned int rate)
{
	int l = sizeof(tp->display);
	if (total > 1 << 30) {
		l -= snprintf(tp->display, l, ", %u.%2.2u GiB",
			      (int)(total >> 30),
			      (int)(total & ((1 << 30) - 1)) / 10737419);
	} else if (total > 1 << 20) {
		int x = total + 5243;  /* for rounding */
		l -= snprintf(tp->display, l, ", %u.%2.2u MiB",
			      x >> 20, ((x & ((1 << 20) - 1)) * 100) >> 20);
	} else if (total > 1 << 10) {
		int x = total + 5;  /* for rounding */
		l -= snprintf(tp->display, l, ", %u.%2.2u KiB",
			      x >> 10, ((x & ((1 << 10) - 1)) * 100) >> 10);
	} else {
		l -= snprintf(tp->display, l, ", %u bytes", (int)total);
	}

	if (rate > 1 << 10) {
		int x = rate + 5;  /* for rounding */
		snprintf(tp->display + sizeof(tp->display) - l, l,
			 " | %u.%2.2u MiB/s",
			 x >> 10, ((x & ((1 << 10) - 1)) * 100) >> 10);
	} else if (rate)
		snprintf(tp->display + sizeof(tp->display) - l, l,
			 " | %u KiB/s", rate);
}

void display_throughput(struct progress *progress, off_t total)
{
	struct throughput *tp;
	struct timeval tv;
	unsigned int misecs;

	if (!progress)
		return;
	tp = progress->throughput;

	gettimeofday(&tv, NULL);

	if (!tp) {
		progress->throughput = tp = calloc(1, sizeof(*tp));
		if (tp) {
			tp->prev_total = tp->curr_total = total;
			tp->prev_tv = tv;
		}
		return;
	}
	tp->curr_total = total;

	/*
	 * We have x = bytes and y = microsecs.  We want z = KiB/s:
	 *
	 *	z = (x / 1024) / (y / 1000000)
	 *	z = x / y * 1000000 / 1024
	 *	z = x / (y * 1024 / 1000000)
	 *	z = x / y'
	 *
	 * To simplify things we'll keep track of misecs, or 1024th of a sec
	 * obtained with:
	 *
	 *	y' = y * 1024 / 1000000
	 *	y' = y / (1000000 / 1024)
	 *	y' = y / 977
	 */
	misecs = (tv.tv_sec - tp->prev_tv.tv_sec) * 1024;
	misecs += (int)(tv.tv_usec - tp->prev_tv.tv_usec) / 977;

	if (misecs > 512) {
		unsigned int count, rate;

		count = total - tp->prev_total;
		tp->prev_total = total;
		tp->prev_tv = tv;
		tp->avg_bytes += count;
		tp->avg_misecs += misecs;
		rate = tp->avg_bytes / tp->avg_misecs;
		tp->avg_bytes -= tp->last_bytes[tp->idx];
		tp->avg_misecs -= tp->last_misecs[tp->idx];
		tp->last_bytes[tp->idx] = count;
		tp->last_misecs[tp->idx] = misecs;
		tp->idx = (tp->idx + 1) % TP_IDX_MAX;

		throughput_string(tp, total, rate);
		if (progress->last_value != -1 && progress_update)
			display(progress, progress->last_value, NULL);
	}
}

int display_progress(struct progress *progress, unsigned n)
{
	return progress ? display(progress, n, NULL) : 0;
}

struct progress *start_progress_delay(const char *title, unsigned total,
				       unsigned percent_treshold, unsigned delay)
{
	struct progress *progress = malloc(sizeof(*progress));
	if (!progress) {
		/* unlikely, but here's a good fallback */
		fprintf(stderr, "%s...\n", title);
		fflush(stderr);
		return NULL;
	}
	progress->title = title;
	progress->total = total;
	progress->last_value = -1;
	progress->last_percent = -1;
	progress->delayed_percent_treshold = percent_treshold;
	progress->delay = delay;
	progress->throughput = NULL;
	set_progress_signal();
	return progress;
}

struct progress *start_progress(const char *title, unsigned total)
{
	return start_progress_delay(title, total, 0, 0);
}

void stop_progress_msg(struct progress **p_progress, const char *pmsg)
{
	struct progress *progress = *p_progress;
	if (!progress)
		return;
	*p_progress = NULL;
	if (progress->last_value != -1) {
		/* Force the last update */
		char buf[128], *bufp;
		size_t len = strlen(pmsg) + 5;
		struct throughput *tp = progress->throughput;

		bufp = (len < sizeof(buf)) ? buf : xmalloc(len + 1);
		if (tp) {
			unsigned int rate = !tp->avg_misecs ? 0 :
					tp->avg_bytes / tp->avg_misecs;
			throughput_string(tp, tp->curr_total, rate);
		}
		progress_update = 1;
		sprintf(bufp, ", %s.\n", pmsg);
		display(progress, progress->last_value, bufp);
		if (buf != bufp)
			free(bufp);
	}
	clear_progress_signal();
	free(progress->throughput);
	free(progress);
}

void stop_progress(struct progress **p_progress)
{
	stop_progress_msg(p_progress, "done");
}


/*******/

static int initiate_seed(void)
{
	ssize_t ret;
	int rand_fd;
	unsigned int randpool;

	/* set randon pool seed */
	rand_fd = open(RANDPOOLSRC, O_RDONLY);
	if (rand_fd < 0)
		err_sys_die(EXIT_FAILINT,
				"Cannot open random pool file %s", RANDPOOLSRC);

	ret = read(rand_fd, &randpool, sizeof(unsigned int));
	if (ret != sizeof(unsigned int)) {
		srandom(time(NULL) & getpid());
		close(rand_fd);
		return FAILURE;
	}

	/* set global seed */
	srandom(randpool);

	close(rand_fd);

	return SUCCESS;
}


static void xgetaddrinfo(const char *node, const char *service,
		struct addrinfo *hints, struct addrinfo **res)
{
	int ret;

	ret = getaddrinfo(node, service, hints, res);
	if (unlikely(ret != 0)) {
		err_msg_die(EXIT_FAILNET, "Call to getaddrinfo() failed: %s!\n",
				(ret == EAI_SYSTEM) ?  strerror(errno) : gai_strerror(ret));
	}

	return;
}

static void xgetnameinfo(const struct sockaddr *sa, socklen_t salen,
		char *host, size_t hostlen,
		char *serv, size_t servlen, int flags)
{
	int ret = getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
	if (unlikely((ret != 0))) {
		err_msg_die(EXIT_FAILNET, "Call to getnameinfo() failed: %s!\n",
				(ret == EAI_SYSTEM) ? strerror(errno) : gai_strerror(ret));

	}
}

static void usage(const char *me)
{
	fprintf(stdout, "%s (-4|-6) (-b <rx-buffer-size>) (-p <port>) (-o <output-filename>) [filename]\n", me);
}


static void enable_multicast_v4(int fd, const struct addrinfo *a)
{
	int on = 1;
	struct ip_mreq mreq;

	memset(&mreq, 0, sizeof(struct ip_mreq));
	memcpy(&mreq.imr_multiaddr,
			&(((struct sockaddr_in *)a->ai_addr)->sin_addr),
			sizeof(struct in_addr));
	mreq.imr_interface.s_addr = INADDR_ANY;

	xsetsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &on,
			sizeof(int), "IP_MULTICAST_LOOP");
	pr_debug("set IP_MULTICAST_LOOP option");

	xsetsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
			sizeof(struct ip_mreq), "IP_ADD_MEMBERSHIP");
	pr_debug("add membership to IPv4 multicast group");
}


static void enable_multicast_v6(int fd, const struct addrinfo *a)
{
	int on = 1;
	struct ipv6_mreq mreq6;

	memset(&mreq6, 0, sizeof(struct ipv6_mreq));

	memcpy(&mreq6.ipv6mr_multiaddr,
			&(((struct sockaddr_in6 *)a->ai_addr)->sin6_addr),
			sizeof(struct in6_addr));
	mreq6.ipv6mr_interface = 0; /* FIXME: determine interface */

	xsetsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			&on, sizeof(int), "IPV6_MULTICAST_LOOP");
	pr_debug("set IPV6_MULTICAST_LOOP option");

	xsetsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			&mreq6, sizeof(struct ipv6_mreq), "IPV6_JOIN_GROUP");
	pr_debug("join IPv6 multicast group");

}


static int socket_bind(const struct addrinfo *a)
{
	int ret, on = 1;
	int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (fd < 0)
		return -1;

	xsetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on,
			sizeof(on), "SO_REUSEADDR");

	ret = bind(fd, a->ai_addr, a->ai_addrlen);
	if (ret) {
		err_msg("bind failed");
		close(fd);
		return -1;
	}

	switch (a->ai_family) {
		case AF_INET:
			enable_multicast_v4(fd, a);
				break;
		case AF_INET6:
			enable_multicast_v6(fd, a);
		default:
			abort();
			break;
	}

	listen(fd, 5);

	return fd;
}


static int set_non_blocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return FAILURE;

	flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (flags < 0)
		return FAILURE;

	return SUCCESS;
}


int init_passive_socket(const char *addr, const char *port, int must_block)
{
	int fd = -1;
	struct addrinfo hosthints, *hostres, *addrtmp;
	char addr_name[NI_MAXHOST];

	memset(&hosthints, 0, sizeof(struct addrinfo));

	hosthints.ai_family   = AF_UNSPEC;
	hosthints.ai_socktype = SOCK_DGRAM;
	hosthints.ai_protocol = IPPROTO_UDP;
	hosthints.ai_flags    = AI_PASSIVE;

	/* probe our values */
	xgetaddrinfo(addr, port, &hosthints, &hostres);

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {

		xgetnameinfo(addrtmp->ai_addr, addrtmp->ai_addrlen,
				addr_name, sizeof(addr_name), NULL, 0,
				NI_NUMERICHOST | NI_NUMERICSERV);

		pr_debug("try to open a passive socket with multicast address %s",
				 addr_name);

		fd = socket_bind(addrtmp);
		if (fd < 0) {
			pr_debug("failed create a socket");
			continue;
		}

		break;
	}

	if (fd < 0) {
		err_msg_die(EXIT_FAILNET, "Cannot find a valid socket!\n");
	}

	/* set nonblocking mode */
	if (!must_block)
		set_non_blocking(fd);

	return fd;
}

static int xopen(const char *file)
{
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		err_sys("cannot open file %s", file);
		return FAILURE;
	}

	return fd;
}

static int srv_init_file_hndl(struct ctx *ctx)
{
	struct stat statb;

	ctx->srv_file_hndl.name = ctx->opts->filename;
	ctx->srv_file_hndl.fd = xopen(ctx->srv_file_hndl.name);

	xfstat(ctx->srv_file_hndl.fd, &statb, ctx->srv_file_hndl.name);

	ctx->srv_file_hndl.filesize = statb.st_size;

	pr_debug("serving file %s of size %u byte",
			ctx->srv_file_hndl.name, ctx->srv_file_hndl.filesize);

	if (!S_ISREG(statb.st_mode)) {
		err_msg_die(EXIT_FAILFILE,
				"File %s is no regular file, giving up!",
				ctx->srv_file_hndl.name);
	}

	return SUCCESS;
}

/* serveral operations are done of the open fd
 * There are several possibilities like seek(fd) to
 * the beginning to the file or: close and reopen
 * the file again */
static void srv_reopen_file(struct ctx *ctx)
{
	close(ctx->srv_file_hndl.fd);
	ctx->srv_file_hndl.fd = xopen(ctx->srv_file_hndl.name);
}

static int init_active_socket(const char *addr, const char *port)
{
	struct addrinfo hints, *res0, *res;
	int err;
	int sock;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_family   = AF_UNSPEC;

	if ((err = getaddrinfo(addr, port, &hints, &res0)) != 0) {
		printf("error %d\n", err);
		return 1;
	}

	for (res=res0; res!=NULL; res=res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock < 0) {
			continue;
		}

		if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
			close(sock);
			continue;
		}

		break;
	}

	if (res == NULL) {
		/* could not create a valid connection */
		fprintf(stderr, "failed\n");

		return 1;
	}

	freeaddrinfo(res0);

	return sock;
}


static char *xstrdup(const char *s)
{
	char *ptr = strdup(s);
	if (!ptr)
		err_sys_die(EXIT_FAILMEM, "failed to duplicate string");

	return ptr;
}


#define	TLV_SKIPN(p, n) do { p += n; } while (0)
#define	TLV_SKIP2(p) TLV_SKIPN(p, 2)
#define	TLV_SKIP4(p) TLV_SKIPN(p, 4)

#define	TLV_WRITE2(p, n) do { *(int16_t *)p = n; TLV_SKIP2(p); } while (0)
#define	TLV_WRITE4(p, n) do { *(int32_t *)p = n; TLV_SKIP4(p); } while (0)

#define	TLV_READ2(p, n) do { n = *(int16_t *)p; TLV_SKIP2(p); } while (0)
#define	TLV_READ4(p, n) do { n = *(int32_t *)p; TLV_SKIP4(p); } while (0)

static int decode_offer_pdu(struct ctx *ctx, char *pdu, size_t pdu_len)
{
	uint32_t tmp;
	char *ptr = pdu;
	struct cl_offer_info *cl_offer_info = &ctx->cl_offer_info;

	if (pdu_len < 4 + 4 + 1) {
		pr_debug("offered file should be at least one character in name");
		return FAILURE;
	}

	TLV_READ4(ptr, tmp);
	cl_offer_info->file_size = ntohl(tmp);

	TLV_READ4(ptr, tmp);
	cl_offer_info->filename_len = ntohl(tmp);

	if (pdu_len < 4 + 4 + cl_offer_info->filename_len) {
		pr_debug("offered filename is %u bytes but transmitted only %u",
				  cl_offer_info->filename_len, pdu_len - 4 - 4);
		return FAILURE;
	}

	pr_debug("offered file \"%s\", filesize: %u bytes",
			ptr, cl_offer_info->file_size);

	cl_offer_info->filename = xstrdup(ptr);

	return SUCCESS;
}


static size_t encode_offer_pdu(struct ctx *ctx, unsigned char *pdu, size_t max_pdu_len)
{
	unsigned char *ptr = pdu;
	size_t len = 0;
	const char *filename = ctx->srv_file_hndl.name;


	TLV_WRITE4(ptr, htonl(ctx->srv_file_hndl.filesize));
	len += 4;

	TLV_WRITE4(ptr, htonl(strlen(filename) + 1));
	len += 4;

	if (strlen(filename) + 1 >= max_pdu_len - len) {
		err_msg_die(EXIT_FAILINT, "remaining buffer (%d byte) to small to "
				"transmit filename (%d byte)!",
				max_pdu_len - len, strlen(filename));
	}

	memcpy(ptr, filename, strlen(filename) + 1);

	len += strlen(filename) + 1;

	return len;
}


/* a little bit over the 802.3 limit but who
 * knowns who use this tool and whose MTU ;-) */
#define	OFFER_PDU_LEN_MAX 2048

static int srv_tx_offer_pdu(struct ctx *ctx, int fd)
{
	ssize_t ret; size_t len;
	unsigned char buf[OFFER_PDU_LEN_MAX];

	memset(buf, 0, sizeof(buf));

	len = encode_offer_pdu(ctx, buf, OFFER_PDU_LEN_MAX);

	ret = write(fd, buf, len);
	if (ret == -1 && !(errno == EWOULDBLOCK)) {
		err_sys_die(EXIT_FAILNET, "Cannot send offer message");
	}

	return SUCCESS;
}

#define	RX_BUF 512

static int srv_try_rx_client_pdu(struct ctx *ctx, int pfd)
{
	ssize_t ret;
	unsigned char rx_buf[RX_BUF];
	struct sockaddr_storage ss;
	socklen_t ss_len = sizeof(ss);
	struct request_pdu_hdr *request_pdu_hdr;

	ret = recvfrom(pfd, rx_buf, RX_BUF, 0, (struct sockaddr *)&ss, &ss_len);
	if (ret < 0 && !(errno == EWOULDBLOCK)) {
		err_sys_die(EXIT_FAILNET, "failed to read()");
	}

	if (ret != sizeof(struct request_pdu_hdr)) {
		pr_debug("received a invalid client request:"
				" is %d byte but should %d byte, ignoring it",
				ret, sizeof(struct request_pdu_hdr));
		return FAILURE;
	}

	request_pdu_hdr = (struct request_pdu_hdr *)rx_buf;


	/* save client address */
	ctx->srv_cl_addr_info.ss_len = ss_len;
	memcpy(&ctx->srv_cl_addr_info.ss, &ss,
			sizeof(ctx->srv_cl_addr_info.ss));

	/* save & convert message into host byte order */
	ctx->srv_cl_request_info.port = htons(request_pdu_hdr->port);


	pr_debug("client requested to open a new TCP data socket on port %u",
			  ctx->srv_cl_request_info.port);

	return SUCCESS;
}


static ssize_t xsendfile(struct ctx *ctx, int connected_fd, int file_fd)
{
	ssize_t rc, write_cnt;
	off_t offset = 0, filesize;
	int tx_calls = 0;

	pr_debug("now try to transfer the file to the peer");

	filesize = write_cnt = ctx->srv_file_hndl.filesize;

	while (filesize - offset - 1 >= write_cnt) {
		rc = sendfile(connected_fd, file_fd, &offset, write_cnt);
		if (rc == -1)
			err_sys_die(EXIT_FAILNET, "Failure in sendfile routine");
		tx_calls++;
	}
	/* and write remaining bytes, if any */
	write_cnt = filesize - offset - 1;
	if (write_cnt >= 0) {
		rc = sendfile(connected_fd, file_fd, &offset, write_cnt + 1);
		if (rc == -1)
			err_sys_die(EXIT_FAILNET, "Failure in sendfile routine");
		 tx_calls++;
	}

	if (offset != filesize)
		err_msg_die(EXIT_FAILNET, "Incomplete transfer from sendfile: %d of %ld bytes",
					offset , filesize);

	pr_debug("transmitted %d bytes with %d calls via sendfile()",
			 filesize, tx_calls);

	return rc;
}

static int srv_open_active_connection(struct ctx *ctx, const char *hostname)
{
	char sport[16];
	int ret, fd = -1;
	struct addrinfo hosthints, *hostres, *addrtmp;
	struct protoent *protoent;

	snprintf(sport, sizeof(sport) - 1, "%d", ctx->srv_cl_request_info.port);

	memset(&hosthints, 0, sizeof(struct addrinfo));

	hosthints.ai_family   = AF_UNSPEC;
	hosthints.ai_socktype = SOCK_STREAM;
	hosthints.ai_protocol = IPPROTO_TCP;
	hosthints.ai_flags    = AI_ADDRCONFIG;

	xgetaddrinfo(hostname, sport, &hosthints, &hostres);

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {

		fd = socket(addrtmp->ai_family, addrtmp->ai_socktype, addrtmp->ai_protocol);
		if (fd < 0)
			continue;

		protoent = getprotobynumber(addrtmp->ai_protocol);
		if (protoent)
			pr_debug("socket created - protocol %s(%d)",
					protoent->p_name, protoent->p_proto);

		ret = connect(fd, addrtmp->ai_addr, addrtmp->ai_addrlen);
		if (ret == -1)
			err_sys_die(EXIT_FAILNET, "Can't connect to %s", hostname);

		/* great, found a valuable socket */
		break;
	}

	if (fd < 0)
		err_msg_die(EXIT_FAILNET,
				"Don't found a suitable TCP socket to connect to the client"
				", giving up");

	freeaddrinfo(hostres);

	pr_debug("open a active TCP socket on port %s to transmit this file", sport);

	return fd;
}


static void srv_tx_file(struct ctx *ctx)
{
	int file_fd, net_fd;
	char peer[1024], portstr[8];

	xgetnameinfo((struct sockaddr *)&ctx->srv_cl_addr_info.ss,
			ctx->srv_cl_addr_info.ss_len, peer,
			sizeof(peer), portstr, sizeof(portstr),
			NI_NUMERICSERV | NI_NUMERICHOST);

	pr_debug("received file request pdu from %s:%s", peer, portstr);
	pr_debug("client wait for data at TCP port %d", ctx->srv_cl_request_info.port);

	file_fd = ctx->srv_file_hndl.fd;

	net_fd = srv_open_active_connection(ctx, peer);
	if (net_fd < 0) {
		close(file_fd);
		err_msg("cannot open a TCP connection to the peer, ignoring this client");
	}

	xsendfile(ctx, net_fd, file_fd);

	close(net_fd);
	close(file_fd);
}


static int srv_init_state(struct ctx *ctx)
{
	struct srv_state srv_state = ctx->srv_state;

	/* initialize random server cookie */
	srv_state.cookie = random();

	pr_debug("initialize random server cookie to %u",
			srv_state.cookie);

	return SUCCESS;
}



/* In server mode the program sends in regular interval
 * a UDP offer PDU to a well known multicast address.
 * If a client want to receive this data the client opens
 * a TCP socket and inform the server that he want this file,
 * we push this file to the server */
int server_mode(struct ctx *ctx)
{
	int pfd, afd, ret;
	int must_block = 0;
	const char *port, *filename;

	port = ctx->opts->port ?: DEFAULT_LISTEN_PORT;
	filename = ctx->opts->filename;

	pr_debug("netpp [server mode, serving file %s]", filename);

	ret = srv_init_file_hndl(ctx);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILFILE, "Cannot open and setup the file");

	ret = srv_init_state(ctx);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILMISC, "Cannot initialize server state");

	pfd = init_passive_socket(DEFAULT_V4_MULT_ADDR, port, must_block);
	afd = init_active_socket(DEFAULT_V4_MULT_ADDR, port);

	while (23) {

		ret = srv_tx_offer_pdu(ctx, afd);
		if (ret != SUCCESS) {
			err_msg_die(EXIT_FAILNET, "Failure in offer broadcast");
		}

		while (666) { /* handle all backloged client requests */
			ret = srv_try_rx_client_pdu(ctx, pfd);
			if (ret != SUCCESS)
				break;

			srv_tx_file(ctx);

			srv_reopen_file(ctx);
		}

		sleep(1);
	}

	close(ctx->srv_file_hndl.fd);
	close(afd);
	close(pfd);

	return EXIT_SUCCESS;
}

static void cl_print_srv_offer(const struct ctx *ctx)
{
	char peer[1024], portstr[8];
	uint32_t filesize = ctx->cl_offer_info.file_size;
	const char *prefix; int divisor; double pretty_filesize;

	if (filesize > 1024 * 1024 * 1024) {
		prefix  = "GiB";
		divisor = 1024 * 1024 * 1024;
	} else if (filesize > 1024 * 1024) {
		prefix  = "MiB";
		divisor = 1024 * 1024;
	} else if (filesize > 1024) {
		prefix  = "KiB";
		divisor = 1024;
	} else {
		prefix  = "";
		divisor = 1;
	}

	pretty_filesize = (double)filesize / divisor;

	xgetnameinfo((struct sockaddr *)&ctx->cl_srv_addr_info.ss,
			ctx->cl_srv_addr_info.ss_len, peer,
			sizeof(peer), portstr, sizeof(portstr),
			NI_NUMERICSERV | NI_NUMERICHOST);

	fprintf(stdout, "host %s provide a offer for file \"%s\" of size %.2lf %s\n",
			peer, ctx->cl_offer_info.filename, pretty_filesize, prefix);
}


static int client_try_read_offer_pdu(struct ctx *ctx, int pfd)
{
	ssize_t ret;
	char rx_buf[RX_BUF];

	ctx->cl_srv_addr_info.ss_len = sizeof(ctx->cl_srv_addr_info.ss);

	ret = recvfrom(pfd, rx_buf, RX_BUF, 0,
			(struct sockaddr *)&ctx->cl_srv_addr_info.ss, &ctx->cl_srv_addr_info.ss_len);
	if (ret < 0) {
		err_sys_die(EXIT_FAILNET, "failed to read()");
	}

	pr_debug("received %u byte from server", ret);

	ret = decode_offer_pdu(ctx, rx_buf, ret);
	if (ret != SUCCESS) {
		pr_debug("server offer pdu does not match our exception, igoring it");
		return FAILURE;
	}

	cl_print_srv_offer(ctx);

	return SUCCESS;
}


/* follow IANA suggestions */
#define	EPHEMERAL_PORT_MIN 49152
#define	EPHEMERAL_PORT_MAX 65534

static uint16_t dice_a_port(void)
{
	return (random() % (EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN)) + EPHEMERAL_PORT_MIN;
}


#define	DEFAULT_TCP_BACKLOG 6

static int client_open_stream_sink(uint16_t *port, int *lfd)
{
	int ret, fd = -1, on = 1;
	const char *hostname = NULL;
	struct addrinfo hosthints, *hostres, *addrtmp;
	uint16_t tport; char sport[16];

	tport = dice_a_port();
	snprintf(sport, sizeof(sport) - 1, "%d", tport);

	memset(&hosthints, 0, sizeof(struct addrinfo));

	hosthints.ai_family   = AF_UNSPEC;
	hosthints.ai_socktype = SOCK_STREAM;
	hosthints.ai_protocol = IPPROTO_TCP;
	hosthints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG;

	xgetaddrinfo(hostname, sport, &hosthints, &hostres);

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {

		fd = socket(addrtmp->ai_family, addrtmp->ai_socktype, addrtmp->ai_protocol);
		if (fd < 0)
			continue;

		xsetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on), "SO_REUSEADDR");

		ret = bind(fd, addrtmp->ai_addr, addrtmp->ai_addrlen);
		if (ret) {
			err_sys("failed to bind TCP socket");
			close(fd);
			fd = -1;
			continue;
		}

		ret = listen(fd, DEFAULT_TCP_BACKLOG);
		if (ret < 0) {
			err_sys("failed to call listen for TCP socket");
			close(fd);
			fd = -1;
			continue;
		}

		/* great, found a valuable socket */
		break;
	}

	if (fd < 0)
		err_msg_die(EXIT_FAILNET, "Don't found a suitable address for binding"
					"the TCP socket, giving up");

	freeaddrinfo(hostres);

	pr_debug("open a passive TCP socket on port %s to receive this file", sport);

	/* fill return arguments */
	*port = tport;
	*lfd  = fd;

	return SUCCESS;
}


static int client_inform_server(const struct ctx *ctx, int afd, uint16_t port)
{
	ssize_t ret;
	struct request_pdu_hdr request_pdu_hdr;

	(void) ctx;

	memset(&request_pdu_hdr, 0, sizeof(request_pdu_hdr));

	request_pdu_hdr.port = htons(port);

	/* send a message to ctx->cl_srv_addr_info.ss */
	ret = write(afd, &request_pdu_hdr, sizeof(request_pdu_hdr));
	if (ret == -1 && !(errno == EWOULDBLOCK)) {
		err_sys_die(EXIT_FAILNET, "Cannot send offer message");
	}

	return SUCCESS;
}

static int client_wait_for_accept(int fd)
{
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof(sa);
	char peer[1024], portstr[8];
	int connected_fd = -1;

	connected_fd = accept(fd, (struct sockaddr *) &sa, &sa_len);
	if (connected_fd == -1)
		err_sys_die(EXIT_FAILNET, "accept");

	xgetnameinfo((struct sockaddr *)&sa, sa_len, peer,
			sizeof(peer), portstr, sizeof(portstr), NI_NUMERICSERV|NI_NUMERICHOST);


	pr_debug("accept connection from host %s via remote port %s", peer, portstr);

	return connected_fd;
}

static int client_read_and_save_file(struct ctx *ctx, int fd)
{
	int ret, buflen;
	char *buf;
	ssize_t rc;
	unsigned long rx_calls, rx_bytes, chunks;
	int i = 1;

	rx_calls = rx_bytes = 0;

	/* allocate the RX buffer */
	buflen = ctx->opts->rx_buf_size;
	buf = xmalloc(ctx->opts->rx_buf_size);

	/* calculate the number of objects based on the announced
	 * file size and the actual RX buffer size */
	chunks = ctx->cl_offer_info.file_size / buflen;

	progress = start_progress("receiving file", chunks);

	while ((rc = read(fd, buf, buflen)) > 0) {
		rx_bytes += rc;
		do {
			ret = write(ctx->cl_file_hndl.fd, buf, rc);
		} while (ret == -1 && errno == EINTR);

		display_progress(progress, i++);
		display_throughput(progress, rx_bytes);

		if (ret != rc) {
			err_sys("write failed");
			break;
		}
	}

	stop_progress(&progress);

	close(ctx->cl_file_hndl.fd);

	free(buf);

	return SUCCESS;
}


static int client_rx_file(struct ctx *ctx, int fd)
{
	int connected_fd;

	/* block until the server connect to our socket */
	connected_fd = client_wait_for_accept(fd);

	/* read the file from the new filedescriptor */
	client_read_and_save_file(ctx, connected_fd);

	close(connected_fd);

	return SUCCESS;
}


static int cli_rx_file(struct ctx *ctx, int afd)
{
	int ret, fd;
	uint16_t port;

	/* open a passive TCP socket as the file sink */
	ret = client_open_stream_sink(&port, &fd);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILNET, "Failed to create TCP socket");
	}

	/* inform the server about the newly created connection */
	ret = client_inform_server(ctx, afd, port);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILNET, "Can't inform the server, upps!");
	}

	/* finally receive the file */
	ret = client_rx_file(ctx, fd);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILNET, "Can't receive the file, strange");
	}

	/* close recently created server port */
	close(fd);

	/* and exit the program gracefully */
	return EXIT_SUCCESS;
}

static int cli_open_file_sink(struct ctx *ctx)
{
	int ret;
	struct stat statbuf;
	const char *remote_filename = ctx->cl_offer_info.filename;
	const char *force_new_filename = ctx->opts->outfilename;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP;

	if (force_new_filename) {
		/* regardless if the file is already present, we
		 * will overide the old content whitout any warning
		 * message. If the user use the "-o" option then
		 * he is a professional user[TM] */
		ctx->cl_file_hndl.fd = open(force_new_filename, O_WRONLY | O_CREAT, mode);
		if (ctx->cl_file_hndl.fd < 0) {
			err_sys_die(EXIT_FAILFILE, "Cannot open file %s for writing",
					force_new_filename);
		}
		return SUCCESS;
	}

	/* now look if this file is already in the current
	 * working directory */
	ret = stat(remote_filename, &statbuf);
	if (ret == 0)
		err_msg_die(EXIT_FAILMISC, "remote file \"%s\" already present!"
				" Please rename the old file or use the option -o"
				" <out-filename to specify an alternative filename",
				remote_filename);

	ctx->cl_file_hndl.fd = open(remote_filename, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (ctx->cl_file_hndl.fd < 0) {
		err_sys_die(EXIT_FAILFILE, "Cannot open file %s for writing",
				force_new_filename);
	}

	return SUCCESS;
}


/* client open a passive multicast socket and
 * wait for server file offer. If the server
 * offer a file the client opens a random TCP port,
 * send this port to the server and waits for the data */
int client_mode(struct ctx *ctx)
{
	int pfd, afd, ret, must_block = 1;
	const char *port = ctx->opts->port ?: DEFAULT_LISTEN_PORT;

	pr_debug("netpp [client mode]");

	pfd = init_passive_socket(DEFAULT_V4_MULT_ADDR, port, must_block);
	afd = init_active_socket(DEFAULT_V4_MULT_ADDR, port);

	while (23) {
		pr_debug("wait to receive a valid offer message from a server");

		/* block until we receive a offer pdu */
		ret = client_try_read_offer_pdu(ctx, pfd);
		if (ret != SUCCESS)
			continue;

		/* fine, we received a valid offer! We will
		 * now open a passice TCP socket, announce this
		 * port to the server and wait for the file from
		 * the server. But first we will open the filesink
		 * where we store the new data */
		ret = cli_open_file_sink(ctx);
		if (ret != SUCCESS) {
			pr_debug("failure in open the data sink");
		}

		ret = cli_rx_file(ctx, afd);
		if (ret == SUCCESS) {
			pr_debug("file transfer completed, exiting now");
			break;
		}
	}

	close(pfd);

	return EXIT_SUCCESS;
}


struct ctx *init_ctx(void)
{
	struct ctx *ctx;

	ctx = xzalloc(sizeof(*ctx));
	ctx->opts = xzalloc(sizeof(*ctx->opts));

	return ctx;
}

void free_ctx(struct ctx *c)
{
	switch (c->mode) {
		case MODE_SERVER:
			close(c->srv_file_hndl.fd);
			break;
		case MODE_CLIENT:
			break;
		default:
			err_msg_die(EXIT_FAILINT, "Internal error in switch/case statement");
			break;
	};

	if (c->cl_offer_info.filename)
		free(c->cl_offer_info.filename);

	free(c->opts); free(c);
}


int main(int ac, char **av)
{
	int c, ret, error;
	struct ctx *ctx;

	ret = initiate_seed();
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILMISC, "Cannot initialize random seed");

	umask(0);

	ctx = init_ctx();

	/* opts defaults */
	ctx->opts->wanted_af_family = PF_UNSPEC;
	ctx->opts->me = xstrdup(av[0]);
	ctx->opts->rx_buf_size = DEFAULT_RX_BUF_SIZE;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"help",            0, 0, 'h'},
			{"ipv4",            0, 0, '4'},
			{"ipv6",            0, 0, '6'},
			{"port",            0, 0, 'p'},
			{"output",          0, 0, 'o'},
			{0, 0, 0, 0}
		};

		c = getopt_long(ac, av, "o:b:p:h46",
						long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case '4':
				ctx->opts->wanted_af_family = PF_INET;
				break;
			case '6':
				ctx->opts->wanted_af_family = PF_INET6;
				break;
			case 'p':
				ctx->opts->port = xstrdup(optarg);
				break;
			case 'o':
				ctx->opts->outfilename = xstrdup(optarg);
				break;
			case 'b':
				ctx->opts->rx_buf_size = xatoi(optarg);
				if (ctx->opts->rx_buf_size < 1)
					err_msg_die(EXIT_FAILOPT, "Buffer size should at least bigger then 0");
				break;
			case 'h':
				usage(ctx->opts->me);
				error = EXIT_SUCCESS;
				goto out_client;
				break;
			case '?':
				error = EXIT_FAILOPT;
				goto out_client;
				break;
			default:
				fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
				break;
		}
	}

	if (optind >= ac) {
		/* FIXME: catch the case where more files are given */
		ctx->mode = MODE_CLIENT;
		error = client_mode(ctx);
		goto out_client;
	}

	ctx->opts->filename = xstrdup(av[optind]);

	ctx->mode = MODE_SERVER;
	error = server_mode(ctx);
	goto out_server;

out_server:
	free(ctx->opts->filename);
out_client:
	if (ctx->opts->port)
		free(ctx->opts->port);
	free(ctx->opts->me);
	return error;
}

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
