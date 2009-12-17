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

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <sys/sendfile.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <limits.h>
#include <netdb.h>
#include <stdarg.h>

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
        } while (0)

#define pr_debug(format, args...) \
        do { \
                if (DEBUG) \
                        msg(format, ##args); \
		} while (0)

/* determine the size of an array */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

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

#define	LISTENADDRESS "224.110.99.112"
#define DEFAULT_LISTEN_PORT "6666"

struct opts {
	int wanted_af_family;
	char *me;
	char *port;
	char *filename;
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
	char filename[0]; /* must end on a 4 byte boundary */
} __attribute__((packed));

/* this message is sent from the client to the
 * server and signals that the client received
 * correctly a offer pdu, opens a passive TCP socket
 * on port port and is now ready to receive the file */
struct request_pdu_hdr {
	uint16_t port;
} __attribute__((packed));


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
		snprintf(buf + len,  sizeof buf - len, " (%s)", strerror(errno_save));
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
	va_list         ap;

	va_start(ap, fmt);
	err_doit(1, file, line_no, fmt, ap);
	va_end(ap);
}


static void * xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (!ptr)
		err_msg_die(EXIT_FAILMEM, "Out of mem: %s!\n", strerror(errno));
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
	int ret;

	ret = getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
	if (unlikely((ret != 0))) {
		err_msg_die(EXIT_FAILNET, "Call to getnameinfo() failed: %s!\n",
				(ret == EAI_SYSTEM) ?  strerror(errno) : gai_strerror(ret));

	}
}

static void usage(const char *me)
{
	fprintf(stdout, "%s (-4|-6) (-p <port>) [filename]\n", me);
}


static void enable_multicast_v4(int fd, const struct addrinfo *a)
{
	int on = 1;
	struct ip_mreq mreq;

	memset(&mreq, 0, sizeof(struct ip_mreq));
	memcpy(&mreq.imr_multiaddr, &(((struct sockaddr_in *)a->ai_addr)->sin_addr), sizeof(struct in_addr));
	mreq.imr_interface.s_addr = INADDR_ANY;

	xsetsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(int), "IP_MULTICAST_LOOP");
	pr_debug("set IP_MULTICAST_LOOP option");

	xsetsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq), "IP_ADD_MEMBERSHIP");
	pr_debug("add membership to IPv4 multicast group");
}


static void enable_multicast_v6(int fd, const struct addrinfo *a)
{
	int on = 1;
	struct ipv6_mreq mreq6;

	memset(&mreq6, 0, sizeof(struct ipv6_mreq));

	memcpy(&mreq6.ipv6mr_multiaddr, &(((struct sockaddr_in6 *)a->ai_addr)->sin6_addr), sizeof(struct in6_addr));
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

	xsetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on), "SO_REUSEADDR");

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
	int fd = -1, ret;
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


struct file_hndl {
	const char *name;
	off_t size;
};


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


static struct file_hndl *init_file_hndl(const char *filename)
{
	int ret;
	struct file_hndl *file_hndl;
	struct stat statb;

	file_hndl = xzalloc(sizeof(*file_hndl));

	file_hndl->name = filename;

	ret = stat(filename, &statb);
	if (ret < 0) {
		err_sys_die(EXIT_FAILFILE, "Cannot open file %s!", filename);
	}

	file_hndl->size = statb.st_size;

	pr_debug("serving file %s of size %u byte", filename, file_hndl->size);

	if (!S_ISREG(statb.st_mode)) {
		err_msg_die(EXIT_FAILFILE, "File %s is no regular file, giving up!", filename);
	}

	return file_hndl;
}


static void free_file_hndl(struct file_hndl *file_hndl)
{
	free(file_hndl);
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

	/* XXX: is this required here */
	set_non_blocking(sock);

	return sock;
}

struct srv_offer_data {
	uint32_t size;
	uint32_t filename_len;
	char *name;
};


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

static int decode_offer_pdu(char *pdu, size_t pdu_len, struct srv_offer_data **sad)
{
	char *ptr = pdu;
	struct srv_offer_data *sadt;

	if (pdu_len < 4 + 4 + 1) {
		pr_debug("offered file should be at least one character in name");
		return FAILURE;
	}

	sadt = xzalloc(sizeof(*sadt));

	TLV_READ4(ptr, sadt->size);
	sadt->size = ntohl(sadt->size);

	TLV_READ4(ptr, sadt->filename_len);
	sadt->filename_len = ntohl(sadt->filename_len);

	if (pdu_len < 4 + 4 + sadt->filename_len) {
		pr_debug("offered filename is %u bytes but transmitted only %u",
				  sadt->filename_len, pdu_len - 4 - 4);
		free(sadt);
		return FAILURE;
	}

	pr_debug("offered file \"%s\", filesize: %u bytes", ptr, sadt->size);

	sadt->name = xstrdup(ptr);

	*sad = sadt;

	return SUCCESS;
}


static void free_srv_offer_data(struct srv_offer_data *s)
{
	assert(s && s->name);
	free(s->name); free(s);
}


static size_t encode_offer_pdu(unsigned char *pdu,
		size_t max_pdu_len, const struct file_hndl *file_hndl)
{
	unsigned char *ptr = pdu;
	size_t len = 0;


	TLV_WRITE4(ptr, htonl(file_hndl->size));
	len += 4;

	TLV_WRITE4(ptr, htonl(strlen(file_hndl->name) + 1));
	len += 4;

	if (strlen(file_hndl->name) + 1 >= max_pdu_len - len) {
		err_msg_die(EXIT_FAILINT, "remaining buffer (%d byte) to small to "
				"transmit filename (%d byte)!",
				max_pdu_len - len, strlen(file_hndl->name));
	}

	memcpy(ptr, file_hndl->name, strlen(file_hndl->name) + 1);

	len += strlen(file_hndl->name) + 1;

	return len;
}


#define	OFFER_PDU_LEN_MAX 512

static int srv_tx_offer_pdu(int fd, const struct file_hndl *file_hndl)
{
	ssize_t ret; size_t len;
	unsigned char buf[OFFER_PDU_LEN_MAX];

	memset(buf, 0, sizeof(buf));

	len = encode_offer_pdu(buf, OFFER_PDU_LEN_MAX, file_hndl);

	ret = write(fd, buf, len);
	if (ret == -1 && !(errno == EWOULDBLOCK)) {
		err_sys_die(EXIT_FAILNET, "Cannot send offer message");
	}

	return SUCCESS;
}

#define	RX_BUF 512

struct client_request_info {
	struct sockaddr_storage sa_storage;
	ssize_t ss_len;
	struct request_pdu_hdr request_pdu_hdr;
};


static int srv_try_rx_client_pdu(int pfd, struct client_request_info **cri)
{
	ssize_t ret;
	unsigned char rx_buf[RX_BUF];
	struct sockaddr_storage ss;
	socklen_t ss_len = sizeof(ss);
	struct client_request_info *client_request_info;

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

	client_request_info = xzalloc(sizeof(*client_request_info));

	/* save client request message */
	memcpy(&client_request_info->request_pdu_hdr,
		   rx_buf, sizeof(struct request_pdu_hdr));

	/* save client address */
	client_request_info->ss_len = ss_len;
	memcpy(&client_request_info->sa_storage, &ss,
		   sizeof(client_request_info->sa_storage));

	/* convert message into host byte order */
	client_request_info->request_pdu_hdr.port =
		htons(client_request_info->request_pdu_hdr.port);

	*cri = client_request_info;

	pr_debug("client requested to open a new TCP data socket on port %u",
			  client_request_info->request_pdu_hdr.port);

	return SUCCESS;
}


static void free_client_request_info(struct client_request_info *c)
{
	free(c);
}

static ssize_t xsendfile(int connected_fd, int file_fd, struct stat *stat_buf)
{
	ssize_t rc, write_cnt;
	off_t offset = 0;
	int tx_calls = 0;

	pr_debug("now try to transfer the file to the peer");

	write_cnt = stat_buf->st_size;

	while (stat_buf->st_size - offset - 1 >= write_cnt) {
		rc = sendfile(connected_fd, file_fd, &offset, write_cnt);
		if (rc == -1)
			err_sys_die(EXIT_FAILNET, "Failure in sendfile routine");
		tx_calls++;
	}
	/* and write remaining bytes, if any */
	write_cnt = stat_buf->st_size - offset - 1;
	if (write_cnt >= 0) {
		rc = sendfile(connected_fd, file_fd, &offset, write_cnt + 1);
		if (rc == -1)
			err_sys_die(EXIT_FAILNET, "Failure in sendfile routine");
		 tx_calls++;
	}

	if (offset != stat_buf->st_size)
		err_msg_die(EXIT_FAILNET, "Incomplete transfer from sendfile: %d of %ld bytes",
					offset , stat_buf->st_size);

	pr_debug("transmitted %d bytes with %d calls via sendfile()",
			 stat_buf->st_size, tx_calls);

	return rc;
}

static int srv_open_active_connection(const char *hostname,
		const struct client_request_info *cri)
{
	int ret, fd = -1, on = 1;
	struct addrinfo hosthints, *hostres, *addrtmp;
	uint16_t tport; char sport[16];
	struct protoent *protoent;

	snprintf(sport, sizeof(sport) - 1, "%d", cri->request_pdu_hdr.port);

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
				"Don't found a suitable socket to connect to the client"
				" TCP socket, giving up");

	freeaddrinfo(hostres);

	pr_debug("open a active TCP socket on port %s to transmit this file", sport);

	return fd;
}

static int srv_open_file(const char *file)
{
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		err_sys("cannot open file %s", file);
		return FAILURE;
	}

	return fd;
}

static void srv_tx_file(const struct client_request_info *cri, const char *file)
{
	int ret, file_fd, net_fd;
	char peer[1024], portstr[8];
	struct stat stat_buf;


	(void) file;

	xgetnameinfo((struct sockaddr *)&cri->sa_storage, cri->ss_len, peer,
			sizeof(peer), portstr, sizeof(portstr),
			NI_NUMERICSERV | NI_NUMERICHOST);

	pr_debug("received file request pdu from %s:%s", peer, portstr);
	pr_debug("client wait for data at TCP port %d", cri->request_pdu_hdr.port);

	file_fd = srv_open_file(file);
	if (file_fd < 0)
		return;

	net_fd = srv_open_active_connection(peer, cri);
	if (net_fd < 0) {
		close(file_fd);
		err_msg("cannot open a TCP connection to the peer, ignoring this client");
	}

	xfstat(file_fd, &stat_buf, file);

	ret = xsendfile(net_fd, file_fd, &stat_buf); // XXX, catch error

	close(net_fd);
	close(file_fd);
}


/* In server mode the program sends in regular interval
 * a UDP offer PDU to a well known multicast address.
 * If a client want to receive this data the client opens
 * a TCP socket and inform the server that he want this file,
 * we push this file to the server */
int server_mode(const struct opts *opts)
{
	int pfd, afd, ret;
	struct client_request_info *client_request_info;
	struct file_hndl *file_hndl;
	int must_block = 0;
	const char *port = opts->port ?: DEFAULT_LISTEN_PORT;

	pr_debug("netpp [server mode, serving file %s]", opts->filename);

	file_hndl = init_file_hndl(opts->filename);

	pfd = init_passive_socket(LISTENADDRESS, port, must_block);
	afd = init_active_socket(LISTENADDRESS, port);


	while (23) {

		ret = srv_tx_offer_pdu(afd, file_hndl);
		if (ret != SUCCESS) {
			err_msg_die(EXIT_FAILNET, "Failure in offer broadcast");
		}

		while (666) { /* handle all backloged client requests */
			ret = srv_try_rx_client_pdu(pfd, &client_request_info);
			if (ret != SUCCESS)
				break;

			srv_tx_file(client_request_info, opts->filename);

			free_client_request_info(client_request_info);
		}

		sleep(1);
	}

	free_file_hndl(file_hndl);
	close(pfd);

	return EXIT_SUCCESS;
}

struct srv_offer_info {
	struct sockaddr_storage srv_ss;
	ssize_t server_ss_len;
	char *srv_offer_pdu;
	size_t srv_offer_pdu_len;
};


static int client_try_read_offer_pdu(int pfd, struct srv_offer_info **crl)
{
	ssize_t ret;
	char rx_buf[RX_BUF];
	struct sockaddr_storage ss;
	socklen_t ss_len = sizeof(ss);
	struct srv_offer_data *sad;

	(void) crl;

	ret = recvfrom(pfd, rx_buf, RX_BUF, 0, (struct sockaddr *)&ss, &ss_len);
	if (ret < 0) {
		err_sys_die(EXIT_FAILNET, "failed to read()");
	}

	pr_debug("received %u byte from server", ret);

	ret = decode_offer_pdu(rx_buf, ret, &sad);
	if (ret != SUCCESS) {
		pr_debug("server offer pdu does not match our exception, igoring it");
		return FAILURE;
	}

	free_srv_offer_data(sad);

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


static int client_inform_server(const struct srv_offer_info *sai, int afd, uint16_t port)
{
	ssize_t ret;
	struct request_pdu_hdr request_pdu_hdr;

	memset(&request_pdu_hdr, 0, sizeof(request_pdu_hdr));

	request_pdu_hdr.port = htons(port);

	/* send a mesage to sai */
	ret = write(afd, &request_pdu_hdr, sizeof(request_pdu_hdr));
	if (ret == -1 && !(errno == EWOULDBLOCK)) {
		err_sys_die(EXIT_FAILNET, "Cannot send offer message");
	}

	return SUCCESS;
}

static int client_wait_for_accept(int fd)
{
	int ret;
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof(sa);
	char peer[1024], portstr[8];
	int connected_fd = -1;

	connected_fd = accept(fd, (struct sockaddr *) &sa, &sa_len);
	if (connected_fd == -1)
		err_sys_die(EXIT_FAILNET, "accept");

	ret = getnameinfo((struct sockaddr *)&sa, sa_len, peer,
			sizeof(peer), portstr, sizeof(portstr), NI_NUMERICSERV|NI_NUMERICHOST);
	if (ret != 0)
		err_msg("getnameinfo error: %s",  gai_strerror(ret));


	pr_debug("accept connection from host %s via remote port %s", peer, portstr);

	return connected_fd;
}

static int client_read_and_save_file(const struct srv_offer_info *sai, int fd)
{
	int buflen; // XXX: make this configurable
	char *buf;
	ssize_t rc;
	unsigned long rx_calls = 0;
	unsigned long rx_bytes = 0;

	buflen = 2048;

	buf = xmalloc(buflen);

	while ((rc = read(fd, buf, buflen)) > 0) {
		ssize_t ret;
		rx_calls++;
		rx_bytes += rc;
		do {
			ret = write(STDOUT_FILENO, buf, rc);
		} while (ret == -1 && errno == EINTR);

		if (ret != rc) {
			err_sys("write failed");
			break;
		}
	}

	free(buf);

	return SUCCESS;
}


static int client_rx_file(const struct srv_offer_info *sai, int fd)
{
	int connected_fd;

	connected_fd = client_wait_for_accept(fd);

	client_read_and_save_file(sai, connected_fd);

	close(connected_fd);

	return SUCCESS;
}


static int cli_rx_file(const struct srv_offer_info *sai, int afd)
{
	uint16_t port;
	int ret, fd;

	/* open a passive TCP socket as the file sink */
	ret = client_open_stream_sink(&port, &fd);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILNET, "Failed to create TCP socket");
	}

	/* inform the server about the newly created connection */
	ret = client_inform_server(sai, afd, port);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILNET, "Can't inform the server, upps!");
	}

	/* finaly receive the file */
	ret = client_rx_file(sai, fd);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILNET, "Can't receive the file, strange");
	}

	/* close recently created server port */
	close(fd);

	/* and exit the program gracefully */
	return EXIT_SUCCESS;
}


/* client open a passive multicast socket and
 * wait for server file offer. If the server
 * offer a file the client opens a random TCP port,
 * send this port to the server and waits for the data */
int client_mode(const struct opts *opts)
{
	int pfd, afd, ret, must_block = 1;
	const char *port = opts->port ?: DEFAULT_LISTEN_PORT;

	pr_debug("netpp [client mode]");

	pfd = init_passive_socket(LISTENADDRESS, port, must_block);
	afd = init_active_socket(LISTENADDRESS, port);

	while (23) {
		struct srv_offer_info *sai; /* XXX: free this */

		pr_debug("wait to receive a valid offer message from a server");

		/* block until we receive a offer pdu */
		ret = client_try_read_offer_pdu(pfd, &sai);
		if (ret != SUCCESS)
			continue;

		/* fine, we received a valid offer! We will
		 * now open a passice TCP socket, announce this
		 * port to the server and wait for the file from
		 * the server. That's all ;) */
		ret = cli_rx_file(sai, afd);
		if (ret == SUCCESS) {
			pr_debug("file transfer completed, exiting now");
			break;
		}
	}

	close(pfd);

	return EXIT_SUCCESS;
}


int main(int ac, char **av)
{
	int c, ret, error;
	struct opts *opts;

	ret = initiate_seed();
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILMISC, "Cannot initialize random seed");

	opts = xzalloc(sizeof(*opts));

	/* opts defaults */
	opts->wanted_af_family = PF_UNSPEC;
	opts->me = xstrdup(av[0]);

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"help",            0, 0, 'h'},
			{"ipv4",            0, 0, '4'},
			{"ipv6",            0, 0, '6'},
			{"port",            0, 0, 'p'},
			{0, 0, 0, 0}
		};

		c = getopt_long(ac, av, "p:h46",
						long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case '4':
				opts->wanted_af_family = PF_INET;
				break;
			case '6':
				opts->wanted_af_family = PF_INET6;
				break;
			case 'p':
				opts->port = xstrdup(optarg);
				break;
			case 'h':
				usage(opts->me);
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
		error = client_mode(opts);
		goto out_client;
	}

	opts->filename = xstrdup(av[optind]);

	error = server_mode(opts);
	goto out_server;

out_server:
	free(opts->filename);
out_client:
	if (opts->port)
		free(opts->port);
	free(opts->me);
	free(opts);
	return error;
}

/* vim: set tw=78 ts=8 sw=8 sts=8 ff=unix noet: */
