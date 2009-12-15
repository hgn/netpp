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

#define EXIT_OK         EXIT_SUCCESS
#define EXIT_FAILMEM    1
#define EXIT_FAILOPT    2
#define EXIT_FAILMISC   3
#define EXIT_FAILNET    4
#define EXIT_FAILHEADER 6
#define EXIT_FAILEVENT  7
#define EXIT_FAILFILE   8
#define EXIT_FAILINT    9 /* INTernal error */

/* determine the size of an array */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define SUCCESS 0
#define FAILURE -1

#define RANDPOOLSRC "/dev/urandom"

#define MAXERRMSG 1024

struct opts {
	int wanted_af_family;
	char *me;
	char *port;
	char *filename;
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
	int     errno_save;
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

#define	LISTENADDRESS "224.110.99.112"
#define DEFAULT_LISTEN_PORT "6666"

static void usage(const char *me)
{
	fprintf(stdout, "%s (-4|-6) [filename]\n",
			me);
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

		ret = getnameinfo(addrtmp->ai_addr, addrtmp->ai_addrlen,
						addr_name, sizeof(addr_name), NULL, 0,
						NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret) {
			err_msg("failure for getnameinfo: %d ", ret);
		}

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

struct client_message {
	uint16_t port;
};

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

	set_non_blocking(sock);

	return sock;
}

struct srv_announce_data {
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

static int decode_announce_pdu(char *pdu, size_t pdu_len, struct srv_announce_data **sad)
{
	char *ptr = pdu;
	struct srv_announce_data *sadt;

	if (pdu_len < 4 + 4 + 1) {
		pr_debug("announced file should be at least one character in name");
		return FAILURE;
	}

	sadt = xzalloc(sizeof(*sadt));

	TLV_READ4(ptr, sadt->size);
	sadt->size = ntohl(sadt->size);
	pr_debug("announced file size: %u bytes", sadt->size);

	TLV_READ4(ptr, sadt->filename_len);
	sadt->filename_len = ntohl(sadt->filename_len);
	pr_debug("announced file len: %u bytes", sadt->filename_len);

	if (pdu_len < 4 + 4 + sadt->filename_len) {
		pr_debug("announced filename is %u bytes but transmitted only %u",
				  sadt->filename_len, pdu_len - 4 - 4);
		free(sadt);
		return FAILURE;
	}

	sadt->name = xstrdup(ptr);

	*sad = sadt;

	return SUCCESS;
}

static void free_srv_announce_data(struct srv_announce_data *s)
{
	assert(s && s->name);

	free(s->name); free(s);
}

static size_t encode_announce_pdu(unsigned char *pdu,
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

#define	ANNOUNCE_PDU_LEN_MAX 512

static int srv_tx_announce_pdu(int fd, const struct file_hndl *file_hndl)
{
	ssize_t ret; size_t len;
	unsigned char buf[ANNOUNCE_PDU_LEN_MAX];

	memset(buf, 0, sizeof(buf));

	len = encode_announce_pdu(buf, ANNOUNCE_PDU_LEN_MAX, file_hndl);

	ret = write(fd, buf, len);
	if (ret == -1 && !(errno == EWOULDBLOCK)) {
		err_sys_die(EXIT_FAILNET, "Cannot send announcement message");
	}

	return SUCCESS;
}

#define	RX_BUF 512

struct client_request_info {
	struct sockaddr_storage sa_storage;
	ssize_t ss_len;
	struct client_message client_message;
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

	if (ret != sizeof(struct client_message)) {
		pr_debug("received a answer that do not match "
				"our expectations, (is %d, should %d) ignoring it",
				ret, sizeof(struct client_message));
		return FAILURE;
	}

	client_request_info = xzalloc(sizeof(*client_request_info));
	memcpy(&client_request_info->client_message,
		   rx_buf, sizeof(struct client_message));
	client_request_info->ss_len = ss_len;

	/* convert message into host byte order */
	client_request_info->client_message.port =
		htons(client_request_info->client_message.port);

	*cri = client_request_info;

	pr_debug("client requested to open a new TCP data socket on port %u",
			  client_request_info->client_message.port);

	return SUCCESS;
}

static void free_client_request_info(struct client_request_info *c)
{
	free(c);
}

static void srv_tx_file(const struct client_request_info *cri, const char *file)
{
	int ret;
	char peer[1024], portstr[8];

	(void) file;

	ret = getnameinfo((struct sockaddr *)&cri->sa_storage, cri->ss_len, peer,
					  sizeof(peer), portstr, sizeof(portstr), NI_NUMERICSERV|NI_NUMERICHOST);

	pr_debug("accept from %s:%s", peer, portstr);
}

/* In server mode the program sends in regular interval
 * a UDP announcement PDU to a well known multicast address.
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

		ret = srv_tx_announce_pdu(afd, file_hndl);
		if (ret != SUCCESS) {
			err_msg_die(EXIT_FAILNET, "Failure in announcement broadcast");
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

struct srv_announcement_info {
	struct sockaddr_storage srv_ss;
	ssize_t server_ss_len;
	char *srv_announcement_pdu;
	size_t srv_announcement_pdu_len;
};

static int client_try_read_announcement_pdu(int pfd, struct srv_announcement_info **crl)
{
	ssize_t ret;
	char rx_buf[RX_BUF];
	struct sockaddr_storage ss;
	socklen_t ss_len = sizeof(ss);
	//struct srv_announcement_info *srv_announcement_info;
	struct srv_announce_data *sad;

	(void) crl;

	ret = recvfrom(pfd, rx_buf, RX_BUF, 0, (struct sockaddr *)&ss, &ss_len);
	if (ret < 0) {
		err_sys_die(EXIT_FAILNET, "failed to read()");
	}

	pr_debug("received %u byte from server", ret);

	ret = decode_announce_pdu(rx_buf, RX_BUF, &sad);
	if (ret != SUCCESS) {
		pr_debug("server announcement pdu does not match our exception, igoring it");
		return FAILURE;
	}

	free_srv_announce_data(sad);

	return SUCCESS;
}

/* client open a passive multicast socket and
 * wait for server file announcements. If the server
 * announce a file the client opens a random TCP port,
 * send this port to the server and waits for the data */
int client_mode(const struct opts *opts)
{
	int pfd, ret;
	struct srv_announcement_info *sai;
	int must_block = 1;
	const char *port = opts->port ?: DEFAULT_LISTEN_PORT;

	(void) opts;

	pr_debug("netpp [client mode]");

	pfd = init_passive_socket(LISTENADDRESS, port, must_block);

	while (23) {
		ret = client_try_read_announcement_pdu(pfd, &sai);
		if (ret != SUCCESS)
			continue;

		/* fine, we got a valid announcement! :-) */
	}

#if 0

	while (23) {

		annouce_pdu = client_try_read_announcement_pdu(pfd);
		if (annouce_pdu) { /* got a proper file announcement */

			/* open a passive TCP socket as the file sink */
			ret = client_open_stream_sink(&client_data);
			if (ret != SUCCESS) {
				err_msg_die(EXIT_FAILNET, "Failed to create TCP socket");
			}

			/* inform the server about the newly created connection */
			ret = client_inform_server(&client_data);
			if (ret != SUCCESS) {
				err_msg_die(EXIT_FAILNET, "Can't inform the server, upps!");
			}

			/* finaly receive the file */
			ret = client_rx_file(&client_data, annouce_pdu);
			if (ret != SUCCESS) {
				err_msg_die(EXIT_FAILNET, "Can't receive the file, strange");
			}

			client_close_sink(&client_data);

			/* and exit the program gracefully */
			return EXIT_SUCCESS;
		}
		sleep(1); /* nothing to do, sleep a moment */
	}

#endif

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
		/* FIXME: handle the case where more files are given */
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

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet cino=(0: */
