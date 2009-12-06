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
#define EXIT_FAILINT    8 /* INTernal error */

/* determine the size of an array */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define SUCCESS 0
#define FAILURE -1

#define DEFAULT_LISTEN_PORT "6666"

#define RANDPOOLSRC "/dev/urandom"

#define MAXERRMSG 1024

static int subtime(struct timeval *op1, struct timeval *op2,
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
        if (ret != 0) {
                err_msg_die(EXIT_FAILNET, "Call to getaddrinfo() failed: %s!\n",
                                (ret == EAI_SYSTEM) ?  strerror(errno) : gai_strerror(ret));
        }

        return;
}

#define	LISTENADDRESS "224.110.99.112"
#define PORT "6666"

static void enable_multicast_v4(int fd, const char *hostname)
{
	int on = 1, ret;
	struct ip_mreq mreq;

	memset(&mreq, 0, sizeof(struct ip_mreq));

	ret = inet_pton(AF_INET, hostname, &mreq.imr_multiaddr);

	mreq.imr_interface.s_addr = INADDR_ANY;

	xsetsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(int), "IP_MULTICAST_LOOP");
	pr_debug("set IP_MULTICAST_LOOP option");

	xsetsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq), "IP_ADD_MEMBERSHIP");
	pr_debug("add membership to IPv4 multicast group");
}

static void enable_multicast_v6(int fd, const char *hostname)
{
	int on = 1, ret;
	struct ipv6_mreq mreq6;

	memset(&mreq6, 0, sizeof(struct ipv6_mreq));

	mreq6.ipv6mr_interface = 0; /* FIXME: interface missing */
	ret = inet_pton(AF_INET6, hostname, &mreq6.ipv6mr_multiaddr);

	xsetsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			&on, sizeof(int), "IPV6_MULTICAST_LOOP");
	pr_debug("set IPV6_MULTICAST_LOOP option");

	xsetsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			&mreq6, sizeof(struct ipv6_mreq), "IPV6_JOIN_GROUP");
	pr_debug("join IPv6 multicast group");

}

static int socket_bind(const struct addrinfo *a, const char *hostname)
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
			enable_multicast_v4(fd, hostname);
				break;
		case AF_INET6:
			enable_multicast_v6(fd, hostname);
		default:
			abort();
			break;
	}

	listen(fd, 5);

	return fd;
}

int init_passive_socket(const char *addr, const char *port, int use_ipv6)
{
	int fd = -1, ret;
	struct addrinfo hosthints, *hostres, *addrtmp;
	struct ip_mreq mreq;
	struct ipv6_mreq mreq6;

	memset(&hosthints, 0, sizeof(struct addrinfo));

	hosthints.ai_family   = AF_UNSPEC;
	hosthints.ai_socktype = SOCK_DGRAM;
	hosthints.ai_protocol = IPPROTO_UDP;
	hosthints.ai_flags    = AI_PASSIVE;

	/* probe our values */
	xgetaddrinfo(addr, port, &hosthints, &hostres);

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {

		fd = socket_bind(addrtmp, addr);
		if (fd < 0) {
			pr_debug("Cannot create a socket");
			continue;
		}

		break;
	}

	if (fd < 0) {
		err_msg_die(EXIT_FAILNET, "Cannot find a valid socket!\n");
	}


#if 0
	/* validate that the address is a valid multicast
	 * address */
	switch(hosthints.ai_family) {
		case AF_INET6:
			if (!IN6_IS_ADDR_MULTICAST(&mreq6.ipv6mr_multiaddr))
				err_msg_die(EXIT_FAILNET,
						"You didn't specify an valid IPv6 multicast address (%s)!",
						addr);
			mreq6.ipv6mr_interface = 0;
			break;
		case AF_INET:
			if (!IN_MULTICAST(ntohl(mreq.imr_multiaddr.s_addr)))
				err_msg_die(EXIT_FAILNET,
						"You didn't specify an valid IPv4 multicast address (%s)!",
						addr);
			mreq.imr_interface.s_addr = INADDR_ANY;
			break;
		default:
			abort();
			break;
	}
#endif

	return fd;

}


int main(void)
{
	int pfd, afd;

	pfd = init_passive_socket(LISTENADDRESS, PORT, 1);

	sleep(10);

	return EXIT_SUCCESS;
}

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
