//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_NET

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

static int
nni_plat_to_sockaddr(struct sockaddr_storage *ss, const nni_sockaddr *sa)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	switch (sa->s_un.s_family) {
	case NNG_AF_INET:
		sin = (void *) ss;
		memset(sin, 0, sizeof (*sin));
		sin->sin_family = PF_INET;
		sin->sin_port = sa->s_un.s_in.sa_port;
		sin->sin_addr.s_addr = sa->s_un.s_in.sa_addr;
		return (sizeof (*sin));

	case NNG_AF_INET6:
		sin6 = (void *) ss;
		memset(&sin6, 0, sizeof (sin6));
#ifdef  SIN6_LEN
		sin6->sin6_len = sizeof (*sin6);
#endif
		sin6->sin6_family = PF_INET6;
		sin6->sin6_port = sa->s_un.s_in6.sa_port;
		memcpy(sin6->sin6_addr.s6_addr, sa->s_un.s_in6.sa_addr, 16);
		return (sizeof (*sin6));
	}
	return (-1);
}


static int
nni_plat_from_sockaddr(nni_sockaddr *sa, const struct sockaddr *ss)
{
	const struct sockaddr_in *sin;
	const struct sockaddr_in6 *sin6;

	memset(sa, 0, sizeof (*sa));
	switch (ss->sa_family) {
	case PF_INET:
		sin = (const void *) ss;
		sa->s_un.s_in.sa_family = NNG_AF_INET;
		sa->s_un.s_in.sa_port = sin->sin_port;
		sa->s_un.s_in.sa_addr = sin->sin_addr.s_addr;
		return (0);

	case PF_INET6:
		sin6 = (const void *) ss;
		sa->s_un.s_in6.sa_family = NNG_AF_INET6;
		sa->s_un.s_in6.sa_port = sin6->sin6_port;
		memcpy(sa->s_un.s_in6.sa_addr, sin6->sin6_addr.s6_addr, 16);
		return (0);
	}
	return (-1);
}


int
nni_plat_lookup_host(const char *host, nni_sockaddr *addr, int flags)
{
	struct addrinfo hint;
	struct addrinfo *ai;

	memset(&hint, 0, sizeof (hint));
	hint.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	if (flags & NNI_FLAG_IPV4ONLY) {
		hint.ai_family = PF_INET;
	}

	if (getaddrinfo(host, NULL, &hint, &ai) != 0) {
		return (NNG_EADDRINVAL);
	}

	if (nni_plat_from_sockaddr(addr, ai->ai_addr) < 0) {
		freeaddrinfo(ai);
		return (NNG_EADDRINVAL);
	}
	freeaddrinfo(ai);
	return (0);
}


int
nni_plat_tcp_send(nni_plat_tcpsock *s, nni_iov *iovs, int cnt)
{
	struct iovec iov[4];    // We never have more than 3 at present
	int i;
	int offset;
	int resid = 0;
	int rv;

	if (cnt > 4) {
		return (NNG_EINVAL);
	}

	for (i = 0; i < cnt; i++) {
		iov[i].iov_base = iovs[i].iov_buf;
		iov[i].iov_len = iovs[i].iov_len;
		resid += iov[i].iov_len;
	}

	i = 0;
	while (resid) {
		rv = writev(s->fd, iov, cnt);
		if (rv < 0) {
			if (rv == EINTR) {
				continue;
			}
			return (nni_plat_errno(errno));
		}
		if (rv > resid) {
			nni_panic("writev says it wrote too much!");
		}
		resid -= rv;
		while (rv) {
			if (iov[i].iov_len <= rv) {
				rv -= iov[i].iov_len;
				i++;
				cnt--;
			} else {
				iov[i].iov_len -= rv;
				iov[i].iov_base += rv;
				rv = 0;
			}
		}
	}

	return (0);
}


int
nni_plat_tcp_recv(nni_plat_tcpsock *s, nni_iov *iovs, int cnt)
{
	struct iovec iov[4];    // We never have more than 3 at present
	int i;
	int offset;
	int resid = 0;
	int rv;

	if (cnt > 4) {
		return (NNG_EINVAL);
	}

	for (i = 0; i < cnt; i++) {
		iov[i].iov_base = iovs[i].iov_buf;
		iov[i].iov_len = iovs[i].iov_len;
		resid += iov[i].iov_len;
	}

	i = 0;
	while (resid) {
		rv = readv(s->fd, iov, cnt);
		if (rv < 0) {
			if (errno == EINTR) {
				continue;
			}
			return (nni_plat_errno(errno));
		}
		if (rv > resid) {
			nni_panic("readv says it read too much!");
		}

		resid -= rv;
		while (rv) {
			if (iov[i].iov_len <= rv) {
				rv -= iov[i].iov_len;
				i++;
				cnt--;
			} else {
				iov[i].iov_len -= rv;
				iov[i].iov_base += rv;
				rv = 0;
			}
		}
	}

	return (0);
}


static void
nni_plat_tcp_setopts(int fd)
{
	int one;

	// Try to ensure that both CLOEXEC is set, and that we don't
	// generate SIGPIPE.  (Note that SIGPIPE suppression in this way
	// only works on BSD systems.  Linux wants us to use sendmsg().)
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
#if defined(F_SETNOSIGPIPE)
	(void) fcntl(fd, F_SETNOSIGPIPE, 1);
#elif defined(SO_NOSIGPIPE)
	one = 1;
	(void) setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof (one));
#endif

	// Also disable Nagle.  We are careful to group data with writev,
	// and latency is king for most of our users.  (Consider adding
	// a method to enable this later.)
	one = 1;
	(void) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
}


void
nni_plat_tcp_close(nni_plat_tcpsock *s)
{
	(void) close(s->fd);
	s->fd = -1;
}

// nni_plat_tcp_bind creates a file descriptor bound to the given address.
// This basically does the equivalent of socket, bind, and listen.  We have
// chosen a default value for the listen backlog of 128, which should be
// plenty.  (If it isn't, then the accept thread can't get enough resources
// to keep up, and your clients are going to experience bad things.  Normally
// the actual backlog should hover near 0 anyway.)
int
nni_plat_tcp_listen(nni_plat_tcpsock *s, const nni_sockaddr *addr)
{
	int fd;
	int len;
	struct sockaddr_storage ss;
	int rv;

	len = nni_plat_to_sockaddr(&ss, addr);
	if (len < 0) {
		return (NNG_EADDRINVAL);
	}

#ifdef SOCK_CLOEXEC
	fd = socket(ss.ss_family, SOCK_STREAM, SOCK_CLOEXEC);
#else
	fd = socket(ss.ss_family, SOCK_STREAM, 0);
#endif
	if (fd < 0) {
		return (nni_plat_errno(errno));
	}

	nni_plat_tcp_setopts(fd);

	if (bind(fd, (struct sockaddr *) &ss, len) < 0) {
		rv = nni_plat_errno(errno);
		(void) close(fd);
		return (rv);
	}

	// Listen -- 128 depth is probably sufficient.  If it isn't, other
	// bad things are going to happen.
	if (listen(fd, 128) != 0) {
		rv = nni_plat_errno(errno);
		(void) close(fd);
		return (rv);
	}

	s->fd = fd;
	return (0);
}


// nni_plat_tcp_connect establishes an outbound connection.  It the
// bind address is not null, then it will attempt to bind to the local
// address specified first.
int
nni_plat_tcp_connect(nni_plat_tcpsock *s, const nni_sockaddr *addr,
    const nni_sockaddr *bindaddr)
{
	int fd;
	int len;
	struct sockaddr_storage ss;
	struct sockaddr_storage bss;
	int rv;

	len = nni_plat_to_sockaddr(&ss, addr);
	if (len < 0) {
		return (NNG_EADDRINVAL);
	}

#ifdef  SOCK_CLOEXEC
	fd = socket(ss.ss_family, SOCK_STREAM, SOCK_CLOEXEC);
#else
	fd = socket(ss.ss_family, SOCK_STREAM, 0);
#endif
	if (fd < 0) {
		return (nni_plat_errno(errno));
	}

	if (bindaddr != NULL) {
		if (bindaddr->s_un.s_family != addr->s_un.s_family) {
			return (NNG_EINVAL);
		}
		if (nni_plat_to_sockaddr(&bss, bindaddr) < 0) {
			return (NNG_EADDRINVAL);
		}
		if (bind(fd, (struct sockaddr *) &bss, len) < 0) {
			rv = nni_plat_errno(errno);
			(void) close(fd);
			return (rv);
		}
	}

	nni_plat_tcp_setopts(fd);

	if (connect(fd, (struct sockaddr *) &ss, len) != 0) {
		rv = nni_plat_errno(errno);
		(void) close(fd);
		return (rv);
	}
	s->fd = fd;
	return (0);
}


int
nni_plat_tcp_accept(nni_plat_tcpsock *s, nni_plat_tcpsock *server)
{
	int fd;

	for (;;) {
#ifdef NNG_USE_ACCEPT4
		fd = accept4(server, NULL, NULL, SOCK_CLOEXEC);
		if ((fd < 0) && ((errrno == ENOSYS) || (errno == ENOTSUP))) {
			fd = accept(server, NULL, NULL);
		}
#else
		fd = accept(server->fd, NULL, NULL);
#endif

		if (fd < 0) {
			if ((errno == EINTR) || (errno == ECONNABORTED)) {
				// These are not fatal errors, keep trying
				continue;
			}
			return (nni_plat_errno(errno));
		} else {
			break;
		}
	}

	nni_plat_tcp_setopts(fd);

	s->fd = fd;
	return (0);
}


#endif // PLATFORM_POSIX_NET
