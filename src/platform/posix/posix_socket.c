//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_SOCKET
#include "platform/posix/posix_aio.h"
#include "platform/posix/posix_socket.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

// Solaris/SunOS systems define this, which collides with our symbol
// names.  Just undefine it now.
#ifdef sun
#undef sun
#endif


#ifdef  SOCK_CLOEXEC
#define NNI_STREAM_SOCKTYPE	(SOCK_STREAM | SOCK_CLOEXEC)
#else
#define NNI_STREAM_SOCKTYPE	SOCK_STREAM
#endif

struct nni_posix_sock {
	int			fd;
	int			devnull;        // for shutting down accept()
	char *			unlink;         // path to unlink at unbind
	nni_posix_pipedesc *	pd;
	int			tcpnodelay;
};

int
nni_posix_to_sockaddr(struct sockaddr_storage *ss, const nni_sockaddr *sa)
{
	struct sockaddr_in *sin;
	struct sockaddr_un *sun;

#ifdef PF_INET6
	struct sockaddr_in6 *sin6;
#endif

	switch (sa->s_un.s_family) {
	case NNG_AF_INET:
		sin = (void *) ss;
		memset(sin, 0, sizeof (*sin));
		sin->sin_family = PF_INET;
		sin->sin_port = sa->s_un.s_in.sa_port;
		sin->sin_addr.s_addr = sa->s_un.s_in.sa_addr;
		return (sizeof (*sin));

#ifdef PF_INET6
	// Not every platform can do IPv6.  Amazingly.
	case NNG_AF_INET6:
		sin6 = (void *) ss;
		memset(sin6, 0, sizeof (*sin6));
#ifdef  SIN6_LEN
		sin6->sin6_len = sizeof (*sin6);
#endif
		sin6->sin6_family = PF_INET6;
		sin6->sin6_port = sa->s_un.s_in6.sa_port;
		memcpy(sin6->sin6_addr.s6_addr, sa->s_un.s_in6.sa_addr, 16);
		return (sizeof (*sin6));

#endif          // PF_INET6

	case NNG_AF_IPC:
		sun = (void *) ss;
		memset(sun, 0, sizeof (*sun));
		// NB: This logic does not support abstract sockets, which
		// have their first byte NULL, and rely on length instead.
		// Probably for dealing with abstract sockets we will just
		// handle @ specially in the future.
		if (strlen(sa->s_un.s_path.sa_path) >=
		    sizeof (sun->sun_path)) {
			return (-1); // caller converts to NNG_EADDRINVAL
		}

		sun->sun_family = PF_UNIX;
		(void) snprintf(sun->sun_path, sizeof (sun->sun_path), "%s",
		    sa->s_un.s_path.sa_path);
		return (sizeof (*sun));
	}
	return (-1);
}


int
nni_posix_from_sockaddr(nni_sockaddr *sa, const struct sockaddr *ss)
{
	const struct sockaddr_in *sin;
	const struct sockaddr_un *sun;

#ifdef PF_INET6
	const struct sockaddr_in6 *sin6;
#endif

	memset(sa, 0, sizeof (*sa));
	switch (ss->sa_family) {
	case PF_INET:
		sin = (const void *) ss;
		sa->s_un.s_in.sa_family = NNG_AF_INET;
		sa->s_un.s_in.sa_port = sin->sin_port;
		sa->s_un.s_in.sa_addr = sin->sin_addr.s_addr;
		return (0);

#ifdef PF_INET6
	case PF_INET6:
		sin6 = (const void *) ss;
		sa->s_un.s_in6.sa_family = NNG_AF_INET6;
		sa->s_un.s_in6.sa_port = sin6->sin6_port;
		memcpy(sa->s_un.s_in6.sa_addr, sin6->sin6_addr.s6_addr, 16);
		return (0);

#endif          // PF_INET6

	case PF_UNIX:
		// NB: This doesn't handle abstract sockets!
		sun = (const void *) ss;
		sa->s_un.s_path.sa_family = NNG_AF_IPC;
		snprintf(sa->s_un.s_path.sa_path,
		    sizeof (sa->s_un.s_path.sa_path), "%s", sun->sun_path);
		return (0);
	}
	return (-1);
}


void
nni_posix_sock_aio_send(nni_posix_sock *s, nni_aio *aio)
{
	nni_posix_pipedesc_write(s->pd, aio);
}


void
nni_posix_sock_aio_recv(nni_posix_sock *s, nni_aio *aio)
{
	nni_posix_pipedesc_read(s->pd, aio);
}


static void
nni_posix_sock_setopts_fd(int fd, int tcpnodelay)
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

	// It's unclear whether this is safe for UNIX domain sockets.  It
	// *should* be.
	if (tcpnodelay) {
		one = 1;
		(void) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one,
		    sizeof (one));
	}
}


int
nni_posix_sock_init(nni_posix_sock **sp)
{
	nni_posix_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	s->fd = -1;
	*sp = s;
	return (0);
}


void
nni_posix_sock_fini(nni_posix_sock *s)
{
	if (s->fd != -1) {
		(void) close(s->fd);
		s->fd = -1;
	}
	if (s->pd != NULL) {
		nni_posix_pipedesc_fini(s->pd);
	}
	if (s->unlink != NULL) {
		(void) unlink(s->unlink);
		nni_free(s->unlink, strlen(s->unlink) + 1);
	}
	NNI_FREE_STRUCT(s);
}


void
nni_posix_sock_shutdown(nni_posix_sock *s)
{
	if (s->fd != -1) {
		(void) shutdown(s->fd, SHUT_RDWR);
		// This causes the equivalent of a close.  Hopefully waking
		// up anything that didn't get the hint with the shutdown.
		// (macOS does not see the shtudown).
		(void) dup2(nni_plat_devnull, s->fd);
	}
	if (s->pd != NULL) {
		nni_posix_pipedesc_close(s->pd);
	}
}


int
nni_posix_sock_listen(nni_posix_sock *s, const nni_sockaddr *saddr)
{
	int len;
	struct sockaddr_storage ss;
	int rv;
	int fd;

	if ((len = nni_posix_to_sockaddr(&ss, saddr)) < 0) {
		return (NNG_EADDRINVAL);
	}

	if ((fd = socket(ss.ss_family, NNI_STREAM_SOCKTYPE, 0)) < 0) {
		return (nni_plat_errno(errno));
	}
	if ((saddr->s_un.s_family == NNG_AF_INET) ||
	    (saddr->s_un.s_family == NNG_AF_INET6)) {
		s->tcpnodelay = 1;
	}

	nni_posix_sock_setopts_fd(fd, s->tcpnodelay);

	// UNIX DOMAIN SOCKETS -- these have names in the file namespace.
	// We are going to check to see if there was a name already there.
	// If there was, and nothing is listening (ECONNREFUSED), then we
	// will just try to cleanup the old socket.  Note that this is not
	// perfect in all scenarios, so use this with caution.
	if ((saddr->s_un.s_family == NNG_AF_IPC) &&
	    (saddr->s_un.s_path.sa_path[0] != 0)) {
		int chkfd;
		if ((chkfd = socket(AF_UNIX, NNI_STREAM_SOCKTYPE, 0)) < 0) {
			(void) close(fd);
			return (nni_plat_errno(errno));
		}

		// Nonblocking; we don't want to wait for remote server.
		(void) fcntl(chkfd, F_SETFL, O_NONBLOCK);
		if (connect(chkfd, (struct sockaddr *) &ss, len) < 0) {
			if (errno == ECONNREFUSED) {
				(void) unlink(saddr->s_un.s_path.sa_path);
			}
		}
		(void) close(chkfd);

		// Record the path so we unlink it later
		s->unlink = nni_alloc(strlen(saddr->s_un.s_path.sa_path) + 1);
		if (s->unlink == NULL) {
			(void) close(fd);
			return (NNG_ENOMEM);
		}
	}


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


// These functions will need to be removed in the future.  They are
// transition functions for now.

int
nni_posix_sock_send_sync(nni_posix_sock *s, nni_iov *iovs, int cnt)
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
		rv = writev(s->fd, &iov[i], cnt);
		if (rv < 0) {
			if (rv == EINTR) {
				continue;
			}
			return (nni_plat_errno(errno));
		}
		NNI_ASSERT(rv <= resid);
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
nni_posix_sock_recv_sync(nni_posix_sock *s, nni_iov *iovs, int cnt)
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
		rv = readv(s->fd, &iov[i], cnt);
		if (rv < 0) {
			if (errno == EINTR) {
				continue;
			}
			return (nni_plat_errno(errno));
		}
		if (rv == 0) {
			return (NNG_ECLOSED);
		}
		NNI_ASSERT(rv <= resid);

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
nni_posix_sock_accept_sync(nni_posix_sock *s, nni_posix_sock *server)
{
	int fd;
	int rv;

	for (;;) {
#ifdef NNG_USE_ACCEPT4
		fd = accept4(server->fd, NULL, NULL, SOCK_CLOEXEC);
		if ((fd < 0) && ((errno == ENOSYS) || (errno == ENOTSUP))) {
			fd = accept(server->fd, NULL, NULL);
		}
#else
		fd = accept(server->fd, NULL, NULL);
#endif

		if (fd < 0) {
			return (nni_plat_errno(errno));
		} else {
			break;
		}
	}

	nni_posix_sock_setopts_fd(fd, s->tcpnodelay);

	if ((rv = nni_posix_pipedesc_init(&s->pd, fd)) != 0) {
		close(fd);
		return (rv);
	}
	s->fd = fd;
	return (0);
}


int
nni_posix_sock_connect_sync(nni_posix_sock *s, const nni_sockaddr *addr,
    const nni_sockaddr *bindaddr)
{
	int fd;
	int len;
	struct sockaddr_storage ss;
	struct sockaddr_storage bss;
	int rv;

	if ((len = nni_posix_to_sockaddr(&ss, addr)) < 0) {
		return (NNG_EADDRINVAL);
	}

	if ((fd = socket(ss.ss_family, NNI_STREAM_SOCKTYPE, 0)) < 0) {
		return (nni_plat_errno(errno));
	}

	if ((addr->s_un.s_family == NNG_AF_INET) ||
	    (addr->s_un.s_family == NNG_AF_INET6)) {
		s->tcpnodelay = 1;
	}

	if (bindaddr != NULL) {
		if (bindaddr->s_un.s_family != addr->s_un.s_family) {
			return (NNG_EINVAL);
		}
		if (nni_posix_to_sockaddr(&bss, bindaddr) < 0) {
			return (NNG_EADDRINVAL);
		}
		if (bind(fd, (struct sockaddr *) &bss, len) < 0) {
			rv = nni_plat_errno(errno);
			(void) close(fd);
			return (rv);
		}
	}

	nni_posix_sock_setopts_fd(fd, s->tcpnodelay);

	if (connect(fd, (struct sockaddr *) &ss, len) != 0) {
		rv = nni_plat_errno(errno);
		(void) close(fd);
		return (rv);
	}
	if ((rv = nni_posix_pipedesc_init(&s->pd, fd)) != 0) {
		(void) close(fd);
		return (rv);
	}
	s->fd = fd;
	return (0);
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_socket_not_used = 0;

#endif // PLATFORM_POSIX_SOCKET
