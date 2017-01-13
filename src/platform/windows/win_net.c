//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_WINDOWS

static struct {
	int	wsa_err;
	int	nng_err;
}
nni_plat_wsa_errnos[] = {
	{ WSAECONNABORTED,	 NNG_ECLOSED	  },
	{ WSAEINTR,		 NNG_EINTR	  },
	// REVIEW THESE!!!
	{ WSAECONNRESET,	 NNG_ECONNREFUSED },
	{ WSAEMSGSIZE,		 NNG_EINVAL	  },
	{ WSAENETDOWN,		 NNG_EUNREACHABLE },
	{ WSAENETRESET,		 NNG_ECLOSED	  },
	{ WSAENOBUFS,		 NNG_ENOMEM	  },
	{ WSAESHUTDOWN,		 NNG_ECLOSED	  },
	{ WSAEWOULDBLOCK,	 NNG_EAGAIN	  },
	{ WSAEBADF,		 NNG_ECLOSED	  },
	{ WSA_INVALID_HANDLE,	 NNG_ECLOSED	  },
	{ WSA_NOT_ENOUGH_MEMORY, NNG_ENOMEM	  },
	{ WSA_INVALID_PARAMETER, NNG_EINVAL	  },
	{ WSAEACCES,		 NNG_EPERM	  },
	{		      0,		0 }, // MUST BE LAST
};


static int
nni_plat_wsa_last_error(void)
{
	int errnum = WSAGetLastError();
	int i;

	if (errnum == 0) {
		return (0);
	}
	for (i = 0; nni_plat_wsa_errnos[i].nng_err != 0; i++) {
		if (errnum == nni_plat_wsa_errnos[i].wsa_err) {
			return (nni_plat_wsa_errnos[i].nng_err);
		}
	}
	// Other system errno.
	return (NNG_ESYSERR + errnum);
}


static int
nni_plat_to_sockaddr(SOCKADDR_STORAGE *ss, const nni_sockaddr *sa)
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
	ADDRINFO hint;
	ADDRINFO *ai;

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
	WSABUF iov[4];    // We never have more than 3 at present
	int i;
	DWORD sent = 0;
	int rv;

	if (cnt > 4) {
		return (NNG_EINVAL);
	}

	for (i = 0; i < cnt; i++) {
		iov[i].buf = iovs[i].iov_buf;
		iov[i].len = iovs[i].iov_len;
	}

	rv = WSASend(s->s, iov, cnt, &sent, 0, NULL, NULL);
	if (rv != 0) {
		// XXX: CONVERT WSAGetLastError code.
		return (nni_plat_wsa_last_error());
	}

	return (0);
}


int
nni_plat_tcp_recv(nni_plat_tcpsock *s, nni_iov *iovs, int cnt)
{
	WSABUF iov[4];    // We never have more than 3 at present
	int i;
	int offset;
	int resid = 0;
	int rv;
	DWORD nrecv;

	if (cnt > 4) {
		return (NNG_EINVAL);
	}

	for (i = 0; i < cnt; i++) {
		iov[i].buf = iovs[i].iov_buf;
		iov[i].len = iovs[i].iov_len;
		resid += iov[i].len;
	}

	i = 0;
	while (resid) {
		rv = WSARecv(s->s, iov, cnt, &nrecv, 0, NULL, NULL);
		if (rv != 0) {
			return (nni_plat_wsa_last_error());
		}
		if (nrecv > resid) {
			nni_panic("readv says it read too much!");
		}

		resid -= nrecv;
		while (nrecv) {
			if (iov[i].len <= nrecv) {
				nrecv -= iov[i].len;
				i++;
				cnt--;
			} else {
				iov[i].len -= nrecv;
				iov[i].buf += nrecv;
				nrecv = 0;
			}
		}
	}

	return (0);
}


static void
nni_plat_tcp_setopts(SOCKET fd)
{
	BOOL yes;

	// Don't inherit the handle (CLOEXEC really).
	SetHandleInformation((HANDLE) fd, HANDLE_FLAG_INHERIT, 0);

	// Also disable Nagle.  We are careful to group data with WSASend,
	// and latency is king for most of our users.  (Consider adding
	// a method to enable this later.)
	yes = 1;
	(void) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &yes,
	    sizeof (yes));
}


void
nni_plat_tcp_init(nni_plat_tcpsock *s)
{
	s->s = INVALID_SOCKET;
}


void
nni_plat_tcp_fini(nni_plat_tcpsock *s)
{
	if (s->s != INVALID_SOCKET) {
		(void) closesocket(s->s);
		s->s = INVALID_SOCKET;
	}
}


void
nni_plat_tcp_shutdown(nni_plat_tcpsock *s)
{
	if (s->s != INVALID_SOCKET) {
		(void) shutdown(s->s, SD_BOTH);
	}
}


// nni_plat_tcp_listen creates a file descriptor bound to the given address.
// This basically does the equivalent of socket, bind, and listen.  We have
// chosen a default value for the listen backlog of 128, which should be
// plenty.  (If it isn't, then the accept thread can't get enough resources
// to keep up, and your clients are going to experience bad things.  Normally
// the actual backlog should hover near 0 anyway.)
int
nni_plat_tcp_listen(nni_plat_tcpsock *s, const nni_sockaddr *addr)
{
	int len;
	SOCKADDR_STORAGE ss;
	int rv;
	BOOL yes;

	len = nni_plat_to_sockaddr(&ss, addr);
	if (len < 0) {
		return (NNG_EADDRINVAL);
	}

	s->s = WSASocket(ss.ss_family, SOCK_STREAM, 0, NULL, 0,
		WSA_FLAG_NO_HANDLE_INHERIT);
	if (s->s == INVALID_SOCKET) {
		return (nni_plat_wsa_last_error());
	}

	nni_plat_tcp_setopts(s->s);

	// Make sure that we use the address exclusively.  Windows lets
	// others hijack us by default.
	yes = 1;
	if (setsockopt(s->s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *) &yes,
	    sizeof (yes)) == SOCKET_ERROR) {
		rv = nni_plat_wsa_last_error();
		(void) closesocket(s->s);
		s->s = INVALID_SOCKET;
		return (rv);
	}
	if (bind(s->s, (struct sockaddr *) &ss, len) != 0) {
		rv = nni_plat_wsa_last_error();
		(void) closesocket(s->s);
		s->s = INVALID_SOCKET;
		return (rv);
	}

	// Listen -- 128 depth is probably sufficient.  If it isn't, other
	// bad things are going to happen.
	if (listen(s->s, 128) != 0) {
		rv = nni_plat_wsa_last_error();
		(void) closesocket(s->s);
		s->s = INVALID_SOCKET;
		return (rv);
	}

	return (0);
}


// nni_plat_tcp_connect establishes an outbound connection.  It the
// bind address is not null, then it will attempt to bind to the local
// address specified first.
int
nni_plat_tcp_connect(nni_plat_tcpsock *s, const nni_sockaddr *addr,
    const nni_sockaddr *bindaddr)
{
	int len;
	SOCKADDR_STORAGE ss;
	SOCKADDR_STORAGE bss;
	int rv;

	len = nni_plat_to_sockaddr(&ss, addr);
	if (len < 0) {
		return (NNG_EADDRINVAL);
	}

	s->s = WSASocket(ss.ss_family, SOCK_STREAM, 0, NULL, 0,
		WSA_FLAG_NO_HANDLE_INHERIT);
	if (s->s == INVALID_SOCKET) {
		return (nni_plat_wsa_last_error());
	}

	if (bindaddr != NULL) {
		if (bindaddr->s_un.s_family != addr->s_un.s_family) {
			(void) closesocket(s->s);
			s->s = INVALID_SOCKET;
			return (NNG_EINVAL);
		}
		if (nni_plat_to_sockaddr(&bss, bindaddr) < 0) {
			(void) closesocket(s->s);
			s->s = INVALID_SOCKET;
			return (NNG_EADDRINVAL);
		}
		if (bind(s->s, (struct sockaddr *) &bss, len) < 0) {
			rv = nni_plat_wsa_last_error();
			(void) closesocket(s->s);
			s->s = INVALID_SOCKET;
			return (rv);
		}
	}

	nni_plat_tcp_setopts(s->s);

	if (connect(s->s, (struct sockaddr *) &ss, len) != 0) {
		rv = nni_plat_wsa_last_error();
		(void) closesocket(s->s);
		s->s = INVALID_SOCKET;
		return (rv);
	}
	return (0);
}


int
nni_plat_tcp_accept(nni_plat_tcpsock *s, nni_plat_tcpsock *server)
{
	SOCKET fd;
	int err;

	for (;;) {
		fd = accept(server->s, NULL, NULL);

		if (fd == INVALID_SOCKET) {
			err = WSAGetLastError();
			if ((err == WSAECONNRESET) || (err == WSAEWOULDBLOCK)) {
				continue;
			}
			return (nni_plat_wsa_last_error());
		} else {
			break;
		}
	}

	nni_plat_tcp_setopts(fd);

	s->s = fd;
	return (0);
}


#endif // PLATFORM_WINDOWS
