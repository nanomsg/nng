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

#include <stdio.h>

// Windows has infinite numbers of error codes it seems.
static struct {
	int	wsa_err;
	int	nng_err;
}
nni_plat_wsa_errnos[] = {
	{ WSA_INVALID_HANDLE,	  NNG_ECLOSED			       },
	{ WSA_NOT_ENOUGH_MEMORY,  NNG_ENOMEM			       },
	{ WSA_INVALID_PARAMETER,  NNG_EINVAL			       },
	{ WSA_OPERATION_ABORTED,  NNG_ECLOSED			       },
	{ WSA_IO_INCOMPLETE,	  NNG_EAGAIN			       },

	{ WSAEINTR,		  NNG_EINTR			       },
	{ WSAEBADF,		  NNG_ECLOSED			       },
	{ WSAEACCES,		  NNG_EPERM			       },
	{ WSAEFAULT,		  NNG_ESYSERR + WSAEFAULT	       },
	{ WSAEWOULDBLOCK,	  NNG_EAGAIN			       },
	{ WSAEINPROGRESS,	  NNG_EAGAIN			       },
	{ WSAEALREADY,		  NNG_ESYSERR + WSAEALREADY	       },
	{ WSAENOTSOCK,		  NNG_ECLOSED			       },
	{ WSAEMSGSIZE,		  NNG_EMSGSIZE			       },
	{ WSAEPROTOTYPE,	  NNG_ESYSERR + WSAEPROTOTYPE	       },
	{ WSAENOPROTOOPT,	  NNG_ENOTSUP			       },
	{ WSAEPROTONOSUPPORT,	  NNG_ENOTSUP			       },
	{ WSAEPROTONOSUPPORT,	  NNG_ENOTSUP			       },
	{ WSAEADDRINUSE,	  NNG_EADDRINUSE		       },
	{ WSAEADDRNOTAVAIL,	  NNG_EADDRINVAL		       },
	{ WSAENETDOWN,		  NNG_EUNREACHABLE		       },
	{ WSAENETUNREACH,	  NNG_EUNREACHABLE		       },
	{ WSAECONNABORTED,	  NNG_ETIMEDOUT			       },
	{ WSAECONNRESET,	  NNG_ECLOSED			       },
	{ WSAENOBUFS,		  NNG_ENOMEM			       },
	{ WSAEISCONN,		  NNG_ESYSERR + WSAEISCONN	       },
	{ WSAENOTCONN,		  NNG_ECLOSED			       },
	{ WSAESHUTDOWN,		  NNG_ECLOSED			       },
	{ WSAETOOMANYREFS,	  NNG_ESYSERR + WSAETOOMANYREFS	       },
	{ WSAETIMEDOUT,		  NNG_ETIMEDOUT			       },
	{ WSAECONNREFUSED,	  NNG_ECONNREFUSED		       },
	{ WSAELOOP,		  NNG_ESYSERR + WSAELOOP	       },
	{ WSAENAMETOOLONG,	  NNG_ESYSERR + WSAENAMETOOLONG	       },
	{ WSAEHOSTDOWN,		  NNG_EUNREACHABLE		       },
	{ WSAEHOSTUNREACH,	  NNG_EUNREACHABLE		       },
	{ WSAENOTEMPTY,		  NNG_ESYSERR + WSAENOTEMPTY	       },
	{ WSAEPROCLIM,		  NNG_ESYSERR + WSAEPROCLIM	       },
	{ WSAEUSERS,		  NNG_ESYSERR + WSAEUSERS	       },
	{ WSAEDQUOT,		  NNG_ESYSERR + WSAEDQUOT	       },
	{ WSAESTALE,		  NNG_ESYSERR + WSAESTALE	       },
	{ WSAEREMOTE,		  NNG_ESYSERR + WSAEREMOTE	       },
	{ WSASYSNOTREADY,	  NNG_ESYSERR + WSASYSNOTREADY	       },
	{ WSAVERNOTSUPPORTED,	  NNG_ENOTSUP			       },
	{ WSANOTINITIALISED,	  NNG_ESYSERR + WSANOTINITIALISED      },
	{ WSAEDISCON,		  NNG_ECLOSED			       },
	{ WSAENOMORE,		  NNG_ESYSERR + WSAENOMORE	       },
	{ WSAECANCELLED,	  NNG_ESYSERR + WSAECANCELLED	       },
	{ WSAEINVALIDPROVIDER,	  NNG_ESYSERR + WSAEINVALIDPROVIDER    },
	{ WSAEPROVIDERFAILEDINIT, NNG_ESYSERR + WSAEPROVIDERFAILEDINIT },
	{ WSASYSCALLFAILURE,	  NNG_ESYSERR + WSASYSCALLFAILURE      },
	{ WSASERVICE_NOT_FOUND,	  NNG_ESYSERR + WSASERVICE_NOT_FOUND   },
	{ WSATYPE_NOT_FOUND,	  NNG_ESYSERR + WSATYPE_NOT_FOUND      },
	{ WSA_E_CANCELLED,	  NNG_ESYSERR + WSA_E_CANCELLED	       },
	{ WSAEREFUSED,		  NNG_ESYSERR + WSAEREFUSED	       },
	{ WSAHOST_NOT_FOUND,	  NNG_EADDRINVAL		       },
	{ WSATRY_AGAIN,		  NNG_EAGAIN			       },
	{ WSANO_RECOVERY,	  NNG_ESYSERR + WSANO_RECOVERY	       },
	{ WSANO_DATA,		  NNG_EADDRINVAL		       },
	// Eliding all the QoS related errors.
	// Must be Last!!
	{		       0,				     0 },
};


static int
nni_winsock_error(int werr)
{
	int i;

	if (werr == 0) {
		return (0);
	}

	for (i = 0; nni_plat_wsa_errnos[i].nng_err != 0; i++) {
		if (werr == nni_plat_wsa_errnos[i].wsa_err) {
			return (nni_plat_wsa_errnos[i].nng_err);
		}
	}
	// Other system errno.
	return (NNG_ESYSERR + werr);
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
	int rv;
	DWORD offset;
	DWORD nsent;
	DWORD resid;
	DWORD flags;
	WSAOVERLAPPED *olp = &s->send_olpd;

	if (cnt > 4) {
		return (NNG_EINVAL);
	}

	for (i = 0, resid = 0; i < cnt; resid += iov[i].len, i++) {
		iov[i].buf = iovs[i].iov_buf;
		iov[i].len = iovs[i].iov_len;
	}

	i = 0;
	while (resid) {
		flags = 0;
		rv = WSASend(s->s, &iov[i], cnt, &nsent, flags, olp, NULL);
		if (rv == SOCKET_ERROR) {
			if ((rv = WSAGetLastError()) != WSA_IO_PENDING) {
				return (nni_winsock_error(rv));
			}
		}
		flags = 0;
		if (!WSAGetOverlappedResult(s->s, olp, &nsent, TRUE, &flags)) {
			return (nni_winsock_error(WSAGetLastError()));
		}

		if (nsent > resid) {
			nni_panic("WSASend says it sent too much");
		}

		resid -= nsent;
		while (nsent) {
			if (iov[i].len <= nsent) {
				nsent -= iov[i].len;
				i++;
				cnt--;
			} else {
				iov[i].len -= nsent;
				iov[i].buf += nsent;
				nsent = 0;
			}
		}
	}

	return (0);
}


int
nni_plat_tcp_recv(nni_plat_tcpsock *s, nni_iov *iovs, int cnt)
{
	WSABUF iov[4];    // We never have more than 3 at present
	int i;
	int rv;
	DWORD offset;
	DWORD resid;
	DWORD nrecv;
	DWORD flags;
	WSAOVERLAPPED *olp = &s->recv_olpd;

	if (cnt > 4) {
		return (NNG_EINVAL);
	}

	for (i = 0, resid = 0; i < cnt; resid += iov[i].len, i++) {
		iov[i].buf = iovs[i].iov_buf;
		iov[i].len = iovs[i].iov_len;
	}

	i = 0;
	while (resid) {
		flags = 0;
		rv = WSARecv(s->s, &iov[i], cnt, &nrecv, &flags, olp, NULL);
		if (rv == SOCKET_ERROR) {
			if ((rv = WSAGetLastError()) != WSA_IO_PENDING) {
				return (nni_winsock_error(rv));
			}
		}
		flags = 0;
		if (!WSAGetOverlappedResult(s->s, olp, &nrecv, TRUE, &flags)) {
			return (nni_winsock_error(WSAGetLastError()));
		}

		if (nrecv > resid) {
			nni_panic("WSARecv says it read too much!");
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


int
nni_plat_tcp_init(nni_plat_tcpsock *s)
{
	int rv;

	ZeroMemory(s, sizeof (*s));
	s->s = INVALID_SOCKET;
	s->recv_olpd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (s->recv_olpd.hEvent == INVALID_HANDLE_VALUE) {
		rv = GetLastError();
		return (NNG_ESYSERR+rv);
	}
	s->send_olpd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (s->send_olpd.hEvent == INVALID_HANDLE_VALUE) {
		rv = GetLastError();
		CloseHandle(s->recv_olpd.hEvent);
		return (NNG_ESYSERR+rv);
	}
	s->conn_olpd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (s->conn_olpd.hEvent == INVALID_HANDLE_VALUE) {
		rv = GetLastError();
		CloseHandle(s->send_olpd.hEvent);
		CloseHandle(s->recv_olpd.hEvent);
		return (NNG_ESYSERR+rv);
	}
	return (0);
}


static int
nni_plat_tcp_open(nni_plat_tcpsock *s)
{
	int rv;
	DWORD nbytes;
	GUID guid1 = WSAID_CONNECTEX;
	GUID guid2 = WSAID_ACCEPTEX;

	s->s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
		WSA_FLAG_NO_HANDLE_INHERIT|WSA_FLAG_OVERLAPPED);
	if (s->s == INVALID_SOCKET) {
		rv = WSAGetLastError();
		return (nni_winsock_error(rv));
	}

	if (WSAIoctl(s->s, SIO_GET_EXTENSION_FUNCTION_POINTER,
	    &guid1, sizeof (guid1), &s->connectex, sizeof (s->connectex),
	    &nbytes, NULL, NULL) == SOCKET_ERROR) {
		nni_panic("failed lookup for ConnectEx function");
	}
	if (WSAIoctl(s->s, SIO_GET_EXTENSION_FUNCTION_POINTER,
	    &guid2, sizeof (guid2), &s->acceptex, sizeof (s->acceptex),
	    &nbytes, NULL, NULL) == SOCKET_ERROR) {
		nni_panic("failed lookup for AcceptEx function");
	}

	nni_plat_tcp_setopts(s->s);

	return (0);
}


static void
nni_plat_tcp_close(nni_plat_tcpsock *s)
{
	SOCKET fd;

	if ((fd = s->s) != INVALID_SOCKET) {
		s->s = INVALID_SOCKET;
		(void) shutdown(fd, SD_BOTH);
		(void) CancelIoEx((HANDLE) fd, &s->conn_olpd);
		(void) CancelIoEx((HANDLE) fd, &s->recv_olpd);
		(void) CancelIoEx((HANDLE) fd, &s->send_olpd);
		(void) closesocket(fd);
	}
}


void
nni_plat_tcp_fini(nni_plat_tcpsock *s)
{
	SOCKET fd;

	if ((fd = s->s) != INVALID_SOCKET) {
		s->s = INVALID_SOCKET;
		(void) CancelIoEx((HANDLE) fd, &s->conn_olpd);
		(void) CancelIoEx((HANDLE) fd, &s->recv_olpd);
		(void) CancelIoEx((HANDLE) fd, &s->send_olpd);
		(void) closesocket(fd);
	}
	CloseHandle(s->recv_olpd.hEvent);
	CloseHandle(s->send_olpd.hEvent);
	CloseHandle(s->conn_olpd.hEvent);
}


void
nni_plat_tcp_shutdown(nni_plat_tcpsock *s)
{
	nni_plat_tcp_close(s);
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
	ULONG yes;
	int rv;

	len = nni_plat_to_sockaddr(&ss, addr);
	if (len < 0) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_plat_tcp_open(s)) != 0) {
		return (rv);
	}

	// Make sure that we use the address exclusively.  Windows lets
	// others hijack us by default.
	yes = 1;
	if (setsockopt(s->s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *) &yes,
	    sizeof (yes)) == SOCKET_ERROR) {
		rv = WSAGetLastError();
		nni_plat_tcp_close(s);
		return (nni_winsock_error(rv));
	}
	if (bind(s->s, (struct sockaddr *) &ss, len) != 0) {
		rv = WSAGetLastError();
		nni_plat_tcp_close(s);
		return (nni_winsock_error(rv));
	}

	// Listen -- 128 depth is probably sufficient.  If it isn't, other
	// bad things are going to happen.
	if (listen(s->s, 128) != 0) {
		rv = WSAGetLastError();
		nni_plat_tcp_close(s);
		return (nni_winsock_error(rv));
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
	WSAOVERLAPPED *olp = &s->conn_olpd;
	BOOL ok;
	DWORD nbytes;
	DWORD flags;
	int rv;

	len = nni_plat_to_sockaddr(&ss, addr);
	if (len < 0) {
		return (NNG_EADDRINVAL);
	}

	if (bindaddr != NULL) {
		if (bindaddr->s_un.s_family != addr->s_un.s_family) {
			return (NNG_EADDRINVAL);
		}
		if (nni_plat_to_sockaddr(&bss, bindaddr) < 0) {
			return (NNG_EADDRINVAL);
		}
	} else {
		ZeroMemory(&bss, sizeof (bss));
		bss.ss_family = ss.ss_family;
	}

	if ((rv = nni_plat_tcp_open(s)) != 0) {
		return (rv);
	}

	// ConnectEx must always be bound first.
	if (bind(s->s, (struct sockaddr *) &bss, len) < 0) {
		rv = WSAGetLastError();
		nni_plat_tcp_close(s);
		return (nni_winsock_error(rv));
	}

	if (!s->connectex(s->s, (struct sockaddr *) &ss, len, NULL, 0, NULL,
	    olp)) {
		if ((rv = WSAGetLastError()) != ERROR_IO_PENDING) {
			nni_plat_tcp_close(s);
			return (nni_winsock_error(rv));
		}
	}
	nbytes = flags = 0;
	if (!WSAGetOverlappedResult(s->s, olp, &nbytes, TRUE, &flags)) {
		rv = WSAGetLastError();
		nni_plat_tcp_close(s);
		return (nni_winsock_error(rv));
	}
	return (0);
}


int
nni_plat_tcp_accept(nni_plat_tcpsock *s, nni_plat_tcpsock *server)
{
	DWORD nbytes;
	DWORD flags;
	WSAOVERLAPPED *olp = &s->conn_olpd;
	char ainfo[512];
	int rv;

	if ((rv = nni_plat_tcp_open(s)) != 0) {
		return (rv);
	}

	// 256 > (sizeof (SOCKADDR_STORAGE) + 16)
	nbytes = 0;
	if (!s->acceptex(server->s, s->s, ainfo, 0, 256, 256, &nbytes, olp)) {
		if ((rv = WSAGetLastError()) != ERROR_IO_PENDING) {
			return (nni_winsock_error(rv));
		}
	}
	nbytes = flags = 0;
	if (!WSAGetOverlappedResult(server->s, olp, &nbytes, TRUE, &flags)) {
		rv = WSAGetLastError();
		return (nni_winsock_error(rv));
	}
	return (0);
}


#endif // PLATFORM_WINDOWS
