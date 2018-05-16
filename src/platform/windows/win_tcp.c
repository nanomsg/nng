//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <malloc.h>
#include <stdio.h>

struct nni_plat_tcp_pipe {
	SOCKET           s;
	nni_win_event    rcv_ev;
	nni_win_event    snd_ev;
	SOCKADDR_STORAGE sockname;
	SOCKADDR_STORAGE peername;
};

struct nni_plat_tcp_ep {
	SOCKET        s;
	SOCKET        acc_s;
	nni_win_event con_ev;
	nni_win_event acc_ev;
	int           started;
	int           bound;

	SOCKADDR_STORAGE remaddr;
	int              remlen;
	SOCKADDR_STORAGE locaddr;
	int              loclen;

	char buf[512]; // to hold acceptex results

	// We have to lookup some function pointers using ioctls.  Winsock,
	// gotta love it.  Especially I love that asynch accept means that
	// getsockname and getpeername don't work.
	LPFN_CONNECTEX            connectex;
	LPFN_ACCEPTEX             acceptex;
	LPFN_GETACCEPTEXSOCKADDRS getacceptexsockaddrs;
};

static int  nni_win_tcp_pipe_start(nni_win_event *, nni_aio *);
static void nni_win_tcp_pipe_finish(nni_win_event *, nni_aio *);
static void nni_win_tcp_pipe_cancel(nni_win_event *);

static nni_win_event_ops nni_win_tcp_pipe_ops = {
	.wev_start  = nni_win_tcp_pipe_start,
	.wev_finish = nni_win_tcp_pipe_finish,
	.wev_cancel = nni_win_tcp_pipe_cancel,
};

static int  nni_win_tcp_acc_start(nni_win_event *, nni_aio *);
static void nni_win_tcp_acc_finish(nni_win_event *, nni_aio *);
static void nni_win_tcp_acc_cancel(nni_win_event *);

static nni_win_event_ops nni_win_tcp_acc_ops = {
	.wev_start  = nni_win_tcp_acc_start,
	.wev_finish = nni_win_tcp_acc_finish,
	.wev_cancel = nni_win_tcp_acc_cancel,
};

static int  nni_win_tcp_con_start(nni_win_event *, nni_aio *);
static void nni_win_tcp_con_finish(nni_win_event *, nni_aio *);
static void nni_win_tcp_con_cancel(nni_win_event *);

static nni_win_event_ops nni_win_tcp_con_ops = {
	.wev_start  = nni_win_tcp_con_start,
	.wev_finish = nni_win_tcp_con_finish,
	.wev_cancel = nni_win_tcp_con_cancel,
};

static void
nni_win_tcp_sockinit(SOCKET s)
{
	BOOL  yes;
	DWORD no;

	// Don't inherit the handle (CLOEXEC really).
	SetHandleInformation((HANDLE) s, HANDLE_FLAG_INHERIT, 0);

	no = 0;
	(void) setsockopt(
	    s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &no, sizeof(no));

	// Also disable Nagle.  We are careful to group data with WSASend,
	// and latency is king for most of our users.  (Consider adding
	// a method to enable this later.)
	yes = 1;
	(void) setsockopt(
	    s, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes));
}

static int
nni_win_tcp_pipe_start(nni_win_event *evt, nni_aio *aio)
{
	int                rv;
	SOCKET             s;
	DWORD              niov;
	DWORD              flags;
	nni_plat_tcp_pipe *pipe = evt->ptr;
	unsigned           i;
	unsigned           naiov;
	nni_iov *          aiov;
	WSABUF *           iov;

	nni_aio_get_iov(aio, &naiov, &aiov);
	iov = _malloca(naiov * sizeof(*iov));

	// Put the AIOs in Windows form.
	for (niov = 0, i = 0; i < naiov; i++) {
		if (aiov[i].iov_len != 0) {
			iov[niov].buf = aiov[i].iov_buf;
			iov[niov].len = (ULONG) aiov[i].iov_len;
			niov++;
		}
	}

	if ((s = pipe->s) == INVALID_SOCKET) {
		_freea(iov);
		evt->status = NNG_ECLOSED;
		evt->count  = 0;
		return (1);
	}

	// Note that the IOVs for the event were prepared on entry already.
	// The actual aio's iov array we don't touch.

	evt->count = 0;
	flags      = 0;
	if (evt == &pipe->snd_ev) {
		rv = WSASend(s, iov, niov, NULL, flags, &evt->olpd, NULL);
	} else {
		rv = WSARecv(s, iov, niov, NULL, &flags, &evt->olpd, NULL);
	}
	_freea(iov);

	if ((rv == SOCKET_ERROR) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		evt->status = nni_win_error(rv);
		evt->count  = 0;
		return (1);
	}

	// Wait for the I/O completion event.  Note that when an I/O
	// completes immediately, the I/O completion packet is still
	// delivered.
	return (0);
}

static void
nni_win_tcp_pipe_cancel(nni_win_event *evt)
{
	nni_plat_tcp_pipe *pipe = evt->ptr;

	(void) CancelIoEx((HANDLE) pipe->s, &evt->olpd);
}

static void
nni_win_tcp_pipe_finish(nni_win_event *evt, nni_aio *aio)
{
	if ((evt->status == 0) && (evt->count == 0)) {
		// Windows sometimes returns a zero read.  Convert these
		// into an NNG_ECLOSED.  (We are never supposed to come
		// back with zero length read.)
		evt->status = NNG_ECLOSED;
	}
	nni_aio_finish(aio, evt->status, evt->count);
}

static int
nni_win_tcp_pipe_init(nni_plat_tcp_pipe **pipep, SOCKET s)
{
	nni_plat_tcp_pipe *pipe;
	int                rv;

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	rv = nni_win_event_init(&pipe->rcv_ev, &nni_win_tcp_pipe_ops, pipe);
	if (rv != 0) {
		nni_plat_tcp_pipe_fini(pipe);
		return (rv);
	}
	rv = nni_win_event_init(&pipe->snd_ev, &nni_win_tcp_pipe_ops, pipe);
	if (rv != 0) {
		nni_plat_tcp_pipe_fini(pipe);
		return (rv);
	}
	nni_win_tcp_sockinit(s);
	pipe->s = s;
	*pipep  = pipe;
	return (0);
}

void
nni_plat_tcp_pipe_send(nni_plat_tcp_pipe *pipe, nni_aio *aio)
{
	nni_win_event_submit(&pipe->snd_ev, aio);
}

void
nni_plat_tcp_pipe_recv(nni_plat_tcp_pipe *pipe, nni_aio *aio)
{
	nni_win_event_submit(&pipe->rcv_ev, aio);
}

void
nni_plat_tcp_pipe_close(nni_plat_tcp_pipe *pipe)
{
	SOCKET s;

	nni_win_event_close(&pipe->rcv_ev);

	if ((s = pipe->s) != INVALID_SOCKET) {
		pipe->s = INVALID_SOCKET;
		closesocket(s);
	}
}

int
nni_plat_tcp_pipe_peername(nni_plat_tcp_pipe *pipe, nni_sockaddr *sa)
{
	if (nni_win_sockaddr2nn(sa, &pipe->peername) < 0) {
		return (NNG_EADDRINVAL);
	}
	return (0);
}

int
nni_plat_tcp_pipe_sockname(nni_plat_tcp_pipe *pipe, nni_sockaddr *sa)
{
	if (nni_win_sockaddr2nn(sa, &pipe->sockname) < 0) {
		return (NNG_EADDRINVAL);
	}
	return (0);
}

int
nni_plat_tcp_pipe_set_nodelay(nni_plat_tcp_pipe *pipe, bool val)
{
	BOOL b;
	b = val ? TRUE : FALSE;
	if (setsockopt(pipe->s, IPPROTO_TCP, TCP_NODELAY, (void *) &b,
	        sizeof(b)) != 0) {
		return (nni_win_error(WSAGetLastError()));
	}
	return (0);
}

int
nni_plat_tcp_pipe_set_keepalive(nni_plat_tcp_pipe *pipe, bool val)
{
	BOOL b;
	b = val ? TRUE : FALSE;
	if (setsockopt(pipe->s, SOL_SOCKET, SO_KEEPALIVE, (void *) &b,
	        sizeof(b)) != 0) {
		return (nni_win_error(WSAGetLastError()));
	}
	return (0);
}

void
nni_plat_tcp_pipe_fini(nni_plat_tcp_pipe *pipe)
{
	nni_plat_tcp_pipe_close(pipe);

	nni_win_event_fini(&pipe->snd_ev);
	nni_win_event_fini(&pipe->rcv_ev);
	NNI_FREE_STRUCT(pipe);
}

int
nni_plat_tcp_ep_init(nni_plat_tcp_ep **epp, const nni_sockaddr *lsa,
    const nni_sockaddr *rsa, int mode)
{
	nni_plat_tcp_ep *ep;
	int              rv;
	SOCKET           s;
	DWORD            nbytes;
	GUID             guid1 = WSAID_CONNECTEX;
	GUID             guid2 = WSAID_ACCEPTEX;
	GUID             guid3 = WSAID_GETACCEPTEXSOCKADDRS;

	NNI_ARG_UNUSED(mode);

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ZeroMemory(ep, sizeof(*ep));

	ep->s = INVALID_SOCKET;

	if ((rsa != NULL) && (rsa->s_family != NNG_AF_UNSPEC)) {
		ep->remlen = nni_win_nn2sockaddr(&ep->remaddr, rsa);
	}
	if ((lsa != NULL) && (lsa->s_family != NNG_AF_UNSPEC)) {
		ep->loclen = nni_win_nn2sockaddr(&ep->locaddr, lsa);
	}

	// Create a scratch socket for use with ioctl.
	s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}

	// Look up the function pointer.
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid1,
	        sizeof(guid1), &ep->connectex, sizeof(ep->connectex), &nbytes,
	        NULL, NULL) == SOCKET_ERROR) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid2,
	        sizeof(guid2), &ep->acceptex, sizeof(ep->acceptex), &nbytes,
	        NULL, NULL) == SOCKET_ERROR) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid3,
	        sizeof(guid3), &ep->getacceptexsockaddrs,
	        sizeof(ep->getacceptexsockaddrs), &nbytes, NULL,
	        NULL) == SOCKET_ERROR) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}

	closesocket(s);
	s = INVALID_SOCKET;

	// Now initialize the win events for later use.
	rv = nni_win_event_init(&ep->acc_ev, &nni_win_tcp_acc_ops, ep);
	if (rv != 0) {
		goto fail;
	}
	rv = nni_win_event_init(&ep->con_ev, &nni_win_tcp_con_ops, ep);
	if (rv != 0) {
		goto fail;
	}

	*epp = ep;
	return (0);

fail:
	if (s != INVALID_SOCKET) {
		closesocket(s);
	}
	nni_plat_tcp_ep_fini(ep);
	return (rv);
}

void
nni_plat_tcp_ep_close(nni_plat_tcp_ep *ep)
{
	nni_win_event_close(&ep->acc_ev);
	nni_win_event_close(&ep->con_ev);
	if (ep->s != INVALID_SOCKET) {
		closesocket(ep->s);
		ep->s = INVALID_SOCKET;
	}
	if (ep->acc_s != INVALID_SOCKET) {
		closesocket(ep->acc_s);
	}
}

void
nni_plat_tcp_ep_fini(nni_plat_tcp_ep *ep)
{
	nni_plat_tcp_ep_close(ep);
	NNI_FREE_STRUCT(ep);
}

static int
nni_win_tcp_listen(nni_plat_tcp_ep *ep, nni_sockaddr *bsa)
{
	int    rv;
	BOOL   yes;
	SOCKET s;

	if (ep->started) {
		return (NNG_EBUSY);
	}

	s = socket(ep->locaddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}

	nni_win_tcp_sockinit(s);

	if ((rv = nni_win_iocp_register((HANDLE) s)) != 0) {
		goto fail;
	}

	// Make sure that we use the address exclusively.  Windows lets
	// others hijack us by default.
	yes = 1;

	rv = setsockopt(
	    s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *) &yes, sizeof(yes));
	if (rv != 0) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}
	if (bind(s, (struct sockaddr *) &ep->locaddr, ep->loclen) != 0) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}

	if (bsa != NULL) {
		SOCKADDR_STORAGE bound;
		int              len = sizeof(bound);
		rv = getsockname(s, (SOCKADDR *) &bound, &len);
		if (rv != 0) {
			rv = nni_win_error(GetLastError());
			goto fail;
		}
		nni_win_sockaddr2nn(bsa, &bound);
	}

	if (listen(s, SOMAXCONN) != 0) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}

	ep->s       = s;
	ep->started = 1;

	return (0);

fail:
	if (s != INVALID_SOCKET) {
		closesocket(s);
	}
	return (rv);
}

int
nni_plat_tcp_ep_listen(nni_plat_tcp_ep *ep, nng_sockaddr *bsa)
{
	int rv;

	nni_mtx_lock(&ep->acc_ev.mtx);
	rv = nni_win_tcp_listen(ep, bsa);
	nni_mtx_unlock(&ep->acc_ev.mtx);
	return (rv);
}

static void
nni_win_tcp_acc_cancel(nni_win_event *evt)
{
	nni_plat_tcp_ep *ep = evt->ptr;
	SOCKET           s  = ep->s;

	if (s != INVALID_SOCKET) {
		CancelIoEx((HANDLE) s, &evt->olpd);
	}
}

static void
nni_win_tcp_acc_finish(nni_win_event *evt, nni_aio *aio)
{
	nni_plat_tcp_ep *  ep = evt->ptr;
	nni_plat_tcp_pipe *pipe;
	SOCKET             s;
	int                rv;
	int                len1;
	int                len2;
	SOCKADDR *         sa1;
	SOCKADDR *         sa2;

	s         = ep->acc_s;
	ep->acc_s = INVALID_SOCKET;

	if (s == INVALID_SOCKET) {
		return;
	}

	if (((rv = evt->status) != 0) ||
	    ((rv = nni_win_iocp_register((HANDLE) s)) != 0) ||
	    ((rv = nni_win_tcp_pipe_init(&pipe, s)) != 0)) {
		closesocket(s);
		nni_aio_finish_error(aio, rv);
		return;
	}

	// Collect the local and peer addresses, because normal getsockname
	// and getpeername don't work with AcceptEx.
	len1 = (int) sizeof(pipe->sockname);
	len2 = (int) sizeof(pipe->peername);
	ep->getacceptexsockaddrs(
	    ep->buf, 0, 256, 256, &sa1, &len1, &sa2, &len2);
	NNI_ASSERT(len1 > 0);
	NNI_ASSERT(len1 < (int) sizeof(SOCKADDR_STORAGE));
	NNI_ASSERT(len2 > 0);
	NNI_ASSERT(len2 < (int) sizeof(SOCKADDR_STORAGE));
	memcpy(&pipe->sockname, sa1, len1);
	memcpy(&pipe->peername, sa2, len2);

	nni_aio_set_output(aio, 0, pipe);
	nni_aio_finish(aio, 0, 0);
}

static int
nni_win_tcp_acc_start(nni_win_event *evt, nni_aio *aio)
{
	nni_plat_tcp_ep *ep = evt->ptr;
	SOCKET           s  = ep->s;
	SOCKET           acc_s;
	DWORD            cnt;

	NNI_ARG_UNUSED(aio);

	acc_s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (acc_s == INVALID_SOCKET) {
		evt->status = nni_win_error(GetLastError());
		evt->count  = 0;
		return (1);
	}
	ep->acc_s = acc_s;

	if (!ep->acceptex(s, acc_s, ep->buf, 0, 256, 256, &cnt, &evt->olpd)) {
		int rv = GetLastError();
		switch (rv) {
		case ERROR_IO_PENDING:
			// Normal asynchronous operation.  Wait for
			// completion.
			return (0);

		default:
			// Fast-fail (synchronous).
			evt->status = nni_win_error(rv);
			evt->count  = 0;
			return (1);
		}
	}

	// Synch completion right now.  I/O completion packet delivered
	// already.
	return (0);
}

void
nni_plat_tcp_ep_accept(nni_plat_tcp_ep *ep, nni_aio *aio)
{
	nni_win_event_submit(&ep->acc_ev, aio);
}

static void
nni_win_tcp_con_cancel(nni_win_event *evt)
{
	nni_plat_tcp_ep *ep = evt->ptr;
	SOCKET           s  = ep->s;

	if (s != INVALID_SOCKET) {
		CancelIoEx((HANDLE) s, &evt->olpd);
	}
}

static void
nni_win_tcp_con_finish(nni_win_event *evt, nni_aio *aio)
{
	nni_plat_tcp_ep *  ep = evt->ptr;
	nni_plat_tcp_pipe *pipe;
	SOCKET             s;
	int                rv;
	DWORD              yes = 1;
	int                len;

	s     = ep->s;
	ep->s = INVALID_SOCKET;

	// The socket was already registered with the IOCP.

	if (((rv = evt->status) != 0) ||
	    ((rv = nni_win_tcp_pipe_init(&pipe, s)) != 0)) {
		// The new pipe is already fine for us.  Discard
		// the old one, since failed to be able to use it.
		closesocket(s);
		nni_aio_finish_error(aio, rv);
		return;
	}

	(void) setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT,
	    (char *) &yes, sizeof(yes));

	// Windows seems to be unable to get peernames for sockets on
	// connect - perhaps because we supplied it already with connectex.
	// Rather than debugging it, just steal the address from the endpoint.
	memcpy(&pipe->peername, &ep->remaddr, ep->remlen);

	len = sizeof(pipe->sockname);
	(void) getsockname(s, (SOCKADDR *) &pipe->sockname, &len);

	nni_aio_set_output(aio, 0, pipe);
	nni_aio_finish(aio, 0, 0);
}

static int
nni_win_tcp_con_start(nni_win_event *evt, nni_aio *aio)
{
	nni_plat_tcp_ep *ep = evt->ptr;
	SOCKET           s;
	SOCKADDR_STORAGE bss;
	int              len;
	int              rv;
	int              family;

	NNI_ARG_UNUSED(aio);

	if (ep->loclen > 0) {
		family = ep->locaddr.ss_family;
	} else {
		family = ep->remaddr.ss_family;
	}

	s = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		evt->status = nni_win_error(GetLastError());
		evt->count  = 0;
		return (1);
	}

	nni_win_tcp_sockinit(s);

	// Windows ConnectEx requires the socket to be bound first.
	if (ep->loclen > 0) {
		bss = ep->locaddr;
		len = ep->loclen;
	} else {
		ZeroMemory(&bss, sizeof(bss));
		bss.ss_family = ep->remaddr.ss_family;
		len           = ep->remlen;
	}
	if (bind(s, (struct sockaddr *) &bss, len) < 0) {
		evt->status = nni_win_error(GetLastError());
		evt->count  = 0;
		closesocket(s);

		return (1);
	}
	// Register with the I/O completion port so we can get the
	// events for the next call.
	if ((rv = nni_win_iocp_register((HANDLE) s)) != 0) {
		closesocket(s);
		evt->status = rv;
		evt->count  = 0;
		return (1);
	}

	ep->s = s;
	if (!ep->connectex(s, (struct sockaddr *) &ep->remaddr, ep->remlen,
	        NULL, 0, NULL, &evt->olpd)) {
		if ((rv = GetLastError()) != ERROR_IO_PENDING) {
			closesocket(s);
			ep->s       = INVALID_SOCKET;
			evt->status = nni_win_error(rv);
			evt->count  = 0;
			return (1);
		}
	}
	return (0);
}

extern void
nni_plat_tcp_ep_connect(nni_plat_tcp_ep *ep, nni_aio *aio)
{
	nni_win_event_submit(&ep->con_ev, aio);
}

int
nni_plat_tcp_ntop(const nni_sockaddr *sa, char *ipstr, char *portstr)
{
	void *   ap;
	uint16_t port;
	int      af;
	switch (sa->s_family) {
	case NNG_AF_INET:
		ap   = (void *) &sa->s_in.sa_addr;
		port = sa->s_in.sa_port;
		af   = AF_INET;
		break;
	case NNG_AF_INET6:
		ap   = (void *) &sa->s_in6.sa_addr;
		port = sa->s_in6.sa_port;
		af   = AF_INET6;
		break;
	default:
		return (NNG_EINVAL);
	}
	if (ipstr != NULL) {
		if (af == AF_INET6) {
			size_t l;
			ipstr[0] = '[';
			InetNtopA(af, ap, ipstr + 1, INET6_ADDRSTRLEN);
			l          = strlen(ipstr);
			ipstr[l++] = ']';
			ipstr[l++] = '\0';
		} else {
			InetNtopA(af, ap, ipstr, INET6_ADDRSTRLEN);
		}
	}
	if (portstr != NULL) {
#ifdef NNG_LITTLE_ENDIAN
		port = ((port >> 8) & 0xff) | ((port & 0xff) << 8);
#endif
		snprintf(portstr, 6, "%u", port);
	}
	return (0);
}

int
nni_win_tcp_sysinit(void)
{
	WSADATA data;
	if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
		NNI_ASSERT(LOBYTE(data.wVersion) == 2);
		NNI_ASSERT(HIBYTE(data.wVersion) == 2);
		return (nni_win_error(GetLastError()));
	}
	return (0);
}

void
nni_win_tcp_sysfini(void)
{
	WSACleanup();
}

#endif // NNG_PLATFORM_WINDOWS
