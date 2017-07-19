//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_WINDOWS

#include <stdio.h>

struct nni_plat_tcp_pipe {
	SOCKET        s;
	nni_win_event rcv_ev;
	nni_win_event snd_ev;
};

struct nni_plat_tcp_ep {
	SOCKET        s;
	SOCKET        acc_s;
	nni_win_event con_ev;
	nni_win_event acc_ev;
	int           mode;
	int           started;
	int           bound;

	SOCKADDR_STORAGE remaddr;
	int              remlen;
	SOCKADDR_STORAGE locaddr;
	int              loclen;

	char buf[512]; // to hold acceptex results

	// We have to lookup some function pointers using ioctls.  Winsock,
	// gotta love it.
	LPFN_CONNECTEX connectex;
	LPFN_ACCEPTEX  acceptex;
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
nni_win_tcp_addr(SOCKADDR_STORAGE *ss, const nni_sockaddr *sa)
{
	SOCKADDR_IN * sin;
	SOCKADDR_IN6 *sin6;

	switch (sa->s_un.s_family) {
	case NNG_AF_INET:
		sin = (void *) ss;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family      = PF_INET;
		sin->sin_port        = sa->s_un.s_in.sa_port;
		sin->sin_addr.s_addr = sa->s_un.s_in.sa_addr;
		return (sizeof(*sin));

	case NNG_AF_INET6:
		sin6 = (void *) ss;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = PF_INET6;
		sin6->sin6_port   = sa->s_un.s_in6.sa_port;
		memcpy(sin6->sin6_addr.s6_addr, sa->s_un.s_in6.sa_addr, 16);
		return (sizeof(*sin6));
	}
	return (-1);
}

static int
nni_win_tcp_pipe_start(nni_win_event *evt, nni_aio *aio)
{
	int                rv;
	SOCKET             s;
	WSABUF             iov[4];
	DWORD              niov;
	DWORD              flags;
	nni_plat_tcp_pipe *pipe = evt->ptr;
	int                i;

	NNI_ASSERT(aio->a_niov > 0);
	NNI_ASSERT(aio->a_niov <= 4);
	NNI_ASSERT(aio->a_iov[0].iov_len > 0);
	NNI_ASSERT(aio->a_iov[0].iov_buf != NULL);

	niov = aio->a_niov;

	// Put the AIOs in Windows form.
	for (i = 0; i < aio->a_niov; i++) {
		iov[i].buf = aio->a_iov[i].iov_buf;
		iov[i].len = aio->a_iov[i].iov_len;
	}

	if ((s = pipe->s) == INVALID_SOCKET) {
		evt->status = ERROR_INVALID_HANDLE;
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

	if ((rv == SOCKET_ERROR) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		evt->status = rv;
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

	if (CancelIoEx((HANDLE) pipe->s, &evt->olpd)) {
		DWORD cnt;

		// If we canceled, make sure that we've completely
		// finished with the overlapped.
		GetOverlappedResult((HANDLE) pipe->s, &evt->olpd, &cnt, TRUE);
	}
}

static void
nni_win_tcp_pipe_finish(nni_win_event *evt, nni_aio *aio)
{
	int   rv;
	DWORD cnt;

	cnt = evt->count;
	if ((rv = evt->status) == 0) {
		int i;
		aio->a_count += cnt;

		while (cnt > 0) {
			// If we didn't write the first full iov,
			// then we're done for now.  Record progress
			// and move on.
			if (cnt < aio->a_iov[0].iov_len) {
				aio->a_iov[0].iov_len -= cnt;
				aio->a_iov[0].iov_buf =
				    (char *) aio->a_iov[0].iov_buf + cnt;
				break;
			}

			// We consumed the full iov, so just move the
			// remaininng ones up, and decrement count handled.
			cnt -= aio->a_iov[0].iov_len;
			for (i = 1; i < aio->a_niov; i++) {
				aio->a_iov[i - 1] = aio->a_iov[i];
			}
			NNI_ASSERT(aio->a_niov > 0);
			aio->a_niov--;
		}

		if (aio->a_niov > 0) {
			// If we have more to do, submit it!
			nni_win_event_resubmit(evt, aio);
			return;
		}
	}

	// All done; hopefully successfully.
	nni_aio_finish(aio, nni_win_error(rv), aio->a_count);
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

void
nni_plat_tcp_pipe_fini(nni_plat_tcp_pipe *pipe)
{
	nni_plat_tcp_pipe_close(pipe);

	nni_win_event_fini(&pipe->snd_ev);
	nni_win_event_fini(&pipe->rcv_ev);
	NNI_FREE_STRUCT(pipe);
}

extern int nni_tcp_parse_url(char *, char **, char **, char **, char **);

int
nni_plat_tcp_ep_init(nni_plat_tcp_ep **epp, const char *url, int mode)
{
	char             buf[NNG_MAXADDRLEN];
	nni_plat_tcp_ep *ep;
	char *           rhost;
	char *           rserv;
	char *           lhost;
	char *           lserv;
	int              rv;
	nni_aio          aio;
	SOCKET           s;
	DWORD            nbytes;
	GUID             guid1 = WSAID_CONNECTEX;
	GUID             guid2 = WSAID_ACCEPTEX;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ZeroMemory(ep, sizeof(ep));

	ep->mode = mode;
	ep->s    = INVALID_SOCKET;

	nni_aio_init(&aio, NULL, NULL);

	snprintf(buf, sizeof(buf), "%s", url);
	if (mode == NNI_EP_MODE_DIAL) {
		rv = nni_tcp_parse_url(buf, &rhost, &rserv, &lhost, &lserv);
		if (rv != 0) {
			goto fail;
		}
		// Have to ahve a remote destination.
		if ((rhost == NULL) || (rserv == NULL)) {
			rv = NNG_EADDRINVAL;
			goto fail;
		}
	} else {
		rv = nni_tcp_parse_url(buf, &lhost, &lserv, &rhost, &rserv);
		if (rv != 0) {
			goto fail;
		}
		// Remote destination makes no sense when listening.
		if ((rhost != NULL) || (rserv != NULL)) {
			rv = NNG_EADDRINVAL;
			goto fail;
		}
		if (lserv == NULL) {
			// missing port to listen on!
			rv = NNG_EADDRINVAL;
			goto fail;
		}
	}

	if ((rserv != NULL) || (rhost != NULL)) {
		nni_plat_tcp_resolv(rhost, rserv, NNG_AF_INET6, 0, &aio);
		nni_aio_wait(&aio);
		if ((rv = nni_aio_result(&aio)) != 0) {
			goto fail;
		}
		ep->remlen = nni_win_tcp_addr(&ep->remaddr, &aio.a_addrs[0]);
	}

	if ((lserv != NULL) || (lhost != NULL)) {
		nni_plat_tcp_resolv(lhost, lserv, NNG_AF_INET6, 1, &aio);
		nni_aio_wait(&aio);
		if ((rv = nni_aio_result(&aio)) != 0) {
			goto fail;
		}
		ep->loclen = nni_win_tcp_addr(&ep->locaddr, &aio.a_addrs[0]);
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

	nni_aio_fini(&aio);
	*epp = ep;
	return (0);

fail:
	if (s != INVALID_SOCKET) {
		closesocket(s);
	}
	nni_plat_tcp_ep_fini(ep);
	nni_aio_fini(&aio);
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
nni_win_tcp_listen(nni_plat_tcp_ep *ep)
{
	int    rv;
	BOOL   yes;
	SOCKET s;

	if (ep->mode != NNI_EP_MODE_LISTEN) {
		return (NNG_EINVAL);
	}
	if (ep->started) {
		return (NNG_EBUSY);
	}

	s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
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
nni_plat_tcp_ep_listen(nni_plat_tcp_ep *ep)
{
	int rv;

	nni_mtx_lock(&ep->acc_ev.mtx);
	rv = nni_win_tcp_listen(ep);
	nni_mtx_unlock(&ep->acc_ev.mtx);
	return (rv);
}

static void
nni_win_tcp_acc_cancel(nni_win_event *evt)
{
	nni_plat_tcp_ep *ep = evt->ptr;
	SOCKET           s  = ep->s;

	if ((s != INVALID_SOCKET) && CancelIoEx((HANDLE) s, &evt->olpd)) {
		DWORD cnt;

		// If we canceled, make sure that we've completely
		// finished with the overlapped.
		GetOverlappedResult((HANDLE) s, &evt->olpd, &cnt, TRUE);
	}
}

static void
nni_win_tcp_acc_finish(nni_win_event *evt, nni_aio *aio)
{
	nni_plat_tcp_ep *  ep = evt->ptr;
	nni_plat_tcp_pipe *pipe;
	SOCKET             s;
	int                rv;

	s         = ep->acc_s;
	ep->acc_s = INVALID_SOCKET;

	if (s == INVALID_SOCKET) {
		return;
	}

	if ((rv = evt->status) != 0) {
		closesocket(s);
		nni_aio_finish(aio, nni_win_error(rv), 0);
		return;
	}

	if (((rv = nni_win_iocp_register((HANDLE) s)) != 0) ||
	    ((rv = nni_win_tcp_pipe_init(&pipe, s)) != 0)) {
		closesocket(s);
		nni_aio_finish(aio, rv, 0);
		return;
	}

	if (nni_aio_finish_pipe(aio, 0, pipe) != 0) {
		nni_plat_tcp_pipe_fini(pipe);
	}
}

static int
nni_win_tcp_acc_start(nni_win_event *evt, nni_aio *aio)
{
	nni_plat_tcp_ep *ep = evt->ptr;
	SOCKET           s  = ep->s;
	SOCKET           acc_s;
	DWORD            cnt;

	acc_s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (acc_s == INVALID_SOCKET) {
		evt->status = GetLastError();
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
			evt->status = rv;
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
	aio->a_pipe = NULL;
	nni_win_event_submit(&ep->acc_ev, aio);
}

static void
nni_win_tcp_con_cancel(nni_win_event *evt)
{
	nni_plat_tcp_ep *ep = evt->ptr;
	SOCKET           s  = ep->s;

	if ((s != INVALID_SOCKET) && CancelIoEx((HANDLE) s, &evt->olpd)) {
		DWORD cnt;

		// If we canceled, make sure that we've completely
		// finished with the overlapped.
		GetOverlappedResult((HANDLE) s, &evt->olpd, &cnt, TRUE);
	}
}

static void
nni_win_tcp_con_finish(nni_win_event *evt, nni_aio *aio)
{
	nni_plat_tcp_ep *  ep = evt->ptr;
	nni_plat_tcp_pipe *pipe;
	SOCKET             s;
	int                rv;

	s     = ep->s;
	ep->s = INVALID_SOCKET;

	if ((rv = evt->status) != 0) {
		closesocket(s);
		nni_aio_finish(aio, nni_win_error(rv), 0);
		return;
	}

	// The socket was already registere with the IOCP.

	if ((rv = nni_win_tcp_pipe_init(&pipe, s)) != 0) {
		// The new pipe is already fine for us.  Discard
		// the old one, since failed to be able to use it.
		closesocket(s);
		nni_aio_finish(aio, rv, 0);
		return;
	}

	aio->a_pipe = pipe;
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

	s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		evt->status = GetLastError();
		evt->count  = 0;
		return (1);
	}

	nni_win_tcp_sockinit(s);

	// Windows ConnectEx requires the socket to be bound first.
	if (ep->loclen != 0) {
		bss = ep->locaddr;
		len = ep->loclen;
	} else {
		ZeroMemory(&bss, sizeof(bss));
		bss.ss_family = ep->remaddr.ss_family;
		len           = ep->remlen;
	}
	if (bind(s, (struct sockaddr *) &bss, len) < 0) {
		evt->status = GetLastError();
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
			evt->status = rv;
			evt->count  = 0;
			return (1);
		}
	}
	return (0);
}

extern void
nni_plat_tcp_ep_connect(nni_plat_tcp_ep *ep, nni_aio *aio)
{
	aio->a_pipe = NULL;
	nni_win_event_submit(&ep->con_ev, aio);
}

int
nni_win_tcp_sysinit(void)
{
	WSADATA data;
	WORD    ver;
	ver = MAKEWORD(2, 2);
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

#else

// Suppress empty symbols warnings in ranlib.
int nni_win_net_not_used = 0;

#endif // PLATFORM_WINDOWS
