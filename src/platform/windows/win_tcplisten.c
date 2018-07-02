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
#include <stdbool.h>
#include <stdio.h>

struct nni_tcp_listener {
	SOCKET                    s;
	SOCKET                    acc_s;
	nni_win_event             acc_ev;
	bool                      started;
	char                      buf[512]; // to hold acceptex results
	LPFN_ACCEPTEX             acceptex;
	LPFN_GETACCEPTEXSOCKADDRS getacceptexsockaddrs;
};

static int  tcp_listener_start(nni_win_event *, nni_aio *);
static void tcp_listener_finish(nni_win_event *, nni_aio *);
static void tcp_listener_cancel(nni_win_event *);

static nni_win_event_ops tcp_listener_ops = {
	.wev_start  = tcp_listener_start,
	.wev_finish = tcp_listener_finish,
	.wev_cancel = tcp_listener_cancel,
};

int
nni_tcp_listener_init(nni_tcp_listener **lp)
{
	nni_tcp_listener *l;
	int               rv;
	SOCKET            s;
	DWORD             nbytes;
	GUID              guid1 = WSAID_ACCEPTEX;
	GUID              guid2 = WSAID_GETACCEPTEXSOCKADDRS;

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	ZeroMemory(l, sizeof(*l));

	l->s = INVALID_SOCKET;

	// Create a scratch socket for use with ioctl.
	s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}

	// Look up the function pointer.
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid1,
	        sizeof(guid1), &l->acceptex, sizeof(l->acceptex), &nbytes,
	        NULL, NULL) == SOCKET_ERROR) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid2,
	        sizeof(guid2), &l->getacceptexsockaddrs,
	        sizeof(l->getacceptexsockaddrs), &nbytes, NULL,
	        NULL) == SOCKET_ERROR) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}

	closesocket(s);
	s = INVALID_SOCKET;

	// Now initialize the win events for later use.
	rv = nni_win_event_init(&l->acc_ev, &tcp_listener_ops, l);
	if (rv != 0) {
		goto fail;
	}

	*lp = l;
	return (0);

fail:
	if (s != INVALID_SOCKET) {
		closesocket(s);
	}
	nni_tcp_listener_fini(l);
	return (rv);
}

void
nni_tcp_listener_close(nni_tcp_listener *l)
{
	nni_win_event_close(&l->acc_ev);
	if (l->s != INVALID_SOCKET) {
		closesocket(l->s);
		l->s = INVALID_SOCKET;
	}
	if (l->acc_s != INVALID_SOCKET) {
		closesocket(l->acc_s);
	}
}

void
nni_tcp_listener_fini(nni_tcp_listener *l)
{
	nni_tcp_listener_close(l);
	NNI_FREE_STRUCT(l);
}

int
nni_tcp_listener_listen(nni_tcp_listener *l, nni_sockaddr *sa)
{
	int              rv;
	SOCKET           s;
	SOCKADDR_STORAGE ss;
	BOOL             yes;
	DWORD            no;
	int              len;

	if ((sa->s_family != NNG_AF_INET) && (sa->s_family != NNG_AF_INET6)) {
		return (NNG_EADDRINVAL);
	}
	len = nni_win_nn2sockaddr(&ss, sa);

	s = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		return (nni_win_error(GetLastError()));
	}

	// Don't inherit the handle (CLOEXEC really).
	SetHandleInformation((HANDLE) s, HANDLE_FLAG_INHERIT, 0);

	no = 0;
	(void) setsockopt(
	    s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &no, sizeof(no));
	yes = 1;
	(void) setsockopt(
	    s, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes));

	if ((rv = nni_win_iocp_register((HANDLE) s)) != 0) {
		closesocket(s);
		return (rv);
	}

	// Make sure that we use the address exclusively.  Windows lets
	// others hijack us by default.
	yes = 1;
	rv  = setsockopt(
            s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *) &yes, sizeof(yes));
	if (rv != 0) {
		rv = nni_win_error(GetLastError());
		closesocket(s);
		return (rv);
	}

	if (l->started) {
		closesocket(s);
		return (NNG_EBUSY);
	}
	if (bind(s, (struct sockaddr *) &ss, len) != 0) {
		rv = nni_win_error(GetLastError());
		closesocket(s);
		return (rv);
	}

	// Update the bound address. This should never fail.
	if ((rv = getsockname(s, (SOCKADDR *) &ss, &len)) == 0) {
		nni_win_sockaddr2nn(sa, &ss);
	}

	if (listen(s, SOMAXCONN) != 0) {
		rv = nni_win_error(GetLastError());
		closesocket(s);
		return (rv);
	}

	l->s       = s;
	l->started = true;

	return (0);
}

static void
tcp_listener_cancel(nni_win_event *evt)
{
	nni_tcp_listener *l = evt->ptr;
	SOCKET            s = l->s;

	if (s != INVALID_SOCKET) {
		CancelIoEx((HANDLE) s, &evt->olpd);
	}
}

static void
tcp_listener_finish(nni_win_event *evt, nni_aio *aio)
{
	nni_tcp_listener *l = evt->ptr;
	nni_tcp_conn *    c;
	SOCKET            s;
	int               rv;
	int               len1;
	int               len2;
	SOCKADDR *        sa1;
	SOCKADDR *        sa2;
	SOCKADDR_STORAGE  ss1;
	SOCKADDR_STORAGE  ss2;

	s        = l->acc_s;
	l->acc_s = INVALID_SOCKET;

	if (s == INVALID_SOCKET) {
		return;
	}

	if (((rv = evt->status) != 0) ||
	    ((rv = nni_win_iocp_register((HANDLE) s)) != 0) ||
	    ((rv = nni_win_tcp_conn_init(&c, s)) != 0)) {
		closesocket(s);
		nni_aio_finish_error(aio, rv);
		return;
	}

	// Collect the local and peer addresses, because normal getsockname
	// and getpeername don't work with AcceptEx.
	len1 = (int) sizeof(sa1);
	len2 = (int) sizeof(sa2);
	l->getacceptexsockaddrs(l->buf, 0, 256, 256, &sa1, &len1, &sa2, &len2);
	NNI_ASSERT(len1 > 0);
	NNI_ASSERT(len1 < (int) sizeof(SOCKADDR_STORAGE));
	NNI_ASSERT(len2 > 0);
	NNI_ASSERT(len2 < (int) sizeof(SOCKADDR_STORAGE));
	memcpy(&ss1, sa1, len1);
	memcpy(&ss2, sa2, len2);

	nni_win_tcp_conn_set_addrs(c, &ss1, &ss2);

	nni_aio_set_output(aio, 0, c);
	nni_aio_finish(aio, 0, 0);
}

static int
tcp_listener_start(nni_win_event *evt, nni_aio *aio)
{
	nni_tcp_listener *l = evt->ptr;
	SOCKET            s = l->s;
	SOCKET            acc_s;
	DWORD             cnt;
	int               rv;

	NNI_ARG_UNUSED(aio);

	// Windows requires us to explicity create the socket before
	// calling accept on it.
	acc_s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (acc_s == INVALID_SOCKET) {
		evt->status = nni_win_error(GetLastError());
		evt->count  = 0;
		return (1);
	}
	l->acc_s = acc_s;

	if ((!l->acceptex(s, acc_s, l->buf, 0, 256, 256, &cnt, &evt->olpd)) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Fast failure (synchronous.)
		evt->status = nni_win_error(rv);
		evt->count  = 0;
		return (1);
	}

	// This is either success, or asynchronous completion.  In either
	// event the I/O completion packet is delivered.
	return (0);
}

void
nni_tcp_listener_accept(nni_tcp_listener *l, nni_aio *aio)
{
	nni_win_event_submit(&l->acc_ev, aio);
}

#endif // NNG_PLATFORM_WINDOWS
