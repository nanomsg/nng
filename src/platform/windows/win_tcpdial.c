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

// XXX: This dialer code unfortunately only supports a single outstanding
// connection request at a time.  Fixing it will require creating
// subordinate contexts.

static int  tcp_dialer_start(nni_win_event *, nni_aio *);
static void tcp_dialer_finish(nni_win_event *, nni_aio *);
static void tcp_dialer_cancel(nni_win_event *);

struct nni_tcp_dialer {
	SOCKET           s;
	nni_win_event    con_ev;
	SOCKADDR_STORAGE ss;
	int              sslen;
	LPFN_CONNECTEX   connectex; // looked up name via ioctl
};

static nni_win_event_ops tcp_dialer_ops = {
	.wev_start  = tcp_dialer_start,
	.wev_finish = tcp_dialer_finish,
	.wev_cancel = tcp_dialer_cancel,
};

int
nni_tcp_dialer_init(nni_tcp_dialer **dp)
{
	nni_tcp_dialer *d;
	int             rv;
	SOCKET          s;
	DWORD           nbytes;
	GUID            guid = WSAID_CONNECTEX;

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	ZeroMemory(d, sizeof(*d));

	d->s = INVALID_SOCKET;

	// Create a scratch socket for use with ioctl.
	s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}

	// Look up the function pointer.
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid,
	        sizeof(guid), &d->connectex, sizeof(d->connectex), &nbytes,
	        NULL, NULL) == SOCKET_ERROR) {
		rv = nni_win_error(GetLastError());
		goto fail;
	}

	closesocket(s);
	s = INVALID_SOCKET;

	// Now initialize the win events for later use.
	rv = nni_win_event_init(&d->con_ev, &tcp_dialer_ops, d);
	if (rv != 0) {
		goto fail;
	}

	*dp = d;
	return (0);

fail:
	if (s != INVALID_SOCKET) {
		closesocket(s);
	}
	nni_tcp_dialer_fini(d);
	return (rv);
}

void
nni_tcp_dialer_close(nni_tcp_dialer *d)
{
	nni_win_event_close(&d->con_ev);
	if (d->s != INVALID_SOCKET) {
		closesocket(d->s);
		d->s = INVALID_SOCKET;
	}
}

void
nni_tcp_dialer_fini(nni_tcp_dialer *d)
{
	nni_tcp_dialer_close(d);
	NNI_FREE_STRUCT(d);
}

static void
tcp_dialer_cancel(nni_win_event *evt)
{
	nni_tcp_dialer *d = evt->ptr;
	SOCKET          s = d->s;

	if (s != INVALID_SOCKET) {
		CancelIoEx((HANDLE) s, &evt->olpd);
	}
}

static void
tcp_dialer_finish(nni_win_event *evt, nni_aio *aio)
{
	nni_tcp_dialer * d = evt->ptr;
	nni_tcp_conn *   c;
	SOCKET           s;
	int              rv;
	DWORD            yes = 1;
	int              len;
	SOCKADDR_STORAGE ss;

	s    = d->s;
	d->s = INVALID_SOCKET;

	// The socket was already registered with the IOCP.

	if (((rv = evt->status) != 0) ||
	    ((rv = nni_win_tcp_conn_init(&c, s)) != 0)) {
		// The new pipe is already fine for us.  Discard
		// the old one, since failed to be able to use it.
		closesocket(s);
		nni_aio_finish_error(aio, rv);
		return;
	}

	(void) setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT,
	    (char *) &yes, sizeof(yes));

	len = sizeof(ss);
	(void) getsockname(s, (SOCKADDR *) &ss, &len);

	// Windows seems to be unable to get peernames for sockets on
	// connect - perhaps because we supplied it already with connectex.
	// For now, just steal the address from the endpoint.
	nni_win_tcp_conn_set_addrs(c, &ss, &d->ss);

	nni_aio_set_output(aio, 0, c);
	nni_aio_finish(aio, 0, 0);
}

static int
tcp_dialer_start(nni_win_event *evt, nni_aio *aio)
{
	nni_tcp_dialer * d = evt->ptr;
	SOCKET           s;
	SOCKADDR_STORAGE bss;
	int              len;
	int              rv;
	DWORD            no;

	NNI_ARG_UNUSED(aio);

	s = socket(d->ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		evt->status = nni_win_error(GetLastError());
		evt->count  = 0;
		return (1);
	}

	// Don't inherit the handle (CLOEXEC really).
	SetHandleInformation((HANDLE) s, HANDLE_FLAG_INHERIT, 0);

	no = 0;
	(void) setsockopt(
	    s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &no, sizeof(no));

	// Windows ConnectEx requires the socket to be bound first.
	// We just bind to an ephemeral address in the same family.
	ZeroMemory(&bss, sizeof(bss));
	bss.ss_family = d->ss.ss_family;
	len           = d->sslen;
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

	d->s = s;
	if (!d->connectex(s, (struct sockaddr *) &d->ss, d->sslen, NULL, 0,
	        NULL, &evt->olpd)) {
		if ((rv = GetLastError()) != ERROR_IO_PENDING) {
			closesocket(s);
			d->s        = INVALID_SOCKET;
			evt->status = nni_win_error(rv);
			evt->count  = 0;
			return (1);
		}
	}
	return (0);
}

extern void
nni_tcp_dialer_dial(nni_tcp_dialer *d, const nni_sockaddr *sa, nni_aio *aio)
{
	d->sslen = nni_win_nn2sockaddr(&d->ss, sa);

	nni_win_event_submit(&d->con_ev, aio);
}

#endif // NNG_PLATFORM_WINDOWS
