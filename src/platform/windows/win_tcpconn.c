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

struct nni_tcp_conn {
	SOCKET           s;
	nni_win_event    rcv_ev;
	nni_win_event    snd_ev;
	SOCKADDR_STORAGE sockname;
	SOCKADDR_STORAGE peername;
};

static int  tcp_conn_start(nni_win_event *, nni_aio *);
static void tcp_conn_finish(nni_win_event *, nni_aio *);
static void tcp_conn_cancel(nni_win_event *);

static nni_win_event_ops tcp_conn_ops = {
	.wev_start  = tcp_conn_start,
	.wev_finish = tcp_conn_finish,
	.wev_cancel = tcp_conn_cancel,
};

static int
tcp_conn_start(nni_win_event *evt, nni_aio *aio)
{
	int           rv;
	SOCKET        s;
	DWORD         niov;
	DWORD         flags;
	nni_tcp_conn *c = evt->ptr;
	unsigned      i;
	unsigned      naiov;
	nni_iov *     aiov;
	WSABUF *      iov;

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

	if ((s = c->s) == INVALID_SOCKET) {
		_freea(iov);
		evt->status = NNG_ECLOSED;
		evt->count  = 0;
		return (1);
	}

	// Note that the IOVs for the event were prepared on entry already.
	// The actual aio's iov array we don't touch.

	evt->count = 0;
	flags      = 0;
	if (evt == &c->snd_ev) {
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
tcp_conn_cancel(nni_win_event *evt)
{
	nni_tcp_conn *c = evt->ptr;

	(void) CancelIoEx((HANDLE) c->s, &evt->olpd);
}

static void
tcp_conn_finish(nni_win_event *evt, nni_aio *aio)
{
	if ((evt->status == 0) && (evt->count == 0)) {
		// Windows sometimes returns a zero read.  Convert these
		// into an NNG_ECLOSED.  (We are never supposed to come
		// back with zero length read.)
		evt->status = NNG_ECLOSED;
	}
	nni_aio_finish(aio, evt->status, evt->count);
}

int
nni_win_tcp_conn_init(nni_tcp_conn **connp, SOCKET s)
{
	nni_tcp_conn *c;
	int           rv;
	BOOL          yes;
	DWORD         no;

	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_win_event_init(&c->rcv_ev, &tcp_conn_ops, c)) != 0) ||
	    ((rv = nni_win_event_init(&c->snd_ev, &tcp_conn_ops, c)) != 0)) {
		nni_tcp_conn_fini(c);
		return (rv);
	}

	// Don't inherit the handle (CLOEXEC really).
	SetHandleInformation((HANDLE) s, HANDLE_FLAG_INHERIT, 0);

	no = 0;
	(void) setsockopt(
	    s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &no, sizeof(no));
	yes = 1;
	(void) setsockopt(
	    s, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes));

	c->s   = s;
	*connp = c;
	return (0);
}

void
nni_win_tcp_conn_set_addrs(
    nni_tcp_conn *c, const SOCKADDR_STORAGE *loc, const SOCKADDR_STORAGE *rem)
{
	memcpy(&c->sockname, loc, sizeof(*loc));
	memcpy(&c->peername, rem, sizeof(*rem));
}

void
nni_tcp_conn_send(nni_tcp_conn *c, nni_aio *aio)
{
	nni_win_event_submit(&c->snd_ev, aio);
}

void
nni_tcp_conn_recv(nni_tcp_conn *c, nni_aio *aio)
{
	nni_win_event_submit(&c->rcv_ev, aio);
}

void
nni_tcp_conn_close(nni_tcp_conn *c)
{
	SOCKET s;

	nni_win_event_close(&c->rcv_ev);

	if ((s = c->s) != INVALID_SOCKET) {
		c->s = INVALID_SOCKET;
		closesocket(s);
	}
}

int
nni_tcp_conn_peername(nni_tcp_conn *c, nni_sockaddr *sa)
{
	if (nni_win_sockaddr2nn(sa, &c->peername) < 0) {
		return (NNG_EADDRINVAL);
	}
	return (0);
}

int
nni_tcp_conn_sockname(nni_tcp_conn *c, nni_sockaddr *sa)
{
	if (nni_win_sockaddr2nn(sa, &c->sockname) < 0) {
		return (NNG_EADDRINVAL);
	}
	return (0);
}

int
nni_tcp_conn_set_nodelay(nni_tcp_conn *c, bool val)
{
	BOOL b;
	b = val ? TRUE : FALSE;
	if (setsockopt(
	        c->s, IPPROTO_TCP, TCP_NODELAY, (void *) &b, sizeof(b)) != 0) {
		return (nni_win_error(WSAGetLastError()));
	}
	return (0);
}

int
nni_tcp_conn_set_keepalive(nni_tcp_conn *c, bool val)
{
	BOOL b;
	b = val ? TRUE : FALSE;
	if (setsockopt(
	        c->s, SOL_SOCKET, SO_KEEPALIVE, (void *) &b, sizeof(b)) != 0) {
		return (nni_win_error(WSAGetLastError()));
	}
	return (0);
}

void
nni_tcp_conn_fini(nni_tcp_conn *c)
{
	nni_tcp_conn_close(c);

	nni_win_event_fini(&c->snd_ev);
	nni_win_event_fini(&c->rcv_ev);
	NNI_FREE_STRUCT(c);
}

#endif // NNG_PLATFORM_WINDOWS
