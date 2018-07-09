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

#include "win_tcp.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <malloc.h>
#include <stdio.h>

static void
tcp_aio_remove(nni_tcp_conn *c, nni_aio *aio)
{
	nni_aio_list_remove(aio);
	if (c->closed) {
		nni_cv_wake(&c->cv);
	}
}

static void
tcp_recv_start(nni_tcp_conn *c)
{
	nni_aio *aio;
	int      rv;
	DWORD    niov;
	DWORD    flags;
	unsigned i;
	unsigned naiov;
	nni_iov *aiov;
	WSABUF * iov;

again:
	if ((aio = nni_list_first(&c->recv_aios)) == NULL) {
		return;
	}

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

	flags = 0;
	rv    = WSARecv(c->s, iov, niov, NULL, &flags, &c->recv_io.olpd, NULL);
	_freea(iov);

	if ((rv == SOCKET_ERROR) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		tcp_aio_remove(c, aio);
		nni_aio_finish_error(aio, nni_win_error(rv));
		goto again;
	}
}

static void
tcp_recv_cb(nni_win_io *io, int rv, size_t num)
{
	nni_aio *     aio;
	nni_tcp_conn *c = io->ptr;
	nni_mtx_lock(&c->mtx);
	aio = nni_list_first(&c->recv_aios);
	tcp_aio_remove(c, aio); // should always be at head
	tcp_recv_start(c);
	nni_mtx_unlock(&c->mtx);

	if ((rv == 0) && (num == 0)) {
		// A zero byte receive is a remote close from the peer.
		rv = NNG_ECLOSED;
	}
	nni_aio_finish_synch(aio, rv, num);
}

static void
tcp_recv_cancel(nni_aio *aio, int rv)
{
	nni_tcp_conn *c = nni_aio_get_prov_data(aio);
	nni_mtx_lock(&c->mtx);
	if (aio == nni_list_first(&c->recv_aios)) {
		CancelIoEx((HANDLE) c->s, &c->recv_io.olpd);
	} else if (nni_aio_list_active(aio)) {
		tcp_aio_remove(c, aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&c->mtx);
}

void
nni_tcp_conn_recv(nni_tcp_conn *c, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);
	if (c->closed) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, tcp_recv_cancel, c)) != 0) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&c->recv_aios, aio);
	if (aio == nni_list_first(&c->recv_aios)) {
		tcp_recv_start(c);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
tcp_send_start(nni_tcp_conn *c)
{
	nni_aio *aio;
	int      rv;
	DWORD    niov;
	unsigned i;
	unsigned naiov;
	nni_iov *aiov;
	WSABUF * iov;

again:
	if ((aio = nni_list_first(&c->send_aios)) == NULL) {
		return;
	}

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

	rv = WSASend(c->s, iov, niov, NULL, 0, &c->send_io.olpd, NULL);
	_freea(iov);

	if ((rv == SOCKET_ERROR) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		tcp_aio_remove(c, aio);
		nni_aio_finish_error(aio, nni_win_error(rv));
		goto again;
	}
}

static void
tcp_send_cancel(nni_aio *aio, int rv)
{
	nni_tcp_conn *c = nni_aio_get_prov_data(aio);
	nni_mtx_lock(&c->mtx);
	if (aio == nni_list_first(&c->send_aios)) {
		CancelIoEx((HANDLE) c->s, &c->send_io.olpd);
	} else if (nni_aio_list_active(aio)) {
		tcp_aio_remove(c, aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
tcp_send_cb(nni_win_io *io, int rv, size_t num)
{
	nni_aio *     aio;
	nni_tcp_conn *c = io->ptr;
	nni_mtx_lock(&c->mtx);
	aio = nni_list_first(&c->send_aios);
	tcp_aio_remove(c, aio); // should always be at head
	tcp_send_start(c);
	nni_mtx_unlock(&c->mtx);

	nni_aio_finish_synch(aio, rv, num);
}

void
nni_tcp_conn_send(nni_tcp_conn *c, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);
	if (c->closed) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, tcp_send_cancel, c)) != 0) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&c->send_aios, aio);
	if (aio == nni_list_first(&c->send_aios)) {
		tcp_send_start(c);
	}
	nni_mtx_unlock(&c->mtx);
}

int
nni_win_tcp_conn_init(nni_tcp_conn **connp, SOCKET s)
{
	nni_tcp_conn *c;
	int           rv;
	BOOL          yes;
	DWORD         no;

	// Don't inherit the handle (CLOEXEC really).
	SetHandleInformation((HANDLE) s, HANDLE_FLAG_INHERIT, 0);

	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}
	c->s = INVALID_SOCKET;
	nni_mtx_init(&c->mtx);
	nni_cv_init(&c->cv, &c->mtx);
	nni_aio_list_init(&c->recv_aios);
	nni_aio_list_init(&c->send_aios);
	c->conn_aio = NULL;

	if (((rv = nni_win_io_init(&c->recv_io, tcp_recv_cb, c)) != 0) ||
	    ((rv = nni_win_io_init(&c->send_io, tcp_send_cb, c)) != 0) ||
	    ((rv = nni_win_io_register((HANDLE) s)) != 0)) {
		nni_tcp_conn_fini(c);
		return (rv);
	}

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
nni_tcp_conn_close(nni_tcp_conn *c)
{
	nni_mtx_lock(&c->mtx);
	if (!c->closed) {
		nni_aio *aio;
		NNI_LIST_FOREACH (&c->recv_aios, aio) {
			nni_aio_close(aio);
		}
		NNI_LIST_FOREACH (&c->send_aios, aio) {
			nni_aio_close(aio);
		}
		if (c->s != INVALID_SOCKET) {
			closesocket(c->s);
			c->s = INVALID_SOCKET;
		}
		c->closed = true;
	}
	nni_mtx_unlock(&c->mtx);
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

	nni_mtx_lock(&c->mtx);
	while ((!nni_list_empty(&c->recv_aios)) ||
	    (!nni_list_empty(&c->send_aios))) {
		nni_cv_wait(&c->cv);
	}
	nni_mtx_unlock(&c->mtx);

	nni_win_io_fini(&c->recv_io);
	nni_win_io_fini(&c->send_io);
	nni_win_io_fini(&c->conn_io);

	nni_cv_fini(&c->cv);
	nni_mtx_fini(&c->mtx);
	NNI_FREE_STRUCT(c);
}

#endif // NNG_PLATFORM_WINDOWS
