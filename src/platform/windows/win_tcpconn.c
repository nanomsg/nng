//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include "win_tcp.h"

#include <malloc.h>
#include <stdio.h>

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
	WSABUF   iov[8]; // we don't support more than this
	DWORD    nrecv;

	c->recv_rv = 0;
	while ((aio = nni_list_first(&c->recv_aios)) != NULL) {

		if (c->closed) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
			continue;
		}
		nni_aio_get_iov(aio, &naiov, &aiov);

		// Put the AIOs in Windows form.
		for (niov = 0, i = 0; i < naiov; i++) {
			if (aiov[i].iov_len != 0) {
				iov[niov].buf = aiov[i].iov_buf;
				iov[niov].len = (ULONG) aiov[i].iov_len;
				niov++;
			}
		}

		c->recving = true;
		flags      = 0;
		rv         = WSARecv(
                    c->s, iov, niov, &nrecv, &flags, &c->recv_io.olpd, NULL);

		if ((rv == SOCKET_ERROR) &&
		    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
			// Synchronous error.
			c->recving = false;
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, nni_win_error(rv));
		} else {
			// Callback completes.
			return;
		}
	}

	// we received all pending requests
	nni_cv_wake(&c->cv);
}

static void
tcp_recv_cb(nni_win_io *io, int rv, size_t num)
{
	nni_aio      *aio;
	nni_tcp_conn *c = io->ptr;

	nni_mtx_lock(&c->mtx);
	aio = nni_list_first(&c->recv_aios);
	NNI_ASSERT(aio != NULL);

	if (c->recv_rv != 0) {
		rv         = c->recv_rv;
		c->recv_rv = 0;
	}
	if ((rv == 0) && (num == 0)) {
		// A zero byte receive is a remote close from the peer.
		rv = NNG_ECONNSHUT;
	}
	c->recving = false;
	nni_aio_list_remove(aio);
	tcp_recv_start(c);
	nni_mtx_unlock(&c->mtx);

	nni_aio_finish_sync(aio, rv, num);
}

static void
tcp_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_tcp_conn *c = arg;
	nni_mtx_lock(&c->mtx);
	if ((aio == nni_list_first(&c->recv_aios)) && (c->recv_rv == 0)) {
		c->recv_rv = rv;
		CancelIoEx((HANDLE) c->s, &c->recv_io.olpd);
	} else {
		nni_aio *srch;
		NNI_LIST_FOREACH (&c->recv_aios, srch) {
			if (aio == srch) {
				nni_aio_list_remove(aio);
				nni_aio_finish_error(aio, rv);
				nni_cv_wake(&c->cv);
				break;
			}
		}
	}
	nni_mtx_unlock(&c->mtx);
}

static void
tcp_recv(void *arg, nni_aio *aio)
{
	nni_tcp_conn *c = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);
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
	WSABUF   iov[8];

	while ((aio = nni_list_first(&c->send_aios)) != NULL) {
		if (c->closed) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
			continue;
		}
		nni_aio_get_iov(aio, &naiov, &aiov);

		// Put the AIOs in Windows form.
		for (niov = 0, i = 0; i < naiov; i++) {
			if (aiov[i].iov_len != 0) {
				iov[niov].buf = aiov[i].iov_buf;
				iov[niov].len = (ULONG) aiov[i].iov_len;
				niov++;
			}
		}

		c->sending = true;
		rv = WSASend(c->s, iov, niov, NULL, 0, &c->send_io.olpd, NULL);

		if ((rv == SOCKET_ERROR) &&
		    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
			// Synchronous failure.
			c->sending = false;
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, nni_win_error(rv));
		} else {
			return;
		}
	}
}

static void
tcp_send_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_tcp_conn *c = arg;
	nni_mtx_lock(&c->mtx);
	if (aio == nni_list_first(&c->send_aios)) {
		c->send_rv = rv;
		CancelIoEx((HANDLE) c->s, &c->send_io.olpd);
	} else {
		nni_aio *srch;
		NNI_LIST_FOREACH (&c->send_aios, srch) {
			if (srch == aio) {
				nni_aio_list_remove(aio);
				nni_aio_finish_error(aio, rv);
				nni_cv_wake(&c->cv);
				break;
			}
		}
	}
	nni_mtx_unlock(&c->mtx);
}

static void
tcp_send_cb(nni_win_io *io, int rv, size_t num)
{
	nni_aio      *aio;
	nni_tcp_conn *c = io->ptr;
	nni_mtx_lock(&c->mtx);
	aio = nni_list_first(&c->send_aios);
	NNI_ASSERT(aio != NULL);
	nni_aio_list_remove(aio); // should always be at head
	c->sending = false;

	if (c->send_rv != 0) {
		rv         = c->send_rv;
		c->send_rv = 0;
	}
	tcp_send_start(c);
	nni_mtx_unlock(&c->mtx);

	nni_aio_finish_sync(aio, rv, num);
}

static void
tcp_send(void *arg, nni_aio *aio)
{
	nni_tcp_conn *c = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);
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

static void
tcp_close(void *arg)
{
	nni_tcp_conn *c = arg;
	nni_mtx_lock(&c->mtx);
	nni_time now;
	if (!c->closed) {
		SOCKET s = c->s;

		c->closed = true;
		c->s      = INVALID_SOCKET;

		if (s != INVALID_SOCKET) {
			CancelIoEx((HANDLE) s, &c->send_io.olpd);
			CancelIoEx((HANDLE) s, &c->recv_io.olpd);
			shutdown(s, SD_BOTH);
			closesocket(s);
		}
	}
	now = nni_clock();
	// wait up to a maximum of 10 seconds before assuming something is
	// badly amiss. from what we can tell, this doesn't happen, and we do
	// see the timer expire properly, but this safeguard can prevent a
	// hang.
	while ((c->recving || c->sending) &&
	    ((nni_clock() - now) < (NNI_SECOND * 10))) {
		nni_mtx_unlock(&c->mtx);
		nni_msleep(1);
		nni_mtx_lock(&c->mtx);
	}
	nni_mtx_unlock(&c->mtx);
}

static int
tcp_get_peername(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c = arg;
	nng_sockaddr  sa;

	if (nni_win_sockaddr2nn(&sa, &c->peername) < 0) {
		return (NNG_EADDRINVAL);
	}
	return (nni_copyout_sockaddr(&sa, buf, szp, t));
}

static int
tcp_get_sockname(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c = arg;
	nng_sockaddr  sa;

	if (nni_win_sockaddr2nn(&sa, &c->sockname) < 0) {
		return (NNG_EADDRINVAL);
	}
	return (nni_copyout_sockaddr(&sa, buf, szp, t));
}

static int
tcp_set_nodelay(void *arg, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_conn *c = arg;
	bool          val;
	BOOL          b;
	int           rv;
	if ((rv = nni_copyin_bool(&val, buf, sz, t)) != 0) {
		return (rv);
	}
	b = val ? TRUE : FALSE;
	if (setsockopt(
	        c->s, IPPROTO_TCP, TCP_NODELAY, (void *) &b, sizeof(b)) != 0) {
		return (nni_win_error(WSAGetLastError()));
	}
	return (0);
}

static int
tcp_set_keepalive(void *arg, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_conn *c = arg;
	bool          val;
	BOOL          b;
	int           rv;

	if ((rv = nni_copyin_bool(&val, buf, sz, t)) != 0) {
		return (rv);
	}
	b = val ? TRUE : FALSE;
	if (setsockopt(
	        c->s, SOL_SOCKET, SO_KEEPALIVE, (void *) &b, sizeof(b)) != 0) {
		return (nni_win_error(WSAGetLastError()));
	}
	return (0);
}

static int
tcp_get_nodelay(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c   = arg;
	BOOL          b   = 0;
	int           bsz = sizeof(b);

	if ((getsockopt(c->s, IPPROTO_TCP, TCP_NODELAY, (void *) &b, &bsz)) !=
	    0) {
		return (nni_win_error(WSAGetLastError()));
	}
	return (nni_copyout_bool(b, buf, szp, t));
}

static int
tcp_get_keepalive(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c   = arg;
	BOOL          b   = 0;
	int           bsz = sizeof(b);

	if ((getsockopt(c->s, SOL_SOCKET, SO_KEEPALIVE, (void *) &b, &bsz)) !=
	    0) {
		return (nni_win_error(WSAGetLastError()));
	}
	return (nni_copyout_bool(b, buf, szp, t));
}

static const nni_option tcp_options[] = {
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_get  = tcp_get_peername,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = tcp_get_sockname,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_get  = tcp_get_nodelay,
	    .o_set  = tcp_set_nodelay,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_get  = tcp_get_keepalive,
	    .o_set  = tcp_set_keepalive,
	},
	{
	    .o_name = NULL,
	},
};

static int
tcp_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c = arg;
	return (nni_getopt(tcp_options, name, c, buf, szp, t));
}

static int
tcp_set(void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_conn *c = arg;
	return (nni_setopt(tcp_options, name, c, buf, sz, t));
}

static void
tcp_free(void *arg)
{
	nni_tcp_conn *c = arg;
	tcp_close(c);

	nni_mtx_lock(&c->mtx);
	while ((!nni_list_empty(&c->recv_aios)) ||
	    (!nni_list_empty(&c->send_aios))) {
		nni_cv_wait(&c->cv);
	}
	nni_mtx_unlock(&c->mtx);

	if (c->s != INVALID_SOCKET) {
		closesocket(c->s);
	}
	nni_cv_fini(&c->cv);
	nni_mtx_fini(&c->mtx);
	NNI_FREE_STRUCT(c);
}

int
nni_win_tcp_init(nni_tcp_conn **connp, SOCKET s)
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
	c->conn_aio    = NULL;
	c->ops.s_close = tcp_close;
	c->ops.s_free  = tcp_free;
	c->ops.s_send  = tcp_send;
	c->ops.s_recv  = tcp_recv;
	c->ops.s_get   = tcp_get;
	c->ops.s_set   = tcp_set;

	nni_win_io_init(&c->recv_io, tcp_recv_cb, c);
	nni_win_io_init(&c->send_io, tcp_send_cb, c);
	if ((rv = nni_win_io_register((HANDLE) s)) != 0) {
		tcp_free(c);
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
