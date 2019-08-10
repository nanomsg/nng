//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include "win_ipc.h"

#include <stdio.h>

#define CONN(c) ((ipc_conn *) (c))

typedef struct ipc_conn {
	nng_stream    stream;
	HANDLE        f;
	nni_win_io    recv_io;
	nni_win_io    send_io;
	nni_win_io    conn_io;
	nni_list      recv_aios;
	nni_list      send_aios;
	nni_aio *     conn_aio;
	nng_sockaddr  sa;
	bool          dialer;
	int           recv_rv;
	int           send_rv;
	int           conn_rv;
	bool          closed;
	nni_mtx       mtx;
	nni_cv        cv;
	nni_reap_item reap;
} ipc_conn;

static void
ipc_recv_start(ipc_conn *c)
{
	nni_aio *aio;
	unsigned idx;
	unsigned naiov;
	nni_iov *aiov;
	void *   buf;
	DWORD    len;
	int      rv;

	if (c->closed) {
		while ((aio = nni_list_first(&c->recv_aios)) != NULL) {
			nni_list_remove(&c->recv_aios, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		nni_cv_wake(&c->cv);
	}
again:
	if ((aio = nni_list_first(&c->recv_aios)) == NULL) {
		return;
	}

	nni_aio_get_iov(aio, &naiov, &aiov);

	idx = 0;
	while ((idx < naiov) && (aiov[idx].iov_len == 0)) {
		idx++;
	}
	NNI_ASSERT(idx < naiov);
	// Now start a transfer.  We assume that only one send can be
	// outstanding on a pipe at a time.  This is important to avoid
	// scrambling the data anyway.  Note that Windows named pipes do
	// not appear to support scatter/gather, so we have to process
	// each element in turn.
	buf = aiov[idx].iov_buf;
	len = (DWORD) aiov[idx].iov_len;
	NNI_ASSERT(buf != NULL);
	NNI_ASSERT(len != 0);

	// We limit ourselves to writing 16MB at a time.  Named Pipes
	// on Windows have limits of between 31 and 64MB.
	if (len > 0x1000000) {
		len = 0x1000000;
	}

	if ((!ReadFile(c->f, buf, len, NULL, &c->recv_io.olpd)) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, nni_win_error(rv));
		goto again;
	}
}

static void
ipc_recv_cb(nni_win_io *io, int rv, size_t num)
{
	nni_aio * aio;
	ipc_conn *c = io->ptr;
	nni_mtx_lock(&c->mtx);
	if ((aio = nni_list_first(&c->recv_aios)) == NULL) {
		// Should indicate that it was closed.
		nni_mtx_unlock(&c->mtx);
		return;
	}
	if (c->recv_rv != 0) {
		rv         = c->recv_rv;
		c->recv_rv = 0;
	}
	nni_aio_list_remove(aio);
	ipc_recv_start(c);
	if (c->closed) {
		nni_cv_wake(&c->cv);
	}
	nni_mtx_unlock(&c->mtx);

	if ((rv == 0) && (num == 0)) {
		// A zero byte receive is a remote close from the peer.
		rv = NNG_ECONNSHUT;
	}
	nni_aio_finish_synch(aio, rv, num);
}
static void
ipc_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	ipc_conn *c = arg;
	nni_mtx_lock(&c->mtx);
	if (aio == nni_list_first(&c->recv_aios)) {
		c->recv_rv = rv;
		CancelIoEx(c->f, &c->recv_io.olpd);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
		nni_cv_wake(&c->cv);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_recv(void *arg, nni_aio *aio)
{
	ipc_conn *c = arg;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);
	if (c->closed) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, ipc_recv_cancel, c)) != 0) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&c->recv_aios, aio);
	if (aio == nni_list_first(&c->recv_aios)) {
		ipc_recv_start(c);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_send_start(ipc_conn *c)
{
	nni_aio *aio;
	unsigned idx;
	unsigned naiov;
	nni_iov *aiov;
	void *   buf;
	DWORD    len;
	int      rv;

	if (c->closed) {
		while ((aio = nni_list_first(&c->send_aios)) != NULL) {
			nni_list_remove(&c->send_aios, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		nni_cv_wake(&c->cv);
	}
again:
	if ((aio = nni_list_first(&c->send_aios)) == NULL) {
		return;
	}

	nni_aio_get_iov(aio, &naiov, &aiov);

	idx = 0;
	while ((idx < naiov) && (aiov[idx].iov_len == 0)) {
		idx++;
	}
	NNI_ASSERT(idx < naiov);
	// Now start a transfer.  We assume that only one send can be
	// outstanding on a pipe at a time.  This is important to avoid
	// scrambling the data anyway.  Note that Windows named pipes do
	// not appear to support scatter/gather, so we have to process
	// each element in turn.
	buf = aiov[idx].iov_buf;
	len = (DWORD) aiov[idx].iov_len;
	NNI_ASSERT(buf != NULL);
	NNI_ASSERT(len != 0);

	// We limit ourselves to writing 16MB at a time.  Named Pipes
	// on Windows have limits of between 31 and 64MB.
	if (len > 0x1000000) {
		len = 0x1000000;
	}

	if ((!WriteFile(c->f, buf, len, NULL, &c->send_io.olpd)) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, nni_win_error(rv));
		goto again;
	}
}

static void
ipc_send_cb(nni_win_io *io, int rv, size_t num)
{
	nni_aio * aio;
	ipc_conn *c = io->ptr;
	nni_mtx_lock(&c->mtx);
	if ((aio = nni_list_first(&c->send_aios)) == NULL) {
		// Should indicate that it was closed.
		nni_mtx_unlock(&c->mtx);
		return;
	}
	if (c->send_rv != 0) {
		rv         = c->send_rv;
		c->send_rv = 0;
	}
	nni_aio_list_remove(aio);
	ipc_send_start(c);
	if (c->closed) {
		nni_cv_wake(&c->cv);
	}
	nni_mtx_unlock(&c->mtx);

	nni_aio_finish_synch(aio, rv, num);
}

static void
ipc_send_cancel(nni_aio *aio, void *arg, int rv)
{
	ipc_conn *c = arg;
	nni_mtx_lock(&c->mtx);
	if (aio == nni_list_first(&c->send_aios)) {
		c->send_rv = rv;
		CancelIoEx(c->f, &c->send_io.olpd);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
		nni_cv_wake(&c->cv);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_send(void *arg, nni_aio *aio)
{
	ipc_conn *c = arg;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);
	if (c->closed) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, ipc_send_cancel, c)) != 0) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&c->send_aios, aio);
	if (aio == nni_list_first(&c->send_aios)) {
		ipc_send_start(c);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_close(void *arg)
{
	ipc_conn *c = arg;
	nni_mtx_lock(&c->mtx);
	if (!c->closed) {
		c->closed = true;
		if (!nni_list_empty(&c->recv_aios)) {
			CancelIoEx(c->f, &c->recv_io.olpd);
		}
		if (!nni_list_empty(&c->send_aios)) {
			CancelIoEx(c->f, &c->send_io.olpd);
		}

		if (c->f != INVALID_HANDLE_VALUE) {
			// NB: closing the pipe is dangerous at this point.
			DisconnectNamedPipe(c->f);
		}
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_conn_reap(ipc_conn *c)
{
	nni_mtx_lock(&c->mtx);
	while ((!nni_list_empty(&c->recv_aios)) ||
	    (!nni_list_empty(&c->send_aios))) {
		nni_cv_wait(&c->cv);
	}
	nni_mtx_unlock(&c->mtx);

	nni_win_io_fini(&c->recv_io);
	nni_win_io_fini(&c->send_io);
	nni_win_io_fini(&c->conn_io);

	if (c->f != INVALID_HANDLE_VALUE) {
		CloseHandle(c->f);
	}
	nni_cv_fini(&c->cv);
	nni_mtx_fini(&c->mtx);
	NNI_FREE_STRUCT(c);
}

static void
ipc_free(void *arg)
{
	ipc_conn *c = arg;
	ipc_close(c);

	nni_reap(&c->reap, (nni_cb) ipc_conn_reap, CONN(c));
}

static int
ipc_conn_get_addr(void *c, void *buf, size_t *szp, nni_opt_type t)
{
	return (nni_copyout_sockaddr(&(CONN(c))->sa, buf, szp, t));
}

static int
ipc_conn_get_peer_pid(void *c, void *buf, size_t *szp, nni_opt_type t)
{
	ULONG id;

	if (CONN(c)->dialer) {
		if (!GetNamedPipeServerProcessId(CONN(c)->f, &id)) {
			return (nni_win_error(GetLastError()));
		}
	} else {
		if (!GetNamedPipeClientProcessId(CONN(c)->f, &id)) {
			return (nni_win_error(GetLastError()));
		}
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static const nni_option ipc_conn_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = ipc_conn_get_addr,
	},
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_get  = ipc_conn_get_addr,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_PID,
	    .o_get  = ipc_conn_get_peer_pid,
	},
	{
	    .o_name = NULL, // terminator
	},
};

static int
ipc_setx(void *arg, const char *nm, const void *val, size_t sz, nni_opt_type t)
{
	ipc_conn *c = arg;
	return (nni_setopt(ipc_conn_options, nm, c, val, sz, t));
}

static int
ipc_getx(void *arg, const char *nm, void *val, size_t *szp, nni_opt_type t)
{
	ipc_conn *c = arg;
	return (nni_getopt(ipc_conn_options, nm, c, val, szp, t));
}

int
nni_win_ipc_init(
    nng_stream **connp, HANDLE p, const nng_sockaddr *sa, bool dialer)
{
	ipc_conn *c;
	int       rv;

	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}
	c->f = INVALID_HANDLE_VALUE;
	nni_mtx_init(&c->mtx);
	nni_cv_init(&c->cv, &c->mtx);
	nni_aio_list_init(&c->recv_aios);
	nni_aio_list_init(&c->send_aios);
	c->dialer         = dialer;
	c->sa             = *sa;
	c->stream.s_free  = ipc_free;
	c->stream.s_close = ipc_close;
	c->stream.s_send  = ipc_send;
	c->stream.s_recv  = ipc_recv;
	c->stream.s_getx  = ipc_getx;
	c->stream.s_setx  = ipc_setx;

	if (((rv = nni_win_io_init(&c->recv_io, ipc_recv_cb, c)) != 0) ||
	    ((rv = nni_win_io_init(&c->send_io, ipc_send_cb, c)) != 0)) {
		ipc_free(c);
		return (rv);
	}

	c->f   = p;
	*connp = (void *) c;
	return (0);
}
