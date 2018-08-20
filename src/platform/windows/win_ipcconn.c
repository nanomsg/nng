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

#include "win_ipc.h"

#include <stdio.h>

static void
ipc_recv_start(nni_ipc_conn *c)
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
	nni_aio *     aio;
	nni_ipc_conn *c = io->ptr;
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
		rv = NNG_ECLOSED;
	}
	nni_aio_finish_synch(aio, rv, num);
}
static void
ipc_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_ipc_conn *c = arg;
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

void
nni_ipc_conn_recv(nni_ipc_conn *c, nni_aio *aio)
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
ipc_send_start(nni_ipc_conn *c)
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
	nni_aio *     aio;
	nni_ipc_conn *c = io->ptr;
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

	if ((rv == 0) && (num == 0)) {
		// A zero byte receive is a remote close from the peer.
		rv = NNG_ECLOSED;
	}
	nni_aio_finish_synch(aio, rv, num);
}

static void
ipc_send_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_ipc_conn *c = arg;
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

void
nni_ipc_conn_send(nni_ipc_conn *c, nni_aio *aio)
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

int
nni_win_ipc_conn_init(nni_ipc_conn **connp, HANDLE p)
{
	nni_ipc_conn *c;
	int           rv;

	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}
	c->f = INVALID_HANDLE_VALUE;
	nni_mtx_init(&c->mtx);
	nni_cv_init(&c->cv, &c->mtx);
	nni_aio_list_init(&c->recv_aios);
	nni_aio_list_init(&c->send_aios);

	if (((rv = nni_win_io_init(&c->recv_io, ipc_recv_cb, c)) != 0) ||
	    ((rv = nni_win_io_init(&c->send_io, ipc_send_cb, c)) != 0)) {
		nni_ipc_conn_fini(c);
		return (rv);
	}

	c->f   = p;
	*connp = c;
	return (0);
}

void
nni_ipc_conn_close(nni_ipc_conn *c)
{
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
ipc_conn_reap(nni_ipc_conn *c)
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

void
nni_ipc_conn_fini(nni_ipc_conn *c)
{
	nni_ipc_conn_close(c);

	nni_reap(&c->reap, (nni_cb) ipc_conn_reap, c);
}

int
nni_ipc_conn_get_peer_uid(nni_ipc_conn *c, uint64_t *id)
{
	NNI_ARG_UNUSED(c);
	NNI_ARG_UNUSED(id);
	return (NNG_ENOTSUP);
}

int
nni_ipc_conn_get_peer_gid(nni_ipc_conn *c, uint64_t *id)
{
	NNI_ARG_UNUSED(c);
	NNI_ARG_UNUSED(id);
	return (NNG_ENOTSUP);
}

int
nni_ipc_conn_get_peer_zoneid(nni_ipc_conn *c, uint64_t *id)
{
	NNI_ARG_UNUSED(c);
	NNI_ARG_UNUSED(id);
	return (NNG_ENOTSUP);
}

int
nni_ipc_conn_get_peer_pid(nni_ipc_conn *c, uint64_t *pid)
{
	ULONG id;
	if (c->dialer) {
		if (!GetNamedPipeServerProcessId(c->f, &id)) {
			return (nni_win_error(GetLastError()));
		}
	} else {
		if (!GetNamedPipeClientProcessId(c->f, &id)) {
			return (nni_win_error(GetLastError()));
		}
	}
	*pid = id;
	return (0);
}

#endif // NNG_PLATFORM_WINDOWS
