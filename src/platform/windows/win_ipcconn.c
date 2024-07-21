//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
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
	nni_list      recv_aios;
	nni_list      send_aios;
	nng_sockaddr  sa;
	bool          dialer;
	int           recv_rv;
	int           send_rv;
	int           conn_rv;
	bool          closed;
	bool          sending;
	bool          recving;
	nni_mtx       mtx;
	nni_cv        cv;
	nni_reap_node reap;
} ipc_conn;

static void
ipc_recv_start(ipc_conn *c)
{
	nni_aio *aio;
	unsigned idx;
	unsigned naiov;
	nni_iov *aiov;
	void    *buf;
	DWORD    len;
	int      rv;

	while ((aio = nni_list_first(&c->recv_aios)) != NULL) {
		if (c->closed) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
			continue;
		}

		nni_aio_get_iov(aio, &naiov, &aiov);

		idx = 0;
		while ((idx < naiov) && (aiov[idx].iov_len == 0)) {
			idx++;
		}
		NNI_ASSERT(idx < naiov);
		// Now start a transfer.  We assume that only one send can be
		// outstanding on a pipe at a time.  This is important to avoid
		// scrambling the data anyway.  Note that Windows named pipes
		// do not appear to support scatter/gather, so we have to
		// process each element in turn.
		buf = aiov[idx].iov_buf;
		len = (DWORD) aiov[idx].iov_len;
		NNI_ASSERT(buf != NULL);
		NNI_ASSERT(len != 0);

		// We limit ourselves to writing 16MB at a time.  Named Pipes
		// on Windows have limits of between 31 and 64MB.
		if (len > 0x1000000) {
			len = 0x1000000;
		}

		c->recving = true;
		if ((!ReadFile(c->f, buf, len, NULL, &c->recv_io.olpd)) &&
		    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
			// Synchronous failure.
			c->recving = false;
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, nni_win_error(rv));
		} else {
			return;
		}
	}
	nni_cv_wake(&c->cv);
}

static void
ipc_recv_cb(nni_win_io *io, int rv, size_t num)
{
	nni_aio  *aio;
	ipc_conn *c = io->ptr;
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
	ipc_recv_start(c);
	nni_mtx_unlock(&c->mtx);

	nni_aio_finish_sync(aio, rv, num);
}

static void
ipc_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	ipc_conn *c = arg;
	nni_mtx_lock(&c->mtx);
	if (aio == nni_list_first(&c->recv_aios)) {
		c->recv_rv = rv;
		CancelIoEx(c->f, &c->recv_io.olpd);
	} else {
		nni_aio *srch;
		NNI_LIST_FOREACH (&c->recv_aios, srch) {
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
	void    *buf;
	DWORD    len;
	int      rv;

	while ((aio = nni_list_first(&c->send_aios)) != NULL) {

		nni_aio_get_iov(aio, &naiov, &aiov);

		idx = 0;
		while ((idx < naiov) && (aiov[idx].iov_len == 0)) {
			idx++;
		}
		NNI_ASSERT(idx < naiov);
		// Now start a transfer.  We assume that only one send can be
		// outstanding on a pipe at a time.  This is important to avoid
		// scrambling the data anyway.  Note that Windows named pipes
		// do not appear to support scatter/gather, so we have to
		// process each element in turn.
		buf = aiov[idx].iov_buf;
		len = (DWORD) aiov[idx].iov_len;
		NNI_ASSERT(buf != NULL);
		NNI_ASSERT(len != 0);

		// We limit ourselves to writing 16MB at a time.  Named Pipes
		// on Windows have limits of between 31 and 64MB.
		if (len > 0x1000000) {
			len = 0x1000000;
		}

		c->sending = true;
		if ((!WriteFile(c->f, buf, len, NULL, &c->send_io.olpd)) &&
		    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
			// Synchronous failure.
			c->sending = false;
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, nni_win_error(rv));
		} else {
			return;
		}
	}
	nni_cv_wake(&c->cv);
}

static void
ipc_send_cb(nni_win_io *io, int rv, size_t num)
{
	nni_aio  *aio;
	ipc_conn *c = io->ptr;
	nni_mtx_lock(&c->mtx);
	aio = nni_list_first(&c->send_aios);
	NNI_ASSERT(aio != NULL);
	nni_aio_list_remove(aio);
	c->sending = false;
	if (c->send_rv != 0) {
		rv         = c->send_rv;
		c->send_rv = 0;
	}
	ipc_send_start(c);
	nni_mtx_unlock(&c->mtx);

	nni_aio_finish_sync(aio, rv, num);
}

static void
ipc_send_cancel(nni_aio *aio, void *arg, int rv)
{
	ipc_conn *c = arg;
	nni_mtx_lock(&c->mtx);
	if (aio == nni_list_first(&c->send_aios)) {
		c->send_rv = rv;
		CancelIoEx(c->f, &c->send_io.olpd);
	} else {
		nni_aio *srch;
		NNI_LIST_FOREACH (&c->recv_aios, srch) {
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
ipc_send(void *arg, nni_aio *aio)
{
	ipc_conn *c = arg;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);
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
	nni_time  now;
	nni_mtx_lock(&c->mtx);
	if (!c->closed) {
		HANDLE f  = c->f;
		c->closed = true;

		c->f = INVALID_HANDLE_VALUE;

		if (f != INVALID_HANDLE_VALUE) {
			CancelIoEx(f, &c->send_io.olpd);
			CancelIoEx(f, &c->recv_io.olpd);
			DisconnectNamedPipe(f);
			CloseHandle(f);
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

static void
ipc_conn_reap(void *arg)
{
	ipc_conn *c = arg;

	nni_mtx_lock(&c->mtx);
	while ((!nni_list_empty(&c->recv_aios)) ||
	    (!nni_list_empty(&c->send_aios))) {
		nni_cv_wait(&c->cv);
	}
	nni_mtx_unlock(&c->mtx);

	if (c->f != INVALID_HANDLE_VALUE) {
		CloseHandle(c->f);
	}
	nni_cv_fini(&c->cv);
	nni_mtx_fini(&c->mtx);
	NNI_FREE_STRUCT(c);
}

static nni_reap_list ipc_reap_list = {
	.rl_offset = offsetof(ipc_conn, reap),
	.rl_func   = ipc_conn_reap,
};

static void
ipc_free(void *arg)
{
	ipc_conn *c = arg;
	ipc_close(c);

	nni_reap(&ipc_reap_list, c);
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
ipc_set(void *arg, const char *nm, const void *val, size_t sz, nni_opt_type t)
{
	ipc_conn *c = arg;
	return (nni_setopt(ipc_conn_options, nm, c, val, sz, t));
}

static int
ipc_get(void *arg, const char *nm, void *val, size_t *szp, nni_opt_type t)
{
	ipc_conn *c = arg;
	return (nni_getopt(ipc_conn_options, nm, c, val, szp, t));
}

int
nni_win_ipc_init(
    nng_stream **connp, HANDLE p, const nng_sockaddr *sa, bool dialer)
{
	ipc_conn *c;

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
	c->stream.s_get   = ipc_get;
	c->stream.s_set   = ipc_set;

	nni_win_io_init(&c->recv_io, ipc_recv_cb, c);
	nni_win_io_init(&c->send_io, ipc_send_cb, c);

	c->f   = p;
	*connp = (void *) c;
	return (0);
}
