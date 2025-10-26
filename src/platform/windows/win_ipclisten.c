//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "../../core/nng_impl.h"

#include "win_ipc.h"

#include <stdio.h>

typedef struct {
	nng_stream_listener sl;
	char               *path;
	bool                started;
	bool                closed;
	bool                accepting;
	HANDLE              f;
	SECURITY_ATTRIBUTES sec_attr;
	nni_list            aios;
	nni_mtx             mtx;
	nni_win_io          io;
	nni_sockaddr        sa;
	int                 rv;
} ipc_listener;

static void
ipc_accept_done(ipc_listener *l, int rv)
{
	nni_aio    *aio;
	HANDLE      f;
	nng_stream *c;

	aio = nni_list_first(&l->aios);
	nni_list_remove(&l->aios, aio);

	if (l->closed) {
		rv = NNG_ECLOSED;
	}
	if (rv != 0) {
		// Closed, so bail.
		DisconnectNamedPipe(l->f);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	// Create a replacement pipe.
	f = CreateNamedPipeA(l->path,
	    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
	    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
	        PIPE_REJECT_REMOTE_CLIENTS,
	    PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &l->sec_attr);
	if (f == INVALID_HANDLE_VALUE) {
		// We couldn't create a replacement pipe, so we have to
		// abort the client from our side, so that we can keep
		// our server pipe available.
		rv = nni_win_error(GetLastError());
		DisconnectNamedPipe(l->f);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (((rv = nni_win_io_register(f)) != 0) ||
	    ((rv = nni_win_ipc_init(&c, l->f, &l->sa, false)) != 0)) {
		DisconnectNamedPipe(l->f);
		DisconnectNamedPipe(f);
		CloseHandle(f);
		nni_aio_finish_error(aio, rv);
		return;
	}
	// Install the replacement pipe.
	l->f = f;
	nni_aio_set_output(aio, 0, c);
	nni_aio_finish(aio, 0, 0);
}

static void
ipc_accept_start(ipc_listener *l)
{
	nni_aio *aio;

	NNI_ASSERT(!l->accepting);
	while ((aio = nni_list_first(&l->aios)) != NULL) {
		int rv;

		if (l->closed) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
			rv = NNG_ECLOSED;
		} else if (ConnectNamedPipe(l->f, &l->io.olpd)) {
			rv = 0;
		} else if ((rv = GetLastError()) == ERROR_IO_PENDING) {
			// asynchronous completion pending
			l->accepting = true;
			return;
		} else if (rv == ERROR_PIPE_CONNECTED) {
			rv = 0;
		}
		// synchronous completion
		ipc_accept_done(l, rv);
	}
}

static void
ipc_accept_cb(nni_win_io *io, int rv, size_t cnt)
{
	ipc_listener *l = io->ptr;

	NNI_ARG_UNUSED(cnt);

	nni_mtx_lock(&l->mtx);
	l->accepting = false;
	if (l->closed) {
		// We're shutting down, and the handle is probably closed.
		// We should not have gotten anything here.
		nni_mtx_unlock(&l->mtx);
		return;
	}
	if (nni_list_empty(&l->aios) && l->rv == 0) {
		// We canceled, and nobody waiting.
		// But... we'll probably have another caller do
		// accept momentarily, so we leave this and it will be
		// ERROR_PIPE_CONNECTED later.
		nni_mtx_unlock(&l->mtx);
		return;
	}
	if (l->rv != 0) {
		rv    = l->rv;
		l->rv = 0;
	}
	ipc_accept_done(l, rv);
	ipc_accept_start(l);
	nni_mtx_unlock(&l->mtx);
}

static nng_err
ipc_listener_set_sec_desc(void *arg, void *desc)
{
	ipc_listener *l = arg;
	int           rv;

	if (!IsValidSecurityDescriptor((SECURITY_DESCRIPTOR *) desc)) {
		return (NNG_EINVAL);
	}
	nni_mtx_lock(&l->mtx);
	if (l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EBUSY);
	}
	l->sec_attr.lpSecurityDescriptor = desc;
	nni_mtx_unlock(&l->mtx);
	return (NNG_OK);
}

static const nni_option ipc_listener_options[] = {
	{
	    .o_name = NULL,
	},
};

static nng_err
ipc_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ipc_listener *l = arg;
	return (nni_setopt(ipc_listener_options, name, l, buf, sz, t));
}

static nng_err
ipc_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ipc_listener *l = arg;
	return (nni_getopt(ipc_listener_options, name, l, buf, szp, t));
}

static nng_err
ipc_listener_listen(void *arg)
{
	ipc_listener *l = arg;
	nng_err       rv;
	HANDLE        f;
	char         *path;

	nni_mtx_lock(&l->mtx);
	if (l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EBUSY);
	}
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_ECLOSED);
	}
	rv = nni_asprintf(&path, IPC_PIPE_PREFIX "%s", l->sa.s_ipc.sa_path);
	if (rv != NNG_OK) {
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}

	f = CreateNamedPipeA(path,
	    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
	        FILE_FLAG_FIRST_PIPE_INSTANCE,
	    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
	        PIPE_REJECT_REMOTE_CLIENTS,
	    PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &l->sec_attr);
	if (f == INVALID_HANDLE_VALUE) {
		if ((rv = GetLastError()) == ERROR_ACCESS_DENIED) {
			rv = NNG_EADDRINUSE;
		} else {
			rv = nni_win_error(rv);
		}
		nni_mtx_unlock(&l->mtx);
		nni_strfree(path);
		return (rv);
	}
	if ((rv = nni_win_io_register(f)) != NNG_OK) {
		CloseHandle(f);
		nni_mtx_unlock(&l->mtx);
		nni_strfree(path);
		return (rv);
	}

	l->f       = f;
	l->path    = path;
	l->started = true;
	nni_mtx_unlock(&l->mtx);
	return (NNG_OK);
}

static void
ipc_accept_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ipc_listener *l = arg;

	nni_mtx_lock(&l->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
ipc_listener_accept(void *arg, nni_aio *aio)
{
	ipc_listener *l = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&l->mtx);
	if (!l->started) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if (!nni_aio_start(aio, ipc_accept_cancel, l)) {
		nni_mtx_unlock(&l->mtx);
		return;
	}
	nni_list_append(&l->aios, aio);
	if (nni_list_first(&l->aios) == aio) {
		ipc_accept_start(l);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
ipc_listener_close(void *arg)
{
	ipc_listener *l = arg;
	nni_aio      *aio;
	int           rv;
	DWORD         nb;

	nni_mtx_lock(&l->mtx);
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		return;
	}
	l->closed = true;
	while ((aio = nni_list_first(&l->aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
ipc_listener_stop(void *arg)
{
	ipc_listener *l = arg;

	ipc_listener_close(l);

	nni_mtx_lock(&l->mtx);
	bool accepting = l->accepting;

	// This craziness because CancelIoEx on ConnectNamedPipe
	// seems to be incredibly unreliable. It does work, sometimes,
	// but often it doesn't.  This entire named pipe business needs
	// to be retired in favor of UNIX domain sockets anyway.

	while (accepting) {
		nni_mtx_unlock(&l->mtx);
		if (!CancelIoEx(l->f, &l->io.olpd)) {
			// operation not found probably
			// We just inject a safety sleep to
			// let it drain and give the callback
			// a chance to fire (although it should
			// already have done so.)
			DisconnectNamedPipe(l->f);
			CloseHandle(l->f);
			nng_msleep(500);
			return;
		}
		nng_msleep(100);
		nni_mtx_lock(&l->mtx);
		accepting = l->accepting;
	}
	nni_mtx_unlock(&l->mtx);
	DisconnectNamedPipe(l->f);
	CloseHandle(l->f);
}

static void
ipc_listener_free(void *arg)
{
	ipc_listener *l = arg;

	nni_strfree(l->path);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

nng_err
nni_ipc_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	ipc_listener *l;

	if ((strcmp(url->u_scheme, "ipc") != 0) || (url->u_path == NULL) ||
	    (strlen(url->u_path) == 0) ||
	    (strlen(url->u_path) >= NNG_MAXADDRLEN)) {
		return (NNG_EADDRINVAL);
	}
	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_win_io_init(&l->io, ipc_accept_cb, l);
	l->started                       = false;
	l->closed                        = false;
	l->sec_attr.nLength              = sizeof(l->sec_attr);
	l->sec_attr.lpSecurityDescriptor = NULL;
	l->sec_attr.bInheritHandle       = FALSE;
	l->sa.s_ipc.sa_family            = NNG_AF_IPC;
	l->sl.sl_free                    = ipc_listener_free;
	l->sl.sl_stop                    = ipc_listener_stop;
	l->sl.sl_close                   = ipc_listener_close;
	l->sl.sl_listen                  = ipc_listener_listen;
	l->sl.sl_accept                  = ipc_listener_accept;
	l->sl.sl_get                     = ipc_listener_get;
	l->sl.sl_set                     = ipc_listener_set;
	l->sl.sl_set_security_descriptor = ipc_listener_set_sec_desc;
	snprintf(l->sa.s_ipc.sa_path, NNG_MAXADDRLEN, "%s", url->u_path);
	nni_aio_list_init(&l->aios);
	nni_mtx_init(&l->mtx);
	*lp = (void *) l;
	return (0);
}
