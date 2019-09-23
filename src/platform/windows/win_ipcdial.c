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

typedef struct ipc_dialer {
	nng_stream_dialer sd;
	bool              closed; // dialers are locked by the worker lock
	nni_list          aios;
	nni_list_node     node; // node on worker list
	char *            path;
	nni_sockaddr      sa;
} ipc_dialer;

// Windows IPC is a bit different on the client side.  There is no
// support for asynchronous connection, but we can fake it with a
// single thread that runs to establish the connection.  That thread
// will run keep looping, sleeping for 10 ms between attempts.  It
// performs non-blocking attempts to connect.
typedef struct ipc_dial_work {
	nni_list waiters;
	nni_list workers;
	nni_mtx  mtx;
	nni_cv   cv;
	nni_thr  thr;
	int      exit;
} ipc_dial_work;

static ipc_dial_work ipc_connecter;

static void
ipc_dial_thr(void *arg)
{
	ipc_dial_work *w = arg;

	nni_mtx_lock(&w->mtx);
	for (;;) {
		ipc_dialer *d;

		if (w->exit) {
			break;
		}
		while ((d = nni_list_first(&w->waiters)) != NULL) {
			nni_list_remove(&w->waiters, d);
			nni_list_append(&w->workers, d);
		}

		while ((d = nni_list_first(&w->workers)) != NULL) {
			nng_stream *c;
			nni_aio *   aio;
			HANDLE      f;
			int         rv;

			if ((aio = nni_list_first(&d->aios)) == NULL) {
				nni_list_remove(&w->workers, d);
				continue;
			}

			f = CreateFileA(d->path, GENERIC_READ | GENERIC_WRITE,
			    0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
			    NULL);

			if (f == INVALID_HANDLE_VALUE) {
				switch ((rv = GetLastError())) {
				case ERROR_PIPE_BUSY:
					// Still in progress.  This
					// shouldn't happen unless the
					// other side aborts the
					// connection.
					// back at the head of the list
					nni_list_remove(&w->workers, d);
					nni_list_prepend(&w->waiters, d);
					continue;

				case ERROR_FILE_NOT_FOUND:
					rv = NNG_ECONNREFUSED;
					break;
				default:
					rv = nni_win_error(rv);
					break;
				}
				nni_list_remove(&d->aios, aio);
				nni_aio_finish_error(aio, rv);
				continue;
			}

			nni_list_remove(&d->aios, aio);

			if (((rv = nni_win_io_register(f)) != 0) ||
			    ((rv = nni_win_ipc_init(&c, f, &d->sa, true)) !=
			        0)) {
				DisconnectNamedPipe(f);
				CloseHandle(f);
				nni_aio_finish_error(aio, rv);
				continue;
			}
			nni_aio_set_output(aio, 0, c);
			nni_aio_finish(aio, 0, 0);
		}

		if (nni_list_empty(&w->waiters)) {
			// Wait until an endpoint is added.
			nni_cv_wait(&w->cv);
		} else {
			// Wait 10 ms, unless woken earlier.
			nni_cv_until(&w->cv, nni_clock() + 10);
		}
	}
	nni_mtx_unlock(&w->mtx);
}

static void
ipc_dial_cancel(nni_aio *aio, void *arg, int rv)
{
	ipc_dialer *   d = arg;
	ipc_dial_work *w = &ipc_connecter;

	nni_mtx_lock(&w->mtx);
	if (nni_aio_list_active(aio)) {
		if (nni_list_active(&w->waiters, d)) {
			nni_list_remove(&w->waiters, d);
			nni_cv_wake(&w->cv);
		}
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&w->mtx);
}

static void
ipc_dialer_dial(ipc_dialer *d, nni_aio *aio)
{
	ipc_dial_work *w = &ipc_connecter;
	int            rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&w->mtx);
	if ((rv = nni_aio_schedule(aio, ipc_dial_cancel, d)) != 0) {
		nni_mtx_unlock(&w->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (d->closed) {
		nni_mtx_unlock(&w->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	nni_list_append(&d->aios, aio);
	if (nni_list_first(&d->aios) == aio) {
		nni_list_append(&w->waiters, d);
		nni_cv_wake(&w->cv);
	}
	nni_mtx_unlock(&w->mtx);
}

static void
ipc_dialer_close(void *arg)
{
	ipc_dialer *   d = arg;
	ipc_dial_work *w = &ipc_connecter;
	nni_aio *      aio;

	nni_mtx_lock(&w->mtx);
	d->closed = true;
	if (nni_list_active(&w->waiters, d)) {
		nni_list_remove(&w->waiters, d);
	}
	while ((aio = nni_list_first(&d->aios)) != NULL) {
		nni_list_remove(&d->aios, aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&w->mtx);
}

static void
ipc_dialer_free(void *arg)
{
	ipc_dialer *d = arg;
	ipc_dialer_close(d);
	if (d->path) {
		nni_strfree(d->path);
	}
	NNI_FREE_STRUCT(d);
}

static const nni_option ipc_dialer_options[] = {
	{
	    .o_name = NULL,
	},
};

int
ipc_dialer_setx(
    void *arg, const char *nm, const void *buf, size_t sz, nni_type t)
{
	ipc_dialer *d = arg;
	return (nni_setopt(ipc_dialer_options, nm, d, buf, sz, t));
}

int
ipc_dialer_getx(void *arg, const char *nm, void *buf, size_t *szp, nni_type t)
{
	ipc_dialer *d = arg;
	return (nni_getopt(ipc_dialer_options, nm, d, buf, szp, t));
}

int
nni_ipc_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	ipc_dialer *d;
	int         rv;

	if ((strcmp(url->u_scheme, "ipc") != 0) || (url->u_path == NULL) ||
	    (strlen(url->u_path) == 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}

	if ((rv = nni_asprintf(&d->path, IPC_PIPE_PREFIX "%s", url->u_path)) !=
	    0) {
		NNI_FREE_STRUCT(d);
		return (rv);
	}
	snprintf(d->sa.s_ipc.sa_path, NNG_MAXADDRLEN, "%s", url->u_path);
	d->sa.s_ipc.sa_family = NNG_AF_IPC;
	d->closed             = false;
	d->sd.sd_free         = ipc_dialer_free;
	d->sd.sd_close        = ipc_dialer_close;
	d->sd.sd_dial         = ipc_dialer_dial;
	d->sd.sd_getx         = ipc_dialer_getx;
	d->sd.sd_setx         = ipc_dialer_setx;
	nni_aio_list_init(&d->aios);
	*dp = (void *) d;
	return (0);
}

int
nni_win_ipc_sysinit(void)
{
	int            rv;
	ipc_dial_work *worker = &ipc_connecter;

	NNI_LIST_INIT(&worker->workers, ipc_dialer, node);
	NNI_LIST_INIT(&worker->waiters, ipc_dialer, node);

	nni_mtx_init(&worker->mtx);
	nni_cv_init(&worker->cv, &worker->mtx);

	rv = nni_thr_init(&worker->thr, ipc_dial_thr, worker);
	if (rv != 0) {
		return (rv);
	}

	nni_thr_run(&worker->thr);

	return (0);
}

void
nni_win_ipc_sysfini(void)
{
	ipc_dial_work *worker = &ipc_connecter;

	nni_reap_drain(); // so that listeners get cleaned up.

	nni_mtx_lock(&worker->mtx);
	worker->exit = 1;
	nni_cv_wake(&worker->cv);
	nni_mtx_unlock(&worker->mtx);
	nni_thr_fini(&worker->thr);
	nni_cv_fini(&worker->cv);
	nni_mtx_fini(&worker->mtx);
}
