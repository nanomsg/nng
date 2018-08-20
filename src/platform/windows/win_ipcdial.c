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

int
nni_ipc_dialer_init(nni_ipc_dialer **dp)
{
	nni_ipc_dialer *d;

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	d->closed = false;
	nni_aio_list_init(&d->aios);
	*dp = d;
	return (0);
}

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
		nni_ipc_dialer *d;

		if (w->exit) {
			break;
		}
		while ((d = nni_list_first(&w->waiters)) != NULL) {
			nni_list_remove(&w->waiters, d);
			nni_list_append(&w->workers, d);
		}

		while ((d = nni_list_first(&w->workers)) != NULL) {
			nni_ipc_conn *c;
			nni_aio *     aio;
			HANDLE        f;
			int           rv;
			char *        path;

			if ((aio = nni_list_first(&d->aios)) == NULL) {
				nni_list_remove(&w->workers, d);
				continue;
			}

			path = nni_aio_get_prov_extra(aio, 0);

			f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0,
			    NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

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
				nni_aio_set_prov_extra(aio, 0, NULL);
				nni_strfree(path);
				nni_aio_finish_error(aio, rv);
				continue;
			}

			nni_list_remove(&d->aios, aio);
			nni_aio_set_prov_extra(aio, 0, NULL);
			nni_strfree(path);

			if (((rv = nni_win_io_register(f)) != 0) ||
			    ((rv = nni_win_ipc_conn_init(&c, f)) != 0)) {
				DisconnectNamedPipe(f);
				CloseHandle(f);
				nni_aio_finish_error(aio, rv);
				continue;
			}
			c->dialer = d;
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
	nni_ipc_dialer *d = arg;
	ipc_dial_work * w = &ipc_connecter;

	nni_mtx_lock(&w->mtx);
	if (nni_aio_list_active(aio)) {
		char *path;
		if (nni_list_active(&w->waiters, d)) {
			nni_list_remove(&w->waiters, d);
			nni_cv_wake(&w->cv);
		}
		nni_aio_list_remove(aio);
		path = nni_aio_get_prov_extra(aio, 0);
		nni_aio_set_prov_extra(aio, 0, NULL);
		nni_strfree(path);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&w->mtx);
}

void
nni_ipc_dialer_dial(nni_ipc_dialer *d, const nni_sockaddr *sa, nni_aio *aio)
{
	ipc_dial_work *w = &ipc_connecter;
	char *         path;
	int            rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if (sa->s_family != NNG_AF_IPC) {
		nni_aio_finish_error(aio, NNG_EADDRINVAL);
		return;
	}
	if ((rv = nni_asprintf(&path, "\\\\.\\pipe\\%s", sa->s_ipc.sa_path)) !=
	    0) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_mtx_lock(&w->mtx);
	if ((rv = nni_aio_schedule(aio, ipc_dial_cancel, d)) != 0) {
		nni_mtx_unlock(&w->mtx);
		nni_strfree(path);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (d->closed) {
		nni_mtx_unlock(&w->mtx);
		nni_strfree(path);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	nni_aio_set_prov_extra(aio, 0, path);
	nni_list_append(&d->aios, aio);
	if (nni_list_first(&d->aios) == aio) {
		nni_list_append(&w->waiters, d);
		nni_cv_wake(&w->cv);
	}
	nni_mtx_unlock(&w->mtx);
}

void
nni_ipc_dialer_fini(nni_ipc_dialer *d)
{
	nni_ipc_dialer_close(d);
	NNI_FREE_STRUCT(d);
}

void
nni_ipc_dialer_close(nni_ipc_dialer *d)
{
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

int
nni_win_ipc_sysinit(void)
{
	int            rv;
	ipc_dial_work *worker = &ipc_connecter;

	NNI_LIST_INIT(&worker->workers, nni_ipc_dialer, node);
	NNI_LIST_INIT(&worker->waiters, nni_ipc_dialer, node);

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

#endif // NNG_PLATFORM_WINDOWS
