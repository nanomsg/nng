//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include "win_tcp.h"
#include "win_unix.h"

#include <string.h>

#ifdef NNG_HAVE_UNIX_SOCKETS

typedef struct unix_dialer unix_dialer;
typedef struct unix_listener unix_listener;

struct unix_dialer {
	nng_stream_dialer sd;
	SOCKADDR_UN        sa;
	nng_sockaddr       nsa;
	nni_list           aios;
	nni_aio           *active;
	SOCKET             active_s;
	nni_mtx            mtx;
	nni_cv             cv;
	nni_thr            thr;
	bool               thread_started;
	bool               closed;
};

struct unix_listener {
	nng_stream_listener sl;
	SOCKADDR_UN          sa;
	nng_sockaddr         nsa;
	SOCKET               s;
	WSAEVENT             event;
	nni_list             aios;
	nni_aio             *active;
	nni_mtx              mtx;
	nni_cv               cv;
	nni_thr              thr;
	bool                 thread_started;
	bool                 started;
	bool                 closed;
};

static nng_err
unix_make_addr(SOCKADDR_UN *sa, nng_sockaddr *nsa, const nng_url *url)
{
	size_t len;

	if ((url->u_path == NULL) || ((len = strlen(url->u_path)) == 0) ||
	    (len >= sizeof(sa->sun_path))) {
		return (NNG_EADDRINVAL);
	}
	memset(sa, 0, sizeof(*sa));
	sa->sun_family = AF_UNIX;
	memcpy(sa->sun_path, url->u_path, len + 1);
	memset(nsa, 0, sizeof(*nsa));
	nsa->s_ipc.sa_family = NNG_AF_IPC;
	nni_strlcpy(nsa->s_ipc.sa_path, url->u_path, NNG_MAXADDRLEN);
	return (NNG_OK);
}

static SOCKET
unix_socket(void)
{
	return (WSASocket(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED));
}

static nng_err
unix_remove_stale(const SOCKADDR_UN *sa)
{
	SOCKET  s;
	u_long  nonblock = 1;
	int     err;
	nng_err rv;

	if ((s = unix_socket()) == INVALID_SOCKET) {
		return (NNG_EADDRINUSE);
	}
	if (ioctlsocket(s, FIONBIO, &nonblock) == SOCKET_ERROR) {
		closesocket(s);
		return (NNG_EADDRINUSE);
	}
	if (connect(s, (SOCKADDR *) sa, sizeof(*sa)) == 0) {
		rv = NNG_EADDRINUSE;
	} else if ((err = WSAGetLastError()) == WSAECONNREFUSED) {
		if (DeleteFileA(sa->sun_path) ||
		    (GetLastError() == ERROR_FILE_NOT_FOUND)) {
			rv = NNG_OK;
		} else {
			rv = nni_win_error(GetLastError());
		}
	} else {
		rv = NNG_EADDRINUSE;
	}
	closesocket(s);
	return (rv);
}

static void
unix_conn_addr(nni_tcp_conn *c, const nng_sockaddr *sa)
{
	c->sockname = *sa;
	c->peername = *sa;
}

static void
unix_dial_finish(unix_dialer *d, nni_aio *aio, SOCKET s, nng_err rv)
{
	nni_tcp_conn *c = NULL;

	if (rv == NNG_OK) {
		WSAEventSelect(s, NULL, 0);
		if ((rv = nni_win_tcp_init(&c, s, true)) == NNG_OK) {
			unix_conn_addr(c, &d->nsa);
		}
	}

	nni_mtx_lock(&d->mtx);
	if ((d->active == aio) && !d->closed) {
		d->active   = NULL;
		d->active_s = INVALID_SOCKET;
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&d->mtx);
		if (rv == NNG_OK) {
			nni_aio_set_output(aio, 0, c);
			nni_aio_finish(aio, 0, 0);
		} else {
			if (s != INVALID_SOCKET) {
				closesocket(s);
			}
			nni_aio_finish_error(aio, rv);
		}
		return;
	}
	nni_mtx_unlock(&d->mtx);
	if (c != NULL) {
		nng_stream_close(&c->ops);
		nng_stream_stop(&c->ops);
		nng_stream_free(&c->ops);
	} else if (s != INVALID_SOCKET) {
		closesocket(s);
	}
}

static void
unix_dial_thr(void *arg)
{
	unix_dialer *d = arg;

	nni_mtx_lock(&d->mtx);
	for (;;) {
		nni_aio *aio;
		SOCKET   s;
		WSAEVENT event;
		int      rv;

		while (!d->closed && ((aio = nni_list_first(&d->aios)) == NULL)) {
			nni_cv_wait(&d->cv);
		}
		if (d->closed) {
			break;
		}
		d->active   = aio;
		d->active_s = INVALID_SOCKET;
		nni_mtx_unlock(&d->mtx);

		if ((s = unix_socket()) == INVALID_SOCKET) {
			unix_dial_finish(d, aio, s, nni_win_error(WSAGetLastError()));
			nni_mtx_lock(&d->mtx);
			continue;
		}
		if ((event = WSACreateEvent()) == WSA_INVALID_EVENT) {
			rv = nni_win_error(WSAGetLastError());
			closesocket(s);
			unix_dial_finish(d, aio, INVALID_SOCKET, rv);
			nni_mtx_lock(&d->mtx);
			continue;
		}
		if (WSAEventSelect(s, event, FD_CONNECT) == SOCKET_ERROR) {
			rv = nni_win_error(WSAGetLastError());
			WSACloseEvent(event);
			unix_dial_finish(d, aio, s, rv);
			nni_mtx_lock(&d->mtx);
			continue;
		}

		nni_mtx_lock(&d->mtx);
		if ((d->active != aio) || d->closed) {
			nni_mtx_unlock(&d->mtx);
			WSACloseEvent(event);
			closesocket(s);
			nni_mtx_lock(&d->mtx);
			continue;
		}
		d->active_s = s;
		nni_mtx_unlock(&d->mtx);

		if (connect(s, (SOCKADDR *) &d->sa, sizeof(d->sa)) == 0) {
			rv = NNG_OK;
		} else {
			int err = WSAGetLastError();
			if ((err != WSAEWOULDBLOCK) && (err != WSAEINPROGRESS)) {
				rv = nni_win_error(err);
			} else {
				rv = NNG_EAGAIN;
				while (rv == NNG_EAGAIN) {
					WSANETWORKEVENTS ne;

					(void) WSAWaitForMultipleEvents(
					    1, &event, FALSE, 10, FALSE);
					nni_mtx_lock(&d->mtx);
					if ((d->active != aio) || d->closed) {
						nni_mtx_unlock(&d->mtx);
						rv = NNG_ECANCELED;
						break;
					}
					nni_mtx_unlock(&d->mtx);
					if (WSAEnumNetworkEvents(s, event, &ne) == SOCKET_ERROR) {
						rv = nni_win_error(WSAGetLastError());
					} else if (ne.lNetworkEvents & FD_CONNECT) {
						rv = ne.iErrorCode[FD_CONNECT_BIT] == 0 ? NNG_OK :
						    nni_win_error(ne.iErrorCode[FD_CONNECT_BIT]);
					}
				}
			}
		}
		WSACloseEvent(event);
		unix_dial_finish(d, aio, s, rv);
		nni_mtx_lock(&d->mtx);
	}
	nni_mtx_unlock(&d->mtx);
}

static void
unix_dial_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	unix_dialer *d = arg;

	nni_mtx_lock(&d->mtx);
	if (nni_aio_list_active(aio)) {
		if (d->active == aio) {
			d->active_s = INVALID_SOCKET;
			d->active   = NULL;
		}
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&d->mtx);
}

static void
unix_dialer_dial(void *arg, nng_aio *aio)
{
	unix_dialer *d = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&d->mtx);
	if (d->closed) {
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, unix_dial_cancel, d)) {
		nni_mtx_unlock(&d->mtx);
		return;
	}
	nni_list_append(&d->aios, aio);
	nni_cv_wake(&d->cv);
	nni_mtx_unlock(&d->mtx);
}

static void
unix_dialer_close(void *arg)
{
	unix_dialer *d = arg;
	nni_aio     *aio;

	nni_mtx_lock(&d->mtx);
	if (d->closed) {
		nni_mtx_unlock(&d->mtx);
		return;
	}
	d->closed   = true;
	d->active   = NULL;
	d->active_s = INVALID_SOCKET;
	while ((aio = nni_list_first(&d->aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_cv_wake(&d->cv);
	nni_mtx_unlock(&d->mtx);
}

static void
unix_dialer_stop(void *arg)
{
	unix_dialer *d = arg;

	unix_dialer_close(d);
	if (d->thread_started) {
		nni_thr_fini(&d->thr);
		d->thread_started = false;
	}
}

static void
unix_dialer_free(void *arg)
{
	unix_dialer *d = arg;

	unix_dialer_stop(d);
	nni_cv_fini(&d->cv);
	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

static nng_err
unix_dialer_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(szp);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}

static nng_err
unix_dialer_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}

nng_err
nni_unix_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	unix_dialer *d;
	nng_err      rv;

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = unix_make_addr(&d->sa, &d->nsa, url)) != NNG_OK) {
		NNI_FREE_STRUCT(d);
		return (rv);
	}
	d->active_s = INVALID_SOCKET;
	nni_mtx_init(&d->mtx);
	nni_cv_init(&d->cv, &d->mtx);
	nni_aio_list_init(&d->aios);
	if ((rv = nni_thr_init(&d->thr, unix_dial_thr, d)) != NNG_OK) {
		nni_cv_fini(&d->cv);
		nni_mtx_fini(&d->mtx);
		NNI_FREE_STRUCT(d);
		return (rv);
	}
	nni_thr_set_name(&d->thr, "nng:unix:dial");
	nni_thr_run(&d->thr);
	d->thread_started = true;
	d->sd.sd_free  = unix_dialer_free;
	d->sd.sd_close = unix_dialer_close;
	d->sd.sd_stop  = unix_dialer_stop;
	d->sd.sd_dial  = unix_dialer_dial;
	d->sd.sd_get   = unix_dialer_get;
	d->sd.sd_set   = unix_dialer_set;
	*dp            = &d->sd;
	return (NNG_OK);
}

static void
unix_listener_finish(unix_listener *l, nni_aio *aio, SOCKET s, nng_err rv)
{
	nni_tcp_conn *c = NULL;

	if (rv == NNG_OK) {
		WSAEventSelect(s, NULL, 0);
		if ((rv = nni_win_tcp_init(&c, s, true)) == NNG_OK) {
			unix_conn_addr(c, &l->nsa);
		}
	}

	nni_mtx_lock(&l->mtx);
	if (!l->closed && (l->active == aio) && nni_aio_list_active(aio)) {
		l->active = NULL;
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&l->mtx);
		if (rv == NNG_OK) {
			nni_aio_set_output(aio, 0, c);
			nni_aio_finish(aio, 0, 0);
		} else {
			if (s != INVALID_SOCKET) {
				closesocket(s);
			}
			nni_aio_finish_error(aio, rv);
		}
		return;
	}
	nni_mtx_unlock(&l->mtx);
	if (c != NULL) {
		nng_stream_close(&c->ops);
		nng_stream_stop(&c->ops);
		nng_stream_free(&c->ops);
	} else if (s != INVALID_SOCKET) {
		closesocket(s);
	}
}

static void
unix_listener_thr(void *arg)
{
	unix_listener *l = arg;

	for (;;) {
		nni_aio *aio;
		SOCKET   s;
		WSANETWORKEVENTS ne;
		int      rv;

		nni_mtx_lock(&l->mtx);
		while (!l->closed && ((aio = nni_list_first(&l->aios)) == NULL)) {
			nni_cv_wait(&l->cv);
		}
		if (l->closed) {
			nni_mtx_unlock(&l->mtx);
			return;
		}
		l->active = aio;
		nni_mtx_unlock(&l->mtx);

		(void) WSAWaitForMultipleEvents(1, &l->event, FALSE, 10, FALSE);
		nni_mtx_lock(&l->mtx);
		if (l->closed) {
			nni_mtx_unlock(&l->mtx);
			return;
		}
		nni_mtx_unlock(&l->mtx);
		if (WSAEnumNetworkEvents(l->s, l->event, &ne) == SOCKET_ERROR) {
			continue;
		}
		if ((s = accept(l->s, NULL, NULL)) == INVALID_SOCKET) {
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK) {
				continue;
			}
			rv = nni_win_error(err);
		} else {
			rv = NNG_OK;
		}
		unix_listener_finish(l, aio, s, rv);
	}
}

static void
unix_listener_accept_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	unix_listener *l = arg;

	nni_mtx_lock(&l->mtx);
	if (nni_aio_list_active(aio)) {
		if (l->active == aio) {
			l->active = NULL;
		}
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
unix_listener_accept(void *arg, nng_aio *aio)
{
	unix_listener *l = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&l->mtx);
	if (!l->started) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, unix_listener_accept_cancel, l)) {
		nni_mtx_unlock(&l->mtx);
		return;
	}
	nni_list_append(&l->aios, aio);
	nni_cv_wake(&l->cv);
	nni_mtx_unlock(&l->mtx);
}

static nng_err
unix_listener_listen(void *arg)
{
	unix_listener *l = arg;
	SOCKET         s;
	nng_err        rv;

	nni_mtx_lock(&l->mtx);
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_ECLOSED);
	}
	if (l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EBUSY);
	}
	if ((s = unix_socket()) == INVALID_SOCKET) {
		rv = nni_win_error(WSAGetLastError());
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}
	if (bind(s, (SOCKADDR *) &l->sa, sizeof(l->sa)) == SOCKET_ERROR) {
		int err = WSAGetLastError();

		rv = nni_win_error(err);
		if ((err == WSAEADDRINUSE) &&
		    ((rv = unix_remove_stale(&l->sa)) == NNG_OK)) {
			if (bind(s, (SOCKADDR *) &l->sa, sizeof(l->sa)) == 0) {
				goto bound;
			}
			rv = nni_win_error(WSAGetLastError());
		}
		closesocket(s);
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}
bound:
	if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
		rv = nni_win_error(WSAGetLastError());
		closesocket(s);
		(void) DeleteFileA(l->sa.sun_path);
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}
	if ((l->event = WSACreateEvent()) == WSA_INVALID_EVENT) {
		rv = nni_win_error(WSAGetLastError());
		closesocket(s);
		(void) DeleteFileA(l->sa.sun_path);
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}
	if (WSAEventSelect(s, l->event, FD_ACCEPT | FD_CLOSE) == SOCKET_ERROR) {
		rv = nni_win_error(WSAGetLastError());
		WSACloseEvent(l->event);
		l->event = WSA_INVALID_EVENT;
		closesocket(s);
		(void) DeleteFileA(l->sa.sun_path);
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}
	l->s       = s;
	l->started = true;
	if ((rv = nni_thr_init(&l->thr, unix_listener_thr, l)) != NNG_OK) {
		l->started = false;
		closesocket(l->s);
		WSACloseEvent(l->event);
		l->event = WSA_INVALID_EVENT;
		(void) DeleteFileA(l->sa.sun_path);
		l->s = INVALID_SOCKET;
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}
	nni_thr_set_name(&l->thr, "nng:unix:listen");
	nni_thr_run(&l->thr);
	l->thread_started = true;
	nni_mtx_unlock(&l->mtx);
	return (NNG_OK);
}

static void
unix_listener_close(void *arg)
{
	unix_listener *l = arg;
	nni_aio       *aio;
	WSAEVENT        event;

	nni_mtx_lock(&l->mtx);
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		return;
	}
	l->closed = true;
	event     = l->event;
	while ((aio = nni_list_first(&l->aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_cv_wake(&l->cv);
	nni_mtx_unlock(&l->mtx);
	if (event != WSA_INVALID_EVENT) {
		WSASetEvent(event);
	}
}

static void
unix_listener_stop(void *arg)
{
	unix_listener *l = arg;

	unix_listener_close(l);
	if (l->thread_started) {
		nni_thr_fini(&l->thr);
		l->thread_started = false;
	}
	if (l->s != INVALID_SOCKET) {
		closesocket(l->s);
		l->s = INVALID_SOCKET;
	}
	if (l->event != WSA_INVALID_EVENT) {
		WSACloseEvent(l->event);
		l->event = WSA_INVALID_EVENT;
	}
	if (l->started) {
		(void) DeleteFileA(l->sa.sun_path);
	}
}

static void
unix_listener_free(void *arg)
{
	unix_listener *l = arg;

	unix_listener_stop(l);
	nni_cv_fini(&l->cv);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

static nng_err
unix_listener_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(szp);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}

static nng_err
unix_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}

nng_err
nni_unix_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	unix_listener *l;
	nng_err        rv;

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = unix_make_addr(&l->sa, &l->nsa, url)) != NNG_OK) {
		NNI_FREE_STRUCT(l);
		return (rv);
	}
	l->s     = INVALID_SOCKET;
	l->event = WSA_INVALID_EVENT;
	nni_mtx_init(&l->mtx);
	nni_cv_init(&l->cv, &l->mtx);
	nni_aio_list_init(&l->aios);
	l->sl.sl_free   = unix_listener_free;
	l->sl.sl_close  = unix_listener_close;
	l->sl.sl_stop   = unix_listener_stop;
	l->sl.sl_listen = unix_listener_listen;
	l->sl.sl_accept = unix_listener_accept;
	l->sl.sl_get    = unix_listener_get;
	l->sl.sl_set    = unix_listener_set;
	*lp             = &l->sl;
	return (NNG_OK);
}

#endif // NNG_HAVE_UNIX_SOCKETS
