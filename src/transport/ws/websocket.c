//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "core/nng_impl.h"
#include "supplemental/websocket/websocket.h"

#include <nng/supplemental/tls/tls.h>
#include <nng/transport/ws/websocket.h>

typedef struct ws_dialer   ws_dialer;
typedef struct ws_listener ws_listener;
typedef struct ws_pipe     ws_pipe;

struct ws_dialer {
	uint16_t           peer; // remote protocol
	nni_list           aios;
	nni_mtx            mtx;
	nni_aio *          connaio;
	nng_stream_dialer *dialer;
	bool               started;
};

struct ws_listener {
	uint16_t             peer; // remote protocol
	nni_list             aios;
	nni_mtx              mtx;
	nni_aio *            accaio;
	nng_stream_listener *listener;
	bool                 started;
};

struct ws_pipe {
	nni_mtx     mtx;
	bool        closed;
	uint16_t    peer;
	nni_aio *   user_txaio;
	nni_aio *   user_rxaio;
	nni_aio *   txaio;
	nni_aio *   rxaio;
	nng_stream *ws;
};

static void
wstran_pipe_send_cb(void *arg)
{
	ws_pipe *p = arg;
	nni_aio *taio;
	nni_aio *uaio;

	nni_mtx_lock(&p->mtx);
	taio          = p->txaio;
	uaio          = p->user_txaio;
	p->user_txaio = NULL;

	if (uaio != NULL) {
		int rv;
		if ((rv = nni_aio_result(taio)) != 0) {
			nni_aio_finish_error(uaio, rv);
		} else {
			nni_aio_finish(uaio, 0, 0);
		}
	}
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_recv_cb(void *arg)
{
	ws_pipe *p    = arg;
	nni_aio *raio = p->rxaio;
	nni_aio *uaio;
	int      rv;

	nni_mtx_lock(&p->mtx);
	uaio          = p->user_rxaio;
	p->user_rxaio = NULL;
	if ((rv = nni_aio_result(raio)) != 0) {
		if (uaio != NULL) {
			nni_aio_finish_error(uaio, rv);
		}
	} else {
		nni_msg *msg = nni_aio_get_msg(raio);
		if (uaio != NULL) {
			nni_aio_finish_msg(uaio, msg);
		} else {
			nni_msg_free(msg);
		}
	}
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	ws_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	if (p->user_rxaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_rxaio = NULL;
	nni_aio_abort(p->rxaio, rv);
	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_recv(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;
	int      rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, wstran_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->user_rxaio = aio;
	nng_stream_recv(p->ws, p->rxaio);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_send_cancel(nni_aio *aio, void *arg, int rv)
{
	ws_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	if (p->user_txaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_txaio = NULL;
	nni_aio_abort(p->txaio, rv);
	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_send(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;
	int      rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, wstran_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->user_txaio = aio;
	nni_aio_set_msg(p->txaio, nni_aio_get_msg(aio));
	nni_aio_set_msg(aio, NULL);

	nng_stream_send(p->ws, p->txaio);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_stop(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
}

static int
wstran_pipe_init(void *arg, nni_pipe *pipe)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(pipe);
	return (0);
}

static void
wstran_pipe_fini(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_free(p->rxaio);
	nni_aio_free(p->txaio);

	nng_stream_free(p->ws);
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static void
wstran_pipe_close(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_close(p->rxaio);
	nni_aio_close(p->txaio);

	nni_mtx_lock(&p->mtx);
	nng_stream_close(p->ws);
	nni_mtx_unlock(&p->mtx);
}

static int
wstran_pipe_alloc(ws_pipe **pipep, void *ws)
{
	ws_pipe *p;
	int      rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	// Initialize AIOs.
	if (((rv = nni_aio_alloc(&p->txaio, wstran_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->rxaio, wstran_pipe_recv_cb, p)) != 0)) {
		wstran_pipe_fini(p);
		return (rv);
	}
	p->ws = ws;

	*pipep = p;
	return (0);
}

static uint16_t
wstran_pipe_peer(void *arg)
{
	ws_pipe *p = arg;

	return (p->peer);
}

static int
ws_listener_bind(void *arg)
{
	ws_listener *l = arg;
	int          rv;

	if ((rv = nng_stream_listener_listen(l->listener)) == 0) {
		l->started = true;
	}
	return (rv);
}

static void
ws_listener_cancel(nni_aio *aio, void *arg, int rv)
{
	ws_listener *l = arg;

	nni_mtx_lock(&l->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
wstran_listener_accept(void *arg, nni_aio *aio)
{
	ws_listener *l = arg;
	int          rv;

	// We already bound, so we just need to look for an available
	// pipe (created by the handler), and match it.
	// Otherwise we stick the AIO in the accept list.
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&l->mtx);
	if ((rv = nni_aio_schedule(aio, ws_listener_cancel, l)) != 0) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&l->aios, aio);
	if (aio == nni_list_first(&l->aios)) {
		nng_stream_listener_accept(l->listener, l->accaio);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
wstran_dialer_cancel(nni_aio *aio, void *arg, int rv)
{
	ws_dialer *d = arg;

	nni_mtx_lock(&d->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&d->mtx);
}

static void
wstran_dialer_connect(void *arg, nni_aio *aio)
{
	ws_dialer *d = arg;
	int        rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&d->mtx);
	if ((rv = nni_aio_schedule(aio, wstran_dialer_cancel, d)) != 0) {
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	NNI_ASSERT(nni_list_empty(&d->aios));
	d->started = true;
	nni_list_append(&d->aios, aio);
	nng_stream_dialer_dial(d->dialer, d->connaio);
	nni_mtx_unlock(&d->mtx);
}

static const nni_option ws_pipe_options[] = {
	// terminate list
	{
	    .o_name = NULL,
	}
};

static int
wstran_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_pipe *p = arg;
	int      rv;

	if ((rv = nni_stream_getx(p->ws, name, buf, szp, t)) == NNG_ENOTSUP) {
		rv = nni_getopt(ws_pipe_options, name, p, buf, szp, t);
	}
	return (rv);
}

static nni_tran_pipe_ops ws_pipe_ops = {
	.p_init   = wstran_pipe_init,
	.p_fini   = wstran_pipe_fini,
	.p_stop   = wstran_pipe_stop,
	.p_send   = wstran_pipe_send,
	.p_recv   = wstran_pipe_recv,
	.p_close  = wstran_pipe_close,
	.p_peer   = wstran_pipe_peer,
	.p_getopt = wstran_pipe_getopt,
};

static void
wstran_dialer_fini(void *arg)
{
	ws_dialer *d = arg;

	nni_aio_stop(d->connaio);
	nng_stream_dialer_free(d->dialer);
	nni_aio_free(d->connaio);
	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

static void
wstran_listener_fini(void *arg)
{
	ws_listener *l = arg;

	nni_aio_stop(l->accaio);
	nng_stream_listener_free(l->listener);
	nni_aio_free(l->accaio);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

static void
wstran_connect_cb(void *arg)
{
	ws_dialer * d = arg;
	ws_pipe *   p;
	nni_aio *   caio = d->connaio;
	nni_aio *   uaio;
	int         rv;
	nng_stream *ws = NULL;

	nni_mtx_lock(&d->mtx);
	if (nni_aio_result(caio) == 0) {
		ws = nni_aio_get_output(caio, 0);
	}
	if ((uaio = nni_list_first(&d->aios)) == NULL) {
		// The client stopped caring about this!
		nng_stream_free(ws);
		nni_mtx_unlock(&d->mtx);
		return;
	}
	nni_aio_list_remove(uaio);
	NNI_ASSERT(nni_list_empty(&d->aios));
	if ((rv = nni_aio_result(caio)) != 0) {
		nni_aio_finish_error(uaio, rv);
	} else if ((rv = wstran_pipe_alloc(&p, ws)) != 0) {
		nng_stream_free(ws);
		nni_aio_finish_error(uaio, rv);
	} else {
		p->peer = d->peer;

		nni_aio_set_output(uaio, 0, p);
		nni_aio_finish(uaio, 0, 0);
	}
	nni_mtx_unlock(&d->mtx);
}

static void
wstran_dialer_close(void *arg)
{
	ws_dialer *d = arg;

	nni_aio_close(d->connaio);
	nng_stream_dialer_close(d->dialer);
}

static void
wstran_listener_close(void *arg)
{
	ws_listener *l = arg;

	nni_aio_close(l->accaio);
	nng_stream_listener_close(l->listener);
}

static void
wstran_accept_cb(void *arg)
{
	ws_listener *l    = arg;
	nni_aio *    aaio = l->accaio;
	nni_aio *    uaio;
	int          rv;

	nni_mtx_lock(&l->mtx);
	uaio = nni_list_first(&l->aios);
	if ((rv = nni_aio_result(aaio)) != 0) {
		if (uaio != NULL) {
			nni_aio_list_remove(uaio);
			nni_aio_finish_error(uaio, rv);
		}
	} else {
		nng_stream *ws = nni_aio_get_output(aaio, 0);
		if (uaio != NULL) {
			ws_pipe *p;
			// Make a pipe
			nni_aio_list_remove(uaio);
			if ((rv = wstran_pipe_alloc(&p, ws)) != 0) {
				nng_stream_close(ws);
				nni_aio_finish_error(uaio, rv);
			} else {
				p->peer = l->peer;

				nni_aio_set_output(uaio, 0, p);
				nni_aio_finish(uaio, 0, 0);
			}
		}
	}
	if (!nni_list_empty(&l->aios)) {
		nng_stream_listener_accept(l->listener, aaio);
	}
	nni_mtx_unlock(&l->mtx);
}

static int
wstran_dialer_init(void **dp, nng_url *url, nni_dialer *ndialer)
{
	ws_dialer *d;
	nni_sock * s = nni_dialer_sock(ndialer);
	int        rv;
	char       name[64];

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&d->mtx);

	nni_aio_list_init(&d->aios);

	d->peer = nni_sock_peer_id(s);

	snprintf(
	    name, sizeof(name), "%s.sp.nanomsg.org",
	    nni_sock_peer_name(s));

	if (((rv = nni_ws_dialer_alloc(&d->dialer, url)) != 0) ||
	    ((rv = nni_aio_alloc(&d->connaio, wstran_connect_cb, d)) != 0) ||
	    ((rv = nng_stream_dialer_set_bool(
	          d->dialer, NNI_OPT_WS_MSGMODE, true)) != 0) ||
	    ((rv = nng_stream_dialer_set_string(
	          d->dialer, NNG_OPT_WS_PROTOCOL, name)) != 0)) {
		wstran_dialer_fini(d);
		return (rv);
	}

	*dp = d;
	return (0);
}

static int
wstran_listener_init(void **lp, nng_url *url, nni_listener *listener)
{
	ws_listener *l;
	int          rv;
	nni_sock *   s = nni_listener_sock(listener);
	char         name[64];

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&l->mtx);

	nni_aio_list_init(&l->aios);

	l->peer = nni_sock_peer_id(s);

	snprintf(name, sizeof(name), "%s.sp.nanomsg.org",
	    nni_sock_proto_name(s));

	if (((rv = nni_ws_listener_alloc(&l->listener, url)) != 0) ||
	    ((rv = nni_aio_alloc(&l->accaio, wstran_accept_cb, l)) != 0) ||
	    ((rv = nng_stream_listener_set_bool(
	          l->listener, NNI_OPT_WS_MSGMODE, true)) != 0) ||
	    ((rv = nng_stream_listener_set_string(
	          l->listener, NNG_OPT_WS_PROTOCOL, name)) != 0)) {
		wstran_listener_fini(l);
		return (rv);
	}
	*lp = l;
	return (0);
}

static int
wstran_init(void)
{
	return (0);
}

static void
wstran_fini(void)
{
}

static const nni_option wstran_ep_opts[] = {
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
wstran_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_dialer *d = arg;
	int        rv;

	rv = nni_stream_dialer_getx(d->dialer, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(wstran_ep_opts, name, d, buf, szp, t);
	}
	return (rv);
}

static int
wstran_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ws_dialer *d = arg;
	int        rv;

	rv = nni_stream_dialer_setx(d->dialer, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(wstran_ep_opts, name, d, buf, sz, t);
	}
	return (rv);
}

static int
wstran_listener_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_listener *l = arg;
	int          rv;

	rv = nni_stream_listener_getx(l->listener, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(wstran_ep_opts, name, l, buf, szp, t);
	}
	return (rv);
}

static int
wstran_listener_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ws_listener *l = arg;
	int          rv;

	rv = nni_stream_listener_setx(l->listener, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(wstran_ep_opts, name, l, buf, sz, t);
	}
	return (rv);
}

static nni_chkoption wstran_check_opts[] = {
	{
	    .o_name = NULL,
	},
};

static int
wstran_checkopt(const char *name, const void *buf, size_t sz, nni_type t)
{
	int rv;
	rv = nni_chkopt(wstran_check_opts, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_checkopt("ws", name, buf, sz, t);
	}
	return (rv);
}

static nni_tran_dialer_ops ws_dialer_ops = {
	.d_init    = wstran_dialer_init,
	.d_fini    = wstran_dialer_fini,
	.d_connect = wstran_dialer_connect,
	.d_close   = wstran_dialer_close,
	.d_setopt  = wstran_dialer_setopt,
	.d_getopt  = wstran_dialer_getopt,
};

static nni_tran_listener_ops ws_listener_ops = {
	.l_init   = wstran_listener_init,
	.l_fini   = wstran_listener_fini,
	.l_bind   = ws_listener_bind,
	.l_accept = wstran_listener_accept,
	.l_close  = wstran_listener_close,
	.l_setopt = wstran_listener_setopt,
	.l_getopt = wstran_listener_getopt,
};

static nni_tran ws_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "ws",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
	.tran_checkopt = wstran_checkopt,
};

int
nng_ws_register(void)
{
	return (nni_tran_register(&ws_tran));
}

#ifdef NNG_TRANSPORT_WSS

static nni_tran wss_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "wss",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
	.tran_checkopt = wstran_checkopt,
};

int
nng_wss_register(void)
{
	return (nni_tran_register(&wss_tran));
}
#else
int
nng_wss_register(void)
{
	return (0);
}

#endif // NNG_TRANSPORT_WSS
