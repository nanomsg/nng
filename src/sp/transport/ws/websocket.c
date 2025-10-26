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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../../../core/nng_impl.h"
#include "../../../supplemental/websocket/websocket.h"

typedef struct ws_dialer   ws_dialer;
typedef struct ws_listener ws_listener;
typedef struct ws_pipe     ws_pipe;

struct ws_dialer {
	uint16_t           peer; // remote protocol
	nni_list           aios;
	nni_mtx            mtx;
	nni_aio            connaio;
	nng_stream_dialer *dialer;
	nni_dialer        *ndialer;
	bool               started;
};

struct ws_listener {
	uint16_t             peer; // remote protocol
	nni_list             aios;
	nni_mtx              mtx;
	nni_aio              accaio;
	nng_stream_listener *listener;
	nni_listener        *nlistener;
	nni_list             wait_pipes;
	bool                 started;
	bool                 closed;
};

struct ws_pipe {
	nni_mtx       mtx;
	bool          closed;
	uint16_t      peer;
	nni_aio      *user_txaio;
	nni_aio      *user_rxaio;
	nni_aio       txaio;
	nni_aio       rxaio;
	nng_stream   *ws;
	nni_pipe     *npipe;
	nni_list_node node;
};

static void wstran_listener_match(ws_listener *l);

static void
wstran_pipe_send_cb(void *arg)
{
	ws_pipe *p    = arg;
	nni_aio *taio = &p->txaio;
	nni_aio *uaio;

	nni_mtx_lock(&p->mtx);
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
	nni_aio *raio = &p->rxaio;
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
wstran_pipe_recv_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ws_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	if (p->user_rxaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_rxaio = NULL;
	nni_aio_abort(&p->rxaio, rv);
	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_recv(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&p->mtx);
	if (!nni_aio_start(aio, wstran_pipe_recv_cancel, p)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_rxaio = aio;
	nng_stream_recv(p->ws, &p->rxaio);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_send_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ws_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	if (p->user_txaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_txaio = NULL;
	nni_aio_abort(&p->txaio, rv);
	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_send(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&p->mtx);
	if (!nni_aio_start(aio, wstran_pipe_send_cancel, p)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_txaio = aio;
	nni_aio_set_msg(&p->txaio, nni_aio_get_msg(aio));
	nni_aio_set_msg(aio, NULL);

	nng_stream_send(p->ws, &p->txaio);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_stop(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_stop(&p->rxaio);
	nni_aio_stop(&p->txaio);
	nng_stream_stop(p->ws);
}

static int
wstran_pipe_init(void *arg, nni_pipe *pipe)
{
	ws_pipe *p = arg;

	p->npipe = pipe;
	nni_mtx_init(&p->mtx);

	// Initialize AIOs.
	nni_aio_init(&p->txaio, wstran_pipe_send_cb, p);
	nni_aio_init(&p->rxaio, wstran_pipe_recv_cb, p);
	return (0);
}

static void
wstran_pipe_fini(void *arg)
{
	ws_pipe *p = arg;

	nng_stream_free(p->ws);
	nni_aio_fini(&p->rxaio);
	nni_aio_fini(&p->txaio);

	nni_mtx_fini(&p->mtx);
}

static void
wstran_pipe_close(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_close(&p->rxaio);
	nni_aio_close(&p->txaio);

	nng_stream_close(p->ws);
}

static uint16_t
wstran_pipe_peer(void *arg)
{
	ws_pipe *p = arg;

	return (p->peer);
}

static nng_err
wstran_listener_bind(void *arg, nng_url *url)
{
	ws_listener *l = arg;
	nng_err      rv;

	if ((rv = nng_stream_listener_listen(l->listener)) == NNG_OK) {
		int port;
		nng_stream_listener_get_int(
		    l->listener, NNG_OPT_BOUND_PORT, &port);
		url->u_port = (uint32_t) port;
	}
	return (rv);
}

static void
wstran_listener_cancel(nni_aio *aio, void *arg, nng_err rv)
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

	// We already bound, so we just need to look for an available
	// pipe (created by the handler), and match it.
	// Otherwise we stick the AIO in the accept list.
	nni_aio_reset(aio);
	nni_mtx_lock(&l->mtx);
	if (!nni_aio_start(aio, wstran_listener_cancel, l)) {
		nni_mtx_unlock(&l->mtx);
		return;
	}
	nni_list_append(&l->aios, aio);
	if (!l->started) {
		l->started = true;
		nng_stream_listener_accept(l->listener, &l->accaio);
	}
	wstran_listener_match(l);
	nni_mtx_unlock(&l->mtx);
}

static void
wstran_dialer_cancel(nni_aio *aio, void *arg, nng_err rv)
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

	nni_aio_reset(aio);

	nni_mtx_lock(&d->mtx);
	if (!nni_aio_start(aio, wstran_dialer_cancel, d)) {
		nni_mtx_unlock(&d->mtx);
		return;
	}
	NNI_ASSERT(nni_list_empty(&d->aios));
	d->started = true;
	nni_list_append(&d->aios, aio);
	nng_stream_dialer_dial(d->dialer, &d->connaio);
	nni_mtx_unlock(&d->mtx);
}

static const nni_option ws_pipe_options[] = {
	// terminate list
	{
	    .o_name = NULL,
	}
};

static nng_err
wstran_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_pipe *p = arg;
	nng_err  rv;

	if ((rv = nni_stream_get(p->ws, name, buf, szp, t)) == NNG_ENOTSUP) {
		rv = nni_getopt(ws_pipe_options, name, p, buf, szp, t);
	}
	return (rv);
}

static nng_err
wstran_pipe_peer_cert(void *arg, nng_tls_cert **certp)
{
	ws_pipe *p = arg;

	return (nng_stream_peer_cert(p->ws, certp));
}

static const nng_sockaddr *
wstran_pipe_peer_addr(void *arg)
{
	ws_pipe *p = arg;
	return (nng_stream_peer_addr(p->ws));
}

static const nng_sockaddr *
wstran_pipe_self_addr(void *arg)
{
	ws_pipe *p = arg;
	return (nng_stream_self_addr(p->ws));
}

static size_t
wstran_pipe_size(void)
{
	return (sizeof(ws_pipe));
}

static nni_sp_pipe_ops ws_pipe_ops = {
	.p_size      = wstran_pipe_size,
	.p_init      = wstran_pipe_init,
	.p_fini      = wstran_pipe_fini,
	.p_stop      = wstran_pipe_stop,
	.p_send      = wstran_pipe_send,
	.p_recv      = wstran_pipe_recv,
	.p_close     = wstran_pipe_close,
	.p_peer      = wstran_pipe_peer,
	.p_getopt    = wstran_pipe_getopt,
	.p_peer_cert = wstran_pipe_peer_cert,
	.p_peer_addr = wstran_pipe_peer_addr,
	.p_self_addr = wstran_pipe_self_addr,
};

static void
wstran_dialer_stop(void *arg)
{
	ws_dialer *d = arg;

	nni_aio_stop(&d->connaio);
	nng_stream_dialer_stop(d->dialer);
}

static void
wstran_dialer_fini(void *arg)
{
	ws_dialer *d = arg;

	nng_stream_dialer_free(d->dialer);
	nni_aio_fini(&d->connaio);
	nni_mtx_fini(&d->mtx);
}

static void
wstran_listener_stop(void *arg)
{
	ws_listener *l = arg;

	nni_aio_stop(&l->accaio);
	nng_stream_listener_stop(l->listener);
}

static void
wstran_listener_fini(void *arg)
{
	ws_listener *l = arg;

	nng_stream_listener_free(l->listener);
	nni_aio_fini(&l->accaio);
	nni_mtx_fini(&l->mtx);
}

static void
wstran_connect_cb(void *arg)
{
	ws_dialer  *d = arg;
	ws_pipe    *p;
	nni_aio    *caio = &d->connaio;
	nni_aio    *uaio;
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
	} else if ((rv = nni_pipe_alloc_dialer((void **) &p, d->ndialer)) !=
	    0) {
		nng_stream_free(ws);
		nni_aio_finish_error(uaio, rv);
	} else {
		p->peer = d->peer;
		p->ws   = ws;

		nni_aio_set_output(uaio, 0, p->npipe);
		nni_aio_finish(uaio, 0, 0);
	}
	nni_mtx_unlock(&d->mtx);
}

static void
wstran_dialer_close(void *arg)
{
	ws_dialer *d = arg;

	nni_aio_close(&d->connaio);
	nng_stream_dialer_close(d->dialer);
}

static void
wstran_listener_close(void *arg)
{
	ws_listener *l = arg;
	ws_pipe     *p;

	nni_mtx_lock(&l->mtx);
	if (!l->closed) {
		l->closed = true;
		nni_aio_close(&l->accaio);
		NNI_LIST_FOREACH (&l->wait_pipes, p) {
			nni_pipe_close(p->npipe);
		}
		nng_stream_listener_close(l->listener);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
wstran_listener_match(ws_listener *l)
{
	nni_aio *uaio;
	ws_pipe *p;
	if (((uaio = nni_list_first(&l->aios)) == NULL) ||
	    ((p = nni_list_first(&l->wait_pipes)) == NULL)) {
		return;
	}

	nni_list_remove(&l->wait_pipes, p);
	nni_aio_list_remove(uaio);

	nni_aio_set_output(uaio, 0, p->npipe);
	nni_aio_finish(uaio, 0, 0);
}

static void
wstran_accept_cb(void *arg)
{
	ws_listener *l    = arg;
	nni_aio     *aaio = &l->accaio;
	nni_aio     *uaio;
	int          rv;
	ws_pipe     *p;
	nng_stream  *ws;

	nni_mtx_lock(&l->mtx);

	ws   = nni_aio_get_output(aaio, 0);
	uaio = nni_list_first(&l->aios);
	if ((rv = nni_aio_result(aaio)) != 0) {
		goto error;
	}

	rv = nni_pipe_alloc_listener((void **) &p, l->nlistener);
	if (rv != 0) {
		nng_stream_free(ws);
		goto error;
	}
	p->peer = l->peer;
	p->ws   = ws;

	nni_list_append(&l->wait_pipes, p);
	wstran_listener_match(l);
	nng_stream_listener_accept(l->listener, aaio);
	nni_mtx_unlock(&l->mtx);
	return;

error:

	// possibly report this upstream
	if ((uaio = nni_list_first(&l->aios)) != NULL) {
		nni_aio_list_remove(uaio);
		nni_aio_finish_error(uaio, rv);
	}
	if (rv != NNG_ECLOSED) {
		nng_stream_listener_accept(l->listener, aaio);
	}
	nni_mtx_unlock(&l->mtx);
}

static nng_err
wstran_dialer_init(void *arg, nng_url *url, nni_dialer *ndialer)
{
	ws_dialer *d = arg;
	nni_sock  *s = nni_dialer_sock(ndialer);
	nng_err    rv;
	char       name[64];

	nni_mtx_init(&d->mtx);

	nni_aio_list_init(&d->aios);
	nni_aio_init(&d->connaio, wstran_connect_cb, d);

	d->peer    = nni_sock_peer_id(s);
	d->ndialer = ndialer;

	snprintf(
	    name, sizeof(name), "%s.sp.nanomsg.org", nni_sock_peer_name(s));

	if (((rv = nni_ws_dialer_alloc(&d->dialer, url)) != NNG_OK) ||
	    ((rv = nng_stream_dialer_set_bool(
	          d->dialer, NNI_OPT_WS_MSGMODE, true)) != NNG_OK) ||
	    ((rv = nng_stream_dialer_set_string(
	          d->dialer, NNG_OPT_WS_PROTOCOL, name)) != NNG_OK)) {
		return (rv);
	}

	return (NNG_OK);
}

static nng_err
wstran_listener_init(void *arg, nng_url *url, nni_listener *listener)
{
	ws_listener *l = arg;
	nng_err      rv;
	nni_sock    *s = nni_listener_sock(listener);
	char         name[64];

	l->nlistener = listener;
	nni_mtx_init(&l->mtx);

	nni_aio_list_init(&l->aios);
	nni_aio_init(&l->accaio, wstran_accept_cb, l);
	NNI_LIST_INIT(&l->wait_pipes, ws_pipe, node);

	l->peer = nni_sock_peer_id(s);

	snprintf(
	    name, sizeof(name), "%s.sp.nanomsg.org", nni_sock_proto_name(s));

	if (((rv = nni_ws_listener_alloc(&l->listener, url)) != NNG_OK) ||
	    ((rv = nng_stream_listener_set_bool(
	          l->listener, NNI_OPT_WS_MSGMODE, true)) != NNG_OK) ||
	    ((rv = nng_stream_listener_set_string(
	          l->listener, NNG_OPT_WS_PROTOCOL, name)) != NNG_OK)) {
		return (rv);
	}
	return (NNG_OK);
}

static void
wstran_init(void)
{
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

static nng_err
wstran_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_dialer *d = arg;
	nng_err    rv;

	rv = nni_stream_dialer_get(d->dialer, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(wstran_ep_opts, name, d, buf, szp, t);
	}
	return (rv);
}

static nng_err
wstran_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ws_dialer *d = arg;
	nng_err    rv;

	rv = nni_stream_dialer_set(d->dialer, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(wstran_ep_opts, name, d, buf, sz, t);
	}
	return (rv);
}

static nng_err
wstran_dialer_get_tls(void *arg, nng_tls_config **tls)
{
	ws_dialer *d = arg;
	return (nni_stream_dialer_get_tls(d->dialer, tls));
}

static nng_err
wstran_dialer_set_tls(void *arg, nng_tls_config *tls)
{
	ws_dialer *d = arg;
	return (nni_stream_dialer_set_tls(d->dialer, tls));
}

static nng_err
wstran_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_listener *l = arg;
	int          rv;

	rv = nni_stream_listener_get(l->listener, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(wstran_ep_opts, name, l, buf, szp, t);
	}
	return (rv);
}

static nng_err
wstran_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ws_listener *l = arg;
	nng_err      rv;

	rv = nni_stream_listener_set(l->listener, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(wstran_ep_opts, name, l, buf, sz, t);
	}
	return (rv);
}

static nng_err
wstran_listener_get_tls(void *arg, nng_tls_config **tls)
{
	ws_listener *l = arg;
	return (nni_stream_listener_get_tls(l->listener, tls));
}

static nng_err
wstran_listener_set_tls(void *arg, nng_tls_config *tls)
{
	ws_listener *l = arg;
	return (nni_stream_listener_set_tls(l->listener, tls));
}

static nni_sp_dialer_ops ws_dialer_ops = {
	.d_size    = sizeof(ws_dialer),
	.d_init    = wstran_dialer_init,
	.d_fini    = wstran_dialer_fini,
	.d_connect = wstran_dialer_connect,
	.d_close   = wstran_dialer_close,
	.d_stop    = wstran_dialer_stop,
	.d_setopt  = wstran_dialer_setopt,
	.d_getopt  = wstran_dialer_getopt,
	.d_get_tls = wstran_dialer_get_tls,
	.d_set_tls = wstran_dialer_set_tls,
};

static nni_sp_listener_ops ws_listener_ops = {
	.l_size    = sizeof(ws_listener),
	.l_init    = wstran_listener_init,
	.l_fini    = wstran_listener_fini,
	.l_bind    = wstran_listener_bind,
	.l_accept  = wstran_listener_accept,
	.l_close   = wstran_listener_close,
	.l_stop    = wstran_listener_stop,
	.l_setopt  = wstran_listener_set,
	.l_getopt  = wstran_listener_get,
	.l_get_tls = wstran_listener_get_tls,
	.l_set_tls = wstran_listener_set_tls,
};

static nni_sp_tran ws_tran = {
	.tran_scheme   = "ws",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

static nni_sp_tran ws4_tran = {
	.tran_scheme   = "ws4",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

static nni_sp_tran ws6_tran = {
	.tran_scheme   = "ws6",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

void
nni_sp_ws_register(void)
{
	nni_sp_tran_register(&ws_tran);
	nni_sp_tran_register(&ws4_tran);
	nni_sp_tran_register(&ws6_tran);
}

#ifdef NNG_TRANSPORT_WSS

static nni_sp_tran wss_tran = {
	.tran_scheme   = "wss",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

static nni_sp_tran wss4_tran = {
	.tran_scheme   = "wss4",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

#ifdef NNG_ENABLE_IPV6
static nni_sp_tran wss6_tran = {
	.tran_scheme   = "wss6",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};
#endif

void
nni_sp_wss_register(void)
{
	nni_sp_tran_register(&wss_tran);
	nni_sp_tran_register(&wss4_tran);
#ifdef NNG_ENABLE_IPV6
	nni_sp_tran_register(&wss6_tran);
#endif
}

#endif // NNG_TRANSPORT_WSS
