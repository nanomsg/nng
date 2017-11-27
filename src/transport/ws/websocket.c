//
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "supplemental/websocket/websocket.h"

typedef struct ws_ep   ws_ep;
typedef struct ws_pipe ws_pipe;

struct ws_ep {
	int              mode; // NNI_EP_MODE_DIAL or NNI_EP_MODE_LISTEN
	char *           addr;
	uint16_t         lproto; // local protocol
	uint16_t         rproto; // remote protocol
	size_t           rcvmax;
	char *           protoname;
	nni_list         aios;
	nni_mtx          mtx;
	nni_aio *        connaio;
	nni_aio *        accaio;
	nni_ws_listener *listener;
	nni_ws_dialer *  dialer;
};

struct ws_pipe {
	int      mode; // NNI_EP_MODE_DIAL or NNI_EP_MODE_LISTEN
	nni_mtx  mtx;
	size_t   rcvmax; // inherited from EP
	bool     closed;
	uint16_t rproto;
	uint16_t lproto;
	nni_aio *user_txaio;
	nni_aio *user_rxaio;
	nni_aio *txaio;
	nni_aio *rxaio;
	nni_ws * ws;
};

static void
ws_pipe_send_cb(void *arg)
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
ws_pipe_recv_cb(void *arg)
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
ws_pipe_recv_cancel(nni_aio *aio, int rv)
{
	ws_pipe *p = aio->a_prov_data;
	nni_mtx_lock(&p->mtx);
	if (p->user_rxaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_cancel(p->rxaio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_recv(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (nni_aio_start(aio, ws_pipe_recv_cancel, p) != 0) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_rxaio = aio;

	nni_ws_recv_msg(p->ws, p->rxaio);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_send_cancel(nni_aio *aio, int rv)
{
	ws_pipe *p = aio->a_prov_data;
	nni_mtx_lock(&p->mtx);
	if (p->user_txaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// This aborts the upper send, which will call back with an error
	// when it is done.
	nni_aio_cancel(p->txaio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_send(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (nni_aio_start(aio, ws_pipe_send_cancel, p) != 0) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_txaio = aio;
	nni_aio_set_msg(p->txaio, nni_aio_get_msg(aio));
	nni_aio_set_msg(aio, NULL);

	nni_ws_send_msg(p->ws, p->txaio);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_fini(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);

	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);

	if (p->ws) {
		nni_ws_fini(p->ws);
	}
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static void
ws_pipe_close(void *arg)
{
	ws_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	nni_ws_close(p->ws);
	nni_mtx_unlock(&p->mtx);
}

static int
ws_pipe_init(ws_pipe **pipep, ws_ep *ep, void *ws)
{
	ws_pipe *p;
	int      rv;
	nni_aio *aio;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	// Initialize AIOs.
	if (((rv = nni_aio_init(&p->txaio, ws_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, ws_pipe_recv_cb, p)) != 0)) {
		ws_pipe_fini(p);
		return (rv);
	}

	p->mode   = ep->mode;
	p->rcvmax = ep->rcvmax;
	// p->addr   = ep->addr;
	p->rproto = ep->rproto;
	p->lproto = ep->lproto;
	p->ws     = ws;

	if ((aio = nni_list_first(&ep->aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_pipe(aio, p);
	}

	*pipep = p;
	return (0);
}

static uint16_t
ws_pipe_peer(void *arg)
{
	ws_pipe *p = arg;

	return (p->rproto);
}

static void
ws_pipe_start(void *arg, nni_aio *aio)
{
	if (nni_aio_start(aio, NULL, NULL) == 0) {
		nni_aio_finish(aio, 0, 0);
	}
}

// We have very different approaches for server and client.
// Servers use the HTTP server framework, and a request methodology.

static int
ws_ep_bind(void *arg)
{
	ws_ep *ep = arg;
	return (nni_ws_listener_listen(ep->listener));
}

static void
ws_ep_cancel(nni_aio *aio, int rv)
{
	ws_ep *ep = aio->a_prov_data;

	nni_mtx_lock(&ep->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ws_ep_accept(void *arg, nni_aio *aio)
{
	ws_ep *ep = arg;

	// We already bound, so we just need to look for an available
	// pipe (created by the handler), and match it.
	// Otherwise we stick the AIO in the accept list.
	nni_mtx_lock(&ep->mtx);
	if (nni_aio_start(aio, ws_ep_cancel, ep) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	nni_list_append(&ep->aios, aio);
	if (aio == nni_list_first(&ep->aios)) {
		nni_ws_listener_accept(ep->listener, ep->accaio);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ws_ep_connect(void *arg, nni_aio *aio)
{
	ws_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(nni_list_empty(&ep->aios));

	// If we can't start, then its dying and we can't report
	// either.
	if ((rv = nni_aio_start(aio, ws_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	nni_list_append(&ep->aios, aio);
	nni_ws_dialer_dial(ep->dialer, ep->connaio);
	nni_mtx_unlock(&ep->mtx);
}

static int
ws_ep_setopt_recvmaxsz(void *arg, const void *v, size_t sz)
{
	ws_ep *ep = arg;
	if (ep == NULL) {
		return (nni_chkopt_size(v, sz, 0, NNI_MAXSZ));
	}
	return (nni_setopt_size(&ep->rcvmax, v, sz, 0, NNI_MAXSZ));
}

static int
ws_ep_getopt_recvmaxsz(void *arg, void *v, size_t *szp)
{
	ws_ep *ep = arg;
	return (nni_getopt_size(ep->rcvmax, v, szp));
}

static nni_tran_pipe_option ws_pipe_options[] = {
#if 0
	// clang-format off
	{ NNG_OPT_LOCADDR, ws_pipe_getopt_locaddr },
	{ NNG_OPT_REMADDR, ws_pipe_getopt_remaddr },
	// clang-format on
#endif
	// terminate list
	{ NULL, NULL }
};

static nni_tran_pipe ws_pipe_ops = {
	.p_fini    = ws_pipe_fini,
	.p_start   = ws_pipe_start,
	.p_send    = ws_pipe_send,
	.p_recv    = ws_pipe_recv,
	.p_close   = ws_pipe_close,
	.p_peer    = ws_pipe_peer,
	.p_options = ws_pipe_options,
};

static nni_tran_ep_option ws_ep_options[] = {
	{
	    .eo_name   = NNG_OPT_RECVMAXSZ,
	    .eo_getopt = ws_ep_getopt_recvmaxsz,
	    .eo_setopt = ws_ep_setopt_recvmaxsz,
	},
	// terminate list
	{ NULL, NULL, NULL },
};

static void
ws_ep_fini(void *arg)
{
	ws_ep *ep = arg;

	nni_aio_stop(ep->accaio);
	nni_aio_stop(ep->connaio);
	nni_aio_fini(ep->accaio);
	nni_aio_fini(ep->connaio);
	if (ep->listener != NULL) {
		nni_ws_listener_fini(ep->listener);
	}
	if (ep->dialer != NULL) {
		nni_ws_dialer_fini(ep->dialer);
	}
	nni_strfree(ep->addr);
	nni_strfree(ep->protoname);
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static void
ws_ep_conn_cb(void *arg)
{
	ws_ep *  ep = arg;
	ws_pipe *p;
	nni_aio *caio = ep->connaio;
	nni_aio *uaio;
	int      rv;
	nni_ws * ws = NULL;

	nni_mtx_lock(&ep->mtx);
	if (nni_aio_result(caio) == 0) {
		ws = nni_aio_get_pipe(caio);
	}
	if ((uaio = nni_list_first(&ep->aios)) == NULL) {
		// The client stopped caring about this!
		if (ws != NULL) {
			nni_ws_fini(ws);
		}
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	nni_aio_list_remove(uaio);
	NNI_ASSERT(nni_list_empty(&ep->aios));
	if ((rv = nni_aio_result(caio)) != 0) {
		nni_aio_finish_error(uaio, rv);
	} else if ((rv = ws_pipe_init(&p, ep, ws)) != 0) {
		nni_ws_fini(ws);
		nni_aio_finish_error(uaio, rv);
	} else {
		nni_aio_finish_pipe(uaio, p);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ws_ep_close(void *arg)
{
	ws_ep *ep = arg;

	if (ep->mode == NNI_EP_MODE_LISTEN) {
		nni_ws_listener_close(ep->listener);
	} else {
		nni_ws_dialer_close(ep->dialer);
	}
}

static void
ws_ep_acc_cb(void *arg)
{
	ws_ep *  ep   = arg;
	nni_aio *aaio = ep->accaio;
	nni_aio *uaio;
	int      rv;

	nni_mtx_lock(&ep->mtx);
	uaio = nni_list_first(&ep->aios);
	if ((rv = nni_aio_result(aaio)) != 0) {
		if (uaio != NULL) {
			nni_aio_list_remove(uaio);
			nni_aio_finish_error(uaio, rv);
		}
	} else {
		nni_ws *ws = nni_aio_get_pipe(aaio);
		if (uaio != NULL) {
			ws_pipe *p;
			// Make a pipe
			nni_aio_list_remove(uaio);
			if ((rv = ws_pipe_init(&p, ep, ws)) != 0) {
				nni_ws_close(ws);
				nni_aio_finish_error(uaio, rv);
			} else {
				nni_aio_finish_pipe(uaio, p);
			}
		}
	}
	if (!nni_list_empty(&ep->aios)) {
		nni_ws_listener_accept(ep->listener, aaio);
	}
	nni_mtx_unlock(&ep->mtx);
}

static int
ws_ep_init(void **epp, const char *url, nni_sock *sock, int mode)
{
	ws_ep *     ep;
	const char *pname;
	int         rv;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&ep->mtx);

	// List of pipes (server only).
	nni_aio_list_init(&ep->aios);

	ep->mode   = mode;
	ep->lproto = nni_sock_proto(sock);
	ep->rproto = nni_sock_peer(sock);

	if (mode == NNI_EP_MODE_DIAL) {
		pname = nni_sock_peer_name(sock);
		rv    = nni_ws_dialer_init(&ep->dialer, url);
	} else {
		pname = nni_sock_proto_name(sock);
		rv    = nni_ws_listener_init(&ep->listener, url);
	}

	if ((rv == 0) && ((ep->addr = nni_strdup(url)) == NULL)) {
		rv = NNG_ENOMEM;
	}
	if ((rv != 0) ||
	    ((rv = nni_aio_init(&ep->connaio, ws_ep_conn_cb, ep)) != 0) ||
	    ((rv = nni_aio_init(&ep->accaio, ws_ep_acc_cb, ep)) != 0) ||
	    ((rv = nni_asprintf(&ep->protoname, "%s.sp.nanomsg.org", pname)) !=
	        0)) {
		ws_ep_fini(ep);
		return (rv);
	}

	*epp = ep;
	return (0);
}
static int
ws_tran_init(void)
{
	return (0);
}

static void
ws_tran_fini(void)
{
}

static nni_tran_ep ws_ep_ops = {
	.ep_init    = ws_ep_init,
	.ep_fini    = ws_ep_fini,
	.ep_connect = ws_ep_connect,
	.ep_bind    = ws_ep_bind,
	.ep_accept  = ws_ep_accept,
	.ep_close   = ws_ep_close,
	.ep_options = ws_ep_options,
};

static nni_tran ws_tran = {
	.tran_version = NNI_TRANSPORT_VERSION,
	.tran_scheme  = "ws",
	.tran_ep      = &ws_ep_ops,
	.tran_pipe    = &ws_pipe_ops,
	.tran_init    = ws_tran_init,
	.tran_fini    = ws_tran_fini,
};

int
nng_ws_register(void)
{
	return (nni_tran_register(&ws_tran));
}
