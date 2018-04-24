//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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
#include "supplemental/http/http_api.h"
#include "supplemental/tls/tls.h"
#include "supplemental/tls/tls_api.h"
#include "supplemental/websocket/websocket.h"

#include "websocket.h"

typedef struct ws_ep   ws_ep;
typedef struct ws_pipe ws_pipe;

typedef struct ws_hdr {
	nni_list_node node;
	char *        name;
	char *        value;
} ws_hdr;

struct ws_ep {
	int              mode;   // NNI_EP_MODE_DIAL or NNI_EP_MODE_LISTEN
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
	nni_list         headers; // to send, res or req
	bool             started;
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
	ws_pipe *p = nni_aio_get_prov_data(aio);
	nni_mtx_lock(&p->mtx);
	if (p->user_rxaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_abort(p->rxaio, rv);
	p->user_rxaio = NULL;
	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_recv(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	nni_aio_schedule(aio, ws_pipe_recv_cancel, p);
	p->user_rxaio = aio;
	nni_ws_recv_msg(p->ws, p->rxaio);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_send_cancel(nni_aio *aio, int rv)
{
	ws_pipe *p = nni_aio_get_prov_data(aio);
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
ws_pipe_send(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	nni_aio_schedule(aio, ws_pipe_send_cancel, p);
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
	p->rproto = ep->rproto;
	p->lproto = ep->lproto;
	p->ws     = ws;

	*pipep = p;
	return (0);
}

static uint16_t
ws_pipe_peer(void *arg)
{
	ws_pipe *p = arg;

	return (p->rproto);
}

// We have very different approaches for server and client.
// Servers use the HTTP server framework, and a request methodology.

static int
ws_hook(void *arg, nni_http_req *req, nni_http_res *res)
{
	ws_ep * ep = arg;
	ws_hdr *h;
	NNI_ARG_UNUSED(req);

	// Eventually we'll want user customizable hooks.
	// For now we just set the headers we want.

	NNI_LIST_FOREACH (&ep->headers, h) {
		int rv;
		rv = nng_http_res_set_header(res, h->name, h->value);
		if (rv != 0) {
			return (rv);
		}
	}
	return (0);
}

static int
ws_ep_bind(void *arg)
{
	ws_ep *ep = arg;
	int    rv;

	nni_ws_listener_hook(ep->listener, ws_hook, ep);
	if ((rv = nni_ws_listener_listen(ep->listener)) == 0) {
		ep->started = true;
	}
	return (rv);
}

static void
ws_ep_cancel(nni_aio *aio, int rv)
{
	ws_ep *ep = nni_aio_get_prov_data(aio);

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
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	nni_aio_schedule(aio, ws_ep_cancel, ep);
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

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if (!ep->started) {
		ws_hdr *h;
		NNI_LIST_FOREACH (&ep->headers, h) {
			int rv = nni_ws_dialer_header(
			    ep->dialer, h->name, h->value);
			if (rv != 0) {
				nni_aio_finish_error(aio, rv);
				return;
			}
		}
	}

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(nni_list_empty(&ep->aios));

	nni_aio_schedule(aio, ws_ep_cancel, ep);
	ep->started = true;
	nni_list_append(&ep->aios, aio);
	nni_ws_dialer_dial(ep->dialer, ep->connaio);
	nni_mtx_unlock(&ep->mtx);
}

static int
ws_ep_setopt_recvmaxsz(void *arg, const void *v, size_t sz, int typ)
{
	ws_ep *ep = arg;
	size_t val;
	int    rv;

	rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, typ);
	if ((rv == 0) && (ep != NULL)) {
		ep->rcvmax = val;
	}
	return (rv);
}

static int
ws_ep_setopt_headers(ws_ep *ep, const char *v)
{
	char *   dupstr;
	size_t   duplen;
	char *   name;
	char *   value;
	char *   nl;
	nni_list l;
	ws_hdr * h;
	int      rv;

	if (ep->started) {
		return (NNG_EBUSY);
	}

	NNI_LIST_INIT(&l, ws_hdr, node);
	if ((dupstr = nni_strdup(v)) == NULL) {
		return (NNG_ENOMEM);
	}
	duplen = strlen(dupstr) + 1; // so we can free it later
	name   = dupstr;
	for (;;) {
		if ((value = strchr(name, ':')) == NULL) {
			// Note that this also means that if
			// a bare word is present, we ignore it.
			break;
		}
		*value = '\0';
		value++;
		while (*value == ' ') {
			// Skip leading whitespace.  Not strictly
			// necessary, but still a good idea.
			value++;
		}
		nl = value;
		// Find the end of the line -- should be CRLF, but can
		// also be unterminated or just LF if user
		while ((*nl != '\0') && (*nl != '\r') && (*nl != '\n')) {
			nl++;
		}
		while ((*nl == '\r') || (*nl == '\n')) {
			*nl = '\0';
			nl++;
		}

		if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
			rv = NNG_ENOMEM;
			goto done;
		}
		nni_list_append(&l, h);
		if (((h->name = nni_strdup(name)) == NULL) ||
		    ((h->value = nni_strdup(value)) == NULL)) {
			rv = NNG_ENOMEM;
			goto done;
		}

		name = nl;
	}

	while ((h = nni_list_first(&ep->headers)) != NULL) {
		nni_list_remove(&ep->headers, h);
		nni_strfree(h->name);
		nni_strfree(h->value);
		NNI_FREE_STRUCT(h);
	}
	while ((h = nni_list_first(&l)) != NULL) {
		nni_list_remove(&l, h);
		nni_list_append(&ep->headers, h);
	}
	rv = 0;

done:
	while ((h = nni_list_first(&l)) != NULL) {
		nni_list_remove(&l, h);
		nni_strfree(h->name);
		nni_strfree(h->value);
		NNI_FREE_STRUCT(h);
	}
	nni_free(dupstr, duplen);
	return (rv);
}

static int
ws_ep_setopt_reqhdrs(void *arg, const void *v, size_t sz, int typ)
{
	ws_ep *ep = arg;

	if ((typ != NNI_TYPE_STRING) && (typ != NNI_TYPE_OPAQUE)) {
		return (NNG_EBADTYPE);
	}

	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}

	if ((ep != NULL) && (ep->mode == NNI_EP_MODE_LISTEN)) {
		return (NNG_EREADONLY);
	}
	return (ws_ep_setopt_headers(ep, v));
}

static int
ws_ep_setopt_reshdrs(void *arg, const void *v, size_t sz, int typ)
{
	ws_ep *ep = arg;

	if ((typ != NNI_TYPE_STRING) && (typ != NNI_TYPE_OPAQUE)) {
		return (NNG_EBADTYPE);
	}

	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}

	if ((ep != NULL) && (ep->mode == NNI_EP_MODE_DIAL)) {
		return (NNG_EREADONLY);
	}
	return (ws_ep_setopt_headers(ep, v));
}

static int
ws_ep_getopt_recvmaxsz(void *arg, void *v, size_t *szp, int typ)
{
	ws_ep *ep = arg;
	return (nni_copyout_size(ep->rcvmax, v, szp, typ));
}

static int
ws_pipe_getopt_locaddr(void *arg, void *v, size_t *szp, int typ)
{
	ws_pipe *    p = arg;
	int          rv;
	nni_sockaddr sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_ws_sock_addr(p->ws, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, typ);
	}
	return (rv);
}

static int
ws_pipe_getopt_remaddr(void *arg, void *v, size_t *szp, int typ)
{
	ws_pipe *    p = arg;
	int          rv;
	nni_sockaddr sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_ws_peer_addr(p->ws, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, typ);
	}
	return (rv);
}

static int
ws_pipe_getopt_reshdrs(void *arg, void *v, size_t *szp, int typ)
{
	ws_pipe *   p = arg;
	const char *s;

	if ((s = nni_ws_response_headers(p->ws)) == NULL) {
		return (NNG_ENOMEM);
	}
	return (nni_copyout_str(s, v, szp, typ));
}

static int
ws_pipe_getopt_reqhdrs(void *arg, void *v, size_t *szp, int typ)
{
	ws_pipe *   p = arg;
	const char *s;

	if ((s = nni_ws_request_headers(p->ws)) == NULL) {
		return (NNG_ENOMEM);
	}
	return (nni_copyout_str(s, v, szp, typ));
}

static int
ws_pipe_getopt_tls_verified(void *arg, void *v, size_t *szp, int typ)
{
	ws_pipe *p = arg;
	return (nni_copyout_bool(nni_ws_tls_verified(p->ws), v, szp, typ));
}

static nni_tran_pipe_option ws_pipe_options[] = {

	{
	    .po_name   = NNG_OPT_LOCADDR,
	    .po_type   = NNI_TYPE_SOCKADDR,
	    .po_getopt = ws_pipe_getopt_locaddr,
	},
	{
	    .po_name   = NNG_OPT_REMADDR,
	    .po_type   = NNI_TYPE_SOCKADDR,
	    .po_getopt = ws_pipe_getopt_remaddr,
	},
	{
	    .po_name   = NNG_OPT_WS_REQUEST_HEADERS,
	    .po_type   = NNI_TYPE_STRING,
	    .po_getopt = ws_pipe_getopt_reqhdrs,
	},
	{
	    .po_name   = NNG_OPT_WS_RESPONSE_HEADERS,
	    .po_type   = NNI_TYPE_STRING,
	    .po_getopt = ws_pipe_getopt_reshdrs,
	},
	{
	    .po_name   = NNG_OPT_TLS_VERIFIED,
	    .po_type   = NNI_TYPE_BOOL,
	    .po_getopt = ws_pipe_getopt_tls_verified,
	},
	// terminate list
	{
	    .po_name = NULL,
	}
};

static nni_tran_pipe ws_pipe_ops = {
	.p_fini    = ws_pipe_fini,
	.p_send    = ws_pipe_send,
	.p_recv    = ws_pipe_recv,
	.p_close   = ws_pipe_close,
	.p_peer    = ws_pipe_peer,
	.p_options = ws_pipe_options,
};

static nni_tran_ep_option ws_ep_options[] = {
	{
	    .eo_name   = NNG_OPT_RECVMAXSZ,
	    .eo_type   = NNI_TYPE_SIZE,
	    .eo_getopt = ws_ep_getopt_recvmaxsz,
	    .eo_setopt = ws_ep_setopt_recvmaxsz,
	},
	{
	    .eo_name   = NNG_OPT_WS_REQUEST_HEADERS,
	    .eo_type   = NNI_TYPE_STRING,
	    .eo_getopt = NULL,
	    .eo_setopt = ws_ep_setopt_reqhdrs,
	},
	{
	    .eo_name   = NNG_OPT_WS_RESPONSE_HEADERS,
	    .eo_type   = NNI_TYPE_STRING,
	    .eo_getopt = NULL,
	    .eo_setopt = ws_ep_setopt_reshdrs,
	},
	// terminate list
	{
	    .eo_name = NULL,
	},
};

static void
ws_ep_fini(void *arg)
{
	ws_ep * ep = arg;
	ws_hdr *hdr;

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
	while ((hdr = nni_list_first(&ep->headers)) != NULL) {
		nni_list_remove(&ep->headers, hdr);
		nni_strfree(hdr->name);
		nni_strfree(hdr->value);
		NNI_FREE_STRUCT(hdr);
	}
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
		ws = nni_aio_get_output(caio, 0);
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
		nni_aio_set_output(uaio, 0, p);
		nni_aio_finish(uaio, 0, 0);
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
		nni_ws *ws = nni_aio_get_output(aaio, 0);
		if (uaio != NULL) {
			ws_pipe *p;
			// Make a pipe
			nni_aio_list_remove(uaio);
			if ((rv = ws_pipe_init(&p, ep, ws)) != 0) {
				nni_ws_close(ws);
				nni_aio_finish_error(uaio, rv);
			} else {
				nni_aio_set_output(uaio, 0, p);
				nni_aio_finish(uaio, 0, 0);
			}
		}
	}
	if (!nni_list_empty(&ep->aios)) {
		nni_ws_listener_accept(ep->listener, aaio);
	}
	nni_mtx_unlock(&ep->mtx);
}

static int
ws_ep_init(void **epp, nni_url *url, nni_sock *sock, int mode)
{
	ws_ep *     ep;
	const char *pname;
	int         rv;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->headers, ws_hdr, node);

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

	if ((rv != 0) ||
	    ((rv = nni_aio_init(&ep->connaio, ws_ep_conn_cb, ep)) != 0) ||
	    ((rv = nni_aio_init(&ep->accaio, ws_ep_acc_cb, ep)) != 0) ||
	    ((rv = nni_asprintf(&ep->protoname, "%s.sp.nanomsg.org", pname)) !=
	        0)) {
		ws_ep_fini(ep);
		return (rv);
	}

	if (mode == NNI_EP_MODE_DIAL) {
		rv = nni_ws_dialer_proto(ep->dialer, ep->protoname);
	} else {
		rv = nni_ws_listener_proto(ep->listener, ep->protoname);
	}

	if (rv != 0) {
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

#ifdef NNG_TRANSPORT_WSS

static int
wss_get_tls(ws_ep *ep, nng_tls_config **tlsp)
{
	switch (ep->mode) {
	case NNI_EP_MODE_DIAL:
		return (nni_ws_dialer_get_tls(ep->dialer, tlsp));
	case NNI_EP_MODE_LISTEN:
		return (nni_ws_listener_get_tls(ep->listener, tlsp));
	}
	return (NNG_EINVAL);
}

static int
wss_ep_getopt_tlsconfig(void *arg, void *v, size_t *szp, int typ)
{
	ws_ep *         ep = arg;
	nng_tls_config *tls;
	int             rv;

	if (((rv = wss_get_tls(ep, &tls)) != 0) ||
	    ((rv = nni_copyout_ptr(tls, v, szp, typ)) != 0)) {
		return (rv);
	}
	return (0);
}

static int
wss_ep_setopt_tlsconfig(void *arg, const void *v, size_t sz, int typ)
{
	ws_ep *         ep = arg;
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nni_copyin_ptr((void **) &cfg, v, sz, typ)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		// NULL is clearly invalid.
		return (NNG_EINVAL);
	}
	if (ep == NULL) {
		return (0);
	}
	if (ep->mode == NNI_EP_MODE_LISTEN) {
		rv = nni_ws_listener_set_tls(ep->listener, cfg);
	} else {
		rv = nni_ws_dialer_set_tls(ep->dialer, cfg);
	}
	return (rv);
}

static int
wss_ep_setopt_tls_cert_key_file(void *arg, const void *v, size_t sz, int typ)
{
	ws_ep *         ep = arg;
	int             rv;
	nng_tls_config *tls;

	if ((typ != NNI_TYPE_OPAQUE) && (typ != NNI_TYPE_STRING)) {
		return (NNG_EBADTYPE);
	}
	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}
	if (ep == NULL) {
		return (0);
	}
	if ((rv = wss_get_tls(ep, &tls)) != 0) {
		return (rv);
	}
	return (nng_tls_config_cert_key_file(tls, v, NULL));
}

static int
wss_ep_setopt_tls_ca_file(void *arg, const void *v, size_t sz, int typ)
{
	ws_ep *         ep = arg;
	int             rv;
	nng_tls_config *tls;

	if ((typ != NNI_TYPE_OPAQUE) && (typ != NNI_TYPE_STRING)) {
		return (NNG_EBADTYPE);
	}

	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}
	if (ep == NULL) {
		return (0);
	}
	if ((rv = wss_get_tls(ep, &tls)) != 0) {
		return (rv);
	}
	return (nng_tls_config_ca_file(tls, v));
}

static int
wss_ep_setopt_tls_auth_mode(void *arg, const void *v, size_t sz, int typ)
{
	ws_ep *         ep = arg;
	int             rv;
	nng_tls_config *tls;
	int             mode;

	rv = nni_copyin_int(&mode, v, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, typ);
	if ((rv != 0) || (ep == NULL)) {
		return (rv);
	}
	if ((rv = wss_get_tls(ep, &tls)) != 0) {
		return (rv);
	}
	return (nng_tls_config_auth_mode(tls, mode));
}

static int
wss_ep_setopt_tls_server_name(void *arg, const void *v, size_t sz, int typ)
{
	ws_ep *         ep = arg;
	int             rv;
	nng_tls_config *tls;

	if ((typ != NNI_TYPE_OPAQUE) && (typ != NNI_TYPE_STRING)) {
		return (NNG_EBADTYPE);
	}

	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}
	if (ep == NULL) {
		return (0);
	}
	if ((rv = wss_get_tls(ep, &tls)) != 0) {
		return (rv);
	}
	return (nng_tls_config_server_name(tls, v));
}

static nni_tran_ep_option wss_ep_options[] = {
	{
	    .eo_name   = NNG_OPT_RECVMAXSZ,
	    .eo_type   = NNI_TYPE_SIZE,
	    .eo_getopt = ws_ep_getopt_recvmaxsz,
	    .eo_setopt = ws_ep_setopt_recvmaxsz,
	},
	{
	    .eo_name   = NNG_OPT_WS_REQUEST_HEADERS,
	    .eo_type   = NNI_TYPE_STRING,
	    .eo_getopt = NULL,
	    .eo_setopt = ws_ep_setopt_reqhdrs,
	},
	{
	    .eo_name   = NNG_OPT_WS_RESPONSE_HEADERS,
	    .eo_type   = NNI_TYPE_STRING,
	    .eo_getopt = NULL,
	    .eo_setopt = ws_ep_setopt_reshdrs,
	},
	{
	    .eo_name   = NNG_OPT_TLS_CONFIG,
	    .eo_type   = NNI_TYPE_POINTER,
	    .eo_getopt = wss_ep_getopt_tlsconfig,
	    .eo_setopt = wss_ep_setopt_tlsconfig,
	},
	{
	    .eo_name   = NNG_OPT_TLS_CERT_KEY_FILE,
	    .eo_type   = NNI_TYPE_STRING,
	    .eo_getopt = NULL,
	    .eo_setopt = wss_ep_setopt_tls_cert_key_file,
	},
	{
	    .eo_name   = NNG_OPT_TLS_CA_FILE,
	    .eo_type   = NNI_TYPE_STRING,
	    .eo_getopt = NULL,
	    .eo_setopt = wss_ep_setopt_tls_ca_file,
	},
	{
	    .eo_name   = NNG_OPT_TLS_AUTH_MODE,
	    .eo_type   = NNI_TYPE_INT32,
	    .eo_getopt = NULL,
	    .eo_setopt = wss_ep_setopt_tls_auth_mode,
	},
	{
	    .eo_name   = NNG_OPT_TLS_SERVER_NAME,
	    .eo_type   = NNI_TYPE_STRING,
	    .eo_getopt = NULL,
	    .eo_setopt = wss_ep_setopt_tls_server_name,
	},
	// terminate list
	{
	    .eo_name = NULL,
	},
};

static nni_tran_ep wss_ep_ops = {
	.ep_init    = ws_ep_init,
	.ep_fini    = ws_ep_fini,
	.ep_connect = ws_ep_connect,
	.ep_bind    = ws_ep_bind,
	.ep_accept  = ws_ep_accept,
	.ep_close   = ws_ep_close,
	.ep_options = wss_ep_options,
};

static nni_tran wss_tran = {
	.tran_version = NNI_TRANSPORT_VERSION,
	.tran_scheme  = "wss",
	.tran_ep      = &wss_ep_ops,
	.tran_pipe    = &ws_pipe_ops,
	.tran_init    = ws_tran_init,
	.tran_fini    = ws_tran_fini,
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
