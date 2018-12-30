//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
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
#include "supplemental/tls/tls_api.h"
#include "supplemental/websocket/websocket.h"

#include <nng/supplemental/tls/tls.h>
#include <nng/transport/ws/websocket.h>

typedef struct ws_dialer   ws_dialer;
typedef struct ws_listener ws_listener;
typedef struct ws_pipe     ws_pipe;

typedef struct ws_hdr {
	nni_list_node node;
	char *        name;
	char *        value;
} ws_hdr;

struct ws_dialer {
	uint16_t       lproto; // local protocol
	uint16_t       rproto; // remote protocol
	size_t         rcvmax;
	char *         prname;
	nni_list       aios;
	nni_mtx        mtx;
	nni_aio *      connaio;
	nni_ws_dialer *dialer;
	nni_list       headers; // req headers
	bool           started;
	nni_dialer *   ndialer;
};

struct ws_listener {
	uint16_t         lproto; // local protocol
	uint16_t         rproto; // remote protocol
	size_t           rcvmax;
	char *           prname;
	nni_list         aios;
	nni_mtx          mtx;
	nni_aio *        accaio;
	nni_ws_listener *listener;
	nni_list         headers; // res headers
	bool             started;
	nni_listener *   nlistener;
};

struct ws_pipe {
	nni_mtx   mtx;
	nni_pipe *npipe;
	size_t    rcvmax;
	bool      closed;
	uint16_t  rproto;
	uint16_t  lproto;
	nni_aio * user_txaio;
	nni_aio * user_rxaio;
	nni_aio * txaio;
	nni_aio * rxaio;
	nni_ws *  ws;
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
ws_pipe_recv_cancel(nni_aio *aio, void *arg, int rv)
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
ws_pipe_recv(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;
	int      rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, ws_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->user_rxaio = aio;
	nni_ws_recv_msg(p->ws, p->rxaio);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_send_cancel(nni_aio *aio, void *arg, int rv)
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
ws_pipe_send(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;
	int      rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, ws_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->user_txaio = aio;
	nni_aio_set_msg(p->txaio, nni_aio_get_msg(aio));
	nni_aio_set_msg(aio, NULL);

	nni_ws_send_msg(p->ws, p->txaio);
	nni_mtx_unlock(&p->mtx);
}

static void
ws_pipe_stop(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
}

static int
ws_pipe_init(void *arg, nni_pipe *npipe)
{
	ws_pipe *p = arg;
	p->npipe   = npipe;
	return (0);
}

static void
ws_pipe_fini(void *arg)
{
	ws_pipe *p = arg;

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

	nni_aio_close(p->rxaio);
	nni_aio_close(p->txaio);

	nni_mtx_lock(&p->mtx);
	nni_ws_close(p->ws);
	nni_mtx_unlock(&p->mtx);
}

static int
ws_pipe_alloc(ws_pipe **pipep, void *ws)
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
	p->ws = ws;

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
	ws_listener *l = arg;
	ws_hdr *     h;
	NNI_ARG_UNUSED(req);

	// Eventually we'll want user customizable hooks.
	// For now we just set the headers we want.

	NNI_LIST_FOREACH (&l->headers, h) {
		int rv;
		rv = nng_http_res_set_header(res, h->name, h->value);
		if (rv != 0) {
			return (rv);
		}
	}
	return (0);
}

static int
ws_listener_bind(void *arg)
{
	ws_listener *l = arg;
	int          rv;

	nni_ws_listener_set_maxframe(l->listener, l->rcvmax);
	nni_ws_listener_hook(l->listener, ws_hook, l);

	if ((rv = nni_ws_listener_listen(l->listener)) == 0) {
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
ws_listener_accept(void *arg, nni_aio *aio)
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
		nni_ws_listener_accept(l->listener, l->accaio);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
ws_dialer_cancel(nni_aio *aio, void *arg, int rv)
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
ws_dialer_connect(void *arg, nni_aio *aio)
{
	ws_dialer *d = arg;
	int        rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if (!d->started) {
		ws_hdr *h;
		NNI_LIST_FOREACH (&d->headers, h) {
			int rv =
			    nni_ws_dialer_header(d->dialer, h->name, h->value);
			if (rv != 0) {
				nni_aio_finish_error(aio, rv);
				return;
			}
		}
	}

	nni_mtx_lock(&d->mtx);
	if ((rv = nni_aio_schedule(aio, ws_dialer_cancel, d)) != 0) {
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	NNI_ASSERT(nni_list_empty(&d->aios));
	d->started = true;
	nni_list_append(&d->aios, aio);
	nni_ws_dialer_set_maxframe(d->dialer, d->rcvmax);
	nni_ws_dialer_dial(d->dialer, d->connaio);
	nni_mtx_unlock(&d->mtx);
}

static int
ws_check_string(const void *v, size_t sz, nni_opt_type t)
{
	if ((t != NNI_TYPE_OPAQUE) && (t != NNI_TYPE_STRING)) {
		return (NNG_EBADTYPE);
	}
	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}
	return (0);
}

static int
ws_dialer_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_dialer *d = arg;
	size_t     val;
	int        rv;

	if (((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) &&
	    (d != NULL)) {
		nni_mtx_lock(&d->mtx);
		d->rcvmax = val;
		nni_mtx_unlock(&d->mtx);
		nni_ws_dialer_set_maxframe(d->dialer, val);
	}
	return (rv);
}

static int
ws_dialer_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	ws_dialer *d = arg;
	int        rv;
	nni_mtx_lock(&d->mtx);
	rv = nni_copyout_size(d->rcvmax, v, szp, t);
	nni_mtx_unlock(&d->mtx);
	return (rv);
}

static int
ws_listener_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_listener *l = arg;
	size_t       val;
	int          rv;

	if (((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) &&
	    (l != NULL)) {
		nni_mtx_lock(&l->mtx);
		l->rcvmax = val;
		nni_mtx_unlock(&l->mtx);
		nni_ws_listener_set_maxframe(l->listener, val);
	}
	return (rv);
}

static int
ws_listener_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	ws_listener *l = arg;
	int          rv;
	nni_mtx_lock(&l->mtx);
	rv = nni_copyout_size(l->rcvmax, v, szp, t);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}

static int
ws_set_headers(nni_list *headers, const char *v)
{
	char *   dupstr;
	size_t   duplen;
	char *   name;
	char *   value;
	char *   nl;
	nni_list l;
	ws_hdr * h;
	int      rv;

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

	while ((h = nni_list_first(headers)) != NULL) {
		nni_list_remove(headers, h);
		nni_strfree(h->name);
		nni_strfree(h->value);
		NNI_FREE_STRUCT(h);
	}
	while ((h = nni_list_first(&l)) != NULL) {
		nni_list_remove(&l, h);
		nni_list_append(headers, h);
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
ws_dialer_set_reqhdrs(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_dialer *d = arg;
	int        rv;

	if (((rv = ws_check_string(v, sz, t)) == 0) && (d != NULL)) {
		if (d->started) {
			return (NNG_EBUSY);
		}
		nni_mtx_lock(&d->mtx);
		rv = ws_set_headers(&d->headers, v);
		nni_mtx_unlock(&d->mtx);
	}
	return (rv);
}

static int
ws_listener_set_reshdrs(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_listener *l = arg;
	int          rv;

	if (((rv = ws_check_string(v, sz, t)) == 0) && (l != NULL)) {
		if (l->started) {
			return (NNG_EBUSY);
		}
		nni_mtx_lock(&l->mtx);
		rv = ws_set_headers(&l->headers, v);
		nni_mtx_unlock(&l->mtx);
	}
	return (rv);
}

static int
ws_pipe_get_reshdrs(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	ws_pipe *   p = arg;
	const char *s;

	if ((s = nni_ws_response_headers(p->ws)) == NULL) {
		return (NNG_ENOMEM);
	}
	return (nni_copyout_str(s, v, szp, t));
}

static int
ws_pipe_get_reqhdrs(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	ws_pipe *   p = arg;
	const char *s;

	if ((s = nni_ws_request_headers(p->ws)) == NULL) {
		return (NNG_ENOMEM);
	}
	return (nni_copyout_str(s, v, szp, t));
}

static const nni_option ws_pipe_options[] = {
	{
	    .o_name = NNG_OPT_WS_REQUEST_HEADERS,
	    .o_get  = ws_pipe_get_reqhdrs,
	},
	{
	    .o_name = NNG_OPT_WS_RESPONSE_HEADERS,
	    .o_get  = ws_pipe_get_reshdrs,
	},
	// terminate list
	{
	    .o_name = NULL,
	}
};

static int
ws_pipe_getopt(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_pipe *p = arg;
	int      rv;

	if ((rv = nni_ws_getopt(p->ws, name, buf, szp, t)) == NNG_ENOTSUP) {
		rv = nni_getopt(ws_pipe_options, name, p, buf, szp, t);
	}
	return (rv);
}

static nni_tran_pipe_ops ws_pipe_ops = {
	.p_init   = ws_pipe_init,
	.p_fini   = ws_pipe_fini,
	.p_stop   = ws_pipe_stop,
	.p_send   = ws_pipe_send,
	.p_recv   = ws_pipe_recv,
	.p_close  = ws_pipe_close,
	.p_peer   = ws_pipe_peer,
	.p_getopt = ws_pipe_getopt,
};

static nni_option ws_dialer_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = ws_dialer_get_recvmaxsz,
	    .o_set  = ws_dialer_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_WS_REQUEST_HEADERS,
	    .o_set  = ws_dialer_set_reqhdrs,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_option ws_listener_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = ws_listener_get_recvmaxsz,
	    .o_set  = ws_listener_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_WS_RESPONSE_HEADERS,
	    .o_set  = ws_listener_set_reshdrs,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static void
ws_dialer_fini(void *arg)
{
	ws_dialer *d = arg;
	ws_hdr *   hdr;

	nni_aio_stop(d->connaio);
	if (d->dialer != NULL) {
		nni_ws_dialer_fini(d->dialer);
	}
	nni_aio_fini(d->connaio);
	while ((hdr = nni_list_first(&d->headers)) != NULL) {
		nni_list_remove(&d->headers, hdr);
		nni_strfree(hdr->name);
		nni_strfree(hdr->value);
		NNI_FREE_STRUCT(hdr);
	}
	nni_strfree(d->prname);
	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

static void
ws_listener_fini(void *arg)
{
	ws_listener *l = arg;
	ws_hdr *     hdr;

	nni_aio_stop(l->accaio);
	if (l->listener != NULL) {
		nni_ws_listener_fini(l->listener);
	}
	nni_aio_fini(l->accaio);
	while ((hdr = nni_list_first(&l->headers)) != NULL) {
		nni_list_remove(&l->headers, hdr);
		nni_strfree(hdr->name);
		nni_strfree(hdr->value);
		NNI_FREE_STRUCT(hdr);
	}
	nni_strfree(l->prname);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

static void
ws_connect_cb(void *arg)
{
	ws_dialer *d = arg;
	ws_pipe *  p;
	nni_aio *  caio = d->connaio;
	nni_aio *  uaio;
	int        rv;
	nni_ws *   ws = NULL;

	nni_mtx_lock(&d->mtx);
	if (nni_aio_result(caio) == 0) {
		ws = nni_aio_get_output(caio, 0);
	}
	if ((uaio = nni_list_first(&d->aios)) == NULL) {
		// The client stopped caring about this!
		if (ws != NULL) {
			nni_ws_fini(ws);
		}
		nni_mtx_unlock(&d->mtx);
		return;
	}
	nni_aio_list_remove(uaio);
	NNI_ASSERT(nni_list_empty(&d->aios));
	if ((rv = nni_aio_result(caio)) != 0) {
		nni_aio_finish_error(uaio, rv);
	} else if ((rv = ws_pipe_alloc(&p, ws)) != 0) {
		nni_ws_fini(ws);
		nni_aio_finish_error(uaio, rv);
	} else {
		p->rcvmax = d->rcvmax;
		p->rproto = d->rproto;
		p->lproto = d->lproto;

		nni_aio_set_output(uaio, 0, p);
		nni_aio_finish(uaio, 0, 0);
	}
	nni_mtx_unlock(&d->mtx);
}

static void
ws_dialer_close(void *arg)
{
	ws_dialer *d = arg;

	nni_aio_close(d->connaio);
	nni_ws_dialer_close(d->dialer);
}

static void
ws_listener_close(void *arg)
{
	ws_listener *l = arg;

	nni_aio_close(l->accaio);
	nni_ws_listener_close(l->listener);
}

static void
ws_accept_cb(void *arg)
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
		nni_ws *ws = nni_aio_get_output(aaio, 0);
		if (uaio != NULL) {
			ws_pipe *p;
			// Make a pipe
			nni_aio_list_remove(uaio);
			if ((rv = ws_pipe_alloc(&p, ws)) != 0) {
				nni_ws_close(ws);
				nni_aio_finish_error(uaio, rv);
			} else {
				p->rcvmax = l->rcvmax;
				p->rproto = l->rproto;
				p->lproto = l->lproto;

				nni_aio_set_output(uaio, 0, p);
				nni_aio_finish(uaio, 0, 0);
			}
		}
	}
	if (!nni_list_empty(&l->aios)) {
		nni_ws_listener_accept(l->listener, aaio);
	}
	nni_mtx_unlock(&l->mtx);
}

static int
ws_dialer_init(void **dp, nni_url *url, nni_dialer *ndialer)
{
	ws_dialer * d;
	nni_sock *  s = nni_dialer_sock(ndialer);
	const char *n;
	int         rv;

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&d->mtx);
	NNI_LIST_INIT(&d->headers, ws_hdr, node);

	nni_aio_list_init(&d->aios);

	d->lproto  = nni_sock_proto_id(s);
	d->rproto  = nni_sock_peer_id(s);
	d->ndialer = ndialer;
	n          = nni_sock_peer_name(s);

	if (((rv = nni_ws_dialer_init(&d->dialer, url)) != 0) ||
	    ((rv = nni_aio_init(&d->connaio, ws_connect_cb, d)) != 0) ||
	    ((rv = nni_asprintf(&d->prname, "%s.sp.nanomsg.org", n)) != 0) ||
	    ((rv = nni_ws_dialer_proto(d->dialer, d->prname)) != 0)) {
		ws_dialer_fini(d);
		return (rv);
	}

	*dp = d;
	return (0);
}

static int
ws_listener_init(void **lp, nni_url *url, nni_listener *nlistener)
{
	ws_listener *l;
	const char * n;
	int          rv;
	nni_sock *   sock = nni_listener_sock(nlistener);

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&l->mtx);
	NNI_LIST_INIT(&l->headers, ws_hdr, node);

	nni_aio_list_init(&l->aios);

	l->lproto    = nni_sock_proto_id(sock);
	l->rproto    = nni_sock_peer_id(sock);
	n            = nni_sock_proto_name(sock);
	l->nlistener = nlistener;

	if (((rv = nni_ws_listener_init(&l->listener, url)) != 0) ||
	    ((rv = nni_aio_init(&l->accaio, ws_accept_cb, l)) != 0) ||
	    ((rv = nni_asprintf(&l->prname, "%s.sp.nanomsg.org", n)) != 0) ||
	    ((rv = nni_ws_listener_proto(l->listener, l->prname)) != 0)) {
		ws_listener_fini(l);
		return (rv);
	}
	*lp = l;
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

static nni_tran_dialer_ops ws_dialer_ops = {
	.d_init    = ws_dialer_init,
	.d_fini    = ws_dialer_fini,
	.d_connect = ws_dialer_connect,
	.d_close   = ws_dialer_close,
	.d_options = ws_dialer_options,
};

static nni_tran_listener_ops ws_listener_ops = {
	.l_init    = ws_listener_init,
	.l_fini    = ws_listener_fini,
	.l_bind    = ws_listener_bind,
	.l_accept  = ws_listener_accept,
	.l_close   = ws_listener_close,
	.l_options = ws_listener_options,
};

static nni_tran ws_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "ws",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = ws_tran_init,
	.tran_fini     = ws_tran_fini,
};

int
nng_ws_register(void)
{
	return (nni_tran_register(&ws_tran));
}

#ifdef NNG_TRANSPORT_WSS

static int
wss_dialer_get_tlsconfig(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	ws_dialer *     d = arg;
	nng_tls_config *tls;
	int             rv;

	if (((rv = nni_ws_dialer_get_tls(d->dialer, &tls)) != 0) ||
	    ((rv = nni_copyout_ptr(tls, v, szp, t)) != 0)) {
		return (rv);
	}
	return (0);
}

static int
wss_listener_get_tlsconfig(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	ws_listener *   l = arg;
	nng_tls_config *tls;
	int             rv;

	if (((rv = nni_ws_listener_get_tls(l->listener, &tls)) != 0) ||
	    ((rv = nni_copyout_ptr(tls, v, szp, t)) != 0)) {
		return (rv);
	}
	return (0);
}

static int
wss_dialer_set_tlsconfig(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_dialer *     d = arg;
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nni_copyin_ptr((void **) &cfg, v, sz, t)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	if (d != NULL) {
		rv = nni_ws_dialer_set_tls(d->dialer, cfg);
	}
	return (rv);
}

static int
wss_listener_set_tlsconfig(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_listener *   l = arg;
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nni_copyin_ptr((void **) &cfg, v, sz, t)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	if (l != NULL) {
		rv = nni_ws_listener_set_tls(l->listener, cfg);
	}
	return (rv);
}

static int
wss_dialer_set_cert_key_file(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_dialer *d = arg;
	int        rv;

	if (((rv = ws_check_string(v, sz, t)) == 0) && (d != NULL)) {
		nng_tls_config *tls;

		if ((rv = nni_ws_dialer_get_tls(d->dialer, &tls)) != 0) {
			return (rv);
		}
		rv = nng_tls_config_cert_key_file(tls, v, NULL);
		nni_tls_config_fini(tls);
	}
	return (rv);
}

static int
wss_listener_set_cert_key_file(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_listener *l = arg;
	int          rv;

	if (((rv = ws_check_string(v, sz, t)) == 0) && (l != NULL)) {
		nng_tls_config *tls;

		if ((rv = nni_ws_listener_get_tls(l->listener, &tls)) != 0) {
			return (rv);
		}
		rv = nng_tls_config_cert_key_file(tls, v, NULL);
		nni_tls_config_fini(tls);
	}
	return (rv);
}

static int
wss_dialer_set_ca_file(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_dialer *d = arg;
	int        rv;

	if (((rv = ws_check_string(v, sz, t)) == 0) && (d != NULL)) {
		nng_tls_config *tls;

		if ((rv = nni_ws_dialer_get_tls(d->dialer, &tls)) != 0) {
			return (rv);
		}
		rv = nng_tls_config_ca_file(tls, v);
		nni_tls_config_fini(tls);
	}
	return (rv);
}

static int
wss_listener_set_ca_file(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_listener *l = arg;
	int          rv;

	if (((rv = ws_check_string(v, sz, t)) == 0) && (l != NULL)) {
		nng_tls_config *tls;

		if ((rv = nni_ws_listener_get_tls(l->listener, &tls)) != 0) {
			return (rv);
		}
		rv = nng_tls_config_ca_file(tls, v);
		nni_tls_config_fini(tls);
	}
	return (rv);
}

static int
wss_dialer_set_auth_mode(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_dialer *d = arg;
	int        rv;
	int        mode;

	rv = nni_copyin_int(&mode, v, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t);

	if ((rv == 0) && (d != NULL)) {
		nng_tls_config *tls;

		if ((rv = nni_ws_dialer_get_tls(d->dialer, &tls)) != 0) {
			return (rv);
		}
		rv = nng_tls_config_auth_mode(tls, mode);
		nni_tls_config_fini(tls);
	}
	return (rv);
}

static int
wss_listener_set_auth_mode(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_listener *l = arg;
	int          rv;
	int          mode;

	rv = nni_copyin_int(&mode, v, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t);

	if ((rv == 0) && (l != NULL)) {
		nng_tls_config *tls;

		if ((rv = nni_ws_listener_get_tls(l->listener, &tls)) != 0) {
			return (rv);
		}
		rv = nng_tls_config_auth_mode(tls, mode);
		nni_tls_config_fini(tls);
	}
	return (rv);
}

static int
wss_dialer_set_tls_server_name(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ws_dialer *d = arg;
	int        rv;

	if (((rv = ws_check_string(v, sz, t)) == 0) && (d != NULL)) {
		nng_tls_config *tls;

		if ((rv = nni_ws_dialer_get_tls(d->dialer, &tls)) != 0) {
			return (rv);
		}

		rv = nng_tls_config_server_name(tls, v);
		nni_tls_config_fini(tls);
	}
	return (rv);
}

static nni_option wss_dialer_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = ws_dialer_get_recvmaxsz,
	    .o_set  = ws_dialer_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_WS_REQUEST_HEADERS,
	    .o_set  = ws_dialer_set_reqhdrs,
	},
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_get  = wss_dialer_get_tlsconfig,
	    .o_set  = wss_dialer_set_tlsconfig,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_set  = wss_dialer_set_cert_key_file,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_set  = wss_dialer_set_ca_file,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_set  = wss_dialer_set_auth_mode,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_set  = wss_dialer_set_tls_server_name,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_option wss_listener_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = ws_listener_get_recvmaxsz,
	    .o_set  = ws_listener_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_WS_RESPONSE_HEADERS,
	    .o_set  = ws_listener_set_reshdrs,
	},
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_get  = wss_listener_get_tlsconfig,
	    .o_set  = wss_listener_set_tlsconfig,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_set  = wss_listener_set_cert_key_file,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_set  = wss_listener_set_ca_file,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_set  = wss_listener_set_auth_mode,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_dialer_ops wss_dialer_ops = {
	.d_init    = ws_dialer_init,
	.d_fini    = ws_dialer_fini,
	.d_connect = ws_dialer_connect,
	.d_close   = ws_dialer_close,
	.d_options = wss_dialer_options,
};

static nni_tran_listener_ops wss_listener_ops = {
	.l_init    = ws_listener_init,
	.l_fini    = ws_listener_fini,
	.l_bind    = ws_listener_bind,
	.l_accept  = ws_listener_accept,
	.l_close   = ws_listener_close,
	.l_options = wss_listener_options,
};

static nni_tran wss_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "wss",
	.tran_dialer   = &wss_dialer_ops,
	.tran_listener = &wss_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = ws_tran_init,
	.tran_fini     = ws_tran_fini,
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
