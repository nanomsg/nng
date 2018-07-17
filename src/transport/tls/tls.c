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
#include <string.h>

#include "core/nng_impl.h"

#include "supplemental/tls/tls.h"
#include "supplemental/tls/tls_api.h"
#include "tls.h"

// TLS over TCP transport.   Platform specific TCP operations must be
// supplied as well, and uses the supplemental TLS v1.2 code.  It is not
// an accident that this very closely resembles the TCP transport itself.

typedef struct tlstran_ep       tlstran_ep;
typedef struct tlstran_dialer   tlstran_dialer;
typedef struct tlstran_listener tlstran_listener;
typedef struct tlstran_pipe     tlstran_pipe;

// tlstran_pipe is one end of a TLS connection.
struct tlstran_pipe {
	nni_tls *tls;
	uint16_t peer;
	uint16_t proto;
	size_t   rcvmax;
	bool     nodelay;
	bool     keepalive;

	nni_list sendq;
	nni_list recvq;
	nni_aio *user_negaio;

	uint8_t  txlen[sizeof(uint64_t)];
	uint8_t  rxlen[sizeof(uint64_t)];
	size_t   gottxhead;
	size_t   gotrxhead;
	size_t   wanttxhead;
	size_t   wantrxhead;
	nni_aio *txaio;
	nni_aio *rxaio;
	nni_aio *negaio;
	nni_msg *rxmsg;
	nni_mtx  mtx;
};

// Stuff that is common to both dialers and listeners.
struct tlstran_ep {
	uint16_t        proto;
	size_t          rcvmax;
	bool            nodelay;
	bool            keepalive;
	int             authmode;
	nng_tls_config *cfg;
	nni_url *       url;
	nni_mtx         mtx;
};

struct tlstran_dialer {
	tlstran_ep      ep; // must be first
	nni_tcp_dialer *dialer;
	uint16_t        af;
	nni_aio *       aio;
	nni_aio *       user_aio;
	bool            resolving;
	nng_sockaddr    sa;
};

struct tlstran_listener {
	tlstran_ep        ep; // must be first
	nni_tcp_listener *listener;
	nni_aio *         aio;
	nni_aio *         user_aio;
	nng_sockaddr      sa;
	nng_sockaddr      bsa; // bound addr
};

static void tlstran_pipe_send_start(tlstran_pipe *);
static void tlstran_pipe_recv_start(tlstran_pipe *);
static void tlstran_pipe_send_cb(void *);
static void tlstran_pipe_recv_cb(void *);
static void tlstran_pipe_nego_cb(void *);
static void tlstran_dialer_cb(void *);
static void tlstran_listener_cb(void *);

static int
tlstran_init(void)
{
	return (0);
}

static void
tlstran_fini(void)
{
}

static void
tlstran_pipe_close(void *arg)
{
	tlstran_pipe *p = arg;

	nni_aio_close(p->rxaio);
	nni_aio_close(p->txaio);
	nni_aio_close(p->negaio);

	nni_tls_close(p->tls);
}

static void
tlstran_pipe_stop(void *arg)
{
	tlstran_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negaio);
}

static void
tlstran_pipe_fini(void *arg)
{
	tlstran_pipe *p = arg;

	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);
	nni_aio_fini(p->negaio);
	if (p->tls != NULL) {
		nni_tls_fini(p->tls);
	}
	nni_msg_free(p->rxmsg);
	NNI_FREE_STRUCT(p);
}

static int
tlstran_pipe_init(tlstran_pipe **pipep, nni_tls *tls)
{
	tlstran_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	if (((rv = nni_aio_init(&p->txaio, tlstran_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, tlstran_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negaio, tlstran_pipe_nego_cb, p)) != 0)) {
		tlstran_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);

	p->tls = tls;
	*pipep = p;
	return (0);
}

static void
tlstran_pipe_cancel_nego(nni_aio *aio, int rv)
{
	tlstran_pipe *p = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&p->mtx);
	if (p->user_negaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_negaio = NULL;
	nni_mtx_unlock(&p->mtx);

	nni_aio_abort(p->negaio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
tlstran_pipe_nego_cb(void *arg)
{
	tlstran_pipe *p   = arg;
	nni_aio *     aio = p->negaio;
	int           rv;

	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		goto done;
	}

	// We start transmitting before we receive.
	if (p->gottxhead < p->wanttxhead) {
		p->gottxhead += nni_aio_count(aio);
	} else if (p->gotrxhead < p->wantrxhead) {
		p->gotrxhead += nni_aio_count(aio);
	}

	if (p->gottxhead < p->wanttxhead) {
		nni_iov iov;
		iov.iov_len = p->wanttxhead - p->gottxhead;
		iov.iov_buf = &p->txlen[p->gottxhead];
		nni_aio_set_iov(aio, 1, &iov);
		// send it down...
		nni_tls_send(p->tls, aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nni_tls_recv(p->tls, aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// We have both sent and received the headers.  Lets check the
	// receive side header.
	if ((p->rxlen[0] != 0) || (p->rxlen[1] != 'S') ||
	    (p->rxlen[2] != 'P') || (p->rxlen[3] != 0) || (p->rxlen[6] != 0) ||
	    (p->rxlen[7] != 0)) {
		rv = NNG_EPROTO;
		goto done;
	}

	NNI_GET16(&p->rxlen[4], p->peer);

done:
	if (rv == 0) {
		// These can fail. Note that the TLS stack automatically
		// starts out in NODELAY to make the handshake performant.
		(void) nni_tls_set_nodelay(p->tls, p->nodelay);
		(void) nni_tls_set_keepalive(p->tls, p->keepalive);
	}
	if ((aio = p->user_negaio) != NULL) {
		p->user_negaio = NULL;
		nni_aio_finish(aio, rv, 0);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
tlstran_pipe_send_cb(void *arg)
{
	tlstran_pipe *p = arg;
	int           rv;
	nni_aio *     aio;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     txaio = p->txaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->sendq);

	if ((rv = nni_aio_result(txaio)) != 0) {
		// Intentionally we do not queue up another transfer.
		// There's an excellent chance that the pipe is no longer
		// usable, with a partial transfer.
		// The protocol should see this error, and close the
		// pipe itself, we hope.
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	n = nni_aio_count(txaio);
	nni_aio_iov_advance(txaio, n);
	if (nni_aio_iov_count(txaio) > 0) {
		nni_tls_send(p->tls, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	tlstran_pipe_send_start(p);
	nni_mtx_unlock(&p->mtx);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_synch(aio, 0, n);
}

static void
tlstran_pipe_recv_cb(void *arg)
{
	tlstran_pipe *p = arg;
	nni_aio *     aio;
	int           rv;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     rxaio = p->rxaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->recvq);

	if ((rv = nni_aio_result(p->rxaio)) != 0) {
		goto recv_error;
	}

	n = nni_aio_count(rxaio);
	nni_aio_iov_advance(rxaio, n);
	if (nni_aio_iov_count(rxaio) > 0) {
		// Was this a partial read?  If so then resubmit for the rest.
		nni_tls_recv(p->tls, rxaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	// If we don't have a message yet, we were reading the TCP message
	// header, which is just the length.  This tells us the size of the
	// message to allocate and how much more to expect.
	if (p->rxmsg == NULL) {
		uint64_t len;
		// We should have gotten a message header.
		NNI_GET64(p->rxlen, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if ((len > p->rcvmax) && (p->rcvmax > 0)) {
			rv = NNG_EMSGSIZE;
			goto recv_error;
		}

		if ((rv = nni_msg_alloc(&p->rxmsg, (size_t) len)) != 0) {
			goto recv_error;
		}

		// Submit the rest of the data for a read -- we want to
		// read the entire message now.
		if (len != 0) {
			nni_iov iov;
			iov.iov_buf = nni_msg_body(p->rxmsg);
			iov.iov_len = (size_t) len;
			nni_aio_set_iov(rxaio, 1, &iov);

			nni_tls_recv(p->tls, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// We read a message completely.  Let the user know the good news.
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	if (!nni_list_empty(&p->recvq)) {
		tlstran_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_synch(aio, 0, nni_msg_len(msg));
	return;

recv_error:
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	// Intentionally, we do not queue up another receive.
	// The protocol should notice this error and close the pipe.
	nni_mtx_unlock(&p->mtx);
	nni_msg_free(msg);
	nni_aio_finish_error(aio, rv);
}

static void
tlstran_pipe_send_cancel(nni_aio *aio, int rv)
{
	tlstran_pipe *p = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// If this is being sent, then cancel the pending transfer.
	// The callback on the txaio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&p->sendq) == aio) {
		nni_aio_abort(p->txaio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);

	nni_aio_finish_error(aio, rv);
}

static void
tlstran_pipe_send_start(tlstran_pipe *p)
{
	nni_aio *txaio;
	nni_aio *aio;
	nni_msg *msg;
	int      niov;
	nni_iov  iov[3];
	uint64_t len;

	if ((aio = nni_list_first(&p->sendq)) == NULL) {
		return;
	}

	msg = nni_aio_get_msg(aio);
	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	NNI_PUT64(p->txlen, len);

	txaio             = p->txaio;
	niov              = 0;
	iov[niov].iov_buf = p->txlen;
	iov[niov].iov_len = sizeof(p->txlen);
	niov++;
	if (nni_msg_header_len(msg) > 0) {
		iov[niov].iov_buf = nni_msg_header(msg);
		iov[niov].iov_len = nni_msg_header_len(msg);
		niov++;
	}
	if (nni_msg_len(msg) > 0) {
		iov[niov].iov_buf = nni_msg_body(msg);
		iov[niov].iov_len = nni_msg_len(msg);
		niov++;
	}

	nni_aio_set_iov(txaio, niov, iov);
	nni_tls_send(p->tls, txaio);
}

static void
tlstran_pipe_send(void *arg, nni_aio *aio)
{
	tlstran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tlstran_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		tlstran_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
tlstran_pipe_recv_cancel(nni_aio *aio, int rv)
{
	tlstran_pipe *p = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// If receive in progress, then cancel the pending transfer.
	// The callback on the rxaio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&p->recvq) == aio) {
		nni_aio_abort(p->rxaio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);
	nni_aio_finish_error(aio, rv);
}

static void
tlstran_pipe_recv_start(tlstran_pipe *p)
{
	nni_aio *rxaio;
	nni_iov  iov;
	NNI_ASSERT(p->rxmsg == NULL);

	// Schedule a read of the IPC header.
	rxaio       = p->rxaio;
	iov.iov_buf = p->rxlen;
	iov.iov_len = sizeof(p->rxlen);
	nni_aio_set_iov(rxaio, 1, &iov);

	nni_tls_recv(p->tls, rxaio);
}

static void
tlstran_pipe_recv(void *arg, nni_aio *aio)
{
	tlstran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tlstran_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_aio_list_append(&p->recvq, aio);
	if (nni_list_first(&p->recvq) == aio) {
		tlstran_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
tlstran_pipe_peer(void *arg)
{
	tlstran_pipe *p = arg;

	return (p->peer);
}

static int
tlstran_pipe_get_locaddr(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_pipe *p = arg;
	int           rv;
	nni_sockaddr  sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_tls_sockname(p->tls, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, t);
	}
	return (rv);
}

static int
tlstran_pipe_get_remaddr(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_pipe *p = arg;
	int           rv;
	nni_sockaddr  sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_tls_peername(p->tls, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, t);
	}
	return (rv);
}

static int
tlstran_pipe_get_keepalive(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_pipe *p = arg;
	return (nni_copyout_bool(p->keepalive, v, szp, t));
}

static int
tlstran_pipe_get_nodelay(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_pipe *p = arg;
	return (nni_copyout_bool(p->nodelay, v, szp, t));
}

static void
tlstran_pipe_start(void *arg, nni_aio *aio)
{
	tlstran_pipe *p = arg;
	nni_aio *     negaio;
	nni_iov       iov;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tlstran_pipe_cancel_nego, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->txlen[0] = 0;
	p->txlen[1] = 'S';
	p->txlen[2] = 'P';
	p->txlen[3] = 0;
	NNI_PUT16(&p->txlen[4], p->proto);
	NNI_PUT16(&p->txlen[6], 0);

	p->user_negaio = aio;
	p->gotrxhead   = 0;
	p->gottxhead   = 0;
	p->wantrxhead  = 8;
	p->wanttxhead  = 8;
	negaio         = p->negaio;
	iov.iov_len    = 8;
	iov.iov_buf    = &p->txlen[0];
	nni_aio_set_iov(negaio, 1, &iov);
	nni_tls_send(p->tls, negaio);
	nni_mtx_unlock(&p->mtx);
}

static void
tlstran_dialer_fini(void *arg)
{
	tlstran_dialer *d = arg;

	nni_aio_stop(d->aio);
	if (d->dialer != NULL) {
		nni_tcp_dialer_fini(d->dialer);
	}
	nni_aio_fini(d->aio);
	if (d->ep.cfg != NULL) {
		nni_tls_config_fini(d->ep.cfg);
	}
	nni_mtx_fini(&d->ep.mtx);
	NNI_FREE_STRUCT(d);
}

static void
tlstran_dialer_close(void *arg)
{
	tlstran_dialer *d = arg;

	nni_aio_close(d->aio);
	nni_tcp_dialer_close(d->dialer);
}

static int
tlstran_dialer_init(void **dp, nni_url *url, nni_sock *sock)
{
	tlstran_dialer *d;
	int             rv;
	uint16_t        af;
	char *          host = url->u_hostname;
	char *          port = url->u_port;

	if (strcmp(url->u_scheme, "tls+tcp") == 0) {
		af = NNG_AF_UNSPEC;
	} else if (strcmp(url->u_scheme, "tls+tcp4") == 0) {
		af = NNG_AF_INET;
	} else if (strcmp(url->u_scheme, "tls+tcp6") == 0) {
		af = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL) || (host == NULL) || (port == NULL) ||
	    (strlen(host) == 0) || (strlen(port) == 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&d->ep.mtx);
	d->ep.authmode  = NNG_TLS_AUTH_MODE_REQUIRED;
	d->ep.url       = url;
	d->ep.proto     = nni_sock_proto_id(sock);
	d->ep.nodelay   = true;
	d->ep.keepalive = false;

	if (((rv = nni_tcp_dialer_init(&d->dialer)) != 0) ||
	    ((rv = nni_tls_config_init(&d->ep.cfg, NNG_TLS_MODE_CLIENT)) !=
	        0) ||
	    ((rv = nng_tls_config_auth_mode(d->ep.cfg, d->ep.authmode)) !=
	        0) ||
	    ((rv = nng_tls_config_server_name(d->ep.cfg, host)) != 0) ||
	    ((rv = nni_aio_init(&d->aio, tlstran_dialer_cb, d)) != 0)) {
		tlstran_dialer_fini(d);
		return (rv);
	}
	d->af = af;

	*dp = d;
	return (0);
}

static void
tlstran_dialer_cb(void *arg)
{
	tlstran_dialer *d = arg;
	tlstran_pipe *  p;
	nni_tcp_conn *  conn;
	nni_tls *       tls;
	nni_aio *       aio;
	int             rv;

	nni_mtx_lock(&d->ep.mtx);
	aio = d->user_aio;
	rv  = nni_aio_result(d->aio);

	if (aio == NULL) {
		nni_mtx_unlock(&d->ep.mtx);
		if ((rv == 0) && !d->resolving) {
			conn = nni_aio_get_output(d->aio, 0);
			nni_tcp_conn_fini(conn);
		}
		return;
	}

	if (rv != 0) {
		d->user_aio = NULL;
		nni_mtx_unlock(&d->ep.mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (d->resolving) {
		// Name resolution complete.  Now go to next step.
		d->resolving = false;
		nni_tcp_dialer_dial(d->dialer, &d->sa, d->aio);
		nni_mtx_unlock(&d->ep.mtx);
		return;
	}
	d->user_aio = NULL;
	conn        = nni_aio_get_output(d->aio, 0);
	NNI_ASSERT(conn != NULL);

	if ((rv = nni_tls_init(&tls, d->ep.cfg, conn)) != 0) {
		nni_mtx_unlock(&d->ep.mtx);
		nni_tcp_conn_fini(conn);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if ((rv = tlstran_pipe_init(&p, tls)) != 0) {
		nni_mtx_unlock(&d->ep.mtx);
		nni_tls_fini(tls);
		nni_aio_finish_error(aio, rv);
		return;
	}

	p->proto     = d->ep.proto;
	p->rcvmax    = d->ep.rcvmax;
	p->nodelay   = d->ep.nodelay;
	p->keepalive = d->ep.keepalive;
	nni_mtx_unlock(&d->ep.mtx);

	(void) nni_tls_set_nodelay(tls, p->nodelay);
	(void) nni_tls_set_keepalive(tls, p->keepalive);

	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
}

static void
tlstran_dialer_cancel(nni_aio *aio, int rv)
{
	tlstran_dialer *d = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&d->ep.mtx);
	if (d->user_aio != aio) {
		nni_mtx_unlock(&d->ep.mtx);
		return;
	}
	d->user_aio = NULL;
	nni_mtx_unlock(&d->ep.mtx);

	nni_aio_abort(d->aio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
tlstran_dialer_connect(void *arg, nni_aio *aio)
{
	tlstran_dialer *d = arg;
	int             rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&d->ep.mtx);
	NNI_ASSERT(d->user_aio == NULL);

	if ((rv = nni_aio_schedule(aio, tlstran_dialer_cancel, d)) != 0) {
		nni_mtx_unlock(&d->ep.mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	d->user_aio = aio;

	d->resolving = true;

	// Start the name resolution.  Callback will see resolving, and then
	// switch to doing actual connect.
	nni_aio_set_input(d->aio, 0, &d->sa);
	nni_tcp_resolv(
	    d->ep.url->u_hostname, d->ep.url->u_port, d->af, 0, d->aio);
	nni_mtx_unlock(&d->ep.mtx);
}

static void
tlstran_listener_fini(void *arg)
{
	tlstran_listener *l = arg;

	nni_aio_stop(l->aio);
	if (l->listener != NULL) {
		nni_tcp_listener_fini(l->listener);
	}
	nni_aio_fini(l->aio);
	if (l->ep.cfg != NULL) {
		nni_tls_config_fini(l->ep.cfg);
	}
	nni_mtx_fini(&l->ep.mtx);
	NNI_FREE_STRUCT(l);
}

static void
tlstran_listener_close(void *arg)
{
	tlstran_listener *l = arg;

	nni_aio_close(l->aio);
	nni_tcp_listener_close(l->listener);
}

static int
tlstran_listener_init(void **lp, nni_url *url, nni_sock *sock)
{
	tlstran_listener *l;
	int               rv;
	nni_aio *         aio;
	uint16_t          af;
	char *            host = url->u_hostname;
	char *            port = url->u_port;

	if (strcmp(url->u_scheme, "tls+tcp") == 0) {
		af = NNG_AF_UNSPEC;
	} else if (strcmp(url->u_scheme, "tls+tcp4") == 0) {
		af = NNG_AF_INET;
	} else if (strcmp(url->u_scheme, "tls+tcp6") == 0) {
		af = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL)) {
		return (NNG_EADDRINVAL);
	}

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&l->ep.mtx);
	l->ep.url       = url;
	l->ep.authmode  = NNG_TLS_AUTH_MODE_NONE;
	l->ep.keepalive = false;
	l->ep.nodelay   = true;
	l->ep.proto     = nni_sock_proto_id(sock);

	if (strlen(host) == 0) {
		host = NULL;
	}

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		tlstran_listener_fini(l);
		return (rv);
	}

	// XXX: We are doing lookup at listener initialization.  There is
	// a valid argument that this should be done at bind time, but that
	// would require making bind asynchronous.  In some ways this would
	// be worse than the cost of just waiting here.  We always recommend
	// using local IP addresses rather than names when possible.

	nni_aio_set_input(aio, 0, &l->sa);

	nni_tcp_resolv(host, port, af, 1, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_fini(aio);

	if (rv != 0) {
		tlstran_listener_fini(l);
		return (rv);
	}

	if (((rv = nni_tcp_listener_init(&l->listener)) != 0) ||
	    ((rv = nni_tls_config_init(&l->ep.cfg, NNG_TLS_MODE_SERVER)) !=
	        0) ||
	    ((rv = nng_tls_config_auth_mode(l->ep.cfg, l->ep.authmode)) !=
	        0) ||
	    ((rv = nni_aio_init(&l->aio, tlstran_listener_cb, l)) != 0)) {
		tlstran_listener_fini(l);
		return (rv);
	}
	l->bsa = l->sa;

	*lp = l;
	return (0);
}

static int
tlstran_listener_bind(void *arg)
{
	tlstran_listener *l = arg;
	int               rv;

	nni_mtx_lock(&l->ep.mtx);
	l->bsa = l->sa;
	rv     = nni_tcp_listener_listen(l->listener, &l->bsa);
	nni_mtx_unlock(&l->ep.mtx);

	return (rv);
}

static void
tlstran_listener_cb(void *arg)
{
	tlstran_listener *l = arg;
	nni_aio *         aio;
	int               rv;
	tlstran_pipe *    p = NULL;
	nni_tcp_conn *    conn;
	nni_tls *         tls;

	nni_mtx_lock(&l->ep.mtx);
	rv          = nni_aio_result(l->aio);
	aio         = l->user_aio;
	l->user_aio = NULL;

	if (aio == NULL) {
		nni_mtx_unlock(&l->ep.mtx);
		if (rv == 0) {
			conn = nni_aio_get_output(l->aio, 0);
			nni_tcp_conn_fini(conn);
		}
		return;
	}
	if (rv != 0) {
		nni_mtx_unlock(&l->ep.mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	conn = nni_aio_get_output(l->aio, 0);
	if ((rv = nni_tls_init(&tls, l->ep.cfg, conn)) != 0) {
		nni_mtx_unlock(&l->ep.mtx);
		nni_tcp_conn_fini(conn);
		nni_aio_finish_error(aio, rv);
		return;
	}
	if ((rv = tlstran_pipe_init(&p, tls)) != 0) {
		nni_mtx_unlock(&l->ep.mtx);
		nni_tls_fini(tls);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->proto     = l->ep.proto;
	p->rcvmax    = l->ep.rcvmax;
	p->nodelay   = l->ep.nodelay;
	p->keepalive = l->ep.keepalive;

	(void) nni_tls_set_nodelay(tls, p->nodelay);
	(void) nni_tls_set_keepalive(tls, p->keepalive);

	nni_mtx_unlock(&l->ep.mtx);

	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
}

static void
tlstran_listener_cancel(nni_aio *aio, int rv)
{
	tlstran_listener *l = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&l->ep.mtx);
	if (l->user_aio != aio) {
		nni_mtx_unlock(&l->ep.mtx);
		return;
	}
	l->user_aio = NULL;
	nni_mtx_unlock(&l->ep.mtx);

	nni_aio_abort(l->aio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
tlstran_listener_accept(void *arg, nni_aio *aio)
{
	tlstran_listener *l = arg;
	int               rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&l->ep.mtx);
	NNI_ASSERT(l->user_aio == NULL);

	if ((rv = nni_aio_schedule(aio, tlstran_listener_cancel, l)) != 0) {
		nni_mtx_unlock(&l->ep.mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	l->user_aio = aio;

	nni_tcp_listener_accept(l->listener, l->aio);
	nni_mtx_unlock(&l->ep.mtx);
}

static int
tlstran_ep_set_nodelay(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	bool        val;
	int         rv;
	if ((rv = nni_copyin_bool(&val, v, sz, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		ep->nodelay = val;
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tlstran_ep_get_nodelay(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_bool(ep->nodelay, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tlstran_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	size_t      val;
	int         rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tlstran_ep_set_keepalive(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	bool        val;
	int         rv;
	if ((rv = nni_copyin_bool(&val, v, sz, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		ep->keepalive = val;
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tlstran_ep_get_keepalive(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_bool(ep->keepalive, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tlstran_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tlstran_check_bool(const void *v, size_t sz, nni_opt_type t)
{
	return (nni_copyin_bool(NULL, v, sz, t));
}

static int
tlstran_dialer_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_dialer *d = arg;

	return (nni_copyout_str(d->ep.url->u_rawurl, v, szp, t));
}

static int
tlstran_listener_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_listener *l = arg;
	char              ustr[128];
	char              ipstr[48];  // max for IPv6 addresses including []
	char              portstr[6]; // max for 16-bit port

	nni_mtx_lock(&l->ep.mtx);
	nni_ntop(&l->bsa, ipstr, portstr);
	nni_mtx_unlock(&l->ep.mtx);
	snprintf(ustr, sizeof(ustr), "tls+tcp://%s:%s", ipstr, portstr);
	return (nni_copyout_str(ustr, v, szp, t));
}

static int
tlstran_listener_get_locaddr(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	tlstran_listener *l = arg;
	int               rv;

	nni_mtx_lock(&l->ep.mtx);
	rv = nni_copyout_sockaddr(&l->bsa, buf, szp, t);
	nni_mtx_unlock(&l->ep.mtx);
	return (rv);
}

static int
tlstran_check_recvmaxsz(const void *v, size_t sz, nni_opt_type t)
{
	return (nni_copyin_size(NULL, v, sz, 0, NNI_MAXSZ, t));
}

static int
tlstran_check_config(const void *data, size_t sz, nni_opt_type t)
{
	void *v;
	int   rv;
	if (((rv = nni_copyin_ptr(&v, data, sz, t)) == 0) && (v == NULL)) {
		rv = NNG_EINVAL;
	}
	return (rv);
}

static int
tlstran_ep_set_config(void *arg, const void *data, size_t sz, nni_opt_type t)
{
	tlstran_ep *    ep = arg;
	nng_tls_config *cfg, *old;
	int             rv;

	if ((rv = nni_copyin_ptr((void **) &cfg, data, sz, t)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	nni_mtx_lock(&ep->mtx);
	old = ep->cfg;
	nni_tls_config_hold(cfg);
	ep->cfg = cfg;
	nni_mtx_unlock(&ep->mtx);
	if (old != NULL) {
		nni_tls_config_fini(old);
	}
	return (0);
}

static int
tlstran_ep_get_config(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_ptr(ep->cfg, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tlstran_check_string(const void *v, size_t sz, nni_opt_type t)
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
tlstran_ep_set_ca_file(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         rv;

	if ((rv = tlstran_check_string(v, sz, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		rv = nng_tls_config_ca_file(ep->cfg, v);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tlstran_check_auth_mode(const void *v, size_t sz, nni_opt_type t)
{
	return (nni_copyin_int(NULL, v, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t));
}

static int
tlstran_ep_set_auth_mode(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         mode;
	int         rv;

	rv = nni_copyin_int(&mode, v, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t);
	if (rv == 0) {
		nni_mtx_lock(&ep->mtx);
		rv = nng_tls_config_auth_mode(ep->cfg, mode);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tlstran_ep_set_server_name(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         rv;

	if ((rv = tlstran_check_string(v, sz, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		rv = nng_tls_config_server_name(ep->cfg, v);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tlstran_ep_set_cert_key_file(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         rv;

	if ((rv = tlstran_check_string(v, sz, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		rv = nng_tls_config_cert_key_file(ep->cfg, v, NULL);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tlstran_pipe_get_verified(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_pipe *p = arg;

	return (nni_copyout_bool(nni_tls_verified(p->tls), v, szp, t));
}

static nni_tran_option tlstran_pipe_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = tlstran_pipe_get_locaddr,
	},
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = tlstran_pipe_get_remaddr,
	},
	{
	    .o_name = NNG_OPT_TLS_VERIFIED,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tlstran_pipe_get_verified,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tlstran_pipe_get_keepalive,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tlstran_pipe_get_nodelay,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_pipe_ops tlstran_pipe_ops = {
	.p_fini    = tlstran_pipe_fini,
	.p_start   = tlstran_pipe_start,
	.p_stop    = tlstran_pipe_stop,
	.p_send    = tlstran_pipe_send,
	.p_recv    = tlstran_pipe_recv,
	.p_close   = tlstran_pipe_close,
	.p_peer    = tlstran_pipe_peer,
	.p_options = tlstran_pipe_options,
};

static nni_tran_option tlstran_dialer_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = tlstran_ep_get_recvmaxsz,
	    .o_set  = tlstran_ep_set_recvmaxsz,
	    .o_chk  = tlstran_check_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_type = NNI_TYPE_STRING,
	    .o_get  = tlstran_dialer_get_url,
	},
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_type = NNI_TYPE_POINTER,
	    .o_get  = tlstran_ep_get_config,
	    .o_set  = tlstran_ep_set_config,
	    .o_chk  = tlstran_check_config,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tlstran_ep_set_cert_key_file,
	    .o_chk  = tlstran_check_string,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tlstran_ep_set_ca_file,
	    .o_chk  = tlstran_check_string,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_type = NNI_TYPE_INT32, // enum really
	    .o_set  = tlstran_ep_set_auth_mode,
	    .o_chk  = tlstran_check_auth_mode,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tlstran_ep_set_server_name,
	    .o_chk  = tlstran_check_string,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tlstran_ep_get_nodelay,
	    .o_set  = tlstran_ep_set_nodelay,
	    .o_chk  = tlstran_check_bool,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tlstran_ep_get_keepalive,
	    .o_set  = tlstran_ep_set_keepalive,
	    .o_chk  = tlstran_check_bool,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_option tlstran_listener_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = tlstran_ep_get_recvmaxsz,
	    .o_set  = tlstran_ep_set_recvmaxsz,
	    .o_chk  = tlstran_check_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_type = NNI_TYPE_STRING,
	    .o_get  = tlstran_listener_get_url,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = tlstran_listener_get_locaddr,
	},
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_type = NNI_TYPE_POINTER,
	    .o_get  = tlstran_ep_get_config,
	    .o_set  = tlstran_ep_set_config,
	    .o_chk  = tlstran_check_config,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tlstran_ep_set_cert_key_file,
	    .o_chk  = tlstran_check_string,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tlstran_ep_set_ca_file,
	    .o_chk  = tlstran_check_string,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_type = NNI_TYPE_INT32, // enum really
	    .o_set  = tlstran_ep_set_auth_mode,
	    .o_chk  = tlstran_check_auth_mode,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tlstran_ep_set_server_name,
	    .o_chk  = tlstran_check_string,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tlstran_ep_get_nodelay,
	    .o_set  = tlstran_ep_set_nodelay,
	    .o_chk  = tlstran_check_bool,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tlstran_ep_get_keepalive,
	    .o_set  = tlstran_ep_set_keepalive,
	    .o_chk  = tlstran_check_bool,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_dialer_ops tlstran_dialer_ops = {
	.d_init    = tlstran_dialer_init,
	.d_fini    = tlstran_dialer_fini,
	.d_connect = tlstran_dialer_connect,
	.d_close   = tlstran_dialer_close,
	.d_options = tlstran_dialer_options,
};

static nni_tran_listener_ops tlstran_listener_ops = {
	.l_init    = tlstran_listener_init,
	.l_fini    = tlstran_listener_fini,
	.l_bind    = tlstran_listener_bind,
	.l_accept  = tlstran_listener_accept,
	.l_close   = tlstran_listener_close,
	.l_options = tlstran_listener_options,
};

static nni_tran tls_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tls+tcp",
	.tran_dialer   = &tlstran_dialer_ops,
	.tran_listener = &tlstran_listener_ops,
	.tran_pipe     = &tlstran_pipe_ops,
	.tran_init     = tlstran_init,
	.tran_fini     = tlstran_fini,
};

static nni_tran tls4_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tls+tcp4",
	.tran_dialer   = &tlstran_dialer_ops,
	.tran_listener = &tlstran_listener_ops,
	.tran_pipe     = &tlstran_pipe_ops,
	.tran_init     = tlstran_init,
	.tran_fini     = tlstran_fini,
};

static nni_tran tls6_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tls+tcp6",
	.tran_dialer   = &tlstran_dialer_ops,
	.tran_listener = &tlstran_listener_ops,
	.tran_pipe     = &tlstran_pipe_ops,
	.tran_init     = tlstran_init,
	.tran_fini     = tlstran_fini,
};

int
nng_tls_register(void)
{
	int rv;
	if (((rv = nni_tran_register(&tls_tran)) != 0) ||
	    ((rv = nni_tran_register(&tls4_tran)) != 0) ||
	    ((rv = nni_tran_register(&tls6_tran)) != 0)) {
		return (rv);
	}
	return (0);
}
