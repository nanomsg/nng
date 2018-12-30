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
#include <string.h>

#include "core/nng_impl.h"

#include "nng/supplemental/tls/tls.h"
#include "nng/transport/tls/tls.h"
#include "supplemental/tls/tls_api.h"

// TLS over TCP transport.   Platform specific TCP operations must be
// supplied as well, and uses the supplemental TLS v1.2 code.  It is not
// an accident that this very closely resembles the TCP transport itself.

typedef struct tlstran_ep       tlstran_ep;
typedef struct tlstran_dialer   tlstran_dialer;
typedef struct tlstran_listener tlstran_listener;
typedef struct tlstran_pipe     tlstran_pipe;

// tlstran_pipe is one end of a TLS connection.
struct tlstran_pipe {
	nni_tls *       tls;
	nni_pipe *      npipe;
	uint16_t        peer;
	uint16_t        proto;
	size_t          rcvmax;
	bool            nodelay;
	bool            keepalive;
	bool            closed;
	nni_list_node   node;
	nni_list        sendq;
	nni_list        recvq;
	tlstran_ep *    ep;
	nni_sockaddr    sa;
	nni_atomic_flag reaped;
	nni_reap_item   reap;
	uint8_t         txlen[sizeof(uint64_t)];
	uint8_t         rxlen[sizeof(uint64_t)];
	size_t          gottxhead;
	size_t          gotrxhead;
	size_t          wanttxhead;
	size_t          wantrxhead;
	nni_aio *       useraio;
	nni_aio *       txaio;
	nni_aio *       rxaio;
	nni_aio *       negoaio;
	nni_aio *       connaio;
	nni_aio *       rslvaio;
	nni_msg *       rxmsg;
	nni_mtx         mtx;
};

// Stuff that is common to both dialers and listeners.
struct tlstran_ep {
	nni_mtx           mtx;
	uint16_t          af;
	uint16_t          proto;
	size_t            rcvmax;
	bool              nodelay;
	bool              keepalive;
	bool              fini;
	int               authmode;
	nng_tls_config *  cfg;
	nni_url *         url;
	nni_list          pipes;
	nni_reap_item     reap;
	nni_tcp_dialer *  dialer;
	nni_tcp_listener *listener;
	const char *      host;
	nng_sockaddr      src;
	nng_sockaddr      sa;
	nng_sockaddr      bsa;
	nni_dialer *      ndialer;
	nni_listener *    nlistener;
};

static void tlstran_pipe_send_start(tlstran_pipe *);
static void tlstran_pipe_recv_start(tlstran_pipe *);
static void tlstran_pipe_send_cb(void *);
static void tlstran_pipe_recv_cb(void *);
static void tlstran_pipe_conn_cb(void *);
static void tlstran_pipe_nego_cb(void *);
static void tlstran_pipe_rslv_cb(void *);
static void tlstran_ep_fini(void *);

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
	nni_aio_close(p->negoaio);
	nni_aio_close(p->connaio);
	nni_aio_close(p->rslvaio);

	nni_tls_close(p->tls);
}

static void
tlstran_pipe_stop(void *arg)
{
	tlstran_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negoaio);
	nni_aio_stop(p->connaio);
	nni_aio_stop(p->rslvaio);
}

static int
tlstran_pipe_init(void *arg, nni_pipe *npipe)
{
	tlstran_pipe *p = arg;
	p->npipe        = npipe;
	return (0);
}

static void
tlstran_pipe_fini(void *arg)
{
	tlstran_pipe *p = arg;
	tlstran_ep *  ep;

	tlstran_pipe_stop(p);
	if ((ep = p->ep) != NULL) {
		nni_mtx_lock(&ep->mtx);
		nni_list_remove(&ep->pipes, p);
		if (ep->fini && nni_list_empty(&ep->pipes)) {
			nni_reap(&ep->reap, tlstran_ep_fini, ep);
		}
		nni_mtx_unlock(&ep->mtx);
	}
	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);
	nni_aio_fini(p->negoaio);
	nni_aio_fini(p->connaio);
	nni_aio_fini(p->rslvaio);
	if (p->tls != NULL) {
		nni_tls_fini(p->tls);
	}
	nni_msg_free(p->rxmsg);
	NNI_FREE_STRUCT(p);
}

static int
tlstran_pipe_alloc(tlstran_pipe **pipep, tlstran_ep *ep)
{
	tlstran_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	if (((rv = nni_aio_init(&p->txaio, tlstran_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, tlstran_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rslvaio, tlstran_pipe_rslv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->connaio, tlstran_pipe_conn_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negoaio, tlstran_pipe_nego_cb, p)) != 0)) {
		tlstran_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);
	nni_atomic_flag_reset(&p->reaped);
	nni_list_append(&ep->pipes, p);

	p->keepalive = ep->keepalive;
	p->nodelay   = ep->nodelay;
	p->rcvmax    = ep->rcvmax;
	p->proto     = ep->proto;
	p->ep        = ep;
	*pipep       = p;
	return (0);
}

static void
tlstran_pipe_reap(tlstran_pipe *p)
{
	if (!nni_atomic_flag_test_and_set(&p->reaped)) {
		if (p->tls != NULL) {
			nni_tls_close(p->tls);
		}
		nni_reap(&p->reap, tlstran_pipe_fini, p);
	}
}

static void
tlstran_pipe_conn_cancel(nni_aio *aio, void *arg, int rv)
{
	tlstran_pipe *p = arg;

	nni_mtx_lock(&p->ep->mtx);
	if (aio == p->useraio) {
		p->useraio = NULL;
		nni_aio_close(p->negoaio);
		nni_aio_close(p->connaio);
		nni_aio_close(p->rslvaio);
		nni_aio_finish_error(aio, rv);
		tlstran_pipe_reap(p);
	}
	nni_mtx_unlock(&p->ep->mtx);
}

static void
tlstran_pipe_rslv_cb(void *arg)
{
	tlstran_pipe *p   = arg;
	tlstran_ep *  ep  = p->ep;
	nni_aio *     aio = p->rslvaio;
	nni_aio *     uaio;
	int           rv;

	nni_mtx_lock(&ep->mtx);
	if ((uaio = p->useraio) == NULL) {
		nni_mtx_unlock(&ep->mtx);
		tlstran_pipe_reap(p);
		return;
	}

	if ((rv = nni_aio_result(aio)) != 0) {
		p->useraio = NULL;
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(uaio, rv);
		tlstran_pipe_reap(p);
		return;
	}
	nni_tcp_dialer_dial(ep->dialer, &p->sa, p->connaio);
	nni_mtx_unlock(&ep->mtx);
}

static void
tlstran_pipe_conn_cb(void *arg)
{
	tlstran_pipe *p   = arg;
	tlstran_ep *  ep  = p->ep;
	nni_aio *     aio = p->connaio;
	nni_aio *     uaio;
	nni_iov       iov;
	nni_tcp_conn *conn;
	int           rv;

	nni_mtx_lock(&ep->mtx);
	if ((rv = nni_aio_result(aio)) == 0) {
		conn = nni_aio_get_output(aio, 0);
	} else {
		conn = NULL;
	}

	if ((uaio = p->useraio) == NULL) {
		if (conn != NULL) {
			nni_tcp_conn_fini(conn);
		}
		nni_mtx_unlock(&ep->mtx);
		tlstran_pipe_reap(p);
		return;
	}

	if ((rv != 0) || ((rv = nni_tls_init(&p->tls, ep->cfg, conn)) != 0)) {
		p->useraio = NULL;
		nni_mtx_unlock(&ep->mtx);
		if (conn != NULL) {
			nni_tcp_conn_fini(conn);
		}
		nni_aio_finish_error(uaio, rv);
		tlstran_pipe_reap(p);
		return;
	}
	p->txlen[0] = 0;
	p->txlen[1] = 'S';
	p->txlen[2] = 'P';
	p->txlen[3] = 0;
	NNI_PUT16(&p->txlen[4], p->proto);
	NNI_PUT16(&p->txlen[6], 0);

	p->gotrxhead  = 0;
	p->gottxhead  = 0;
	p->wantrxhead = 8;
	p->wanttxhead = 8;
	iov.iov_len   = 8;
	iov.iov_buf   = &p->txlen[0];
	nni_aio_set_iov(p->negoaio, 1, &iov);
	nni_tls_send(p->tls, p->negoaio);
	nni_mtx_unlock(&ep->mtx);
}

static void
tlstran_pipe_nego_cb(void *arg)
{
	tlstran_pipe *p   = arg;
	tlstran_ep *  ep  = p->ep;
	nni_aio *     aio = p->negoaio;
	nni_aio *     uaio;
	int           rv;

	nni_mtx_lock(&ep->mtx);
	if ((uaio = p->useraio) == NULL) {
		nni_mtx_unlock(&ep->mtx);
		tlstran_pipe_reap(p);
		return;
	}

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
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
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nni_tls_recv(p->tls, aio);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	// We have both sent and received the headers.  Lets check the
	// receive side header.
	if ((p->rxlen[0] != 0) || (p->rxlen[1] != 'S') ||
	    (p->rxlen[2] != 'P') || (p->rxlen[3] != 0) || (p->rxlen[6] != 0) ||
	    (p->rxlen[7] != 0)) {
		rv = NNG_EPROTO;
		goto error;
	}

	NNI_GET16(&p->rxlen[4], p->peer);
	p->useraio = NULL;
	nni_mtx_unlock(&ep->mtx);

	(void) nni_tls_setopt(p->tls, NNG_OPT_TCP_NODELAY, &p->nodelay,
	    sizeof(p->nodelay), NNI_TYPE_BOOL);
	(void) nni_tls_setopt(p->tls, NNG_OPT_TCP_KEEPALIVE, &p->keepalive,
	    sizeof(p->keepalive), NNI_TYPE_BOOL);

	nni_aio_set_output(uaio, 0, p);
	nni_aio_finish(uaio, 0, 0);
	return;

error:
	p->useraio = NULL;
	nni_mtx_unlock(&ep->mtx);
	nni_aio_finish_error(uaio, rv);
	tlstran_pipe_reap(p);
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
tlstran_pipe_send_cancel(nni_aio *aio, void *arg, int rv)
{
	tlstran_pipe *p = arg;

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
tlstran_pipe_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	tlstran_pipe *p = arg;

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

static void
tlstran_ep_fini(void *arg)
{
	tlstran_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	ep->fini = true;
	if (!nni_list_empty(&ep->pipes)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (ep->dialer != NULL) {
		nni_tcp_dialer_fini(ep->dialer);
	}
	if (ep->listener != NULL) {
		nni_tcp_listener_fini(ep->listener);
	}
	nni_mtx_unlock(&ep->mtx);

	if (ep->cfg != NULL) {
		nni_tls_config_fini(ep->cfg);
	}
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static void
tlstran_ep_close(void *arg)
{
	tlstran_ep *  ep = arg;
	tlstran_pipe *p;

	nni_mtx_lock(&ep->mtx);
	NNI_LIST_FOREACH (&ep->pipes, p) {
		nni_aio_close(p->negoaio);
		nni_aio_close(p->connaio);
		nni_aio_close(p->rslvaio);
		nni_aio_close(p->txaio);
		nni_aio_close(p->rxaio);
		if (p->tls != NULL) {
			nni_tls_close(p->tls);
		}
	}
	if (ep->dialer != NULL) {
		nni_tcp_dialer_close(ep->dialer);
	}
	if (ep->listener != NULL) {
		nni_tcp_listener_close(ep->listener);
	}
	nni_mtx_unlock(&ep->mtx);
}

static int
tlstran_ep_init_dialer(void **dp, nni_url *url, nni_dialer *ndialer)
{
	tlstran_ep * ep;
	int          rv;
	uint16_t     af;
	char *       host;
	nng_sockaddr srcsa;
	nni_sock *   sock = nni_dialer_sock(ndialer);

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
	    (url->u_query != NULL) || (strlen(url->u_hostname) == 0) ||
	    (strlen(url->u_port) == 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->pipes, tlstran_pipe, node);

	ep->authmode  = NNG_TLS_AUTH_MODE_REQUIRED;
	ep->url       = url;
	ep->af        = af;
	ep->proto     = nni_sock_proto_id(sock);
	ep->nodelay   = true;
	ep->keepalive = false;
	ep->ndialer   = ndialer;

	// Detect an embedded local interface name in the hostname.  This
	// syntax is only valid with dialers.
	if ((host = strchr(url->u_hostname, ';')) != NULL) {
		size_t   len;
		char *   src = NULL;
		nni_aio *aio;
		len = (uintptr_t) host - (uintptr_t) url->u_hostname;
		host++;
		if ((len < 2) || (strlen(host) == 0)) {
			tlstran_ep_fini(ep);
			return (NNG_EADDRINVAL);
		}
		if ((src = nni_alloc(len + 1)) == NULL) {
			tlstran_ep_fini(ep);
			return (NNG_ENOMEM);
		}
		memcpy(src, url->u_hostname, len);
		src[len] = 0;

		if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
			tlstran_ep_fini(ep);
			nni_strfree(src);
			return (rv);
		}
		nni_aio_set_input(aio, 0, &srcsa);
		nni_tcp_resolv(src, 0, af, 1, aio);
		nni_aio_wait(aio);
		rv = nni_aio_result(aio);
		nni_aio_fini(aio);
		nni_strfree(src);
		ep->host = host;
	} else {
		srcsa.s_family = NNG_AF_UNSPEC;
		ep->host       = url->u_hostname;
		rv             = 0;
	}

	if ((rv != 0) || ((rv = nni_tcp_dialer_init(&ep->dialer)) != 0) ||
	    ((rv = nni_tls_config_init(&ep->cfg, NNG_TLS_MODE_CLIENT)) != 0) ||
	    ((rv = nng_tls_config_auth_mode(ep->cfg, ep->authmode)) != 0) ||
	    ((rv = nng_tls_config_server_name(ep->cfg, ep->host)) != 0)) {
		tlstran_ep_fini(ep);
		return (rv);
	}

	*dp = ep;
	return (0);
}

static int
tlstran_ep_init_listener(void **lp, nni_url *url, nni_listener *nlistener)
{
	tlstran_ep *ep;
	int         rv;
	uint16_t    af;
	char *      host = url->u_hostname;
	nni_aio *   aio;
	nni_sock *  sock = nni_listener_sock(nlistener);

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
	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->pipes, tlstran_pipe, node);

	ep->authmode  = NNG_TLS_AUTH_MODE_NONE;
	ep->url       = url;
	ep->af        = af;
	ep->proto     = nni_sock_proto_id(sock);
	ep->nodelay   = true;
	ep->keepalive = false;
	ep->nlistener = nlistener;

	if (strlen(host) == 0) {
		host = NULL;
	}

	// XXX: We are doing lookup at listener initialization.  There is
	// a valid argument that this should be done at bind time, but that
	// would require making bind asynchronous.  In some ways this would
	// be worse than the cost of just waiting here.  We always recommend
	// using local IP addresses rather than names when possible.

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		tlstran_ep_fini(ep);
		return (rv);
	}
	nni_aio_set_input(aio, 0, &ep->sa);
	nni_tcp_resolv(host, url->u_port, af, 1, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_fini(aio);

	ep->bsa = ep->sa;
	if (((rv = nni_tcp_listener_init(&ep->listener)) != 0) ||
	    ((rv = nni_tls_config_init(&ep->cfg, NNG_TLS_MODE_SERVER)) != 0) ||
	    ((rv = nng_tls_config_auth_mode(ep->cfg, ep->authmode)) != 0)) {
		tlstran_ep_fini(ep);
		return (rv);
	}

	*lp = ep;
	return (0);
}

static void
tlstran_ep_connect(void *arg, nni_aio *aio)
{
	tlstran_ep *  ep = arg;
	tlstran_pipe *p;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	if ((rv = tlstran_pipe_alloc(&p, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if ((rv = nni_aio_schedule(aio, tlstran_pipe_conn_cancel, p)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		tlstran_pipe_reap(p);
		return;
	}
	p->useraio = aio;
	nni_aio_set_input(p->rslvaio, 0, &p->sa);
	nni_tcp_resolv(ep->host, ep->url->u_port, ep->af, 0, p->rslvaio);
	nni_mtx_unlock(&ep->mtx);
}

static int
tlstran_ep_bind(void *arg)
{
	tlstran_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	ep->bsa = ep->sa;
	rv      = nni_tcp_listener_listen(ep->listener, &ep->bsa);
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void
tlstran_ep_accept(void *arg, nni_aio *aio)
{
	tlstran_ep *  ep = arg;
	tlstran_pipe *p;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	if ((rv = tlstran_pipe_alloc(&p, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if ((rv = nni_aio_schedule(aio, tlstran_pipe_conn_cancel, p)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		tlstran_pipe_reap(p);
		return;
	}

	p->useraio = aio;
	nni_tcp_listener_accept(ep->listener, p->connaio);
	nni_mtx_unlock(&ep->mtx);
}

static int
tlstran_ep_set_nodelay(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	bool        val;
	int         rv;
	if (((rv = nni_copyin_bool(&val, v, sz, t)) == 0) && (ep != NULL)) {
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
	if (((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) &&
	    (ep != NULL)) {
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
	if (((rv = nni_copyin_bool(&val, v, sz, t)) == 0) && (ep != NULL)) {
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
tlstran_ep_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	char        ustr[128];
	char        ipstr[48];  // max for IPv6 addresses including []
	char        portstr[6]; // max for 16-bit port

	if (ep->dialer != NULL) {
		return (nni_copyout_str(ep->url->u_rawurl, v, szp, t));
	}
	nni_mtx_lock(&ep->mtx);
	nni_ntop(&ep->bsa, ipstr, portstr);
	nni_mtx_unlock(&ep->mtx);
	snprintf(ustr, sizeof(ustr), "tls+tcp://%s:%s", ipstr, portstr);
	return (nni_copyout_str(ustr, v, szp, t));
}

static int
tlstran_ep_get_locaddr(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_sockaddr(&ep->bsa, buf, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tlstran_ep_set_config(void *arg, const void *data, size_t sz, nni_opt_type t)
{
	tlstran_ep *    ep = arg;
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nni_copyin_ptr((void **) &cfg, data, sz, t)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	if (ep != NULL) {
		nng_tls_config *old;

		nni_mtx_lock(&ep->mtx);
		old = ep->cfg;
		nni_tls_config_hold(cfg);
		ep->cfg = cfg;
		nni_mtx_unlock(&ep->mtx);
		if (old != NULL) {
			nni_tls_config_fini(old);
		}
	}
	return (0);
}

static int
tlstran_ep_get_config(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_ep *    ep = arg;
	nng_tls_config *cfg;
	int             rv;
	nni_mtx_lock(&ep->mtx);
	if ((cfg = ep->cfg) != NULL) {
		nni_tls_config_hold(cfg);
	}
	rv = nni_copyout_ptr(cfg, v, szp, t);
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

	if (((rv = tlstran_check_string(v, sz, t)) == 0) && (ep != NULL)) {
		nni_mtx_lock(&ep->mtx);
		rv = nng_tls_config_ca_file(ep->cfg, v);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tlstran_ep_set_auth_mode(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         mode;
	int         rv;

	rv = nni_copyin_int(&mode, v, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t);
	if ((rv == 0) && (ep != NULL)) {
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

	if (((rv = tlstran_check_string(v, sz, t)) == 0) && (ep != NULL)) {
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

	if (((rv = tlstran_check_string(v, sz, t)) == 0) && (ep != NULL)) {
		nni_mtx_lock(&ep->mtx);
		rv = nng_tls_config_cert_key_file(ep->cfg, v, NULL);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static const nni_option tlstran_pipe_opts[] = {
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
tlstran_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tlstran_pipe *p = arg;
	int           rv;

	if ((rv = nni_tls_getopt(p->tls, name, buf, szp, t)) == NNG_ENOTSUP) {
		rv = nni_getopt(tlstran_pipe_opts, name, p, buf, szp, t);
	}
	return (rv);
}

static nni_tran_pipe_ops tlstran_pipe_ops = {
	.p_init   = tlstran_pipe_init,
	.p_fini   = tlstran_pipe_fini,
	.p_stop   = tlstran_pipe_stop,
	.p_send   = tlstran_pipe_send,
	.p_recv   = tlstran_pipe_recv,
	.p_close  = tlstran_pipe_close,
	.p_peer   = tlstran_pipe_peer,
	.p_getopt = tlstran_pipe_getopt,
};

static nni_option tlstran_dialer_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = tlstran_ep_get_recvmaxsz,
	    .o_set  = tlstran_ep_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_get  = tlstran_ep_get_url,
	},
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_get  = tlstran_ep_get_config,
	    .o_set  = tlstran_ep_set_config,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_set  = tlstran_ep_set_cert_key_file,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_set  = tlstran_ep_set_ca_file,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_set  = tlstran_ep_set_auth_mode,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_set  = tlstran_ep_set_server_name,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_get  = tlstran_ep_get_nodelay,
	    .o_set  = tlstran_ep_set_nodelay,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_get  = tlstran_ep_get_keepalive,
	    .o_set  = tlstran_ep_set_keepalive,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_option tlstran_listener_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = tlstran_ep_get_recvmaxsz,
	    .o_set  = tlstran_ep_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_get  = tlstran_ep_get_url,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = tlstran_ep_get_locaddr,
	},
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_get  = tlstran_ep_get_config,
	    .o_set  = tlstran_ep_set_config,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_set  = tlstran_ep_set_cert_key_file,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_set  = tlstran_ep_set_ca_file,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_set  = tlstran_ep_set_auth_mode,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_set  = tlstran_ep_set_server_name,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_get  = tlstran_ep_get_nodelay,
	    .o_set  = tlstran_ep_set_nodelay,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_get  = tlstran_ep_get_keepalive,
	    .o_set  = tlstran_ep_set_keepalive,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_dialer_ops tlstran_dialer_ops = {
	.d_init    = tlstran_ep_init_dialer,
	.d_fini    = tlstran_ep_fini,
	.d_connect = tlstran_ep_connect,
	.d_close   = tlstran_ep_close,
	.d_options = tlstran_dialer_options,
};

static nni_tran_listener_ops tlstran_listener_ops = {
	.l_init    = tlstran_ep_init_listener,
	.l_fini    = tlstran_ep_fini,
	.l_bind    = tlstran_ep_bind,
	.l_accept  = tlstran_ep_accept,
	.l_close   = tlstran_ep_close,
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
