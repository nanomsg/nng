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
#include <string.h>

#include "core/nng_impl.h"

#include "nng/supplemental/tls/tls.h"
#include "nng/transport/tls/tls.h"

// TLS over TCP transport.   Platform specific TCP operations must be
// supplied as well, and uses the supplemental TLS v1.2 code.  It is not
// an accident that this very closely resembles the TCP transport itself.

typedef struct tlstran_ep       tlstran_ep;
typedef struct tlstran_dialer   tlstran_dialer;
typedef struct tlstran_listener tlstran_listener;
typedef struct tlstran_pipe     tlstran_pipe;

// tlstran_pipe is one end of a TLS connection.
struct tlstran_pipe {
	nng_stream *    tls;
	nni_pipe *      npipe;
	uint16_t        peer;
	uint16_t        proto;
	size_t          rcvmax;
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
	nni_aio *       txaio;
	nni_aio *       rxaio;
	nni_aio *       negoaio;
	nni_msg *       rxmsg;
	nni_mtx         mtx;
};

// Stuff that is common to both dialers and listeners.
struct tlstran_ep {
	nni_mtx              mtx;
	uint16_t             af;
	uint16_t             proto;
	size_t               rcvmax;
	bool                 started;
	bool                 closed;
	bool                 fini;
	int                  refcnt;
	int                  authmode;
	nni_url *            url;
	nni_list             pipes;
	nni_reap_item        reap;
	nng_stream_dialer *  dialer;
	nng_stream_listener *listener;
	nni_aio *            useraio;
	nni_aio *            connaio;
	nni_aio *            timeaio;
	nni_list             busypipes; // busy pipes -- ones passed to socket
	nni_list             waitpipes; // pipes waiting to match to socket
	nni_list             negopipes; // pipes busy negotiating
	const char *         host;
	nng_sockaddr         src;
	nng_sockaddr         sa;
	nni_dialer *         ndialer;
	nni_listener *       nlistener;
	nni_stat_item        st_rcvmaxsz;
};

static void tlstran_pipe_send_start(tlstran_pipe *);
static void tlstran_pipe_recv_start(tlstran_pipe *);
static void tlstran_pipe_send_cb(void *);
static void tlstran_pipe_recv_cb(void *);
static void tlstran_pipe_nego_cb(void *);
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

	nng_stream_close(p->tls);
}

static void
tlstran_pipe_stop(void *arg)
{
	tlstran_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negoaio);
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
		nni_list_node_remove(&p->node);
		ep->refcnt--;
		if (ep->fini && (ep->refcnt == 0)) {
			nni_reap(&ep->reap, tlstran_ep_fini, ep);
		}
		nni_mtx_unlock(&ep->mtx);
	}
	nni_aio_free(p->rxaio);
	nni_aio_free(p->txaio);
	nni_aio_free(p->negoaio);
	nng_stream_free(p->tls);
	nni_msg_free(p->rxmsg);
	NNI_FREE_STRUCT(p);
}

static int
tlstran_pipe_alloc(tlstran_pipe **pipep)
{
	tlstran_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	if (((rv = nni_aio_alloc(&p->txaio, tlstran_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->rxaio, tlstran_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->negoaio, tlstran_pipe_nego_cb, p)) != 0)) {
		tlstran_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);
	nni_atomic_flag_reset(&p->reaped);

	*pipep = p;
	return (0);
}

static void
tlstran_pipe_reap(tlstran_pipe *p)
{
	if (!nni_atomic_flag_test_and_set(&p->reaped)) {
		if (p->tls != NULL) {
			nng_stream_close(p->tls);
		}
		nni_reap(&p->reap, tlstran_pipe_fini, p);
	}
}

static void
tlstran_ep_match(tlstran_ep *ep)
{
	nni_aio *     aio;
	tlstran_pipe *p;

	if (((aio = ep->useraio) == NULL) ||
	    ((p = nni_list_first(&ep->waitpipes)) == NULL)) {
		return;
	}
	nni_list_remove(&ep->waitpipes, p);
	nni_list_append(&ep->busypipes, p);
	ep->useraio = NULL;
	p->rcvmax   = ep->rcvmax;
	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
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
		nng_stream_send(p->tls, aio);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_recv(p->tls, aio);
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

	// We are all ready now.  We put this in the wait list, and
	// then try to run the matcher.
	nni_list_remove(&ep->negopipes, p);
	nni_list_append(&ep->waitpipes, p);

	tlstran_ep_match(ep);
	nni_mtx_unlock(&ep->mtx);

	return;

error:
	if (ep->ndialer != NULL) {
		nni_dialer_bump_error(ep->ndialer, rv);
	} else {
		nni_listener_bump_error(ep->nlistener, rv);
	}

	nng_stream_close(p->tls);

	// If we are waiting to negotiate on a client side, then a failure
	// here has to be passed to the user app.
	if ((ep->dialer != NULL) && ((uaio = ep->useraio) != NULL)) {
		ep->useraio = NULL;
		nni_aio_finish_error(uaio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
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
		nni_pipe_bump_error(p->npipe, rv);
		return;
	}

	n = nni_aio_count(txaio);
	nni_aio_iov_advance(txaio, n);
	if (nni_aio_iov_count(txaio) > 0) {
		nng_stream_send(p->tls, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	tlstran_pipe_send_start(p);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_pipe_bump_tx(p->npipe, n);
	nni_mtx_unlock(&p->mtx);
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
		nng_stream_recv(p->tls, rxaio);
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

			nng_stream_recv(p->tls, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// We read a message completely.  Let the user know the good news.
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	n        = nni_msg_len(msg);
	if (!nni_list_empty(&p->recvq)) {
		tlstran_pipe_recv_start(p);
	}
	nni_pipe_bump_rx(p->npipe, n);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_synch(aio, 0, n);
	return;

recv_error:
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	nni_pipe_bump_error(p->npipe, rv);
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
	nng_stream_send(p->tls, txaio);
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

	nng_stream_recv(p->tls, rxaio);
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
tlstran_pipe_start(tlstran_pipe *p, nng_stream *conn, tlstran_ep *ep)
{
	nni_iov iov;

	ep->refcnt++;

	p->tls   = conn;
	p->ep    = ep;
	p->proto = ep->proto;

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
	nni_list_append(&ep->negopipes, p);

	nni_aio_set_timeout(p->negoaio, 10000); // 10 sec timeout to negotiate
	nng_stream_send(p->tls, p->negoaio);
}

static void
tlstran_ep_fini(void *arg)
{
	tlstran_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	ep->fini = true;
	if (ep->refcnt != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	nni_mtx_unlock(&ep->mtx);
	nni_aio_stop(ep->timeaio);
	nni_aio_stop(ep->connaio);
	nng_stream_dialer_free(ep->dialer);
	nng_stream_listener_free(ep->listener);
	nni_aio_free(ep->timeaio);
	nni_aio_free(ep->connaio);

	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static void
tlstran_ep_close(void *arg)
{
	tlstran_ep *  ep = arg;
	tlstran_pipe *p;

	nni_mtx_lock(&ep->mtx);
	ep->closed = true;
	nni_aio_close(ep->timeaio);

	if (ep->dialer != NULL) {
		nng_stream_dialer_close(ep->dialer);
	}
	if (ep->listener != NULL) {
		nng_stream_listener_close(ep->listener);
	}
	NNI_LIST_FOREACH (&ep->negopipes, p) {
		tlstran_pipe_close(p);
	}
	NNI_LIST_FOREACH (&ep->waitpipes, p) {
		tlstran_pipe_close(p);
	}
	NNI_LIST_FOREACH (&ep->busypipes, p) {
		tlstran_pipe_close(p);
	}
	if (ep->useraio != NULL) {
		nni_aio_finish_error(ep->useraio, NNG_ECLOSED);
		ep->useraio = NULL;
	}
	nni_mtx_unlock(&ep->mtx);
}

// This parses off the optional source address that this transport uses.
// The special handling of this URL format is quite honestly an historical
// mistake, which we would remove if we could.
static int
tlstran_url_parse_source(nni_url *url, nng_sockaddr *sa, const nni_url *surl)
{
	int      af;
	char *   semi;
	char *   src;
	size_t   len;
	int      rv;
	nni_aio *aio;

	// We modify the URL.  This relies on the fact that the underlying
	// transport does not free this, so we can just use references.

	url->u_scheme   = surl->u_scheme;
	url->u_port     = surl->u_port;
	url->u_hostname = surl->u_hostname;

	if ((semi = strchr(url->u_hostname, ';')) == NULL) {
		memset(sa, 0, sizeof(*sa));
		return (0);
	}

	len             = (size_t)(semi - url->u_hostname);
	url->u_hostname = semi + 1;

	if (strcmp(surl->u_scheme, "tls+tcp") == 0) {
		af = NNG_AF_UNSPEC;
	} else if (strcmp(surl->u_scheme, "tls+tcp4") == 0) {
		af = NNG_AF_INET;
	} else if (strcmp(surl->u_scheme, "tls+tcp6") == 0) {
		af = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}

	if ((src = nni_alloc(len + 1)) == NULL) {
		return (NNG_ENOMEM);
	}
	memcpy(src, surl->u_hostname, len);
	src[len] = '\0';

	if ((rv = nni_aio_alloc(&aio, NULL, NULL)) != 0) {
		nni_free(src, len + 1);
		return (rv);
	}

	nni_tcp_resolv(src, 0, af, 1, aio);
	nni_aio_wait(aio);
	if ((rv = nni_aio_result(aio)) == 0) {
		nni_aio_get_sockaddr(aio, sa);
	}
	nni_aio_free(aio);
	nni_free(src, len + 1);
	return (rv);
}

static void
tlstran_timer_cb(void *arg)
{
	tlstran_ep *ep = arg;
	if (nni_aio_result(ep->timeaio) == 0) {
		nng_stream_listener_accept(ep->listener, ep->connaio);
	}
}

static void
tlstran_accept_cb(void *arg)
{
	tlstran_ep *  ep  = arg;
	nni_aio *     aio = ep->connaio;
	tlstran_pipe *p;
	int           rv;
	nng_stream *  conn;

	nni_mtx_lock(&ep->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);
	if ((rv = tlstran_pipe_alloc(&p)) != 0) {
		nng_stream_free(conn);
		goto error;
	}

	if (ep->closed) {
		tlstran_pipe_fini(p);
		nng_stream_free(conn);
		rv = NNG_ECLOSED;
		goto error;
	}
	tlstran_pipe_start(p, conn, ep);
	nng_stream_listener_accept(ep->listener, ep->connaio);
	nni_mtx_unlock(&ep->mtx);
	return;

error:
	nni_listener_bump_error(ep->nlistener, rv);
	switch (rv) {

	case NNG_ENOMEM:
		nng_sleep_aio(10, ep->timeaio);
		break;

	default:
		if (!ep->closed) {
			nng_stream_listener_accept(ep->listener, ep->connaio);
		}
		break;
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
tlstran_dial_cb(void *arg)
{
	tlstran_ep *  ep  = arg;
	nni_aio *     aio = ep->connaio;
	tlstran_pipe *p;
	int           rv;
	nng_stream *  conn;

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);
	if ((rv = tlstran_pipe_alloc(&p)) != 0) {
		nng_stream_free(conn);
		goto error;
	}
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		tlstran_pipe_fini(p);
		nng_stream_free(conn);
		rv = NNG_ECLOSED;
	} else {
		tlstran_pipe_start(p, conn, ep);
	}
	nni_mtx_unlock(&ep->mtx);
	return;

error:
	// Error connecting.  We need to pass this straight back
	// to the user.
	nni_dialer_bump_error(ep->ndialer, rv);
	nni_mtx_lock(&ep->mtx);
	if ((aio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static int
tlstran_ep_init(tlstran_ep **epp, nng_url *url, nni_sock *sock)
{
	tlstran_ep *ep;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->busypipes, tlstran_pipe, node);
	NNI_LIST_INIT(&ep->waitpipes, tlstran_pipe, node);
	NNI_LIST_INIT(&ep->negopipes, tlstran_pipe, node);

	ep->proto = nni_sock_proto_id(sock);
	ep->url   = url;

	nni_stat_init(&ep->st_rcvmaxsz, "rcvmaxsz", "maximum receive size");
	nni_stat_set_type(&ep->st_rcvmaxsz, NNG_STAT_LEVEL);
	nni_stat_set_unit(&ep->st_rcvmaxsz, NNG_UNIT_BYTES);

	*epp = ep;
	return (0);
}

static int
tlstran_ep_init_dialer(void **dp, nni_url *url, nni_dialer *ndialer)
{
	tlstran_ep * ep;
	int          rv;
	nng_sockaddr srcsa;
	nni_sock *   sock = nni_dialer_sock(ndialer);
	nni_url      myurl;

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL) || (strlen(url->u_hostname) == 0) ||
	    (strlen(url->u_port) == 0)) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = tlstran_url_parse_source(&myurl, &srcsa, url)) != 0) {
		return (rv);
	}

	if (((rv = tlstran_ep_init(&ep, url, sock)) != 0) ||
	    ((rv = nni_aio_alloc(&ep->connaio, tlstran_dial_cb, ep)) != 0)) {
		return (rv);
	}
	ep->authmode = NNG_TLS_AUTH_MODE_REQUIRED;
	ep->ndialer  = ndialer;

	if ((rv != 0) ||
	    ((rv = nng_stream_dialer_alloc_url(&ep->dialer, &myurl)) != 0)) {
		tlstran_ep_fini(ep);
		return (rv);
	}
	if ((srcsa.s_family != NNG_AF_UNSPEC) &&
	    ((rv = nni_stream_dialer_setx(ep->dialer, NNG_OPT_LOCADDR, &srcsa,
	          sizeof(srcsa), NNI_TYPE_SOCKADDR)) != 0)) {
		tlstran_ep_fini(ep);
		return (rv);
	}
	nni_dialer_add_stat(ndialer, &ep->st_rcvmaxsz);
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
	if (((rv = tlstran_ep_init(&ep, url, sock)) != 0) ||
	    ((rv = nni_aio_alloc(&ep->connaio, tlstran_accept_cb, ep)) != 0) ||
	    ((rv = nni_aio_alloc(&ep->timeaio, tlstran_timer_cb, ep)) != 0)) {
		return (rv);
	}

	ep->authmode  = NNG_TLS_AUTH_MODE_NONE;
	ep->af        = af;
	ep->nlistener = nlistener;

	if (strlen(host) == 0) {
		host = NULL;
	}

	// XXX: We are doing lookup at listener initialization.  There is
	// a valid argument that this should be done at bind time, but that
	// would require making bind asynchronous.  In some ways this would
	// be worse than the cost of just waiting here.  We always recommend
	// using local IP addresses rather than names when possible.

	if ((rv = nni_aio_alloc(&aio, NULL, NULL)) != 0) {
		tlstran_ep_fini(ep);
		return (rv);
	}
	nni_aio_set_input(aio, 0, &ep->sa);
	nni_tcp_resolv(host, url->u_port, af, 1, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_free(aio);

	if ((rv != 0) ||
	    ((rv = nng_stream_listener_alloc_url(&ep->listener, url)) != 0) ||
	    ((rv = nni_stream_listener_setx(ep->listener,
	          NNG_OPT_TLS_AUTH_MODE, &ep->authmode, sizeof(ep->authmode),
	          NNI_TYPE_INT32)) != 0)) {
		tlstran_ep_fini(ep);
		return (rv);
	}

	nni_listener_add_stat(nlistener, &ep->st_rcvmaxsz);
	*lp = ep;
	return (0);
}

static void
tlstran_ep_cancel(nni_aio *aio, void *arg, int rv)
{
	tlstran_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (ep->useraio == aio) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
		if (ep->ndialer) {
			nni_dialer_bump_error(ep->ndialer, rv);
		} else {
			nni_listener_bump_error(ep->nlistener, rv);
		}
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
tlstran_ep_connect(void *arg, nni_aio *aio)
{
	tlstran_ep *ep = arg;
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		nni_dialer_bump_error(ep->ndialer, NNG_ECLOSED);
		return;
	}
	if (ep->useraio != NULL) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		nni_dialer_bump_error(ep->ndialer, NNG_EBUSY);
		return;
	}
	if ((rv = nni_aio_schedule(aio, tlstran_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_dialer_bump_error(ep->ndialer, rv);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ep->useraio = aio;

	nng_stream_dialer_dial(ep->dialer, ep->connaio);
	nni_mtx_unlock(&ep->mtx);
}

static int
tlstran_ep_bind(void *arg)
{
	tlstran_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	if ((rv = nng_stream_listener_listen(ep->listener)) != 0) {
		nni_listener_bump_error(ep->nlistener, rv);
	}
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void
tlstran_ep_accept(void *arg, nni_aio *aio)
{
	tlstran_ep *ep = arg;
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		nni_listener_bump_error(ep->nlistener, NNG_ECLOSED);
		return;
	}
	if (ep->useraio != NULL) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		nni_listener_bump_error(ep->nlistener, NNG_EBUSY);
		return;
	}
	if ((rv = nni_aio_schedule(aio, tlstran_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		nni_listener_bump_error(ep->nlistener, rv);
		return;
	}
	ep->useraio = aio;
	if (!ep->started) {
		ep->started = true;
		nng_stream_listener_accept(ep->listener, ep->connaio);
	} else {
		tlstran_ep_match(ep);
	}
	nni_mtx_unlock(&ep->mtx);
}

static int
tlstran_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_type t)
{
	tlstran_ep *ep = arg;
	size_t      val;
	int         rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		tlstran_pipe *p;
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		NNI_LIST_FOREACH (&ep->waitpipes, p) {
			p->rcvmax = val;
		}
		NNI_LIST_FOREACH (&ep->negopipes, p) {
			p->rcvmax = val;
		}
		NNI_LIST_FOREACH (&ep->busypipes, p) {
			p->rcvmax = val;
		}
		nni_stat_set_value(&ep->st_rcvmaxsz, val);

		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tlstran_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_type t)
{
	tlstran_ep *ep = arg;
	int         rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tlstran_ep_get_url(void *arg, void *v, size_t *szp, nni_type t)
{
	tlstran_ep *ep = arg;
	char *      s;
	int         rv;
	int         port = 0;

	if (ep->listener != NULL) {
		(void) nng_stream_listener_get_int(
		    ep->listener, NNG_OPT_TCP_BOUND_PORT, &port);
	}
	if ((rv = nni_url_asprintf_port(&s, ep->url, port)) == 0) {
		rv = nni_copyout_str(s, v, szp, t);
		nni_strfree(s);
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

	if ((rv = nni_stream_getx(p->tls, name, buf, szp, t)) == NNG_ENOTSUP) {
		rv = nni_getopt(tlstran_pipe_opts, name, p, buf, szp, t);
	}
	return (rv);
}

static int
tlstran_check_recvmaxsz(const void *v, size_t sz, nni_type t)
{
	size_t val;
	return (nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t));
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

static nni_option tlstran_ep_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = tlstran_ep_get_recvmaxsz,
	    .o_set  = tlstran_ep_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_get  = tlstran_ep_get_url,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_chkoption tlstran_checkopts[] = {
	{
	    .o_name  = NNG_OPT_RECVMAXSZ,
	    .o_check = tlstran_check_recvmaxsz,
	},
	{
	    .o_name = NULL,
	},
};

static int
tlstran_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	int         rv;
	tlstran_ep *ep = arg;

	rv = nni_stream_dialer_getx(ep->dialer, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tlstran_ep_options, name, ep, buf, szp, t);
	}
	return (rv);
}

static int
tlstran_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	int         rv;
	tlstran_ep *ep = arg;

	rv = nni_stream_dialer_setx(
	    ep != NULL ? ep->dialer : NULL, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tlstran_ep_options, name, ep, buf, sz, t);
	}
	return (rv);
}

static int
tlstran_listener_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	int         rv;
	tlstran_ep *ep = arg;

	rv = nni_stream_listener_getx(ep->listener, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tlstran_ep_options, name, ep, buf, szp, t);
	}
	return (rv);
}

static int
tlstran_listener_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	int         rv;
	tlstran_ep *ep = arg;

	rv = nni_stream_listener_setx(
	    ep != NULL ? ep->listener : NULL, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tlstran_ep_options, name, ep, buf, sz, t);
	}
	return (rv);
}

static int
tlstran_checkopt(const char *name, const void *buf, size_t sz, nni_type t)
{
	int rv;
	rv = nni_chkopt(tlstran_checkopts, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_checkopt("tls+tcp", name, buf, sz, t);
	}
	return (rv);
}

static nni_tran_dialer_ops tlstran_dialer_ops = {
	.d_init    = tlstran_ep_init_dialer,
	.d_fini    = tlstran_ep_fini,
	.d_connect = tlstran_ep_connect,
	.d_close   = tlstran_ep_close,
	.d_getopt  = tlstran_dialer_getopt,
	.d_setopt  = tlstran_dialer_setopt,
};

static nni_tran_listener_ops tlstran_listener_ops = {
	.l_init   = tlstran_ep_init_listener,
	.l_fini   = tlstran_ep_fini,
	.l_bind   = tlstran_ep_bind,
	.l_accept = tlstran_ep_accept,
	.l_close  = tlstran_ep_close,
	.l_getopt = tlstran_listener_getopt,
	.l_setopt = tlstran_listener_setopt,
};

static nni_tran tls_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tls+tcp",
	.tran_dialer   = &tlstran_dialer_ops,
	.tran_listener = &tlstran_listener_ops,
	.tran_pipe     = &tlstran_pipe_ops,
	.tran_init     = tlstran_init,
	.tran_fini     = tlstran_fini,
	.tran_checkopt = tlstran_checkopt,
};

static nni_tran tls4_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tls+tcp4",
	.tran_dialer   = &tlstran_dialer_ops,
	.tran_listener = &tlstran_listener_ops,
	.tran_pipe     = &tlstran_pipe_ops,
	.tran_init     = tlstran_init,
	.tran_fini     = tlstran_fini,
	.tran_checkopt = tlstran_checkopt,
};

static nni_tran tls6_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tls+tcp6",
	.tran_dialer   = &tlstran_dialer_ops,
	.tran_listener = &tlstran_listener_ops,
	.tran_pipe     = &tlstran_pipe_ops,
	.tran_init     = tlstran_init,
	.tran_fini     = tlstran_fini,
	.tran_checkopt = tlstran_checkopt,
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
