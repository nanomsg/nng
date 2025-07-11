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

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "nng/nng.h"

// TCP transport.   Platform specific TCP operations must be
// supplied as well.

typedef struct tcptran_pipe tcptran_pipe;
typedef struct tcptran_ep   tcptran_ep;

// tcp_pipe is one end of a TCP connection.
struct tcptran_pipe {
	nng_stream   *conn;
	nni_pipe     *npipe;
	uint16_t      peer;
	uint16_t      proto;
	size_t        rcvmax;
	bool          closed;
	nni_list_node node;
	tcptran_ep   *ep;
	uint8_t       txlen[sizeof(uint64_t)];
	uint8_t       rxlen[sizeof(uint64_t)];
	size_t        gottxhead;
	size_t        gotrxhead;
	size_t        wanttxhead;
	size_t        wantrxhead;
	nni_list      recvq;
	nni_list      sendq;
	nni_aio       txaio;
	nni_aio       rxaio;
	nni_aio       negoaio;
	nni_msg      *rxmsg;
	nni_mtx       mtx;
};

struct tcptran_ep {
	nni_mtx              mtx;
	uint16_t             proto;
	size_t               rcvmax;
	bool                 fini;
	bool                 started;
	bool                 closed;
	const char          *host; // for dialers
	nni_aio             *useraio;
	nni_aio              connaio;
	nni_aio              timeaio;
	nni_list             waitpipes; // pipes waiting to match to socket
	nni_list             negopipes; // pipes busy negotiating
	nng_stream_dialer   *dialer;
	nng_stream_listener *listener;
	nni_listener        *nlistener;
	nni_dialer          *ndialer;

#ifdef NNG_ENABLE_STATS
	nni_stat_item st_rcv_max;
#endif
};

static void tcptran_pipe_send_start(tcptran_pipe *);
static void tcptran_pipe_recv_start(tcptran_pipe *);
static void tcptran_pipe_send_cb(void *);
static void tcptran_pipe_recv_cb(void *);
static void tcptran_pipe_nego_cb(void *);
static void tcptran_ep_fini(void *);
static void tcptran_pipe_fini(void *);

static void
tcptran_init(void)
{
}

static void
tcptran_fini(void)
{
}

static void
tcptran_pipe_close(void *arg)
{
	tcptran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	p->closed = true;
	nni_mtx_unlock(&p->mtx);

	nni_aio_close(&p->rxaio);
	nni_aio_close(&p->txaio);
	nni_aio_close(&p->negoaio);

	nng_stream_close(p->conn);
}

static void
tcptran_pipe_stop(void *arg)
{
	tcptran_pipe *p  = arg;
	tcptran_ep   *ep = p->ep;

	nni_aio_stop(&p->rxaio);
	nni_aio_stop(&p->txaio);
	nni_aio_stop(&p->negoaio);
	nng_stream_stop(p->conn);
	nni_mtx_lock(&ep->mtx);
	nni_list_node_remove(&p->node);
	nni_mtx_unlock(&ep->mtx);
}

static int
tcptran_pipe_init(void *arg, nni_pipe *npipe)
{
	tcptran_pipe *p = arg;
	p->npipe        = npipe;
	nni_mtx_init(&p->mtx);
	nni_aio_init(&p->txaio, tcptran_pipe_send_cb, p);
	nni_aio_init(&p->rxaio, tcptran_pipe_recv_cb, p);
	nni_aio_init(&p->negoaio, tcptran_pipe_nego_cb, p);
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);

	return (0);
}

static void
tcptran_pipe_fini(void *arg)
{
	tcptran_pipe *p = arg;

	tcptran_pipe_stop(p);
	nng_stream_free(p->conn);
	nni_aio_fini(&p->rxaio);
	nni_aio_fini(&p->txaio);
	nni_aio_fini(&p->negoaio);
	nni_msg_free(p->rxmsg);
	nni_mtx_fini(&p->mtx);
}

static void
tcptran_ep_match(tcptran_ep *ep)
{
	nni_aio      *aio;
	tcptran_pipe *p;

	if (((aio = ep->useraio) == NULL) ||
	    ((p = nni_list_first(&ep->waitpipes)) == NULL)) {
		return;
	}
	nni_list_remove(&ep->waitpipes, p);
	ep->useraio = NULL;
	p->rcvmax   = ep->rcvmax;
	nni_aio_set_output(aio, 0, p->npipe);
	nni_aio_finish(aio, 0, 0);
}

static void
tcptran_pipe_nego_cb(void *arg)
{
	tcptran_pipe *p   = arg;
	tcptran_ep   *ep  = p->ep;
	nni_aio      *aio = &p->negoaio;
	nni_aio      *uaio;
	int           rv;

	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		rv = NNG_ECLOSED;
		goto error;
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
		// send it down...
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_send(p->conn, aio);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_recv(p->conn, aio);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	// We have both sent and received the headers.  Let's check the
	// receiver.
	if ((p->rxlen[0] != 0) || (p->rxlen[1] != 'S') ||
	    (p->rxlen[2] != 'P') || (p->rxlen[3] != 0) || (p->rxlen[6] != 0) ||
	    (p->rxlen[7] != 0)) {
		rv = NNG_EPROTO;
		goto error;
	}

	NNI_GET16(&p->rxlen[4], p->peer);

	// We are ready now.  We put this in the wait list, and
	// then try to run the matcher.
	nni_list_remove(&ep->negopipes, p);
	nni_list_append(&ep->waitpipes, p);

	tcptran_ep_match(ep);
	nni_mtx_unlock(&ep->mtx);

	return;

error:
	// If the connection is closed, we need to pass back a different
	// error code.  This is necessary to avoid a problem where the
	// closed status is confused with the accept file descriptor
	// being closed.
	if (rv == NNG_ECLOSED) {
		rv = NNG_ECONNSHUT;
	}
	nni_list_remove(&ep->negopipes, p);
	nng_stream_close(p->conn);

	if ((uaio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(uaio, rv);
	}
	nni_mtx_unlock(&ep->mtx);

	nni_pipe_close(p->npipe);
	nni_pipe_rele(p->npipe);
}

static void
tcptran_pipe_send_cb(void *arg)
{
	tcptran_pipe *p = arg;
	int           rv;
	nni_aio      *aio;
	size_t        n;
	nni_msg      *msg;
	nni_aio      *txaio = &p->txaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->sendq);

	if ((rv = nni_aio_result(txaio)) != 0) {
		nni_pipe_bump_error(p->npipe, rv);
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
		nng_stream_send(p->conn, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	nni_aio_list_remove(aio);
	tcptran_pipe_send_start(p);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_pipe_bump_tx(p->npipe, n);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_sync(aio, 0, n);
}

static void
tcptran_pipe_recv_cb(void *arg)
{
	tcptran_pipe *p = arg;
	nni_aio      *aio;
	int           rv;
	size_t        n;
	nni_msg      *msg;
	nni_aio      *rxaio = &p->rxaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->recvq);

	if ((rv = nni_aio_result(rxaio)) != 0) {
		goto recv_error;
	}

	if (p->closed) {
		rv = NNG_ECLOSED;
		goto recv_error;
	}

	n = nni_aio_count(rxaio);
	nni_aio_iov_advance(rxaio, n);
	if (nni_aio_iov_count(rxaio) > 0) {
		nng_stream_recv(p->conn, rxaio);
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
			nng_sockaddr_storage ss;
			nng_sockaddr        *sa = (nng_sockaddr *) &ss;
			char                 peername[64] = "unknown";
			if ((rv = nng_stream_get_addr(
			         p->conn, NNG_OPT_REMADDR, sa)) == 0) {
				(void) nng_str_sockaddr(
				    sa, peername, sizeof(peername));
			}
			nng_log_warn("NNG-RCVMAX",
			    "Oversize message of %lu bytes (> %lu) "
			    "on socket<%u> pipe<%u> from TCP %s",
			    (unsigned long) len, (unsigned long) p->rcvmax,
			    nni_pipe_sock_id(p->npipe), nni_pipe_id(p->npipe),
			    peername);
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
			nng_stream_recv(p->conn, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// We read a message completely.  Let the user know the good news.
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	n        = nni_msg_len(msg);

	nni_pipe_bump_rx(p->npipe, n);
	tcptran_pipe_recv_start(p);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_sync(aio, 0, n);
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
tcptran_pipe_send_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	tcptran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// If this is being sent, then cancel the pending transfer.
	// The callback on the txaio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&p->sendq) == aio) {
		nni_aio_abort(&p->txaio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);

	nni_aio_finish_error(aio, rv);
}

static void
tcptran_pipe_send_start(tcptran_pipe *p)
{
	nni_aio *aio;
	nni_aio *txaio;
	nni_msg *msg;
	int      niov;
	nni_iov  iov[3];
	uint64_t len;

	if (p->closed) {
		while ((aio = nni_list_first(&p->sendq)) != NULL) {
			nni_list_remove(&p->sendq, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}

	if ((aio = nni_list_first(&p->sendq)) == NULL) {
		return;
	}

	// This runs to send the message.
	msg = nni_aio_get_msg(aio);
	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	NNI_PUT64(p->txlen, len);

	txaio          = &p->txaio;
	niov           = 0;
	iov[0].iov_buf = p->txlen;
	iov[0].iov_len = sizeof(p->txlen);
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
	nng_stream_send(p->conn, txaio);
}

static void
tcptran_pipe_send(void *arg, nni_aio *aio)
{
	tcptran_pipe *p = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&p->mtx);
	if (!nni_aio_start(aio, tcptran_pipe_send_cancel, p)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		tcptran_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
tcptran_pipe_recv_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	tcptran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// If receive in progress, then cancel the pending transfer.
	// The callback on the rxaio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&p->recvq) == aio) {
		nni_aio_abort(&p->rxaio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);
	nni_aio_finish_error(aio, rv);
}

static void
tcptran_pipe_recv_start(tcptran_pipe *p)
{
	nni_aio *rxaio = &p->rxaio;
	nni_iov  iov;
	NNI_ASSERT(p->rxmsg == NULL);

	if (p->closed) {
		nni_aio *aio;
		while ((aio = nni_list_first(&p->recvq)) != NULL) {
			nni_list_remove(&p->recvq, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}
	if (nni_list_empty(&p->recvq)) {
		return;
	}

	// Schedule a read of the header.
	iov.iov_buf = p->rxlen;
	iov.iov_len = sizeof(p->rxlen);
	nni_aio_set_iov(rxaio, 1, &iov);

	nng_stream_recv(p->conn, rxaio);
}

static void
tcptran_pipe_recv(void *arg, nni_aio *aio)
{
	tcptran_pipe *p = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&p->mtx);
	if (!nni_aio_start(aio, tcptran_pipe_recv_cancel, p)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}

	nni_list_append(&p->recvq, aio);
	if (nni_list_first(&p->recvq) == aio) {
		tcptran_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
tcptran_pipe_peer(void *arg)
{
	tcptran_pipe *p = arg;

	return (p->peer);
}

static nng_err
tcptran_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tcptran_pipe *p = arg;
	return (nni_stream_get(p->conn, name, buf, szp, t));
}

static void
tcptran_pipe_start(tcptran_pipe *p, nng_stream *conn, tcptran_ep *ep)
{
	nni_iov iov;

	p->conn  = conn;
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
	nni_aio_set_iov(&p->negoaio, 1, &iov);
	nni_list_append(&ep->negopipes, p);

	nni_aio_set_timeout(&p->negoaio, 10000); // 10 sec timeout to negotiate
	nng_stream_send(p->conn, &p->negoaio);
}

static void
tcptran_ep_stop(void *arg)
{
	tcptran_ep *ep = arg;

	nni_aio_stop(&ep->timeaio);
	nni_aio_stop(&ep->connaio);
	nng_stream_dialer_stop(ep->dialer);
	nng_stream_listener_stop(ep->listener);
}

static void
tcptran_ep_fini(void *arg)
{
	tcptran_ep *ep = arg;

	nni_aio_fini(&ep->timeaio);
	nni_aio_fini(&ep->connaio);
	nng_stream_dialer_free(ep->dialer);
	nng_stream_listener_free(ep->listener);
	nni_mtx_fini(&ep->mtx);
}

static void
tcptran_ep_close(void *arg)
{
	tcptran_ep   *ep = arg;
	tcptran_pipe *p;

	nni_aio_close(&ep->timeaio);
	nni_aio_close(&ep->connaio);

	nni_mtx_lock(&ep->mtx);
	ep->closed = true;
	if (ep->dialer != NULL) {
		nng_stream_dialer_close(ep->dialer);
	}
	if (ep->listener != NULL) {
		nng_stream_listener_close(ep->listener);
	}
	if (ep->useraio != NULL) {
		nni_aio_finish_error(ep->useraio, NNG_ECLOSED);
		ep->useraio = NULL;
	}
	NNI_LIST_FOREACH (&ep->negopipes, p) {
		nni_pipe_close(p->npipe);
	}
	NNI_LIST_FOREACH (&ep->waitpipes, p) {
		nni_pipe_close(p->npipe);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
tcptran_timer_cb(void *arg)
{
	tcptran_ep *ep = arg;
	if (nni_aio_result(&ep->timeaio) == 0) {
		nng_stream_listener_accept(ep->listener, &ep->connaio);
	}
}

static void
tcptran_accept_cb(void *arg)
{
	tcptran_ep   *ep  = arg;
	nni_aio      *aio = &ep->connaio;
	tcptran_pipe *p;
	int           rv;
	nng_stream   *conn;

	nni_mtx_lock(&ep->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);

	if (ep->closed) {
		nng_stream_free(conn);
		rv = NNG_ECLOSED;
		goto error;
	}
	rv = nni_pipe_alloc_listener((void **) &p, ep->nlistener);
	if (rv != 0) {
		nng_stream_free(conn);
		goto error;
	}
	tcptran_pipe_start(p, conn, ep);
	nng_stream_listener_accept(ep->listener, &ep->connaio);
	nni_mtx_unlock(&ep->mtx);
	return;

error:
	// When an error here occurs, let's send a notice up to the consumer.
	// That way it can be reported properly.
	if ((aio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	switch (rv) {
	case NNG_ECLOSED:
	case NNG_ESTOPPED:
		break;

	case NNG_ENOMEM:
	case NNG_ENOFILES:
		nng_sleep_aio(10, &ep->timeaio);
		break;

	default:
		if (!ep->closed) {
			nng_stream_listener_accept(ep->listener, &ep->connaio);
		}
		break;
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
tcptran_dial_cb(void *arg)
{
	tcptran_ep   *ep  = arg;
	nni_aio      *aio = &ep->connaio;
	tcptran_pipe *p;
	int           rv;
	nng_stream   *conn;

	nni_mtx_lock(&ep->mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);

	if (ep->closed) {
		nng_stream_free(conn);
		rv = NNG_ECLOSED;
		goto error;
	}
	if ((rv = nni_pipe_alloc_dialer((void **) &p, ep->ndialer)) != 0) {
		nng_stream_free(conn);
		goto error;
	}
	tcptran_pipe_start(p, conn, ep);
	nni_mtx_unlock(&ep->mtx);
	return;

error:
	// Error connecting.  We need to pass this straight back
	// to the user.
	if ((aio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
tcptran_ep_init(tcptran_ep *ep, nni_sock *sock, void (*conn_cb)(void *))
{
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->waitpipes, tcptran_pipe, node);
	NNI_LIST_INIT(&ep->negopipes, tcptran_pipe, node);

	ep->proto = nni_sock_proto_id(sock);
	nni_aio_init(&ep->connaio, conn_cb, ep);
	nni_aio_init(&ep->timeaio, tcptran_timer_cb, ep);

#ifdef NNG_ENABLE_STATS
	static const nni_stat_info rcv_max_info = {
		.si_name   = "rcv_max",
		.si_desc   = "maximum receive size",
		.si_type   = NNG_STAT_LEVEL,
		.si_unit   = NNG_UNIT_BYTES,
		.si_atomic = true,
	};
	nni_stat_init(&ep->st_rcv_max, &rcv_max_info);
#endif
}

static nng_err
tcptran_dialer_init(void *arg, nng_url *url, nni_dialer *ndialer)
{
	tcptran_ep *ep = arg;
	nng_err     rv;
	nni_sock   *sock = nni_dialer_sock(ndialer);

	ep->ndialer = ndialer;
	tcptran_ep_init(ep, sock, tcptran_dial_cb);

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL) || (strlen(url->u_hostname) == 0) ||
	    (url->u_port == 0)) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = nng_stream_dialer_alloc_url(&ep->dialer, url)) != NNG_OK) {
		return (rv);
	}

#ifdef NNG_ENABLE_STATS
	nni_dialer_add_stat(ndialer, &ep->st_rcv_max);
#endif
	return (NNG_OK);
}

static nng_err
tcptran_listener_init(void *arg, nng_url *url, nni_listener *nlistener)
{
	tcptran_ep *ep = arg;
	nng_err     rv;
	nni_sock   *sock = nni_listener_sock(nlistener);

	ep->nlistener = nlistener;
	tcptran_ep_init(ep, sock, tcptran_accept_cb);

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL)) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = nng_stream_listener_alloc_url(&ep->listener, url)) !=
	    NNG_OK) {
		return (rv);
	}
#ifdef NNG_ENABLE_STATS
	nni_listener_add_stat(nlistener, &ep->st_rcv_max);
#endif

	return (NNG_OK);
}

static void
tcptran_ep_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	tcptran_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (ep->useraio == aio) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
tcptran_ep_connect(void *arg, nni_aio *aio)
{
	tcptran_ep *ep = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (ep->useraio != NULL) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}
	if (!nni_aio_start(aio, tcptran_ep_cancel, ep)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	ep->useraio = aio;

	nng_stream_dialer_dial(ep->dialer, &ep->connaio);
	nni_mtx_unlock(&ep->mtx);
}

static nng_err
tcptran_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_ep *ep = arg;
	nng_err     rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static nng_err
tcptran_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tcptran_ep *ep = arg;
	size_t      val;
	nng_err     rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == NNG_OK) {
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		nni_mtx_unlock(&ep->mtx);
#ifdef NNG_ENABLE_STATS
		nni_stat_set_value(&ep->st_rcv_max, val);
#endif
	}
	return (rv);
}

static nng_err
tcptran_ep_bind(void *arg, nng_url *url)
{
	tcptran_ep *ep = arg;
	nng_err     rv;

	nni_mtx_lock(&ep->mtx);
	rv = nng_stream_listener_listen(ep->listener);
	if (rv == NNG_OK) {
		int port;
		nng_stream_listener_get_int(
		    ep->listener, NNG_OPT_TCP_BOUND_PORT, &port);
		url->u_port = (uint32_t) port;
	}
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void
tcptran_ep_accept(void *arg, nni_aio *aio)
{
	tcptran_ep *ep = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (ep->useraio != NULL) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}
	if (!nni_aio_start(aio, tcptran_ep_cancel, ep)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	ep->useraio = aio;
	if (!ep->started) {
		ep->started = true;
		nng_stream_listener_accept(ep->listener, &ep->connaio);
	} else {
		tcptran_ep_match(ep);
	}
	nni_mtx_unlock(&ep->mtx);
}

static size_t
tcptran_pipe_size(void)
{
	return (sizeof(tcptran_pipe));
}

static nni_sp_pipe_ops tcptran_pipe_ops = {
	.p_size   = tcptran_pipe_size,
	.p_init   = tcptran_pipe_init,
	.p_fini   = tcptran_pipe_fini,
	.p_stop   = tcptran_pipe_stop,
	.p_send   = tcptran_pipe_send,
	.p_recv   = tcptran_pipe_recv,
	.p_close  = tcptran_pipe_close,
	.p_peer   = tcptran_pipe_peer,
	.p_getopt = tcptran_pipe_getopt,
};

static const nni_option tcptran_ep_opts[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = tcptran_ep_get_recvmaxsz,
	    .o_set  = tcptran_ep_set_recvmaxsz,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nng_err
tcptran_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tcptran_ep *ep = arg;
	nng_err     rv;

	rv = nni_stream_dialer_get(ep->dialer, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tcptran_ep_opts, name, ep, buf, szp, t);
	}
	return (rv);
}

static nng_err
tcptran_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tcptran_ep *ep = arg;
	nng_err     rv;

	rv = nni_stream_dialer_set(ep->dialer, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tcptran_ep_opts, name, ep, buf, sz, t);
	}
	return (rv);
}

static nng_err
tcptran_listener_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tcptran_ep *ep = arg;
	nng_err     rv;

	rv = nni_stream_listener_get(ep->listener, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tcptran_ep_opts, name, ep, buf, szp, t);
	}
	return (rv);
}

static nng_err
tcptran_listener_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tcptran_ep *ep = arg;
	nng_err     rv;

	rv = nni_stream_listener_set(ep->listener, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tcptran_ep_opts, name, ep, buf, sz, t);
	}
	return (rv);
}

static nni_sp_dialer_ops tcptran_dialer_ops = {
	.d_size    = sizeof(tcptran_ep),
	.d_init    = tcptran_dialer_init,
	.d_fini    = tcptran_ep_fini,
	.d_connect = tcptran_ep_connect,
	.d_close   = tcptran_ep_close,
	.d_stop    = tcptran_ep_stop,
	.d_getopt  = tcptran_dialer_getopt,
	.d_setopt  = tcptran_dialer_setopt,
};

static nni_sp_listener_ops tcptran_listener_ops = {
	.l_size   = sizeof(tcptran_ep),
	.l_init   = tcptran_listener_init,
	.l_fini   = tcptran_ep_fini,
	.l_bind   = tcptran_ep_bind,
	.l_accept = tcptran_ep_accept,
	.l_close  = tcptran_ep_close,
	.l_stop   = tcptran_ep_stop,
	.l_getopt = tcptran_listener_getopt,
	.l_setopt = tcptran_listener_setopt,
};

static nni_sp_tran tcp_tran = {
	.tran_scheme   = "tcp",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
};

static nni_sp_tran tcp4_tran = {
	.tran_scheme   = "tcp4",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
};

#ifdef NNG_ENABLE_IPV6
static nni_sp_tran tcp6_tran = {
	.tran_scheme   = "tcp6",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
};
#endif

void
nni_sp_tcp_register(void)
{
	nni_sp_tran_register(&tcp_tran);
	nni_sp_tran_register(&tcp4_tran);
#ifdef NNG_ENABLE_IPV6
	nni_sp_tran_register(&tcp6_tran);
#endif
}
