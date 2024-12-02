//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
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

#include "core/defs.h"
#include "core/nng_impl.h"

// Socket transport.  This takes sockets that may have been
// created via another mechanism (usually socketpair) and
// builds a connection using them.  The socket is passed in to the listener
// using the NNG_OPT_SOCKFD_FD option.

typedef struct sfd_tran_pipe sfd_tran_pipe;
typedef struct sfd_tran_ep   sfd_tran_ep;

// sfd_tran_pipe wraps an open file descriptor
struct sfd_tran_pipe {
	nng_stream   *conn;
	nni_pipe     *npipe;
	uint16_t      peer;
	uint16_t      proto;
	size_t        rcvmax;
	bool          closed;
	nni_list_node node;
	sfd_tran_ep  *ep;
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

struct sfd_tran_ep {
	nni_mtx              mtx;
	uint16_t             proto;
	size_t               rcvmax;
	bool                 started;
	bool                 closed;
	nng_sockaddr         src;
	nni_aio             *useraio;
	nni_aio              connaio;
	nni_aio              timeaio;
	nni_list             waitpipes; // pipes waiting to match to socket
	nni_list             negopipes; // pipes busy negotiating
	nng_stream_listener *listener;
	nni_listener        *nlistener;

#ifdef NNG_ENABLE_STATS
	nni_stat_item st_rcv_max;
#endif
};

static void sfd_tran_pipe_send_start(sfd_tran_pipe *);
static void sfd_tran_pipe_recv_start(sfd_tran_pipe *);
static void sfd_tran_pipe_send_cb(void *);
static void sfd_tran_pipe_recv_cb(void *);
static void sfd_tran_pipe_nego_cb(void *);
static void sfd_tran_ep_fini(void *);
static void sfd_tran_pipe_fini(void *);

static void
sfd_tran_init(void)
{
}

static void
sfd_tran_fini(void)
{
}

static void
sfd_tran_pipe_close(void *arg)
{
	sfd_tran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	p->closed = true;
	nni_mtx_unlock(&p->mtx);
	if (p->conn != NULL) {
		nng_stream_close(p->conn);
	}

	nni_aio_close(&p->rxaio);
	nni_aio_close(&p->txaio);
	nni_aio_close(&p->negoaio);
}

static void
sfd_tran_pipe_stop(void *arg)
{
	sfd_tran_pipe *p = arg;

	nni_aio_stop(&p->rxaio);
	nni_aio_stop(&p->txaio);
	nni_aio_stop(&p->negoaio);
}

static int
sfd_tran_pipe_init(void *arg, nni_pipe *npipe)
{
	sfd_tran_pipe *p = arg;
	p->npipe         = npipe;
	nni_mtx_init(&p->mtx);
	nni_aio_init(&p->txaio, sfd_tran_pipe_send_cb, p);
	nni_aio_init(&p->rxaio, sfd_tran_pipe_recv_cb, p);
	nni_aio_init(&p->negoaio, sfd_tran_pipe_nego_cb, p);
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);

	return (0);
}

static void
sfd_tran_pipe_fini(void *arg)
{
	sfd_tran_pipe *p = arg;
	sfd_tran_ep   *ep;

	sfd_tran_pipe_stop(p);
	if ((ep = p->ep) != NULL) {
		nni_mtx_lock(&ep->mtx);
		nni_list_node_remove(&p->node);
		nni_mtx_unlock(&ep->mtx);
	}
	if (p->conn != NULL) {
		nng_stream_free(p->conn);
	}

	nni_aio_fini(&p->rxaio);
	nni_aio_fini(&p->txaio);
	nni_aio_fini(&p->negoaio);
	nni_msg_free(p->rxmsg);
	nni_mtx_fini(&p->mtx);
}

static void
sfd_tran_ep_match(sfd_tran_ep *ep)
{
	nni_aio       *aio;
	sfd_tran_pipe *p;

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
sfd_tran_pipe_nego_cb(void *arg)
{
	sfd_tran_pipe *p   = arg;
	sfd_tran_ep   *ep  = p->ep;
	nni_aio       *aio = &p->negoaio;
	nni_aio       *uaio;
	int            rv;

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

	sfd_tran_ep_match(ep);
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

	if ((uaio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(uaio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
	nni_pipe_close(p->npipe);
}

static void
sfd_tran_pipe_send_cb(void *arg)
{
	sfd_tran_pipe *p = arg;
	int            rv;
	nni_aio       *aio;
	size_t         n;
	nni_msg       *msg;
	nni_aio       *txaio = &p->txaio;

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
	sfd_tran_pipe_send_start(p);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_pipe_bump_tx(p->npipe, n);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_sync(aio, 0, n);
}

static void
sfd_tran_pipe_recv_cb(void *arg)
{
	sfd_tran_pipe *p = arg;
	nni_aio       *aio;
	int            rv;
	size_t         n;
	nni_msg       *msg;
	nni_aio       *rxaio = &p->rxaio;

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

	// If we don't have a message yet, we were reading the message
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
	sfd_tran_pipe_recv_start(p);
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
sfd_tran_pipe_send_cancel(nni_aio *aio, void *arg, int rv)
{
	sfd_tran_pipe *p = arg;

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
sfd_tran_pipe_send_start(sfd_tran_pipe *p)
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
sfd_tran_pipe_send(void *arg, nni_aio *aio)
{
	sfd_tran_pipe *p = arg;
	int            rv;

	if (nni_aio_begin(aio) != 0) {
		// No way to give the message back to the protocol, so
		// we just discard it silently to prevent it from leaking.
		nni_msg_free(nni_aio_get_msg(aio));
		nni_aio_set_msg(aio, NULL);
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, sfd_tran_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		sfd_tran_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
sfd_tran_pipe_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	sfd_tran_pipe *p = arg;

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
sfd_tran_pipe_recv_start(sfd_tran_pipe *p)
{
	nni_aio *rxaio;
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
	rxaio       = &p->rxaio;
	iov.iov_buf = p->rxlen;
	iov.iov_len = sizeof(p->rxlen);
	nni_aio_set_iov(rxaio, 1, &iov);

	nng_stream_recv(p->conn, rxaio);
}

static void
sfd_tran_pipe_recv(void *arg, nni_aio *aio)
{
	sfd_tran_pipe *p = arg;
	int            rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, sfd_tran_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_list_append(&p->recvq, aio);
	if (nni_list_first(&p->recvq) == aio) {
		sfd_tran_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
sfd_tran_pipe_peer(void *arg)
{
	sfd_tran_pipe *p = arg;

	return (p->peer);
}

static int
sfd_tran_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	sfd_tran_pipe *p = arg;
	return (nni_stream_get(p->conn, name, buf, szp, t));
}

static void
sfd_tran_pipe_start(sfd_tran_pipe *p, nng_stream *conn, sfd_tran_ep *ep)
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

	// No timeouts here -- the purpose of timeouts was to guard against
	// untrusted callers forcing us to burn files.  In this case the
	// application is providing us with a file, and should be reasonably
	// trusted not to be doing a DoS against itself! :-)  Part of the
	// rationale is that it may take a while for a child process to reach
	// the point where it is ready to negotiate the other side of a
	// connection.
	nni_aio_set_timeout(&p->negoaio, NNG_DURATION_INFINITE);
	nng_stream_send(p->conn, &p->negoaio);
}

static void
sfd_tran_ep_fini(void *arg)
{
	sfd_tran_ep *ep = arg;

	nni_aio_stop(&ep->timeaio);
	nni_aio_stop(&ep->connaio);
	nng_stream_listener_free(ep->listener);
	nni_aio_fini(&ep->timeaio);
	nni_aio_fini(&ep->connaio);

	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static void
sfd_tran_ep_close(void *arg)
{
	sfd_tran_ep   *ep = arg;
	sfd_tran_pipe *p;

	nni_mtx_lock(&ep->mtx);

	ep->closed = true;
	nni_aio_close(&ep->timeaio);
	if (ep->listener != NULL) {
		nng_stream_listener_close(ep->listener);
	}
	while (((p = nni_list_first(&ep->negopipes)) != NULL) ||
	    ((p = nni_list_first(&ep->waitpipes)) != NULL)) {
		nni_list_node_remove(&p->node);
		nni_mtx_unlock(&ep->mtx);
		nni_pipe_close(p->npipe);
		nni_pipe_rele(p->npipe);
		nni_mtx_lock(&ep->mtx);
	}
	if (ep->useraio != NULL) {
		nni_aio_finish_error(ep->useraio, NNG_ECLOSED);
		ep->useraio = NULL;
	}

	nni_mtx_unlock(&ep->mtx);
}

static void
sfd_tran_timer_cb(void *arg)
{
	sfd_tran_ep *ep = arg;
	if (nni_aio_result(&ep->timeaio) == 0) {
		nng_stream_listener_accept(ep->listener, &ep->connaio);
	}
}

static void
sfd_tran_accept_cb(void *arg)
{
	sfd_tran_ep   *ep  = arg;
	nni_aio       *aio = &ep->connaio;
	sfd_tran_pipe *p;
	int            rv;
	nng_stream    *conn;

	nni_mtx_lock(&ep->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);
	if ((rv = nni_sp_pipe_alloc((void **) &p, NULL, ep->nlistener)) != 0) {
		nng_stream_free(conn);
		goto error;
	}
	p->conn = conn;
	p->ep   = ep;

	if (ep->closed) {
		nni_pipe_close(p->npipe);
		nni_pipe_rele(p->npipe);
		rv = NNG_ECLOSED;
		goto error;
	}
	sfd_tran_pipe_start(p, conn, ep);
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

static int
sfd_tran_ep_init(sfd_tran_ep **epp, nni_listener *nlistener)
{
	sfd_tran_ep *ep;
	nni_sock    *sock = nni_listener_sock(nlistener);

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->waitpipes, sfd_tran_pipe, node);
	NNI_LIST_INIT(&ep->negopipes, sfd_tran_pipe, node);

	ep->nlistener = nlistener;
	ep->proto     = nni_sock_proto_id(sock);

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

	*epp = ep;
	return (0);
}

static int
sfd_tran_listener_init(void **lp, nng_url *url, nni_listener *nlistener)
{
	sfd_tran_ep *ep;
	int          rv;

	// Check for invalid URL components -- we only accept a bare scheme
	if ((url->u_hostname != NULL) || (strlen(url->u_path) != 0) ||
	    (url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL)) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = sfd_tran_ep_init(&ep, nlistener)) != 0) {
		return (rv);
	}

	nni_aio_init(&ep->connaio, sfd_tran_accept_cb, ep);
	nni_aio_init(&ep->timeaio, sfd_tran_timer_cb, ep);

	if ((rv = nng_stream_listener_alloc_url(&ep->listener, url)) != 0) {
		sfd_tran_ep_fini(ep);
		return (rv);
	}

#ifdef NNG_ENABLE_STATS
	nni_listener_add_stat(nlistener, &ep->st_rcv_max);
#endif

	*lp = ep;
	return (0);
}

static void
sfd_tran_ep_cancel(nni_aio *aio, void *arg, int rv)
{
	sfd_tran_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (ep->useraio == aio) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static int
sfd_tran_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	sfd_tran_ep *ep = arg;
	int          rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
sfd_tran_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	sfd_tran_ep *ep = arg;
	size_t       val;
	int          rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		nni_mtx_unlock(&ep->mtx);
#ifdef NNG_ENABLE_STATS
		nni_stat_set_value(&ep->st_rcv_max, val);
#endif
	}
	return (rv);
}

static int
sfd_tran_ep_bind(void *arg, nng_url *url)
{
	sfd_tran_ep *ep = arg;
	NNI_ARG_UNUSED(url);
	return (nng_stream_listener_listen(ep->listener));
}

static void
sfd_tran_ep_accept(void *arg, nni_aio *aio)
{
	sfd_tran_ep *ep = arg;
	int          rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
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
	if ((rv = nni_aio_schedule(aio, sfd_tran_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ep->useraio = aio;
	if (!ep->started) {
		ep->started = true;
		nng_stream_listener_accept(ep->listener, &ep->connaio);
	} else {
		sfd_tran_ep_match(ep);
	}
	nni_mtx_unlock(&ep->mtx);
}

static nni_sp_pipe_ops sfd_tran_pipe_ops = {
	.p_size   = sizeof(sfd_tran_pipe),
	.p_init   = sfd_tran_pipe_init,
	.p_fini   = sfd_tran_pipe_fini,
	.p_stop   = sfd_tran_pipe_stop,
	.p_send   = sfd_tran_pipe_send,
	.p_recv   = sfd_tran_pipe_recv,
	.p_close  = sfd_tran_pipe_close,
	.p_peer   = sfd_tran_pipe_peer,
	.p_getopt = sfd_tran_pipe_getopt,
};

static const nni_option sfd_tran_ep_opts[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = sfd_tran_ep_get_recvmaxsz,
	    .o_set  = sfd_tran_ep_set_recvmaxsz,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
sfd_tran_listener_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	sfd_tran_ep *ep = arg;
	int          rv;

	rv = nni_stream_listener_get(ep->listener, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(sfd_tran_ep_opts, name, ep, buf, szp, t);
	}
	return (rv);
}

static int
sfd_tran_listener_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	sfd_tran_ep *ep = arg;
	int          rv;

	rv = nni_stream_listener_set(ep->listener, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(sfd_tran_ep_opts, name, ep, buf, sz, t);
	}
	return (rv);
}

static nni_sp_listener_ops sfd_tran_listener_ops = {
	.l_init   = sfd_tran_listener_init,
	.l_fini   = sfd_tran_ep_fini,
	.l_bind   = sfd_tran_ep_bind,
	.l_accept = sfd_tran_ep_accept,
	.l_close  = sfd_tran_ep_close,
	.l_getopt = sfd_tran_listener_getopt,
	.l_setopt = sfd_tran_listener_setopt,
};

static nni_sp_tran sfd_tran = {
	.tran_scheme   = "socket",
	.tran_dialer   = NULL,
	.tran_listener = &sfd_tran_listener_ops,
	.tran_pipe     = &sfd_tran_pipe_ops,
	.tran_init     = sfd_tran_init,
	.tran_fini     = sfd_tran_fini,
};

void
nni_sp_sfd_register(void)
{
	nni_sp_tran_register(&sfd_tran);
}
