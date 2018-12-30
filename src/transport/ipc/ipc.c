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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

#include <nng/transport/ipc/ipc.h>

// IPC transport.   Platform specific IPC operations must be
// supplied as well.  Normally the IPC is UNIX domain sockets or
// Windows named pipes.  Other platforms could use other mechanisms,
// but all implementations on the platform must use the same mechanism.

typedef struct ipctran_pipe ipctran_pipe;
typedef struct ipctran_ep   ipctran_ep;

// ipc_pipe is one end of an IPC connection.
struct ipctran_pipe {
	nni_ipc_conn *  conn;
	uint16_t        peer;
	uint16_t        proto;
	size_t          rcvmax;
	bool            closed;
	nni_sockaddr    sa;
	ipctran_ep *    ep;
	nni_pipe *      npipe;
	nni_list_node   node;
	nni_atomic_flag reaped;
	nni_reap_item   reap;

	uint8_t txhead[1 + sizeof(uint64_t)];
	uint8_t rxhead[1 + sizeof(uint64_t)];
	size_t  gottxhead;
	size_t  gotrxhead;
	size_t  wanttxhead;
	size_t  wantrxhead;

	nni_list recvq;
	nni_list sendq;
	nni_aio *useraio;
	nni_aio *txaio;
	nni_aio *rxaio;
	nni_aio *negoaio;
	nni_aio *connaio;
	nni_msg *rxmsg;
	nni_mtx  mtx;
};

struct ipctran_ep {
	nni_mtx           mtx;
	nni_sockaddr      sa;
	size_t            rcvmax;
	uint16_t          proto;
	nni_list          pipes;
	bool              fini;
	nni_ipc_dialer *  dialer;
	nni_ipc_listener *listener;
	nni_reap_item     reap;
	nni_dialer *      ndialer;
	nni_listener *    nlistener;
};

static void ipctran_pipe_send_start(ipctran_pipe *);
static void ipctran_pipe_recv_start(ipctran_pipe *);
static void ipctran_pipe_send_cb(void *);
static void ipctran_pipe_recv_cb(void *);
static void ipctran_pipe_nego_cb(void *);
static void ipctran_pipe_conn_cb(void *);
static void ipctran_ep_fini(void *);

static int
ipctran_init(void)
{
	return (0);
}

static void
ipctran_fini(void)
{
}

static void
ipctran_pipe_close(void *arg)
{
	ipctran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	p->closed = true;
	nni_mtx_unlock(&p->mtx);

	nni_aio_close(p->rxaio);
	nni_aio_close(p->txaio);
	nni_aio_close(p->negoaio);
	nni_aio_close(p->connaio);

	nni_ipc_conn_close(p->conn);
}

static void
ipctran_pipe_stop(void *arg)
{
	ipctran_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negoaio);
	nni_aio_stop(p->connaio);
}

static int
ipctran_pipe_init(void *arg, nni_pipe *npipe)
{
	ipctran_pipe *p = arg;
	p->npipe        = npipe;
	return (0);
}

static void
ipctran_pipe_fini(void *arg)
{
	ipctran_pipe *p = arg;
	ipctran_ep *  ep;

	ipctran_pipe_stop(p);
	if ((ep = p->ep) != NULL) {
		nni_mtx_lock(&ep->mtx);
		nni_list_remove(&ep->pipes, p);
		if (ep->fini && nni_list_empty(&ep->pipes)) {
			nni_reap(&ep->reap, ipctran_ep_fini, ep);
		}
		nni_mtx_unlock(&ep->mtx);
	}
	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);
	nni_aio_fini(p->negoaio);
	nni_aio_fini(p->connaio);
	if (p->conn != NULL) {
		nni_ipc_conn_fini(p->conn);
	}
	if (p->rxmsg) {
		nni_msg_free(p->rxmsg);
	}
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static void
ipctran_pipe_reap(ipctran_pipe *p)
{
	if (!nni_atomic_flag_test_and_set(&p->reaped)) {
		if (p->conn != NULL) {
			nni_ipc_conn_close(p->conn);
		}
		nni_reap(&p->reap, ipctran_pipe_fini, p);
	}
}

static int
ipctran_pipe_alloc(ipctran_pipe **pipep, ipctran_ep *ep)
{
	ipctran_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_init(&p->txaio, ipctran_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, ipctran_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->connaio, ipctran_pipe_conn_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negoaio, ipctran_pipe_nego_cb, p)) != 0)) {
		ipctran_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->sendq);
	nni_aio_list_init(&p->recvq);
	nni_atomic_flag_reset(&p->reaped);
	nni_list_append(&ep->pipes, p);

	// 5 seconds each for connection and negotiation; should be more than
	// sufficient.
	nni_aio_set_timeout(p->connaio, 5000);
	nni_aio_set_timeout(p->negoaio, 5000);

	p->proto  = ep->proto;
	p->rcvmax = ep->rcvmax;
	p->sa     = ep->sa;
	p->ep     = ep;

	*pipep = p;
	return (0);
}

static void
ipctran_pipe_conn_cb(void *arg)
{
	ipctran_pipe *p   = arg;
	ipctran_ep *  ep  = p->ep;
	nni_aio *     aio = p->connaio;
	nni_aio *     uaio;
	nni_iov       iov;
	int           rv;

	nni_mtx_lock(&ep->mtx);
	uaio = p->useraio;
	if ((rv = nni_aio_result(aio)) == 0) {
		p->conn = nni_aio_get_output(aio, 0);
	}
	if (uaio == NULL) {
		nni_mtx_unlock(&ep->mtx);
		ipctran_pipe_reap(p);
		return;
	}
	if (rv != 0) {
		p->useraio = NULL;
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(uaio, rv);
		ipctran_pipe_reap(p);
		return;
	}
	p->conn      = nni_aio_get_output(aio, 0);
	p->txhead[0] = 0;
	p->txhead[1] = 'S';
	p->txhead[2] = 'P';
	p->txhead[3] = 0;
	NNI_PUT16(&p->txhead[4], p->proto);
	NNI_PUT16(&p->txhead[6], 0);

	p->gotrxhead  = 0;
	p->gottxhead  = 0;
	p->wantrxhead = 8;
	p->wanttxhead = 8;
	iov.iov_len   = 8;
	iov.iov_buf   = &p->txhead[0];
	nni_aio_set_iov(p->negoaio, 1, &iov);
	nni_ipc_conn_send(p->conn, p->negoaio);
	nni_mtx_unlock(&ep->mtx);
}

static void
ipctran_pipe_nego_cb(void *arg)
{
	ipctran_pipe *p   = arg;
	nni_aio *     aio = p->negoaio;
	nni_aio *     uaio;
	int           rv;

	nni_mtx_lock(&p->ep->mtx);
	if ((uaio = p->useraio) == NULL) {
		nni_mtx_unlock(&p->ep->mtx);
		ipctran_pipe_reap(p);
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
		iov.iov_buf = &p->txhead[p->gottxhead];
		nni_aio_set_iov(aio, 1, &iov);
		// send it down...
		nni_ipc_conn_send(p->conn, aio);
		nni_mtx_unlock(&p->ep->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxhead[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nni_ipc_conn_recv(p->conn, aio);
		nni_mtx_unlock(&p->ep->mtx);
		return;
	}
	// We have both sent and received the headers.  Lets check the
	// receive side header.
	if ((p->rxhead[0] != 0) || (p->rxhead[1] != 'S') ||
	    (p->rxhead[2] != 'P') || (p->rxhead[3] != 0) ||
	    (p->rxhead[6] != 0) || (p->rxhead[7] != 0)) {
		rv = NNG_EPROTO;
		goto error;
	}

	NNI_GET16(&p->rxhead[4], p->peer);
	p->useraio = NULL;
	nni_mtx_unlock(&p->ep->mtx);
	nni_aio_set_output(uaio, 0, p);
	nni_aio_finish(uaio, 0, 0);
	return;

error:
	p->useraio = NULL;
	nni_mtx_unlock(&p->ep->mtx);
	nni_aio_finish_error(uaio, rv);
	ipctran_pipe_reap(p);
}

static void
ipctran_pipe_send_cb(void *arg)
{
	ipctran_pipe *p = arg;
	int           rv;
	nni_aio *     aio;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     txaio = p->txaio;

	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_result(txaio)) != 0) {
		// Intentionally we do not queue up another transfer.
		// There's an excellent chance that the pipe is no longer
		// usable, with a partial transfer.
		// The protocol should see this error, and close the
		// pipe itself, we hope.

		while ((aio = nni_list_first(&p->sendq)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
		}
		nni_mtx_unlock(&p->mtx);
		return;
	}

	n = nni_aio_count(txaio);
	nni_aio_iov_advance(txaio, n);
	if (nni_aio_iov_count(txaio) != 0) {
		nni_ipc_conn_send(p->conn, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	aio = nni_list_first(&p->sendq);
	nni_aio_list_remove(aio);
	ipctran_pipe_send_start(p);

	nni_mtx_unlock(&p->mtx);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_synch(aio, 0, n);
}

static void
ipctran_pipe_recv_cb(void *arg)
{
	ipctran_pipe *p = arg;
	nni_aio *     aio;
	int           rv;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     rxaio = p->rxaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->recvq);

	if ((rv = nni_aio_result(rxaio)) != 0) {
		// Error on receive.  This has to cause an error back
		// to the user.  Also, if we had allocated an rxmsg, lets
		// toss it.
		goto error;
	}

	n = nni_aio_count(rxaio);
	nni_aio_iov_advance(rxaio, n);
	if (nni_aio_iov_count(rxaio) != 0) {
		// Was this a partial read?  If so then resubmit for the rest.
		nni_ipc_conn_recv(p->conn, rxaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	// If we don't have a message yet, we were reading the message
	// header, which is just the length.  This tells us the size of the
	// message to allocate and how much more to expect.
	if (p->rxmsg == NULL) {
		uint64_t len;

		// Check to make sure we got msg type 1.
		if (p->rxhead[0] != 1) {
			rv = NNG_EPROTO;
			goto error;
		}

		// We should have gotten a message header.
		NNI_GET64(p->rxhead + 1, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if ((len > p->rcvmax) && (p->rcvmax > 0)) {
			rv = NNG_EMSGSIZE;
			goto error;
		}

		// Note that all IO on this pipe is blocked behind this
		// allocation.  We could possibly look at using a separate
		// lock for the read side in the future, so that we allow
		// transmits to proceed normally.  In practice this is
		// unlikely to be much of an issue though.
		if ((rv = nni_msg_alloc(&p->rxmsg, (size_t) len)) != 0) {
			goto error;
		}

		if (len != 0) {
			nni_iov iov;
			// Submit the rest of the data for a read -- we want to
			// read the entire message now.
			iov.iov_buf = nni_msg_body(p->rxmsg);
			iov.iov_len = (size_t) len;

			nni_aio_set_iov(rxaio, 1, &iov);
			nni_ipc_conn_recv(p->conn, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// Otherwise we got a message read completely.  Let the user know the
	// good news.

	aio = nni_list_first(&p->recvq);
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	ipctran_pipe_recv_start(p);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_synch(aio, 0, nni_msg_len(msg));
	return;

error:
	while ((aio = nni_list_first(&p->recvq)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	// Intentionally, we do not queue up another receive.
	// The protocol should notice this error and close the pipe.
	nni_mtx_unlock(&p->mtx);

	nni_msg_free(msg);
}

static void
ipctran_pipe_send_cancel(nni_aio *aio, void *arg, int rv)
{
	ipctran_pipe *p = arg;

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
ipctran_pipe_send_start(ipctran_pipe *p)
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

	p->txhead[0] = 1; // message type, 1.
	NNI_PUT64(p->txhead + 1, len);

	txaio          = p->txaio;
	niov           = 0;
	iov[0].iov_buf = p->txhead;
	iov[0].iov_len = sizeof(p->txhead);
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
	nni_ipc_conn_send(p->conn, txaio);
}

static void
ipctran_pipe_send(void *arg, nni_aio *aio)
{
	ipctran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, ipctran_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		ipctran_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ipctran_pipe_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	ipctran_pipe *p = arg;

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
ipctran_pipe_recv_start(ipctran_pipe *p)
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

	// Schedule a read of the IPC header.
	rxaio       = p->rxaio;
	iov.iov_buf = p->rxhead;
	iov.iov_len = sizeof(p->rxhead);
	nni_aio_set_iov(rxaio, 1, &iov);

	nni_ipc_conn_recv(p->conn, rxaio);
}

static void
ipctran_pipe_recv(void *arg, nni_aio *aio)
{
	ipctran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if (p->closed) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, ipctran_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_list_append(&p->recvq, aio);
	if (nni_list_first(&p->recvq) == aio) {
		ipctran_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
ipctran_pipe_peer(void *arg)
{
	ipctran_pipe *p = arg;

	return (p->peer);
}

static void
ipctran_pipe_conn_cancel(nni_aio *aio, void *arg, int rv)
{
	ipctran_pipe *p = arg;

	nni_mtx_lock(&p->ep->mtx);
	if (aio == p->useraio) {
		nni_aio_close(p->negoaio);
		nni_aio_close(p->connaio);
		p->useraio = NULL;
		nni_aio_finish_error(aio, rv);
		ipctran_pipe_reap(p);
	}
	nni_mtx_unlock(&p->ep->mtx);
}

static void
ipctran_ep_fini(void *arg)
{
	ipctran_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	ep->fini = true;
	if (!nni_list_empty(&ep->pipes)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (ep->dialer != NULL) {
		nni_ipc_dialer_fini(ep->dialer);
	}
	if (ep->listener != NULL) {
		nni_ipc_listener_fini(ep->listener);
	}
	nni_mtx_unlock(&ep->mtx);
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static void
ipctran_ep_close(void *arg)
{
	ipctran_ep *  ep = arg;
	ipctran_pipe *p;

	nni_mtx_lock(&ep->mtx);
	NNI_LIST_FOREACH (&ep->pipes, p) {
		nni_aio_close(p->negoaio);
		nni_aio_close(p->connaio);
		nni_aio_close(p->txaio);
		nni_aio_close(p->rxaio);
		if (p->conn != NULL) {
			nni_ipc_conn_close(p->conn);
		}
	}
	if (ep->dialer != NULL) {
		nni_ipc_dialer_close(ep->dialer);
	}
	if (ep->listener != NULL) {
		nni_ipc_listener_close(ep->listener);
	}
	nni_mtx_unlock(&ep->mtx);
}

static int
ipctran_ep_init_dialer(void **dp, nni_url *url, nni_dialer *ndialer)
{
	ipctran_ep *ep;
	int         rv;
	size_t      sz;
	nni_sock *  sock = nni_dialer_sock(ndialer);

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->pipes, ipctran_pipe, node);

	sz                     = sizeof(ep->sa.s_ipc.sa_path);
	ep->sa.s_ipc.sa_family = NNG_AF_IPC;
	ep->proto              = nni_sock_proto_id(sock);
	ep->ndialer            = ndialer;

	if (nni_strlcpy(ep->sa.s_ipc.sa_path, url->u_path, sz) >= sz) {
		ipctran_ep_fini(ep);
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_ipc_dialer_init(&ep->dialer)) != 0) {
		ipctran_ep_fini(ep);
		return (rv);
	}

	*dp = ep;
	return (0);
}

static int
ipctran_ep_init_listener(void **dp, nni_url *url, nni_listener *nlistener)
{
	ipctran_ep *ep;
	int         rv;
	size_t      sz;
	nni_sock *  sock = nni_listener_sock(nlistener);

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->pipes, ipctran_pipe, node);

	sz                     = sizeof(ep->sa.s_ipc.sa_path);
	ep->sa.s_ipc.sa_family = NNG_AF_IPC;
	ep->proto              = nni_sock_proto_id(sock);
	ep->nlistener          = nlistener;

	if (nni_strlcpy(ep->sa.s_ipc.sa_path, url->u_path, sz) >= sz) {
		ipctran_ep_fini(ep);
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_ipc_listener_init(&ep->listener)) != 0) {
		ipctran_ep_fini(ep);
		return (rv);
	}

	*dp = ep;
	return (0);
}

static void
ipctran_ep_connect(void *arg, nni_aio *aio)
{
	ipctran_ep *  ep = arg;
	ipctran_pipe *p  = NULL;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	if ((rv = ipctran_pipe_alloc(&p, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	if ((rv = nni_aio_schedule(aio, ipctran_pipe_conn_cancel, p)) != 0) {
		nni_list_remove(&ep->pipes, p);
		p->ep = NULL;
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		ipctran_pipe_fini(p);
		return;
	}
	p->useraio = aio;
	nni_ipc_dialer_dial(ep->dialer, &p->sa, p->connaio);
	nni_mtx_unlock(&ep->mtx);
}

static int
ipctran_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_type t)
{
	ipctran_ep *ep = arg;
	int         rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
ipctran_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_type t)
{
	ipctran_ep *ep = arg;
	size_t      val;
	int         rv;
	if (((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) &&
	    (ep != NULL)) {

		ipctran_pipe *p;
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		NNI_LIST_FOREACH (&ep->pipes, p) {
			p->rcvmax = val;
		}
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
ipctran_ep_bind(void *arg)
{
	ipctran_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_ipc_listener_listen(ep->listener, &ep->sa);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static void
ipctran_ep_accept(void *arg, nni_aio *aio)
{
	ipctran_ep *  ep = arg;
	ipctran_pipe *p  = NULL;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	if ((rv = ipctran_pipe_alloc(&p, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	if ((rv = nni_aio_schedule(aio, ipctran_pipe_conn_cancel, p)) != 0) {
		nni_list_remove(&ep->pipes, p);
		p->ep = NULL;
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		ipctran_pipe_fini(p);
		return;
	}
	p->useraio = aio;
	nni_ipc_listener_accept(ep->listener, p->connaio);
	nni_mtx_unlock(&ep->mtx);
}

static int
ipctran_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ipctran_pipe *p = arg;

	// We defer to the platform getopt code for IPC connections.
	return (nni_ipc_conn_getopt(p->conn, name, buf, szp, t));
}

static nni_tran_pipe_ops ipctran_pipe_ops = {
	.p_init   = ipctran_pipe_init,
	.p_fini   = ipctran_pipe_fini,
	.p_stop   = ipctran_pipe_stop,
	.p_send   = ipctran_pipe_send,
	.p_recv   = ipctran_pipe_recv,
	.p_close  = ipctran_pipe_close,
	.p_peer   = ipctran_pipe_peer,
	.p_getopt = ipctran_pipe_getopt,
};

static const nni_option ipctran_ep_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = ipctran_ep_get_recvmaxsz,
	    .o_set  = ipctran_ep_set_recvmaxsz,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
ipctran_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ipctran_ep *ep = arg;
	int         rv;

	rv = nni_getopt(ipctran_ep_options, name, ep, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_ipc_dialer_getopt(ep->dialer, name, buf, szp, t);
	}
	return (rv);
}

static int
ipctran_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ipctran_ep *ep = arg;
	int         rv;

	rv = nni_setopt(ipctran_ep_options, name, ep, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_ipc_dialer_setopt(
		    ep != NULL ? ep->dialer : NULL, name, buf, sz, t);
	}
	return (rv);
}

static int
ipctran_listener_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ipctran_ep *ep = arg;
	int         rv;

	rv = nni_getopt(ipctran_ep_options, name, ep, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_ipc_listener_getopt(ep->listener, name, buf, szp, t);
	}
	return (rv);
}

static int
ipctran_listener_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ipctran_ep *ep = arg;
	int         rv;

	rv = nni_setopt(ipctran_ep_options, name, ep, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_ipc_listener_setopt(
		    ep != NULL ? ep->listener : NULL, name, buf, sz, t);
	}
	return (rv);
}

static nni_tran_dialer_ops ipctran_dialer_ops = {
	.d_init    = ipctran_ep_init_dialer,
	.d_fini    = ipctran_ep_fini,
	.d_connect = ipctran_ep_connect,
	.d_close   = ipctran_ep_close,
	.d_getopt  = ipctran_dialer_getopt,
	.d_setopt  = ipctran_dialer_setopt,
};

static nni_tran_listener_ops ipctran_listener_ops = {
	.l_init   = ipctran_ep_init_listener,
	.l_fini   = ipctran_ep_fini,
	.l_bind   = ipctran_ep_bind,
	.l_accept = ipctran_ep_accept,
	.l_close  = ipctran_ep_close,
	.l_getopt = ipctran_listener_getopt,
	.l_setopt = ipctran_listener_setopt,
};

static nni_tran ipc_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "ipc",
	.tran_dialer   = &ipctran_dialer_ops,
	.tran_listener = &ipctran_listener_ops,
	.tran_pipe     = &ipctran_pipe_ops,
	.tran_init     = ipctran_init,
	.tran_fini     = ipctran_fini,
};

int
nng_ipc_register(void)
{
	return (nni_tran_register(&ipc_tran));
}
