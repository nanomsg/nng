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

#include <stdio.h>

#include "core/defs.h"
#include "core/nng_impl.h"
#include "core/pipe.h"
#include "nng/nng.h"

// IPC transport.   Platform specific IPC operations must be
// supplied as well.  Normally the IPC is UNIX domain sockets or
// Windows named pipes.  Other platforms could use other mechanisms,
// but all implementations on the platform must use the same mechanism.

typedef struct ipc_pipe ipc_pipe;
typedef struct ipc_ep   ipc_ep;

// ipc_pipe is one end of an IPC connection.
struct ipc_pipe {
	nng_stream   *conn;
	uint16_t      peer;
	uint16_t      proto;
	size_t        rcv_max;
	bool          closed;
	ipc_ep       *ep;
	nni_pipe     *pipe;
	nni_list_node node;
	uint8_t       tx_head[1 + sizeof(uint64_t)];
	uint8_t       rx_head[1 + sizeof(uint64_t)];
	size_t        got_tx_head;
	size_t        got_rx_head;
	size_t        want_tx_head;
	size_t        want_rx_head;
	nni_list      recv_q;
	nni_list      send_q;
	nni_aio       tx_aio;
	nni_aio       rx_aio;
	nni_aio       neg_aio;
	nni_msg      *rx_msg;
	nni_mtx       mtx;
};

struct ipc_ep {
	nni_mtx              mtx;
	size_t               rcv_max;
	uint16_t             proto;
	bool                 started;
	bool                 closed;
	bool                 fini;
	nng_stream_dialer   *dialer;
	nng_stream_listener *listener;
	nni_listener        *nlistener;
	nni_dialer          *ndialer;
	nni_aio             *user_aio;
	nni_aio              conn_aio;
	nni_aio              time_aio;
	nni_list             wait_pipes; // pipes waiting to match to socket
	nni_list             nego_pipes; // pipes busy negotiating
#ifdef NNG_ENABLE_STATS
	nni_stat_item st_rcv_max;
#endif
};

static void ipc_pipe_send_start(ipc_pipe *p);
static void ipc_pipe_recv_start(ipc_pipe *p);
static void ipc_pipe_send_cb(void *);
static void ipc_pipe_recv_cb(void *);
static void ipc_pipe_nego_cb(void *);

static void
ipc_tran_init(void)
{
}

static void
ipc_tran_fini(void)
{
}

static void
ipc_pipe_close(void *arg)
{
	ipc_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	p->closed = true;
	nni_mtx_unlock(&p->mtx);

	nni_aio_close(&p->rx_aio);
	nni_aio_close(&p->tx_aio);
	nni_aio_close(&p->neg_aio);

	nng_stream_close(p->conn);
}

static void
ipc_pipe_stop(void *arg)
{
	ipc_pipe *p  = arg;
	ipc_ep   *ep = p->ep;

	nni_aio_stop(&p->rx_aio);
	nni_aio_stop(&p->tx_aio);
	nni_aio_stop(&p->neg_aio);
	nng_stream_stop(p->conn);
	nni_mtx_lock(&ep->mtx);
	nni_list_node_remove(&p->node);
	nni_mtx_unlock(&ep->mtx);
}

static int
ipc_pipe_init(void *arg, nni_pipe *pipe)
{
	ipc_pipe *p = arg;
	p->pipe     = pipe;
	nni_mtx_init(&p->mtx);
	nni_aio_init(&p->tx_aio, ipc_pipe_send_cb, p);
	nni_aio_init(&p->rx_aio, ipc_pipe_recv_cb, p);
	nni_aio_init(&p->neg_aio, ipc_pipe_nego_cb, p);
	nni_aio_list_init(&p->send_q);
	nni_aio_list_init(&p->recv_q);
	return (0);
}

static void
ipc_pipe_fini(void *arg)
{
	ipc_pipe *p = arg;

	ipc_pipe_stop(p);
	nng_stream_free(p->conn);
	nni_aio_fini(&p->rx_aio);
	nni_aio_fini(&p->tx_aio);
	nni_aio_fini(&p->neg_aio);
	nni_msg_free(p->rx_msg);
	nni_mtx_fini(&p->mtx);
}

static void
ipc_ep_match(ipc_ep *ep)
{
	nni_aio  *aio;
	ipc_pipe *p;

	if (((aio = ep->user_aio) == NULL) ||
	    ((p = nni_list_first(&ep->wait_pipes)) == NULL)) {
		return;
	}
	nni_list_remove(&ep->wait_pipes, p);
	ep->user_aio = NULL;
	p->rcv_max   = ep->rcv_max;
	nni_aio_set_output(aio, 0, p->pipe);
	nni_aio_finish(aio, 0, 0);
}

static void
ipc_pipe_nego_cb(void *arg)
{
	ipc_pipe *p   = arg;
	ipc_ep   *ep  = p->ep;
	nni_aio  *aio = &p->neg_aio;
	nni_aio  *user_aio;
	int       rv;

	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		rv = NNG_ECLOSED;
		goto error;
	}
	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	// We start transmitting before we receive.
	if (p->got_tx_head < p->want_tx_head) {
		p->got_tx_head += nni_aio_count(aio);
	} else if (p->got_rx_head < p->want_rx_head) {
		p->got_rx_head += nni_aio_count(aio);
	}
	if (p->got_tx_head < p->want_tx_head) {
		nni_iov iov;
		iov.iov_len = p->want_tx_head - p->got_tx_head;
		iov.iov_buf = &p->tx_head[p->got_tx_head];
		nni_aio_set_iov(aio, 1, &iov);
		// send it down...
		nng_stream_send(p->conn, aio);
		nni_mtx_unlock(&p->ep->mtx);
		return;
	}
	if (p->got_rx_head < p->want_rx_head) {
		nni_iov iov;
		iov.iov_len = p->want_rx_head - p->got_rx_head;
		iov.iov_buf = &p->rx_head[p->got_rx_head];
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_recv(p->conn, aio);
		nni_mtx_unlock(&p->ep->mtx);
		return;
	}
	// We have both sent and received the headers.  Let's check the
	// receiver.
	if ((p->rx_head[0] != 0) || (p->rx_head[1] != 'S') ||
	    (p->rx_head[2] != 'P') || (p->rx_head[3] != 0) ||
	    (p->rx_head[6] != 0) || (p->rx_head[7] != 0)) {
		rv = NNG_EPROTO;
		goto error;
	}

	NNI_GET16(&p->rx_head[4], p->peer);

	// We are ready now.  We put this in the wait list, and
	// then try to run the matcher.
	nni_list_remove(&ep->nego_pipes, p);
	nni_list_append(&ep->wait_pipes, p);

	ipc_ep_match(ep);
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
	nni_list_remove(&ep->nego_pipes, p);
	nng_stream_close(p->conn);
	// If we are waiting to negotiate on a client side, then a failure
	// here has to be passed to the user app.
	if ((user_aio = ep->user_aio) != NULL) {
		ep->user_aio = NULL;
		nni_aio_finish_error(user_aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
	nni_pipe_close(p->pipe);
	nni_pipe_rele(p->pipe);
}

static void
ipc_pipe_send_cb(void *arg)
{
	ipc_pipe *p = arg;
	int       rv;
	nni_aio  *aio;
	size_t    n;
	nni_msg  *msg;
	nni_aio  *tx_aio = &p->tx_aio;

	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_result(tx_aio)) != 0) {
		nni_pipe_bump_error(p->pipe, rv);
		// Intentionally we do not queue up another transfer.
		// There's an excellent chance that the pipe is no longer
		// usable, with a partial transfer.
		// The protocol should see this error, and close the
		// pipe itself, we hope.

		while ((aio = nni_list_first(&p->send_q)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
		}
		nni_mtx_unlock(&p->mtx);
		return;
	}

	n = nni_aio_count(tx_aio);
	nni_aio_iov_advance(tx_aio, n);
	if (nni_aio_iov_count(tx_aio) != 0) {
		nng_stream_send(p->conn, tx_aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	aio = nni_list_first(&p->send_q);
	nni_aio_list_remove(aio);
	ipc_pipe_send_start(p);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_pipe_bump_tx(p->pipe, n);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_sync(aio, 0, n);
}

static void
ipc_pipe_recv_cb(void *arg)
{
	ipc_pipe *p = arg;
	nni_aio  *aio;
	int       rv;
	size_t    n;
	nni_msg  *msg;
	nni_aio  *rx_aio = &p->rx_aio;

	nni_mtx_lock(&p->mtx);

	if ((rv = nni_aio_result(rx_aio)) != 0) {
		// Error on receive.  This has to cause an error back
		// to the user.  Also, if we had an allocated rx_msg, lets
		// toss it.
		goto error;
	}

	n = nni_aio_count(rx_aio);
	nni_aio_iov_advance(rx_aio, n);
	if (nni_aio_iov_count(rx_aio) != 0) {
		// Was this a partial read?  If so then resubmit for the rest.
		nng_stream_recv(p->conn, rx_aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	// If we don't have a message yet, we were reading the message
	// header, which is just the length.  This tells us the size of the
	// message to allocate and how much more to expect.
	if (p->rx_msg == NULL) {
		uint64_t len;

		// Check to make sure we got msg type 1.
		if (p->rx_head[0] != 1) {
			rv = NNG_EPROTO;
			goto error;
		}

		// We should have gotten a message header.
		NNI_GET64(p->rx_head + 1, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if ((len > p->rcv_max) && (p->rcv_max > 0)) {
			int  pid;
			char peer[64] = "";
			if (nng_stream_get_int(
			        p->conn, NNG_OPT_PEER_PID, &pid) == 0) {
				snprintf(peer, sizeof(peer), " from PID %lu",
				    (unsigned long) pid);
			}
			nng_log_warn("NNG-RCVMAX",
			    "Oversize message of %lu bytes (> %lu) "
			    "on socket<%u> pipe<%u> from IPC%s",
			    (unsigned long) len, (unsigned long) p->rcv_max,
			    nni_pipe_sock_id(p->pipe), nni_pipe_id(p->pipe),
			    peer);
			rv = NNG_EMSGSIZE;
			goto error;
		}

		// Note that all IO on this pipe is blocked behind this
		// allocation.  We could possibly look at using a separate
		// lock for the read side in the future, so that we allow
		// transmits to proceed normally.  In practice this is
		// unlikely to be much of an issue though.
		if ((rv = nni_msg_alloc(&p->rx_msg, (size_t) len)) != 0) {
			goto error;
		}

		if (len != 0) {
			nni_iov iov;
			// Submit the rest of the data for a read -- we want to
			// read the entire message now.
			iov.iov_buf = nni_msg_body(p->rx_msg);
			iov.iov_len = (size_t) len;

			nni_aio_set_iov(rx_aio, 1, &iov);
			nng_stream_recv(p->conn, rx_aio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// Otherwise, we got a message read completely.  Let the user know the
	// good news.

	aio = nni_list_first(&p->recv_q);
	nni_aio_list_remove(aio);
	msg       = p->rx_msg;
	p->rx_msg = NULL;
	n         = nni_msg_len(msg);
	nni_pipe_bump_rx(p->pipe, n);
	ipc_pipe_recv_start(p);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_sync(aio, 0, n);
	return;

error:
	while ((aio = nni_list_first(&p->recv_q)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	msg       = p->rx_msg;
	p->rx_msg = NULL;
	nni_pipe_bump_error(p->pipe, rv);
	// Intentionally, we do not queue up another receive.
	// The protocol should notice this error and close the pipe.
	nni_mtx_unlock(&p->mtx);

	nni_msg_free(msg);
}

static void
ipc_pipe_send_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ipc_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// If this is being sent, then cancel the pending transfer.
	// The callback on the tx_aio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&p->send_q) == aio) {
		nni_aio_abort(&p->tx_aio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);

	nni_aio_finish_error(aio, rv);
}

static void
ipc_pipe_send_start(ipc_pipe *p)
{
	nni_aio *aio;
	nni_msg *msg;
	int      nio;
	nni_iov  iov[3];
	uint64_t len;

	if (p->closed) {
		while ((aio = nni_list_first(&p->send_q)) != NULL) {
			nni_list_remove(&p->send_q, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}
	if ((aio = nni_list_first(&p->send_q)) == NULL) {
		return;
	}

	// This runs to send the message.
	msg = nni_aio_get_msg(aio);
	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	p->tx_head[0] = 1; // message type, 1.
	NNI_PUT64(p->tx_head + 1, len);

	nio            = 0;
	iov[0].iov_buf = p->tx_head;
	iov[0].iov_len = sizeof(p->tx_head);
	nio++;
	if (nni_msg_header_len(msg) > 0) {
		iov[nio].iov_buf = nni_msg_header(msg);
		iov[nio].iov_len = nni_msg_header_len(msg);
		nio++;
	}
	if (nni_msg_len(msg) > 0) {
		iov[nio].iov_buf = nni_msg_body(msg);
		iov[nio].iov_len = nni_msg_len(msg);
		nio++;
	}
	nni_aio_set_iov(&p->tx_aio, nio, iov);
	nng_stream_send(p->conn, &p->tx_aio);
}

static void
ipc_pipe_send(void *arg, nni_aio *aio)
{
	ipc_pipe *p = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&p->mtx);
	if (!nni_aio_start(aio, ipc_pipe_send_cancel, p)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_list_append(&p->send_q, aio);
	if (nni_list_first(&p->send_q) == aio) {
		ipc_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ipc_pipe_recv_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ipc_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// If receive in progress, then cancel the pending transfer.
	// The callback on the rx_aio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&p->recv_q) == aio) {
		nni_aio_abort(&p->rx_aio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);
	nni_aio_finish_error(aio, rv);
}

static void
ipc_pipe_recv_start(ipc_pipe *p)
{
	nni_iov iov;
	NNI_ASSERT(p->rx_msg == NULL);

	if (p->closed) {
		nni_aio *aio;
		while ((aio = nni_list_first(&p->recv_q)) != NULL) {
			nni_list_remove(&p->recv_q, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}
	if (nni_list_empty(&p->recv_q)) {
		return;
	}

	// Schedule a read of the IPC header.
	iov.iov_buf = p->rx_head;
	iov.iov_len = sizeof(p->rx_head);
	nni_aio_set_iov(&p->rx_aio, 1, &iov);

	nng_stream_recv(p->conn, &p->rx_aio);
}

static void
ipc_pipe_recv(void *arg, nni_aio *aio)
{
	ipc_pipe *p = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&p->mtx);
	if (p->closed) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, ipc_pipe_recv_cancel, p)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}

	nni_list_append(&p->recv_q, aio);
	if (nni_list_first(&p->recv_q) == aio) {
		ipc_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
ipc_pipe_peer(void *arg)
{
	ipc_pipe *p = arg;

	return (p->peer);
}

static void
ipc_pipe_start(ipc_pipe *p, nng_stream *conn, ipc_ep *ep)
{
	nni_iov iov;

	p->conn  = conn;
	p->ep    = ep;
	p->proto = ep->proto;

	p->tx_head[0] = 0;
	p->tx_head[1] = 'S';
	p->tx_head[2] = 'P';
	p->tx_head[3] = 0;
	NNI_PUT16(&p->tx_head[4], p->proto);
	NNI_PUT16(&p->tx_head[6], 0);

	p->got_rx_head  = 0;
	p->got_tx_head  = 0;
	p->want_rx_head = 8;
	p->want_tx_head = 8;
	iov.iov_len     = 8;
	iov.iov_buf     = &p->tx_head[0];
	nni_aio_set_iov(&p->neg_aio, 1, &iov);
	nni_list_append(&ep->nego_pipes, p);

	nni_aio_set_timeout(&p->neg_aio, 10000); // 10 sec timeout to negotiate
	nng_stream_send(p->conn, &p->neg_aio);
}

static void
ipc_ep_close(void *arg)
{
	ipc_ep   *ep = arg;
	ipc_pipe *p;

	nni_aio_close(&ep->time_aio);
	nni_aio_close(&ep->conn_aio);

	nni_mtx_lock(&ep->mtx);
	ep->closed = true;
	if (ep->dialer != NULL) {
		nng_stream_dialer_close(ep->dialer);
	}
	if (ep->listener != NULL) {
		nng_stream_listener_close(ep->listener);
	}
	if (ep->user_aio != NULL) {
		nni_aio_finish_error(ep->user_aio, NNG_ECLOSED);
		ep->user_aio = NULL;
	}
	NNI_LIST_FOREACH (&ep->nego_pipes, p) {
		nni_pipe_close(p->pipe);
	}
	NNI_LIST_FOREACH (&ep->wait_pipes, p) {
		nni_pipe_close(p->pipe);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ipc_ep_stop(void *arg)
{
	ipc_ep *ep = arg;

	nni_aio_stop(&ep->time_aio);
	nni_aio_stop(&ep->conn_aio);
	nng_stream_dialer_stop(ep->dialer);
	nng_stream_listener_stop(ep->listener);
}

static void
ipc_ep_fini(void *arg)
{
	ipc_ep *ep = arg;

	nni_aio_fini(&ep->time_aio);
	nni_aio_fini(&ep->conn_aio);
	nng_stream_dialer_free(ep->dialer);
	nng_stream_listener_free(ep->listener);
	nni_mtx_fini(&ep->mtx);
}

static void
ipc_ep_timer_cb(void *arg)
{
	ipc_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	if (nni_aio_result(&ep->time_aio) == 0) {
		nng_stream_listener_accept(ep->listener, &ep->conn_aio);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ipc_ep_accept_cb(void *arg)
{
	ipc_ep     *ep  = arg;
	nni_aio    *aio = &ep->conn_aio;
	ipc_pipe   *p;
	int         rv;
	nng_stream *conn;

	nni_mtx_lock(&ep->mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);

	if (ep->closed) {
		rv = NNG_ECLOSED;
		nng_stream_free(conn);
		goto error;
	}
	rv = nni_pipe_alloc_listener((void **) &p, ep->nlistener);
	if (rv != 0) {
		nng_stream_free(conn);
		goto error;
	}

	ipc_pipe_start(p, conn, ep);

	nng_stream_listener_accept(ep->listener, &ep->conn_aio);
	nni_mtx_unlock(&ep->mtx);
	return;

error:
	// When an error here occurs, let's send a notice up to the consumer.
	// That way it can be reported properly.
	if ((aio = ep->user_aio) != NULL) {
		ep->user_aio = NULL;
		nni_aio_finish_error(aio, rv);
	}

	switch (rv) {
	case NNG_ECLOSED:
	case NNG_ESTOPPED:
		break;
	case NNG_ENOMEM:
	case NNG_ENOFILES:
		nng_sleep_aio(10, &ep->time_aio);
		break;

	default:
		nng_stream_listener_accept(ep->listener, &ep->conn_aio);
		break;
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ipc_ep_dial_cb(void *arg)
{
	ipc_ep     *ep  = arg;
	nni_aio    *aio = &ep->conn_aio;
	nni_aio    *uaio;
	ipc_pipe   *p;
	int         rv;
	nng_stream *conn;

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

	ipc_pipe_start(p, conn, ep);
	nni_mtx_unlock(&ep->mtx);
	return;

error:
	// Error connecting.  We need to pass this straight back
	// to the user.
	if ((uaio = ep->user_aio) != NULL) {
		ep->user_aio = NULL;
		nni_aio_finish_error(uaio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ipc_ep_init(ipc_ep *ep, nni_sock *sock, void (*conn_cb)(void *))
{
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->wait_pipes, ipc_pipe, node);
	NNI_LIST_INIT(&ep->nego_pipes, ipc_pipe, node);
	nni_aio_init(&ep->conn_aio, conn_cb, ep);
	nni_aio_init(&ep->time_aio, ipc_ep_timer_cb, ep);

	ep->proto = nni_sock_proto_id(sock);

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
ipc_ep_init_dialer(void *arg, nng_url *url, nni_dialer *dialer)
{
	ipc_ep   *ep = arg;
	nng_err   rv;
	nni_sock *sock = nni_dialer_sock(dialer);

	ipc_ep_init(ep, sock, ipc_ep_dial_cb);
	ep->ndialer = dialer;

	if ((rv = nng_stream_dialer_alloc_url(&ep->dialer, url)) != NNG_OK) {
		return (rv);
	}
#ifdef NNG_ENABLE_STATS
	nni_dialer_add_stat(dialer, &ep->st_rcv_max);
#endif
	return (NNG_OK);
}

static nng_err
ipc_ep_init_listener(void *arg, nng_url *url, nni_listener *listener)
{
	ipc_ep   *ep = arg;
	nng_err   rv;
	nni_sock *sock = nni_listener_sock(listener);

	ipc_ep_init(ep, sock, ipc_ep_accept_cb);
	ep->nlistener = listener;

	if ((rv = nng_stream_listener_alloc_url(&ep->listener, url)) !=
	    NNG_OK) {
		return (rv);
	}

#ifdef NNG_ENABLE_STATS
	nni_listener_add_stat(listener, &ep->st_rcv_max);
#endif
	return (NNG_OK);
}

static void
ipc_ep_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ipc_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (aio == ep->user_aio) {
		ep->user_aio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ipc_ep_connect(void *arg, nni_aio *aio)
{
	ipc_ep *ep = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (ep->user_aio != NULL) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}

	if (!nni_aio_start(aio, ipc_ep_cancel, ep)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	ep->user_aio = aio;
	nng_stream_dialer_dial(ep->dialer, &ep->conn_aio);
	nni_mtx_unlock(&ep->mtx);
}

static nng_err
ipc_ep_get_recv_max_sz(void *arg, void *v, size_t *szp, nni_type t)
{
	ipc_ep *ep = arg;
	nng_err rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcv_max, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static nng_err
ipc_ep_set_recv_max_sz(void *arg, const void *v, size_t sz, nni_type t)
{
	ipc_ep *ep = arg;
	size_t  val;
	nng_err rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == NNG_OK) {

		nni_mtx_lock(&ep->mtx);
		ep->rcv_max = val;
		nni_mtx_unlock(&ep->mtx);
#ifdef NNG_ENABLE_STATS
		nni_stat_set_value(&ep->st_rcv_max, val);
#endif
	}
	return (rv);
}

static nng_err
ipc_ep_bind(void *arg, nng_url *url)
{
	ipc_ep *ep = arg;
	nng_err rv;
	NNI_ARG_UNUSED(url);

	nni_mtx_lock(&ep->mtx);
	rv = nng_stream_listener_listen(ep->listener);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static void
ipc_ep_accept(void *arg, nni_aio *aio)
{
	ipc_ep *ep = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (ep->user_aio != NULL) {
		nni_aio_finish_error(aio, NNG_EBUSY);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (!nni_aio_start(aio, ipc_ep_cancel, ep)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	ep->user_aio = aio;
	if (!ep->started) {
		ep->started = true;
		nng_stream_listener_accept(ep->listener, &ep->conn_aio);
	} else {
		ipc_ep_match(ep);
	}

	nni_mtx_unlock(&ep->mtx);
}

static nng_err
ipc_pipe_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ipc_pipe *p = arg;

	return (nni_stream_get(p->conn, name, buf, szp, t));
}

static size_t
ipc_pipe_size(void)
{
	return (sizeof(ipc_pipe));
}

static nni_sp_pipe_ops ipc_tran_pipe_ops = {
	.p_size   = ipc_pipe_size,
	.p_init   = ipc_pipe_init,
	.p_fini   = ipc_pipe_fini,
	.p_stop   = ipc_pipe_stop,
	.p_send   = ipc_pipe_send,
	.p_recv   = ipc_pipe_recv,
	.p_close  = ipc_pipe_close,
	.p_peer   = ipc_pipe_peer,
	.p_getopt = ipc_pipe_get,
};

static const nni_option ipc_ep_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = ipc_ep_get_recv_max_sz,
	    .o_set  = ipc_ep_set_recv_max_sz,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nng_err
ipc_dialer_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ipc_ep *ep = arg;
	nng_err rv;

	rv = nni_getopt(ipc_ep_options, name, ep, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_dialer_get(ep->dialer, name, buf, szp, t);
	}
	return (rv);
}

static nng_err
ipc_dialer_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ipc_ep *ep = arg;
	nng_err rv;

	rv = nni_setopt(ipc_ep_options, name, ep, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_dialer_set(ep->dialer, name, buf, sz, t);
	}
	return (rv);
}

static nng_err
ipc_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ipc_ep *ep = arg;
	nng_err rv;

	rv = nni_getopt(ipc_ep_options, name, ep, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_listener_get(ep->listener, name, buf, szp, t);
	}
	return (rv);
}

static nng_err
ipc_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ipc_ep *ep = arg;
	nng_err rv;

	rv = nni_setopt(ipc_ep_options, name, ep, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_listener_set(ep->listener, name, buf, sz, t);
	}
	return (rv);
}

static nng_err
ipc_listener_set_sec_desc(void *arg, void *pdesc)
{
	ipc_ep *ep = arg;

	return (
	    nng_stream_listener_set_security_descriptor(ep->listener, pdesc));
}

static nni_sp_dialer_ops ipc_dialer_ops = {
	.d_size    = sizeof(ipc_ep),
	.d_init    = ipc_ep_init_dialer,
	.d_fini    = ipc_ep_fini,
	.d_connect = ipc_ep_connect,
	.d_close   = ipc_ep_close,
	.d_stop    = ipc_ep_stop,
	.d_getopt  = ipc_dialer_get,
	.d_setopt  = ipc_dialer_set,
};

static nni_sp_listener_ops ipc_listener_ops = {
	.l_size                    = sizeof(ipc_ep),
	.l_init                    = ipc_ep_init_listener,
	.l_fini                    = ipc_ep_fini,
	.l_bind                    = ipc_ep_bind,
	.l_accept                  = ipc_ep_accept,
	.l_close                   = ipc_ep_close,
	.l_stop                    = ipc_ep_stop,
	.l_getopt                  = ipc_listener_get,
	.l_setopt                  = ipc_listener_set,
	.l_set_security_descriptor = ipc_listener_set_sec_desc,
};

static nni_sp_tran ipc_tran = {
	.tran_scheme   = "ipc",
	.tran_dialer   = &ipc_dialer_ops,
	.tran_listener = &ipc_listener_ops,
	.tran_pipe     = &ipc_tran_pipe_ops,
	.tran_init     = ipc_tran_init,
	.tran_fini     = ipc_tran_fini,
};

#ifdef NNG_PLATFORM_POSIX
static nni_sp_tran ipc_tran_unix = {
	.tran_scheme   = "unix",
	.tran_dialer   = &ipc_dialer_ops,
	.tran_listener = &ipc_listener_ops,
	.tran_pipe     = &ipc_tran_pipe_ops,
	.tran_init     = ipc_tran_init,
	.tran_fini     = ipc_tran_fini,
};
#endif

#ifdef NNG_HAVE_ABSTRACT_SOCKETS
static nni_sp_tran ipc_tran_abstract = {
	.tran_scheme   = "abstract",
	.tran_dialer   = &ipc_dialer_ops,
	.tran_listener = &ipc_listener_ops,
	.tran_pipe     = &ipc_tran_pipe_ops,
	.tran_init     = ipc_tran_init,
	.tran_fini     = ipc_tran_fini,
};
#endif

void
nni_sp_ipc_register(void)
{
	nni_sp_tran_register(&ipc_tran);
#ifdef NNG_PLATFORM_POSIX
	nni_sp_tran_register(&ipc_tran_unix);
#endif
#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	nni_sp_tran_register(&ipc_tran_abstract);
#endif
}
