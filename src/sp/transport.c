//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdio.h>
#include <string.h>

static int  sp_pipe_alloc(nni_sp_tran_pipe **);
static void sp_pipe_reap(nni_sp_tran_pipe *);
static void sp_pipe_recv_cancel(nni_aio *, void *, int);
static void sp_pipe_send_cancel(nni_aio *, void *, int);
static void sp_pipe_send_start(nni_sp_tran_pipe *);
static void sp_pipe_recv_start(nni_sp_tran_pipe *);
static void sp_pipe_send_cb(void *);
static void sp_pipe_recv_cb(void *);
static void sp_pipe_nego_cb(void *);
static void sp_pipe_start(nni_sp_tran_pipe *, nng_stream *, nni_sp_tran_ep *);
static int  sp_ep_init(nni_sp_tran_ep **, nng_url *, nni_sock *);
static void sp_ep_accept_cb(void *);
static void sp_ep_timer_cb(void *);
static void sp_ep_dial_cb(void *);

static nni_list   sp_tran_list;
static nni_rwlock sp_tran_lk;

static nni_reap_list sp_ep_reap_list = {
	.rl_offset = offsetof(nni_sp_tran_ep, reap),
	.rl_func   = nni_sp_ep_fini,
};

static nni_reap_list sp_pipe_reap_list = {
	.rl_offset = offsetof(nni_sp_tran_pipe, reap),
	.rl_func   = nni_sp_pipe_fini,
};

void
nni_sp_tran_init(void)
{
}

void
nni_sp_tran_fini(void)
{
}

static int
sp_pipe_alloc(nni_sp_tran_pipe **pipep)
{
	nni_sp_tran_pipe *p;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	nni_aio_init(&p->txaio, sp_pipe_send_cb, p);
	nni_aio_init(&p->rxaio, sp_pipe_recv_cb, p);
	nni_aio_init(&p->negoaio, sp_pipe_nego_cb, p);
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);
	nni_atomic_flag_reset(&p->reaped);

	*pipep = p;

	return (0);
}

int
nni_sp_pipe_init(void *arg, nni_pipe *pipe)
{
	nni_sp_tran_pipe *p = arg;
	p->pipe = pipe;

	return (0);
}

void
nni_sp_pipe_fini(void *arg)
{
	nni_sp_tran_pipe *p = arg;
	nni_sp_tran_ep *  ep;

	nni_sp_pipe_stop(p);
	if ((ep = p->ep) != NULL) {
		nni_mtx_lock(&ep->mtx);
		nni_list_node_remove(&p->node);
		ep->refcnt--;
		if (ep->fini && (ep->refcnt == 0)) {
			nni_reap(&sp_ep_reap_list, ep);
		}
		nni_mtx_unlock(&ep->mtx);
	}
	nni_aio_fini(&p->rxaio);
	nni_aio_fini(&p->txaio);
	nni_aio_fini(&p->negoaio);
	nng_stream_free(p->conn);
	nni_msg_free(p->rxmsg);
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

void
nni_sp_pipe_close(void *arg)
{
	nni_sp_tran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	p->closed = true;
	nni_mtx_unlock(&p->mtx);

	nni_aio_close(&p->rxaio);
	nni_aio_close(&p->txaio);
	nni_aio_close(&p->negoaio);

	nng_stream_close(p->conn);
}

void
nni_sp_pipe_stop(void *arg)
{
	nni_sp_tran_pipe *p = arg;

	nni_aio_stop(&p->rxaio);
	nni_aio_stop(&p->txaio);
	nni_aio_stop(&p->negoaio);
}

static void
sp_pipe_reap(nni_sp_tran_pipe *p)
{
	if (!nni_atomic_flag_test_and_set(&p->reaped)) {
		if (p->conn != NULL) {
			nng_stream_close(p->conn);
		}
		nni_reap(&sp_pipe_reap_list, p);
	}
}

static void
sp_pipe_send_cb(void *arg)
{
	nni_sp_tran_pipe *p = arg;
	int               rv;
	nni_aio *         aio;
	size_t            n;
	nni_msg *         msg;
	nni_aio *         txaio = &p->txaio;

	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_result(txaio)) != 0) {
		nni_pipe_bump_error(p->pipe, rv);
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
	if (nni_aio_iov_count(txaio) > 0) {
		nng_stream_send(p->conn, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	aio = nni_list_first(&p->sendq);
	nni_aio_list_remove(aio);
	sp_pipe_send_start(p);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_pipe_bump_tx(p->pipe, n);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_sync(aio, 0, n);
}

static void
sp_pipe_recv_cb(void *arg)
{
	nni_sp_tran_pipe *p = arg;
	nni_aio *         aio;
	int               rv;
	size_t            n;
	nni_msg *         msg;
	nni_aio *         rxaio = &p->rxaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->recvq);

	if ((rv = nni_aio_result(rxaio)) != 0) {
		goto error;
	}

	n = nni_aio_count(rxaio);
	nni_aio_iov_advance(rxaio, n);
	if (nni_aio_iov_count(rxaio) > 0) {
		// Was this a partial read?  If so then resubmit for the rest.
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
		NNI_GET64(p->rxbuf, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if ((len > p->rcvmax) && (p->rcvmax > 0)) {
			rv = NNG_EMSGSIZE;
			goto error;
		}

		if ((rv = nni_msg_alloc(&p->rxmsg, (size_t) len)) != 0) {
			goto error;
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

	nni_pipe_bump_rx(p->pipe, n);
	sp_pipe_recv_start(p);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_sync(aio, 0, n);
	return;

error:
	while ((aio = nni_list_first(&p->recvq)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	nni_pipe_bump_error(p->pipe, rv);
	// Intentionally, we do not queue up another receive.
	// The protocol should notice this error and close the pipe.
	nni_mtx_unlock(&p->mtx);

	nni_msg_free(msg);
}

static void
sp_pipe_send_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_sp_tran_pipe *p = arg;

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
sp_pipe_send_start(nni_sp_tran_pipe *p)
{
	nni_aio *aio;
	nni_aio *txaio = &p->txaio;
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

	NNI_PUT64(p->txbuf, len);

	niov = 0;
	iov[niov].iov_buf = p->txbuf;
	iov[niov].iov_len = sizeof(p->txbuf);
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

void
nni_sp_pipe_send(void *arg, nni_aio *aio)
{
	nni_sp_tran_pipe *p = arg;
	int               rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, sp_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		sp_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
sp_pipe_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_sp_tran_pipe *p = arg;

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
sp_pipe_recv_start(nni_sp_tran_pipe *p)
{
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
	iov.iov_buf = p->rxbuf;
	iov.iov_len = sizeof(p->rxbuf);
	nni_aio_set_iov(&p->rxaio, 1, &iov);

	nng_stream_recv(p->conn, &p->rxaio);
}

void
nni_sp_pipe_recv(void *arg, nni_aio *aio)
{
	nni_sp_tran_pipe *p = arg;
	int               rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if (p->closed) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, sp_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_list_append(&p->recvq, aio);
	if (nni_list_first(&p->recvq) == aio) {
		sp_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
sp_pipe_start(nni_sp_tran_pipe *p, nng_stream *conn, nni_sp_tran_ep *ep)
{
	nni_iov iov;

	ep->refcnt++;

	p->conn  = conn;
	p->ep    = ep;
	p->proto = ep->proto;

	p->txbuf[0] = 0;
	p->txbuf[1] = 'S';
	p->txbuf[2] = 'P';
	p->txbuf[3] = 0;
	NNI_PUT16(&p->txbuf[4], p->proto);
	NNI_PUT16(&p->txbuf[6], 0);

	p->gotrxhead  = 0;
	p->gottxhead  = 0;
	p->wantrxhead = sizeof(p->rxbuf);
	p->wanttxhead = sizeof(p->txbuf);
	iov.iov_buf   = p->txbuf;
	iov.iov_len   = sizeof(p->txbuf);
	nni_aio_set_iov(&p->negoaio, 1, &iov);
	nni_list_append(&ep->negopipes, p);

	nni_aio_set_timeout(&p->negoaio, 10000); // 10 sec timeout to negotiate
	nng_stream_send(p->conn, &p->negoaio);
}

uint16_t
nni_sp_pipe_peer(void *arg)
{
	nni_sp_tran_pipe *p = arg;

	return (p->peer);
}

int
nni_sp_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	nni_sp_tran_pipe *p = arg;
	return (nni_stream_get(p->conn, name, buf, szp, t));
}

static int
sp_ep_init(nni_sp_tran_ep **epp, nng_url *url, nni_sock *sock)
{
	nni_sp_tran_ep *ep;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->busypipes, nni_sp_tran_pipe, node);
	NNI_LIST_INIT(&ep->waitpipes, nni_sp_tran_pipe, node);
	NNI_LIST_INIT(&ep->negopipes, nni_sp_tran_pipe, node);

	ep->proto = nni_sock_proto_id(sock);
	ep->url   = url;

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

void
nni_sp_ep_fini(void *arg)
{
	nni_sp_tran_ep *ep = arg;

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

void
nni_sp_ep_close(void *arg)
{
	nni_sp_tran_ep *  ep = arg;
	nni_sp_tran_pipe *p;

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
		nni_sp_pipe_close(p);
	}
	NNI_LIST_FOREACH (&ep->waitpipes, p) {
		nni_sp_pipe_close(p);
	}
	NNI_LIST_FOREACH (&ep->busypipes, p) {
		nni_sp_pipe_close(p);
	}
	if (ep->useraio != NULL) {
		nni_aio_finish_error(ep->useraio, NNG_ECLOSED);
		ep->useraio = NULL;
	}

	nni_mtx_unlock(&ep->mtx);
}

int
nni_sp_ep_bind(void *arg)
{
	nni_sp_tran_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nng_stream_listener_listen(ep->listener);
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

void
sp_ep_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_sp_tran_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (ep->useraio == aio) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

void
nni_sp_ep_accept(void *arg, nni_aio *aio)
{
	nni_sp_tran_ep *ep = arg;
	int         rv;

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
	if ((rv = nni_aio_schedule(aio, sp_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ep->useraio = aio;
	if (!ep->started) {
		ep->started = true;
		nng_stream_listener_accept(ep->listener, ep->connaio);
	} else {
		nni_sp_ep_match(ep);
	}
	nni_mtx_unlock(&ep->mtx);
}

void
nni_sp_ep_connect(void *arg, nni_aio *aio)
{
	nni_sp_tran_ep *ep = arg;
	int             rv;

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
	if ((rv = nni_aio_schedule(aio, sp_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ep->useraio = aio;

	nng_stream_dialer_dial(ep->dialer, ep->connaio);
	nni_mtx_unlock(&ep->mtx);
}

void
nni_sp_ep_match(nni_sp_tran_ep *ep)
{
 	nni_aio *         aio;
 	nni_sp_tran_pipe *p;

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
sp_pipe_nego_cb(void *arg)
{
	nni_sp_tran_pipe *p   = arg;
	nni_sp_tran_ep *  ep  = p->ep;
	nni_aio *         aio = &p->negoaio;
	nni_aio *         uaio;
	int               rv;

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
		iov.iov_buf = &p->txbuf[p->gottxhead];
		// send it down...
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_send(p->conn, aio);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxbuf[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_recv(p->conn, aio);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	// We have both sent and received the headers.  Lets check the
	// receive side header.
	if ((p->rxbuf[0] != 0) || (p->rxbuf[1] != 'S') ||
	    (p->rxbuf[2] != 'P') || (p->rxbuf[3] != 0) || (p->rxbuf[6] != 0) ||
	    (p->rxbuf[7] != 0)) {
		rv = NNG_EPROTO;
		goto error;
	}

	NNI_GET16(&p->rxbuf[4], p->peer);

	// We are all ready now.  We put this in the wait list, and
	// then try to run the matcher.
	nni_list_remove(&ep->negopipes, p);
	nni_list_append(&ep->waitpipes, p);

	nni_sp_ep_match(ep);
	nni_mtx_unlock(&ep->mtx);

	return;

error:
	nng_stream_close(p->conn);
	// If we are waiting to negotiate on a client side, then a failure
	// here has to be passed to the user app.
	if ((uaio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(uaio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
	sp_pipe_reap(p);
}

static void
sp_ep_accept_cb(void *arg)
{
	nni_sp_tran_ep *  ep  = arg;
	nni_aio *         aio = ep->connaio;
	nni_sp_tran_pipe *p;
	int               rv;
	nng_stream *      conn;

	nni_mtx_lock(&ep->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);
	if ((rv = sp_pipe_alloc(&p)) != 0) {
		nng_stream_free(conn);
		goto error;
	}

	if (ep->closed) {
		nni_sp_pipe_fini(p);
		nng_stream_free(conn);
		rv = NNG_ECLOSED;
		goto error;
	}
	sp_pipe_start(p, conn, ep);
	nng_stream_listener_accept(ep->listener, ep->connaio);
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
sp_ep_timer_cb(void *arg)
{
	nni_sp_tran_ep *ep = arg;
	if (nni_aio_result(ep->timeaio) == 0) {
		nng_stream_listener_accept(ep->listener, ep->connaio);
	}
}

static void
sp_ep_dial_cb(void *arg)
{
	nni_sp_tran_ep *  ep  = arg;
	nni_aio *         aio = ep->connaio;
	nni_sp_tran_pipe *p;
	int               rv;
	nng_stream *      conn;

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);
	if ((rv = sp_pipe_alloc(&p)) != 0) {
		nng_stream_free(conn);
		goto error;
	}
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_sp_pipe_fini(p);
		nng_stream_free(conn);
		rv = NNG_ECLOSED;
		nni_mtx_unlock(&ep->mtx);
		goto error;
	} else {
		sp_pipe_start(p, conn, ep);
	}
	nni_mtx_unlock(&ep->mtx);
	return;

error:
	// Error connecting.  We need to pass this straight back
	// to the user.
	nni_mtx_lock(&ep->mtx);
	if ((aio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

int
nni_sp_ep_dialer_init(nni_sp_tran_ep **epp, nng_url *url,
    nng_url *dialurl, nni_sock *sock)
{
	nni_sp_tran_ep *ep;
	int             rv;

	if ((rv = sp_ep_init(&ep, url, sock)) != 0) {
		return (rv);
	}

	if (((rv = nni_aio_alloc(&ep->connaio, sp_ep_dial_cb, ep)) != 0) ||
	    ((rv = nng_stream_dialer_alloc_url(&ep->dialer, dialurl)) != 0)) {
		nni_sp_ep_fini(ep);
		return (rv);
	}

	*epp = ep;

	return (0);
}

int
nni_sp_ep_dialer_get(nni_sp_tran_ep *ep, const nni_option *opts,
    const char *name, void *buf, size_t *szp, nni_type t)
{
	int rv;

	rv = nni_getopt(opts, name, ep, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_dialer_get(ep->dialer, name, buf, szp, t);
	}
	return (rv);
}

int
nni_sp_ep_dialer_set(nni_sp_tran_ep *ep, const nni_option *opts,
    const char *name, const void *buf, size_t sz, nni_type t)
{
	int rv;

	rv = nni_setopt(opts, name, ep, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_dialer_set(ep->dialer, name, buf, sz, t);
	}
	return (rv);
}

int
nni_sp_ep_listener_init(nni_sp_tran_ep **epp, nng_url *url, nni_sock *sock)
{
	nni_sp_tran_ep *ep;
	int             rv;

	if ((rv = sp_ep_init(&ep, url, sock)) != 0) {
		return (rv);
	}

	if (((rv = nni_aio_alloc(&ep->connaio, sp_ep_accept_cb, ep)) != 0) ||
	    ((rv = nni_aio_alloc(&ep->timeaio, sp_ep_timer_cb, ep)) != 0) ||
	    ((rv = nng_stream_listener_alloc_url(&ep->listener, url)) != 0)) {
		nni_sp_ep_fini(ep);
		return (rv);
	}

	*epp = ep;

	return (0);
}

int
nni_sp_ep_listener_get(nni_sp_tran_ep *ep, const nni_option *opts,
    const char *name, void *buf, size_t *szp, nni_type t)
{
	int rv;

	rv = nni_getopt(opts, name, ep, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_listener_get(ep->listener, name, buf, szp, t);
	}
	return (rv);
}

int
nni_sp_ep_listener_set(nni_sp_tran_ep *ep, const nni_option *opts,
    const char *name, const void *buf, size_t sz, nni_type t)
{
	int rv;

	rv = nni_setopt(opts, name, ep, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_listener_set(ep->listener, name, buf, sz, t);
	}
	return (rv);
}

int
nni_sp_ep_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	nni_sp_tran_ep *ep = arg;
	char *          s;
	int             rv;
	int             port = 0;

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

int
nni_sp_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	nni_sp_tran_ep *ep = arg;
	int             rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

int
nni_sp_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	nni_sp_tran_ep *ep = arg;
	size_t          val;
	int             rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_sp_tran_pipe *p;
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
		nni_mtx_unlock(&ep->mtx);
#ifdef NNG_ENABLE_STATS
		nni_stat_set_value(&ep->st_rcv_max, val);
#endif
	}
	return (rv);
}

// This parses off the optional source address that this transport uses.
// The special handling of this URL format is quite honestly an historical
// mistake, which we would remove if we could.
int
nni_sp_url_parse_source(nni_url *url, nng_sockaddr *sa, const nni_url *surl,
    int (* getaf)(const nni_url *, int *))
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

	len             = (size_t) (semi - url->u_hostname);
	url->u_hostname = semi + 1;

	if ((rv = getaf(surl, &af)) != 0) {
		return rv;
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

	nni_resolv_ip(src, "0", af, true, sa, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_free(aio);
	nni_free(src, len + 1);
	return (rv);
}

void
nni_sp_tran_register(nni_sp_tran *tran)
{
	nni_rwlock_wrlock(&sp_tran_lk);
	if (!nni_list_node_active(&tran->tran_link)) {
		tran->tran_init();
		nni_list_append(&sp_tran_list, tran);
	}
	nni_rwlock_unlock(&sp_tran_lk);
}

nni_sp_tran *
nni_sp_tran_find(nni_url *url)
{
	// address is of the form "<scheme>://blah..."
	nni_sp_tran *t;

	nni_rwlock_rdlock(&sp_tran_lk);
	NNI_LIST_FOREACH (&sp_tran_list, t) {
		if (strcmp(url->u_scheme, t->tran_scheme) == 0) {
			nni_rwlock_unlock(&sp_tran_lk);
			return (t);
		}
	}
	nni_rwlock_unlock(&sp_tran_lk);
	return (NULL);
}

// nni_sp_tran_sys_init initializes the entire transport subsystem, including
// each individual transport.

#ifdef NNG_TRANSPORT_INPROC
extern void nni_sp_inproc_register(void);
#endif
#ifdef NNG_TRANSPORT_IPC
extern void nni_sp_ipc_register(void);
#endif
#ifdef NNG_TRANSPORT_TCP
extern void nni_sp_tcp_register(void);
#endif
#ifdef NNG_TRANSPORT_TLS
extern void nni_sp_tls_register(void);
#endif
#ifdef NNG_TRANSPORT_WS
extern void nni_sp_ws_register(void);
#endif
#ifdef NNG_TRANSPORT_WSS
extern void nni_sp_wss_register(void);
#endif
#ifdef NNG_TRANSPORT_ZEROTIER
extern void nni_sp_zt_register(void);
#endif

void
nni_sp_tran_sys_init(void)
{
	NNI_LIST_INIT(&sp_tran_list, nni_sp_tran, tran_link);
	nni_rwlock_init(&sp_tran_lk);

#ifdef NNG_TRANSPORT_INPROC
	nni_sp_inproc_register();
#endif
#ifdef NNG_TRANSPORT_IPC
	nni_sp_ipc_register();
#endif
#ifdef NNG_TRANSPORT_TCP
	nni_sp_tcp_register();
#endif
#ifdef NNG_TRANSPORT_TLS
	nni_sp_tls_register();
#endif
#ifdef NNG_TRANSPORT_WS
	nni_sp_ws_register();
#endif
#ifdef NNG_TRANSPORT_WSS
	nni_sp_wss_register();
#endif
#ifdef NNG_TRANSPORT_ZEROTIER
	nni_sp_zt_register();
#endif
}

// nni_sp_tran_sys_fini finalizes the entire transport system, including all
// transports.
void
nni_sp_tran_sys_fini(void)
{
	nni_sp_tran *t;

	while ((t = nni_list_first(&sp_tran_list)) != NULL) {
		nni_list_remove(&sp_tran_list, t);
		t->tran_fini();
	}
	nni_rwlock_fini(&sp_tran_lk);
}
