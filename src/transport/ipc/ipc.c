//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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
#include "ipc.h"

// IPC transport.   Platform specific IPC operations must be
// supplied as well.  Normally the IPC is UNIX domain sockets or
// Windows named pipes.  Other platforms could use other mechanisms,
// but all implementations on the platform must use the same mechanism.

typedef struct ipc_pipe ipc_pipe;
typedef struct ipc_ep   ipc_ep;

// ipc_pipe is one end of an IPC connection.
struct ipc_pipe {
	nni_plat_ipc_pipe *ipp;
	uint16_t           peer;
	uint16_t           proto;
	size_t             rcvmax;
	nni_sockaddr       sa;

	uint8_t txhead[1 + sizeof(uint64_t)];
	uint8_t rxhead[1 + sizeof(uint64_t)];
	size_t  gottxhead;
	size_t  gotrxhead;
	size_t  wanttxhead;
	size_t  wantrxhead;

	nni_list recvq;
	nni_list sendq;
	nni_aio *user_negaio;
	nni_aio *txaio;
	nni_aio *rxaio;
	nni_aio *negaio;
	nni_msg *rxmsg;
	nni_mtx  mtx;
};

struct ipc_ep {
	nni_sockaddr     sa;
	nni_plat_ipc_ep *iep;
	uint16_t         proto;
	size_t           rcvmax;
	nni_aio *        aio;
	nni_aio *        user_aio;
	nni_mtx          mtx;
};

static void ipc_pipe_dosend(ipc_pipe *, nni_aio *);
static void ipc_pipe_dorecv(ipc_pipe *);
static void ipc_pipe_send_cb(void *);
static void ipc_pipe_recv_cb(void *);
static void ipc_pipe_nego_cb(void *);
static void ipc_ep_cb(void *);

static int
ipc_tran_init(void)
{
	return (0);
}

static void
ipc_tran_fini(void)
{
}

static void
ipc_pipe_close(void *arg)
{
	ipc_pipe *pipe = arg;

	nni_aio_close(pipe->rxaio);
	nni_aio_close(pipe->txaio);
	nni_aio_close(pipe->negaio);

	nni_plat_ipc_pipe_close(pipe->ipp);
}

static void
ipc_pipe_stop(void *arg)
{
	ipc_pipe *pipe = arg;

	nni_aio_stop(pipe->rxaio);
	nni_aio_stop(pipe->txaio);
	nni_aio_stop(pipe->negaio);
}

static void
ipc_pipe_fini(void *arg)
{
	ipc_pipe *pipe = arg;

	nni_aio_fini(pipe->rxaio);
	nni_aio_fini(pipe->txaio);
	nni_aio_fini(pipe->negaio);
	if (pipe->ipp != NULL) {
		nni_plat_ipc_pipe_fini(pipe->ipp);
	}
	if (pipe->rxmsg) {
		nni_msg_free(pipe->rxmsg);
	}
	nni_mtx_fini(&pipe->mtx);
	NNI_FREE_STRUCT(pipe);
}

static int
ipc_pipe_init(ipc_pipe **pipep, ipc_ep *ep, void *ipp)
{
	ipc_pipe *p;
	int       rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_init(&p->txaio, ipc_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, ipc_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negaio, ipc_pipe_nego_cb, p)) != 0)) {
		ipc_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->sendq);
	nni_aio_list_init(&p->recvq);

	p->proto              = ep->proto;
	p->rcvmax             = ep->rcvmax;
	p->ipp                = ipp;
	p->sa.s_ipc.sa_family = NNG_AF_IPC;
	p->sa                 = ep->sa;

	*pipep = p;
	return (0);
}

static void
ipc_cancel_start(nni_aio *aio, int rv)
{
	ipc_pipe *pipe = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&pipe->mtx);
	if (pipe->user_negaio != aio) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	pipe->user_negaio = NULL;
	nni_mtx_unlock(&pipe->mtx);

	nni_aio_abort(pipe->negaio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
ipc_pipe_nego_cb(void *arg)
{
	ipc_pipe *pipe = arg;
	nni_aio * aio  = pipe->negaio;
	int       rv;

	nni_mtx_lock(&pipe->mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		goto done;
	}

	// We start transmitting before we receive.
	if (pipe->gottxhead < pipe->wanttxhead) {
		pipe->gottxhead += nni_aio_count(aio);
	} else if (pipe->gotrxhead < pipe->wantrxhead) {
		pipe->gotrxhead += nni_aio_count(aio);
	}

	if (pipe->gottxhead < pipe->wanttxhead) {
		nni_iov iov;
		iov.iov_len = pipe->wanttxhead - pipe->gottxhead;
		iov.iov_buf = &pipe->txhead[pipe->gottxhead];
		nni_aio_set_iov(aio, 1, &iov);
		// send it down...
		nni_plat_ipc_pipe_send(pipe->ipp, aio);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	if (pipe->gotrxhead < pipe->wantrxhead) {
		nni_iov iov;
		iov.iov_len = pipe->wantrxhead - pipe->gotrxhead;
		iov.iov_buf = &pipe->rxhead[pipe->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nni_plat_ipc_pipe_recv(pipe->ipp, aio);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	// We have both sent and received the headers.  Lets check the
	// receive side header.
	if ((pipe->rxhead[0] != 0) || (pipe->rxhead[1] != 'S') ||
	    (pipe->rxhead[2] != 'P') || (pipe->rxhead[3] != 0) ||
	    (pipe->rxhead[6] != 0) || (pipe->rxhead[7] != 0)) {
		rv = NNG_EPROTO;
		goto done;
	}

	NNI_GET16(&pipe->rxhead[4], pipe->peer);

done:
	if ((aio = pipe->user_negaio) != NULL) {
		pipe->user_negaio = NULL;
		nni_aio_finish(aio, rv, 0);
	}
	nni_mtx_unlock(&pipe->mtx);
}

static void
ipc_pipe_send_cb(void *arg)
{
	ipc_pipe *pipe = arg;
	nni_aio * aio;
	nni_aio * txaio = pipe->txaio;
	nni_msg * msg;
	int       rv;
	size_t    n;

	nni_mtx_lock(&pipe->mtx);
	aio = nni_list_first(&pipe->sendq);

	if ((rv = nni_aio_result(txaio)) != 0) {
		// Intentionally we do not queue up another transfer.
		// There's an excellent chance that the pipe is no longer
		// usable, with a partial transfer.
		// The protocol should see this error, and close the
		// pipe itself, we hope.
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&pipe->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	n = nni_aio_count(txaio);
	nni_aio_iov_advance(txaio, n);
	if (nni_aio_iov_count(txaio) != 0) {
		nni_plat_ipc_pipe_send(pipe->ipp, txaio);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	nni_aio_list_remove(aio);
	if (!nni_list_empty(&pipe->sendq)) {
		// schedule next send
		ipc_pipe_dosend(pipe, nni_list_first(&pipe->sendq));
	}
	nni_mtx_unlock(&pipe->mtx);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_synch(aio, 0, n);
}

static void
ipc_pipe_recv_cb(void *arg)
{
	ipc_pipe *pipe = arg;
	nni_aio * aio;
	int       rv;
	size_t    n;
	nni_msg * msg;
	nni_aio * rxaio = pipe->rxaio;

	nni_mtx_lock(&pipe->mtx);
	aio = nni_list_first(&pipe->recvq);

	if ((rv = nni_aio_result(rxaio)) != 0) {
		// Error on receive.  This has to cause an error back
		// to the user.  Also, if we had allocated an rxmsg, lets
		// toss it.
		goto recv_error;
	}

	n = nni_aio_count(rxaio);
	nni_aio_iov_advance(rxaio, n);
	if (nni_aio_iov_count(rxaio) != 0) {
		// Was this a partial read?  If so then resubmit for the rest.
		nni_plat_ipc_pipe_recv(pipe->ipp, rxaio);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	// If we don't have a message yet, we were reading the message
	// header, which is just the length.  This tells us the size of the
	// message to allocate and how much more to expect.
	if (pipe->rxmsg == NULL) {
		uint64_t len;

		// Check to make sure we got msg type 1.
		if (pipe->rxhead[0] != 1) {
			rv = NNG_EPROTO;
			goto recv_error;
		}

		// We should have gotten a message header.
		NNI_GET64(pipe->rxhead + 1, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if ((len > pipe->rcvmax) && (pipe->rcvmax > 0)) {
			rv = NNG_EMSGSIZE;
			goto recv_error;
		}

		// Note that all IO on this pipe is blocked behind this
		// allocation.  We could possibly look at using a separate
		// lock for the read side in the future, so that we allow
		// transmits to proceed normally.  In practice this is
		// unlikely to be much of an issue though.
		if ((rv = nni_msg_alloc(&pipe->rxmsg, (size_t) len)) != 0) {
			goto recv_error;
		}

		if (len != 0) {
			nni_iov iov;
			// Submit the rest of the data for a read -- we want to
			// read the entire message now.
			iov.iov_buf = nni_msg_body(pipe->rxmsg);
			iov.iov_len = (size_t) len;
			nni_aio_set_iov(rxaio, 1, &iov);
			nni_plat_ipc_pipe_recv(pipe->ipp, rxaio);
			nni_mtx_unlock(&pipe->mtx);
			return;
		}
	}

	// Otherwise we got a message read completely.  Let the user know the
	// good news.

	nni_aio_list_remove(aio);
	msg         = pipe->rxmsg;
	pipe->rxmsg = NULL;
	if (!nni_list_empty(&pipe->recvq)) {
		ipc_pipe_dorecv(pipe);
	}
	nni_mtx_unlock(&pipe->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_synch(aio, 0, nni_msg_len(msg));
	return;

recv_error:
	nni_aio_list_remove(aio);
	msg         = pipe->rxmsg;
	pipe->rxmsg = NULL;
	// Intentionally, we do not queue up another receive.
	// The protocol should notice this error and close the pipe.
	nni_mtx_unlock(&pipe->mtx);

	nni_msg_free(msg);
	nni_aio_finish_error(aio, rv);
}

static void
ipc_cancel_tx(nni_aio *aio, int rv)
{
	ipc_pipe *pipe = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&pipe->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	// If this is being sent, then cancel the pending transfer.
	// The callback on the txaio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&pipe->sendq) == aio) {
		nni_aio_abort(pipe->txaio, rv);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&pipe->mtx);
	nni_aio_finish_error(aio, rv);
}

static void
ipc_pipe_dosend(ipc_pipe *pipe, nni_aio *aio)
{
	nni_aio *txaio;
	nni_msg *msg;
	int      niov;
	nni_iov  iov[3];
	uint64_t len;

	// This runs to send the message.
	msg = nni_aio_get_msg(aio);
	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	pipe->txhead[0] = 1; // message type, 1.
	NNI_PUT64(pipe->txhead + 1, len);

	txaio          = pipe->txaio;
	niov           = 0;
	iov[0].iov_buf = pipe->txhead;
	iov[0].iov_len = sizeof(pipe->txhead);
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
	nni_plat_ipc_pipe_send(pipe->ipp, txaio);
}

static void
ipc_pipe_send(void *arg, nni_aio *aio)
{
	ipc_pipe *pipe = arg;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&pipe->mtx);
	if ((rv = nni_aio_schedule(aio, ipc_cancel_tx, pipe)) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&pipe->sendq, aio);
	if (nni_list_first(&pipe->sendq) == aio) {
		ipc_pipe_dosend(pipe, aio);
	}
	nni_mtx_unlock(&pipe->mtx);
}

static void
ipc_cancel_rx(nni_aio *aio, int rv)
{
	ipc_pipe *pipe = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&pipe->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	// If receive in progress, then cancel the pending transfer.
	// The callback on the rxaio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&pipe->recvq) == aio) {
		nni_aio_abort(pipe->rxaio, rv);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&pipe->mtx);
	nni_aio_finish_error(aio, rv);
}

static void
ipc_pipe_dorecv(ipc_pipe *pipe)
{
	nni_aio *rxaio;
	nni_iov  iov;
	NNI_ASSERT(pipe->rxmsg == NULL);

	// Schedule a read of the IPC header.
	rxaio       = pipe->rxaio;
	iov.iov_buf = pipe->rxhead;
	iov.iov_len = sizeof(pipe->rxhead);
	nni_aio_set_iov(rxaio, 1, &iov);

	nni_plat_ipc_pipe_recv(pipe->ipp, rxaio);
}

static void
ipc_pipe_recv(void *arg, nni_aio *aio)
{
	ipc_pipe *pipe = arg;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&pipe->mtx);

	if ((rv = nni_aio_schedule(aio, ipc_cancel_rx, pipe)) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_list_append(&pipe->recvq, aio);
	if (nni_list_first(&pipe->recvq) == aio) {
		ipc_pipe_dorecv(pipe);
	}
	nni_mtx_unlock(&pipe->mtx);
}

static void
ipc_pipe_start(void *arg, nni_aio *aio)
{
	ipc_pipe *pipe = arg;
	nni_aio * negaio;
	nni_iov   iov;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&pipe->mtx);
	if ((rv = nni_aio_schedule(aio, ipc_cancel_start, pipe)) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	pipe->txhead[0] = 0;
	pipe->txhead[1] = 'S';
	pipe->txhead[2] = 'P';
	pipe->txhead[3] = 0;
	NNI_PUT16(&pipe->txhead[4], pipe->proto);
	NNI_PUT16(&pipe->txhead[6], 0);

	pipe->user_negaio = aio;
	pipe->gotrxhead   = 0;
	pipe->gottxhead   = 0;
	pipe->wantrxhead  = 8;
	pipe->wanttxhead  = 8;
	negaio            = pipe->negaio;
	iov.iov_len       = 8;
	iov.iov_buf       = &pipe->txhead[0];
	nni_aio_set_iov(negaio, 1, &iov);
	nni_plat_ipc_pipe_send(pipe->ipp, negaio);
	nni_mtx_unlock(&pipe->mtx);
}

static uint16_t
ipc_pipe_peer(void *arg)
{
	ipc_pipe *pipe = arg;

	return (pipe->peer);
}

static int
ipc_pipe_get_addr(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipc_pipe *p = arg;
	return (nni_copyout_sockaddr(&p->sa, buf, szp, t));
}

static int
ipc_pipe_get_peer_uid(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipc_pipe *p = arg;
	uint64_t  id;
	int       rv;
	if ((rv = nni_plat_ipc_pipe_get_peer_uid(p->ipp, &id)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipc_pipe_get_peer_gid(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipc_pipe *p = arg;
	uint64_t  id;
	int       rv;
	if ((rv = nni_plat_ipc_pipe_get_peer_gid(p->ipp, &id)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipc_pipe_get_peer_pid(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipc_pipe *p = arg;
	uint64_t  id;
	int       rv;
	if ((rv = nni_plat_ipc_pipe_get_peer_pid(p->ipp, &id)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipc_pipe_get_peer_zoneid(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipc_pipe *p = arg;
	uint64_t  id;
	int       rv;
	if ((rv = nni_plat_ipc_pipe_get_peer_zoneid(p->ipp, &id)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static void
ipc_ep_fini(void *arg)
{
	ipc_ep *ep = arg;

	nni_aio_stop(ep->aio);
	nni_plat_ipc_ep_fini(ep->iep);
	nni_aio_fini(ep->aio);
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static int
ipc_ep_init(void **epp, nni_url *url, nni_sock *sock, int mode)
{
	ipc_ep *ep;
	int     rv;
	size_t  sz;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);

	sz                     = sizeof(ep->sa.s_ipc.sa_path);
	ep->sa.s_ipc.sa_family = NNG_AF_IPC;

	if (nni_strlcpy(ep->sa.s_ipc.sa_path, url->u_path, sz) >= sz) {
		ipc_ep_fini(ep);
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_plat_ipc_ep_init(&ep->iep, &ep->sa, mode)) != 0) {
		ipc_ep_fini(ep);
		return (rv);
	}

	if ((rv = nni_aio_init(&ep->aio, ipc_ep_cb, ep)) != 0) {
		ipc_ep_fini(ep);
		return (rv);
	}
	ep->proto = nni_sock_proto_id(sock);

	*epp = ep;
	return (0);
}

static int
ipc_dialer_init(void **epp, nni_url *url, nni_sock *sock)
{
	return (ipc_ep_init(epp, url, sock, NNI_EP_MODE_DIAL));
}

static int
ipc_listener_init(void **epp, nni_url *url, nni_sock *sock)
{
	return (ipc_ep_init(epp, url, sock, NNI_EP_MODE_LISTEN));
}

static void
ipc_ep_close(void *arg)
{
	ipc_ep *ep = arg;

	nni_aio_close(ep->aio);

	nni_mtx_lock(&ep->mtx);
	nni_plat_ipc_ep_close(ep->iep);
	nni_mtx_unlock(&ep->mtx);
}

static int
ipc_ep_bind(void *arg)
{
	ipc_ep *ep = arg;
	int     rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_plat_ipc_ep_listen(ep->iep);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static void
ipc_ep_finish(ipc_ep *ep)
{
	nni_aio * aio;
	int       rv;
	ipc_pipe *pipe = NULL;

	if ((rv = nni_aio_result(ep->aio)) != 0) {
		goto done;
	}
	NNI_ASSERT(nni_aio_get_output(ep->aio, 0) != NULL);

	// Attempt to allocate the parent pipe.  If this fails we'll
	// drop the connection (ENOMEM probably).
	rv = ipc_pipe_init(&pipe, ep, nni_aio_get_output(ep->aio, 0));

done:
	aio          = ep->user_aio;
	ep->user_aio = NULL;

	if ((aio != NULL) && (rv == 0)) {
		NNI_ASSERT(pipe != NULL);
		nni_aio_set_output(aio, 0, pipe);
		nni_aio_finish(aio, 0, 0);
		return;
	}

	if (pipe != NULL) {
		ipc_pipe_fini(pipe);
	}
	if (aio != NULL) {
		NNI_ASSERT(rv != 0);
		nni_aio_finish_error(aio, rv);
	}
}

static void
ipc_ep_cb(void *arg)
{
	ipc_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	ipc_ep_finish(ep);
	nni_mtx_unlock(&ep->mtx);
}

static void
ipc_cancel_ep(nni_aio *aio, int rv)
{
	ipc_ep *ep = nni_aio_get_prov_data(aio);

	NNI_ASSERT(rv != 0);
	nni_mtx_lock(&ep->mtx);
	if (ep->user_aio != aio) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	ep->user_aio = NULL;
	nni_mtx_unlock(&ep->mtx);

	nni_aio_abort(ep->aio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
ipc_ep_accept(void *arg, nni_aio *aio)
{
	ipc_ep *ep = arg;
	int     rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	if ((rv = nni_aio_schedule(aio, ipc_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ep->user_aio = aio;

	nni_plat_ipc_ep_accept(ep->iep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static void
ipc_ep_connect(void *arg, nni_aio *aio)
{
	ipc_ep *ep = arg;
	int     rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	if ((rv = nni_aio_schedule(aio, ipc_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ep->user_aio = aio;

	nni_plat_ipc_ep_connect(ep->iep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static int
ipc_ep_set_recvmaxsz(void *arg, const void *data, size_t sz, nni_opt_type t)
{
	ipc_ep *ep = arg;
	size_t  val;
	int     rv;

	if ((rv = nni_copyin_size(&val, data, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
ipc_ep_chk_recvmaxsz(const void *data, size_t sz, nni_opt_type t)
{
	return (nni_copyin_size(NULL, data, sz, 0, NNI_MAXSZ, t));
}

static int
ipc_ep_get_recvmaxsz(void *arg, void *data, size_t *szp, nni_opt_type t)
{
	ipc_ep *ep = arg;
	int     rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, data, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
ipc_ep_get_addr(void *arg, void *data, size_t *szp, nni_opt_type t)
{
	ipc_ep *ep = arg;
	int     rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_sockaddr(&ep->sa, data, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
ipc_ep_set_perms(void *arg, const void *data, size_t sz, nni_opt_type t)
{
	ipc_ep *ep = arg;
	int     val;
	int     rv;

	// Probably we could further limit this -- most systems don't have
	// meaningful chmod beyond the lower 9 bits.
	if ((rv = nni_copyin_int(&val, data, sz, 0, 0x7FFFFFFF, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		rv = nni_plat_ipc_ep_set_permissions(ep->iep, val);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
ipc_ep_chk_perms(const void *data, size_t sz, nni_opt_type t)
{
	return (nni_copyin_int(NULL, data, sz, 0, 0x7FFFFFFF, t));
}

static int
ipc_ep_set_sec_desc(void *arg, const void *data, size_t sz, nni_opt_type t)
{
	ipc_ep *ep = arg;
	void *  ptr;
	int     rv;

	if ((rv = nni_copyin_ptr(&ptr, data, sz, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		rv = nni_plat_ipc_ep_set_security_descriptor(ep->iep, ptr);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
ipc_ep_chk_sec_desc(const void *data, size_t sz, nni_opt_type t)
{
	return (nni_copyin_ptr(NULL, data, sz, t));
}

static nni_tran_option ipc_pipe_options[] = {
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = ipc_pipe_get_addr,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = ipc_pipe_get_addr,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_UID,
	    .o_type = NNI_TYPE_UINT64,
	    .o_get  = ipc_pipe_get_peer_uid,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_GID,
	    .o_type = NNI_TYPE_UINT64,
	    .o_get  = ipc_pipe_get_peer_gid,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_PID,
	    .o_type = NNI_TYPE_UINT64,
	    .o_get  = ipc_pipe_get_peer_pid,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_ZONEID,
	    .o_type = NNI_TYPE_UINT64,
	    .o_get  = ipc_pipe_get_peer_zoneid,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_pipe_ops ipc_pipe_ops = {
	.p_fini    = ipc_pipe_fini,
	.p_start   = ipc_pipe_start,
	.p_stop    = ipc_pipe_stop,
	.p_send    = ipc_pipe_send,
	.p_recv    = ipc_pipe_recv,
	.p_close   = ipc_pipe_close,
	.p_peer    = ipc_pipe_peer,
	.p_options = ipc_pipe_options,
};

static nni_tran_option ipc_dialer_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = ipc_ep_get_recvmaxsz,
	    .o_set  = ipc_ep_set_recvmaxsz,
	    .o_chk  = ipc_ep_chk_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = ipc_ep_get_addr,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_option ipc_listener_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = ipc_ep_get_recvmaxsz,
	    .o_set  = ipc_ep_set_recvmaxsz,
	    .o_chk  = ipc_ep_chk_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = ipc_ep_get_addr,
	},
	{
	    .o_name = NNG_OPT_IPC_SECURITY_DESCRIPTOR,
	    .o_type = NNI_TYPE_POINTER,
	    .o_get  = NULL,
	    .o_set  = ipc_ep_set_sec_desc,
	    .o_chk  = ipc_ep_chk_sec_desc,
	},
	{
	    .o_name = NNG_OPT_IPC_PERMISSIONS,
	    .o_type = NNI_TYPE_INT32,
	    .o_get  = NULL,
	    .o_set  = ipc_ep_set_perms,
	    .o_chk  = ipc_ep_chk_perms,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_dialer_ops ipc_dialer_ops = {
	.d_init    = ipc_dialer_init,
	.d_fini    = ipc_ep_fini,
	.d_connect = ipc_ep_connect,
	.d_close   = ipc_ep_close,
	.d_options = ipc_dialer_options,
};

static nni_tran_listener_ops ipc_listener_ops = {
	.l_init    = ipc_listener_init,
	.l_fini    = ipc_ep_fini,
	.l_bind    = ipc_ep_bind,
	.l_accept  = ipc_ep_accept,
	.l_close   = ipc_ep_close,
	.l_options = ipc_listener_options,
};

static nni_tran ipc_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "ipc",
	.tran_dialer   = &ipc_dialer_ops,
	.tran_listener = &ipc_listener_ops,
	.tran_pipe     = &ipc_pipe_ops,
	.tran_init     = ipc_tran_init,
	.tran_fini     = ipc_tran_fini,
};

int
nng_ipc_register(void)
{
	return (nni_tran_register(&ipc_tran));
}
