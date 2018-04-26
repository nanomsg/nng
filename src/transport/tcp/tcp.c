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

// TCP transport.   Platform specific TCP operations must be
// supplied as well.

typedef struct nni_tcp_pipe nni_tcp_pipe;
typedef struct nni_tcp_ep   nni_tcp_ep;

// nni_tcp_pipe is one end of a TCP connection.
struct nni_tcp_pipe {
	nni_plat_tcp_pipe *tpp;
	uint16_t           peer;
	uint16_t           proto;
	size_t             rcvmax;
	bool               nodelay;
	bool               keepalive;

	nni_list recvq;
	nni_list sendq;
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

struct nni_tcp_ep {
	nni_plat_tcp_ep *tep;
	uint16_t         proto;
	size_t           rcvmax;
	bool             nodelay;
	bool             keepalive;
	nni_aio *        aio;
	nni_aio *        user_aio;
	nni_url *        url;
	nng_sockaddr     bsa; // bound addr
	int              mode;
	nni_mtx          mtx;
};

static void nni_tcp_pipe_dosend(nni_tcp_pipe *, nni_aio *);
static void nni_tcp_pipe_dorecv(nni_tcp_pipe *);
static void nni_tcp_pipe_send_cb(void *);
static void nni_tcp_pipe_recv_cb(void *);
static void nni_tcp_pipe_nego_cb(void *);
static void nni_tcp_ep_cb(void *arg);

static int
nni_tcp_tran_init(void)
{
	return (0);
}

static void
nni_tcp_tran_fini(void)
{
}

static void
nni_tcp_pipe_close(void *arg)
{
	nni_tcp_pipe *pipe = arg;

	nni_plat_tcp_pipe_close(pipe->tpp);
}

static void
nni_tcp_pipe_fini(void *arg)
{
	nni_tcp_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negaio);

	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);
	nni_aio_fini(p->negaio);
	if (p->tpp != NULL) {
		nni_plat_tcp_pipe_fini(p->tpp);
	}
	if (p->rxmsg) {
		nni_msg_free(p->rxmsg);
	}

	NNI_FREE_STRUCT(p);
}

static int
nni_tcp_pipe_init(nni_tcp_pipe **pipep, nni_tcp_ep *ep, void *tpp)
{
	nni_tcp_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_init(&p->txaio, nni_tcp_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, nni_tcp_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negaio, nni_tcp_pipe_nego_cb, p)) != 0)) {
		nni_tcp_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);

	p->proto     = ep->proto;
	p->rcvmax    = ep->rcvmax;
	p->nodelay   = ep->nodelay;
	p->keepalive = ep->keepalive;
	p->tpp       = tpp;

	// We try to set the nodelay and keepalive, but if these fail for
	// some reason, its not really fatal to the communication channel.
	// So ignore the return values.
	(void) nni_plat_tcp_pipe_set_nodelay(tpp, p->nodelay);
	(void) nni_plat_tcp_pipe_set_keepalive(tpp, p->keepalive);

	*pipep = p;
	return (0);
}

static void
nni_tcp_cancel_nego(nni_aio *aio, int rv)
{
	nni_tcp_pipe *p = nni_aio_get_prov_data(aio);

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
nni_tcp_pipe_nego_cb(void *arg)
{
	nni_tcp_pipe *p   = arg;
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
		// send it down...
		nni_aio_set_iov(aio, 1, &iov);
		nni_plat_tcp_pipe_send(p->tpp, aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nni_plat_tcp_pipe_recv(p->tpp, aio);
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
	if ((aio = p->user_negaio) != NULL) {
		p->user_negaio = NULL;
		nni_aio_finish(aio, rv, 0);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
nni_tcp_pipe_send_cb(void *arg)
{
	nni_tcp_pipe *p = arg;
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
		nni_plat_tcp_pipe_send(p->tpp, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	nni_aio_list_remove(aio);
	if (!nni_list_empty(&p->sendq)) {
		// schedule next send
		nni_tcp_pipe_dosend(p, nni_list_first(&p->sendq));
	}
	nni_mtx_unlock(&p->mtx);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_synch(aio, 0, n);
}

static void
nni_tcp_pipe_recv_cb(void *arg)
{
	nni_tcp_pipe *p = arg;
	nni_aio *     aio;
	int           rv;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     rxaio = p->rxaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->recvq);

	if ((rv = nni_aio_result(rxaio)) != 0) {
		goto recv_error;
	}

	n = nni_aio_count(rxaio);
	nni_aio_iov_advance(rxaio, n);
	if (nni_aio_iov_count(rxaio) > 0) {
		nni_plat_tcp_pipe_recv(p->tpp, rxaio);
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
		if (len > p->rcvmax) {
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
			nni_plat_tcp_pipe_recv(p->tpp, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// We read a message completely.  Let the user know the good news.
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	if (!nni_list_empty(&p->recvq)) {
		nni_tcp_pipe_dorecv(p);
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
nni_tcp_cancel_tx(nni_aio *aio, int rv)
{
	nni_tcp_pipe *p = nni_aio_get_prov_data(aio);

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
nni_tcp_pipe_dosend(nni_tcp_pipe *p, nni_aio *aio)
{
	nni_aio *txaio;
	nni_msg *msg;
	int      niov;
	nni_iov  iov[3];
	uint64_t len;

	// This runs to send the message.
	msg = nni_aio_get_msg(aio);
	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	NNI_PUT64(p->txlen, len);

	txaio          = p->txaio;
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
	nni_plat_tcp_pipe_send(p->tpp, txaio);
}

static void
nni_tcp_pipe_send(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *p = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	nni_aio_schedule(aio, nni_tcp_cancel_tx, p);
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		nni_tcp_pipe_dosend(p, aio);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
nni_tcp_cancel_rx(nni_aio *aio, int rv)
{
	nni_tcp_pipe *p = nni_aio_get_prov_data(aio);

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
nni_tcp_pipe_dorecv(nni_tcp_pipe *p)
{
	nni_aio *rxaio;
	nni_iov  iov;
	NNI_ASSERT(p->rxmsg == NULL);

	// Schedule a read of the IPC header.
	rxaio       = p->rxaio;
	iov.iov_buf = p->rxlen;
	iov.iov_len = sizeof(p->rxlen);
	nni_aio_set_iov(rxaio, 1, &iov);

	nni_plat_tcp_pipe_recv(p->tpp, rxaio);
}

static void
nni_tcp_pipe_recv(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *p = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	nni_aio_schedule(aio, nni_tcp_cancel_rx, p);
	nni_list_append(&p->recvq, aio);
	if (nni_list_first(&p->recvq) == aio) {
		nni_tcp_pipe_dorecv(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
nni_tcp_pipe_peer(void *arg)
{
	nni_tcp_pipe *p = arg;

	return (p->peer);
}

static int
nni_tcp_pipe_getopt_locaddr(void *arg, void *v, size_t *szp, int typ)
{
	nni_tcp_pipe *p = arg;
	int           rv;
	nni_sockaddr  sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_plat_tcp_pipe_sockname(p->tpp, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, typ);
	}
	return (rv);
}

static int
nni_tcp_pipe_getopt_remaddr(void *arg, void *v, size_t *szp, int typ)
{
	nni_tcp_pipe *p = arg;
	int           rv;
	nni_sockaddr  sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_plat_tcp_pipe_peername(p->tpp, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, typ);
	}
	return (rv);
}

static int
nni_tcp_pipe_getopt_keepalive(void *arg, void *v, size_t *szp, int typ)
{
	nni_tcp_pipe *p = arg;
	return (nni_copyout_bool(p->keepalive, v, szp, typ));
}

static int
nni_tcp_pipe_getopt_nodelay(void *arg, void *v, size_t *szp, int typ)
{
	nni_tcp_pipe *p = arg;
	return (nni_copyout_bool(p->nodelay, v, szp, typ));
}

// Note that the url *must* be in a modifiable buffer.
static void
nni_tcp_pipe_start(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *p = arg;
	nni_aio *     negaio;
	nni_iov       iov;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
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
	nni_aio_schedule(aio, nni_tcp_cancel_nego, p);
	nni_plat_tcp_pipe_send(p->tpp, negaio);
	nni_mtx_unlock(&p->mtx);
}

static void
nni_tcp_ep_fini(void *arg)
{
	nni_tcp_ep *ep = arg;

	nni_aio_stop(ep->aio);
	if (ep->tep != NULL) {
		nni_plat_tcp_ep_fini(ep->tep);
	}
	nni_aio_fini(ep->aio);
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static int
nni_tcp_ep_init(void **epp, nni_url *url, nni_sock *sock, int mode)
{
	nni_tcp_ep * ep;
	int          rv;
	char *       host;
	char *       serv;
	nni_sockaddr rsa, lsa;
	nni_aio *    aio;
	int          passive;

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL)) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		return (rv);
	}

	if (strlen(url->u_hostname) == 0) {
		host = NULL;
	} else {
		host = url->u_hostname;
	}

	if (strlen(url->u_port) == 0) {
		serv = NULL;
	} else {
		serv = url->u_port;
	}
	// XXX: arguably we could defer this part to the point we do a bind
	// or connect!
	if (mode == NNI_EP_MODE_DIAL) {
		passive      = 0;
		lsa.s_family = NNG_AF_UNSPEC;
		nni_aio_set_input(aio, 0, &rsa);
		if ((host == NULL) || (serv == NULL)) {
			nni_aio_fini(aio);
			return (NNG_EADDRINVAL);
		}
	} else {
		passive      = 1;
		rsa.s_family = NNG_AF_UNSPEC;
		nni_aio_set_input(aio, 0, &lsa);
	}

	nni_plat_tcp_resolv(host, serv, NNG_AF_UNSPEC, passive, aio);
	nni_aio_wait(aio);
	if ((rv = nni_aio_result(aio)) != 0) {
		nni_aio_fini(aio);
		return (rv);
	}

	nni_aio_fini(aio);

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);
	ep->url = url;

	if ((rv = nni_plat_tcp_ep_init(&ep->tep, &lsa, &rsa, mode)) != 0) {
		nni_tcp_ep_fini(ep);
		return (rv);
	}

	if ((rv = nni_aio_init(&ep->aio, nni_tcp_ep_cb, ep)) != 0) {
		nni_tcp_ep_fini(ep);
		return (rv);
	}
	ep->proto     = nni_sock_proto(sock);
	ep->mode      = mode;
	ep->nodelay   = true;
	ep->keepalive = false;

	*epp = ep;
	return (0);
}

static void
nni_tcp_ep_close(void *arg)
{
	nni_tcp_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	nni_plat_tcp_ep_close(ep->tep);
	nni_mtx_unlock(&ep->mtx);

	nni_aio_stop(ep->aio);
}

static int
nni_tcp_ep_bind(void *arg)
{
	nni_tcp_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_plat_tcp_ep_listen(ep->tep, &ep->bsa);
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void
nni_tcp_ep_finish(nni_tcp_ep *ep)
{
	nni_aio *     aio;
	int           rv;
	nni_tcp_pipe *pipe = NULL;

	if ((rv = nni_aio_result(ep->aio)) != 0) {
		goto done;
	}
	NNI_ASSERT(nni_aio_get_output(ep->aio, 0) != NULL);

	// Attempt to allocate the parent pipe.  If this fails we'll
	// drop the connection (ENOMEM probably).
	rv = nni_tcp_pipe_init(&pipe, ep, nni_aio_get_output(ep->aio, 0));

done:
	aio          = ep->user_aio;
	ep->user_aio = NULL;

	if ((aio != NULL) && (rv == 0)) {
		nni_aio_set_output(aio, 0, pipe);
		nni_aio_finish(aio, 0, 0);
		return;
	}
	if (pipe != NULL) {
		nni_tcp_pipe_fini(pipe);
	}
	if (aio != NULL) {
		NNI_ASSERT(rv != 0);
		nni_aio_finish_error(aio, rv);
	}
}

static void
nni_tcp_ep_cb(void *arg)
{
	nni_tcp_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	nni_tcp_ep_finish(ep);
	nni_mtx_unlock(&ep->mtx);
}

static void
nni_tcp_cancel_ep(nni_aio *aio, int rv)
{
	nni_tcp_ep *ep = nni_aio_get_prov_data(aio);

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
nni_tcp_ep_accept(void *arg, nni_aio *aio)
{
	nni_tcp_ep *ep = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	nni_aio_schedule(aio, nni_tcp_cancel_ep, ep);
	ep->user_aio = aio;

	nni_plat_tcp_ep_accept(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static void
nni_tcp_ep_connect(void *arg, nni_aio *aio)
{
	nni_tcp_ep *ep = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	nni_aio_schedule(aio, nni_tcp_cancel_ep, ep);
	ep->user_aio = aio;

	nni_plat_tcp_ep_connect(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static int
nni_tcp_ep_setopt_recvmaxsz(void *arg, const void *v, size_t sz, int typ)
{
	nni_tcp_ep *ep = arg;
	size_t      val;
	int         rv;
	rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, typ);
	if ((rv == 0) && (ep != NULL)) {
		ep->rcvmax = val;
	}
	return (rv);
}

static int
nni_tcp_ep_setopt_nodelay(void *arg, const void *v, size_t sz, int typ)
{
	nni_tcp_ep *ep = arg;
	bool        val;
	int         rv;
	rv = nni_copyin_bool(&val, v, sz, typ);
	if ((rv == 0) && (ep != NULL)) {
		ep->nodelay = val;
	}
	return (rv);
}

static int
nni_tcp_ep_getopt_nodelay(void *arg, void *v, size_t *szp, int typ)
{
	nni_tcp_ep *ep = arg;
	return (nni_copyout_bool(ep->nodelay, v, szp, typ));
}

static int
nni_tcp_ep_setopt_keepalive(void *arg, const void *v, size_t sz, int typ)
{
	nni_tcp_ep *ep = arg;
	bool        val;
	int         rv;
	rv = nni_copyin_bool(&val, v, sz, typ);
	if ((rv == 0) && (ep != NULL)) {
		ep->keepalive = val;
	}
	return (rv);
}

static int
nni_tcp_ep_getopt_keepalive(void *arg, void *v, size_t *szp, int typ)
{
	nni_tcp_ep *ep = arg;
	return (nni_copyout_bool(ep->keepalive, v, szp, typ));
}

static int
nni_tcp_ep_getopt_url(void *arg, void *v, size_t *szp, int typ)
{
	nni_tcp_ep *ep = arg;
	char        ustr[128];
	char        ipstr[48];  // max for IPv6 addresses including []
	char        portstr[6]; // max for 16-bit port

	if (ep->mode == NNI_EP_MODE_DIAL) {
		return (nni_copyout_str(ep->url->u_rawurl, v, szp, typ));
	}
	nni_plat_tcp_ntop(&ep->bsa, ipstr, portstr);
	snprintf(ustr, sizeof(ustr), "tcp://%s:%s", ipstr, portstr);
	return (nni_copyout_str(ustr, v, szp, typ));
}

static int
nni_tcp_ep_getopt_recvmaxsz(void *arg, void *v, size_t *szp, int typ)
{
	nni_tcp_ep *ep = arg;
	return (nni_copyout_size(ep->rcvmax, v, szp, typ));
}

static nni_tran_pipe_option nni_tcp_pipe_options[] = {
	{
	    .po_name   = NNG_OPT_LOCADDR,
	    .po_type   = NNI_TYPE_SOCKADDR,
	    .po_getopt = nni_tcp_pipe_getopt_locaddr,
	},
	{
	    .po_name   = NNG_OPT_REMADDR,
	    .po_type   = NNI_TYPE_SOCKADDR,
	    .po_getopt = nni_tcp_pipe_getopt_remaddr,
	},
	{
	    .po_name   = NNG_OPT_TCP_KEEPALIVE,
	    .po_type   = NNI_TYPE_BOOL,
	    .po_getopt = nni_tcp_pipe_getopt_keepalive,
	},
	{
	    .po_name   = NNG_OPT_TCP_NODELAY,
	    .po_type   = NNI_TYPE_BOOL,
	    .po_getopt = nni_tcp_pipe_getopt_nodelay,
	},
	// terminate list
	{
	    .po_name = NULL,
	},
};

static nni_tran_pipe nni_tcp_pipe_ops = {
	.p_fini    = nni_tcp_pipe_fini,
	.p_start   = nni_tcp_pipe_start,
	.p_send    = nni_tcp_pipe_send,
	.p_recv    = nni_tcp_pipe_recv,
	.p_close   = nni_tcp_pipe_close,
	.p_peer    = nni_tcp_pipe_peer,
	.p_options = nni_tcp_pipe_options,
};

static nni_tran_ep_option nni_tcp_ep_options[] = {
	{
	    .eo_name   = NNG_OPT_RECVMAXSZ,
	    .eo_type   = NNI_TYPE_SIZE,
	    .eo_getopt = nni_tcp_ep_getopt_recvmaxsz,
	    .eo_setopt = nni_tcp_ep_setopt_recvmaxsz,
	},
	{
	    .eo_name   = NNG_OPT_URL,
	    .eo_type   = NNI_TYPE_STRING,
	    .eo_getopt = nni_tcp_ep_getopt_url,
	    .eo_setopt = NULL,
	},
	{
	    .eo_name   = NNG_OPT_TCP_NODELAY,
	    .eo_type   = NNI_TYPE_BOOL,
	    .eo_getopt = nni_tcp_ep_getopt_nodelay,
	    .eo_setopt = nni_tcp_ep_setopt_nodelay,
	},
	{
	    .eo_name   = NNG_OPT_TCP_KEEPALIVE,
	    .eo_type   = NNI_TYPE_BOOL,
	    .eo_getopt = nni_tcp_ep_getopt_keepalive,
	    .eo_setopt = nni_tcp_ep_setopt_keepalive,
	},
	// terminate list
	{
	    .eo_name = NULL,
	},
};

static nni_tran_ep nni_tcp_ep_ops = {
	.ep_init    = nni_tcp_ep_init,
	.ep_fini    = nni_tcp_ep_fini,
	.ep_connect = nni_tcp_ep_connect,
	.ep_bind    = nni_tcp_ep_bind,
	.ep_accept  = nni_tcp_ep_accept,
	.ep_close   = nni_tcp_ep_close,
	.ep_options = nni_tcp_ep_options,
};

static nni_tran nni_tcp_tran = {
	.tran_version = NNI_TRANSPORT_VERSION,
	.tran_scheme  = "tcp",
	.tran_ep      = &nni_tcp_ep_ops,
	.tran_pipe    = &nni_tcp_pipe_ops,
	.tran_init    = nni_tcp_tran_init,
	.tran_fini    = nni_tcp_tran_fini,
};

int
nng_tcp_register(void)
{
	return (nni_tran_register(&nni_tcp_tran));
}
