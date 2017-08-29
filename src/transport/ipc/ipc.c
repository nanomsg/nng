//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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

// IPC transport.   Platform specific IPC operations must be
// supplied as well.  Normally the IPC is UNIX domain sockets or
// Windows named pipes.  Other platforms could use other mechanisms.

typedef struct nni_ipc_pipe nni_ipc_pipe;
typedef struct nni_ipc_ep   nni_ipc_ep;

// nni_ipc_pipe is one end of an IPC connection.
struct nni_ipc_pipe {
	const char *       addr;
	nni_plat_ipc_pipe *ipp;
	uint16_t           peer;
	uint16_t           proto;
	size_t             rcvmax;

	uint8_t txhead[1 + sizeof(uint64_t)];
	uint8_t rxhead[1 + sizeof(uint64_t)];
	size_t  gottxhead;
	size_t  gotrxhead;
	size_t  wanttxhead;
	size_t  wantrxhead;

	nni_aio *user_txaio;
	nni_aio *user_rxaio;
	nni_aio *user_negaio;
	nni_aio *txaio;
	nni_aio *rxaio;
	nni_aio *negaio;
	nni_msg *rxmsg;
	nni_mtx  mtx;
};

struct nni_ipc_ep {
	char             addr[NNG_MAXADDRLEN + 1];
	nni_plat_ipc_ep *iep;
	uint16_t         proto;
	size_t           rcvmax;
	nni_aio *        aio;
	nni_aio *        user_aio;
	nni_mtx          mtx;
};

static void nni_ipc_pipe_send_cb(void *);
static void nni_ipc_pipe_recv_cb(void *);
static void nni_ipc_pipe_nego_cb(void *);
static void nni_ipc_ep_cb(void *);

static int
nni_ipc_tran_chkopt(int o, const void *data, size_t sz)
{
	if (o == nng_optid_recvmaxsz) {
		return (nni_chkopt_size(data, sz, 0, NNI_MAXSZ));
	}
	return (NNG_ENOTSUP);
}

static int
nni_ipc_tran_init(void)
{
	return (0);
}

static void
nni_ipc_tran_fini(void)
{
}

static void
nni_ipc_pipe_close(void *arg)
{
	nni_ipc_pipe *pipe = arg;

	nni_plat_ipc_pipe_close(pipe->ipp);
}

static void
nni_ipc_pipe_fini(void *arg)
{
	nni_ipc_pipe *pipe = arg;

	nni_aio_stop(pipe->rxaio);
	nni_aio_stop(pipe->txaio);
	nni_aio_stop(pipe->negaio);

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
nni_ipc_pipe_init(nni_ipc_pipe **pipep, nni_ipc_ep *ep, void *ipp)
{
	nni_ipc_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_init(&p->txaio, nni_ipc_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, nni_ipc_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negaio, nni_ipc_pipe_nego_cb, p)) != 0)) {
		nni_ipc_pipe_fini(p);
		return (rv);
	}

	p->proto  = ep->proto;
	p->rcvmax = ep->rcvmax;
	p->ipp    = ipp;
	p->addr   = ep->addr;

	*pipep = p;
	return (0);
}

static void
nni_ipc_cancel_start(nni_aio *aio, int rv)
{
	nni_ipc_pipe *pipe = aio->a_prov_data;

	nni_mtx_lock(&pipe->mtx);
	if (pipe->user_negaio != aio) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	pipe->user_negaio = NULL;
	nni_mtx_unlock(&pipe->mtx);

	nni_aio_cancel(pipe->negaio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
nni_ipc_pipe_nego_cb(void *arg)
{
	nni_ipc_pipe *pipe = arg;
	nni_aio *     aio  = pipe->negaio;
	int           rv;

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
		aio->a_niov           = 1;
		aio->a_iov[0].iov_len = pipe->wanttxhead - pipe->gottxhead;
		aio->a_iov[0].iov_buf = &pipe->txhead[pipe->gottxhead];
		// send it down...
		nni_plat_ipc_pipe_send(pipe->ipp, aio);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	if (pipe->gotrxhead < pipe->wantrxhead) {
		aio->a_niov           = 1;
		aio->a_iov[0].iov_len = pipe->wantrxhead - pipe->gotrxhead;
		aio->a_iov[0].iov_buf = &pipe->rxhead[pipe->gotrxhead];
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
nni_ipc_pipe_send_cb(void *arg)
{
	nni_ipc_pipe *pipe = arg;
	nni_aio *     aio;
	int           rv;
	size_t        len;

	nni_mtx_lock(&pipe->mtx);
	if ((aio = pipe->user_txaio) == NULL) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	pipe->user_txaio = NULL;
	if ((rv = nni_aio_result(pipe->txaio)) != 0) {
		len = 0;
	} else {
		nni_msg *msg = nni_aio_get_msg(aio);
		len          = nni_msg_len(msg);
		nni_msg_free(msg);
		nni_aio_set_msg(aio, NULL);
	}
	nni_aio_finish(aio, rv, len);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_ipc_pipe_recv_cb(void *arg)
{
	nni_ipc_pipe *pipe = arg;
	nni_aio *     aio;
	int           rv;
	nni_msg *     msg;

	nni_mtx_lock(&pipe->mtx);
	if ((aio = pipe->user_rxaio) == NULL) {
		// aio was canceled
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	if ((rv = nni_aio_result(pipe->rxaio)) != 0) {
		// Error on receive.  This has to cause an error back
		// to the user.  Also, if we had allocated an rxmsg, lets
		// toss it.
		if (pipe->rxmsg != NULL) {
			nni_msg_free(pipe->rxmsg);
			pipe->rxmsg = NULL;
		}
		pipe->user_rxaio = NULL;
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	// If we don't have a message yet, we were reading the TCP message
	// header, which is just the length.  This tells us the size of the
	// message to allocate and how much more to expect.
	if (pipe->rxmsg == NULL) {
		uint64_t len;
		nni_aio *rxaio;

		// Check to make sure we got msg type 1.
		if (pipe->rxhead[0] != 1) {
			nni_aio_finish_error(aio, NNG_EPROTO);
			nni_mtx_unlock(&pipe->mtx);
			return;
		}

		// We should have gotten a message header.
		NNI_GET64(pipe->rxhead + 1, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if (len > pipe->rcvmax) {
			pipe->user_rxaio = NULL;
			nni_aio_finish_error(aio, NNG_EMSGSIZE);
			nni_mtx_unlock(&pipe->mtx);
			return;
		}

		// Note that all IO on this pipe is blocked behind this
		// allocation.  We could possibly look at using a separate
		// lock for the read side in the future, so that we allow
		// transmits to proceed normally.  In practice this is
		// unlikely to be much of an issue though.
		if ((rv = nng_msg_alloc(&pipe->rxmsg, (size_t) len)) != 0) {
			pipe->user_rxaio = NULL;
			nni_aio_finish_error(aio, rv);
			nni_mtx_unlock(&pipe->mtx);
			return;
		}

		// Submit the rest of the data for a read -- we want to
		// read the entire message now.
		rxaio                   = pipe->rxaio;
		rxaio->a_iov[0].iov_buf = nni_msg_body(pipe->rxmsg);
		rxaio->a_iov[0].iov_len = nni_msg_len(pipe->rxmsg);
		rxaio->a_niov           = 1;

		nni_plat_ipc_pipe_recv(pipe->ipp, rxaio);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	// Otherwise we got a message read completely.  Let the user know the
	// good news.
	pipe->user_rxaio = NULL;
	msg              = pipe->rxmsg;
	pipe->rxmsg      = NULL;
	nni_aio_finish_msg(aio, msg);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_ipc_cancel_tx(nni_aio *aio, int rv)
{
	nni_ipc_pipe *pipe = aio->a_prov_data;

	nni_mtx_lock(&pipe->mtx);
	if (pipe->user_txaio != aio) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	pipe->user_txaio = NULL;
	nni_mtx_unlock(&pipe->mtx);

	nni_aio_cancel(pipe->txaio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
nni_ipc_pipe_send(void *arg, nni_aio *aio)
{
	nni_ipc_pipe *pipe = arg;
	nni_msg *     msg  = nni_aio_get_msg(aio);
	uint64_t      len;
	nni_aio *     txaio;

	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	nni_mtx_lock(&pipe->mtx);
	if (nni_aio_start(aio, nni_ipc_cancel_tx, pipe) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	pipe->user_txaio = aio;

	pipe->txhead[0] = 1; // message type, 1.
	NNI_PUT64(pipe->txhead + 1, len);

	txaio                   = pipe->txaio;
	txaio->a_iov[0].iov_buf = pipe->txhead;
	txaio->a_iov[0].iov_len = sizeof(pipe->txhead);
	txaio->a_iov[1].iov_buf = nni_msg_header(msg);
	txaio->a_iov[1].iov_len = nni_msg_header_len(msg);
	txaio->a_iov[2].iov_buf = nni_msg_body(msg);
	txaio->a_iov[2].iov_len = nni_msg_len(msg);
	txaio->a_niov           = 3;

	nni_plat_ipc_pipe_send(pipe->ipp, txaio);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_ipc_cancel_rx(nni_aio *aio, int rv)
{
	nni_ipc_pipe *pipe = aio->a_prov_data;

	nni_mtx_lock(&pipe->mtx);
	if (pipe->user_rxaio != aio) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	pipe->user_rxaio = NULL;
	nni_mtx_unlock(&pipe->mtx);

	nni_aio_cancel(pipe->rxaio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
nni_ipc_pipe_recv(void *arg, nni_aio *aio)
{
	nni_ipc_pipe *pipe = arg;
	nni_aio *     rxaio;

	nni_mtx_lock(&pipe->mtx);

	if (nni_aio_start(aio, nni_ipc_cancel_rx, pipe) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	pipe->user_rxaio = aio;
	NNI_ASSERT(pipe->rxmsg == NULL);

	// Schedule a read of the IPC header.
	rxaio                   = pipe->rxaio;
	rxaio->a_iov[0].iov_buf = pipe->rxhead;
	rxaio->a_iov[0].iov_len = sizeof(pipe->rxhead);
	rxaio->a_niov           = 1;

	nni_plat_ipc_pipe_recv(pipe->ipp, rxaio);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_ipc_pipe_start(void *arg, nni_aio *aio)
{
	nni_ipc_pipe *pipe = arg;
	int           rv;
	nni_aio *     negaio;

	nni_mtx_lock(&pipe->mtx);
	pipe->txhead[0] = 0;
	pipe->txhead[1] = 'S';
	pipe->txhead[2] = 'P';
	pipe->txhead[3] = 0;
	NNI_PUT16(&pipe->txhead[4], pipe->proto);
	NNI_PUT16(&pipe->txhead[6], 0);

	pipe->user_negaio        = aio;
	pipe->gotrxhead          = 0;
	pipe->gottxhead          = 0;
	pipe->wantrxhead         = 8;
	pipe->wanttxhead         = 8;
	negaio                   = pipe->negaio;
	negaio->a_niov           = 1;
	negaio->a_iov[0].iov_len = 8;
	negaio->a_iov[0].iov_buf = &pipe->txhead[0];
	rv = nni_aio_start(aio, nni_ipc_cancel_start, pipe);
	if (rv != 0) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	nni_plat_ipc_pipe_send(pipe->ipp, negaio);
	nni_mtx_unlock(&pipe->mtx);
}

static uint16_t
nni_ipc_pipe_peer(void *arg)
{
	nni_ipc_pipe *pipe = arg;

	return (pipe->peer);
}

static int
nni_ipc_pipe_getopt(void *arg, int option, void *buf, size_t *szp)
{
#if 0
	nni_inproc_pipe *pipe = arg;
	size_t len;

	switch (option) {
	case NNG_OPT_LOCALADDR:
	case NNG_OPT_REMOTEADDR:
		len = strlen(pipe->addr) + 1;
		if (len > *szp) {
			(void) memcpy(buf, pipe->addr, *szp);
		} else {
			(void) memcpy(buf, pipe->addr, len);
		}
		*szp = len;
		return (0);
	}
#endif
	return (NNG_ENOTSUP);
}

static void
nni_ipc_ep_fini(void *arg)
{
	nni_ipc_ep *ep = arg;

	nni_aio_stop(ep->aio);
	nni_plat_ipc_ep_fini(ep->iep);
	nni_aio_fini(ep->aio);
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static int
nni_ipc_ep_init(void **epp, const char *url, nni_sock *sock, int mode)
{
	nni_ipc_ep * ep;
	int          rv;
	nni_sockaddr sa;
	size_t       sz;

	if (strncmp(url, "ipc://", strlen("ipc://")) != 0) {
		return (NNG_EADDRINVAL);
	}
	url += strlen("ipc://");

	sz                       = sizeof(sa.s_un.s_path.sa_path);
	sa.s_un.s_path.sa_family = NNG_AF_IPC;

	if (nni_strlcpy(sa.s_un.s_path.sa_path, url, sz) >= sz) {
		return (NNG_EADDRINVAL);
	}

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}

	if (nni_strlcpy(ep->addr, url, sizeof(ep->addr)) >= sizeof(ep->addr)) {
		NNI_FREE_STRUCT(ep);
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_plat_ipc_ep_init(&ep->iep, &sa, mode)) != 0) {
		NNI_FREE_STRUCT(ep);
		return (rv);
	}

	nni_mtx_init(&ep->mtx);
	nni_aio_init(&ep->aio, nni_ipc_ep_cb, ep);

	ep->proto = nni_sock_proto(sock);

	*epp = ep;
	return (0);
}

static void
nni_ipc_ep_close(void *arg)
{
	nni_ipc_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	nni_plat_ipc_ep_close(ep->iep);
	nni_mtx_unlock(&ep->mtx);

	nni_aio_stop(ep->aio);
}

static int
nni_ipc_ep_bind(void *arg)
{
	nni_ipc_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_plat_ipc_ep_listen(ep->iep);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static void
nni_ipc_ep_finish(nni_ipc_ep *ep)
{
	nni_aio *     aio;
	int           rv;
	nni_ipc_pipe *pipe = NULL;

	if ((rv = nni_aio_result(ep->aio)) != 0) {
		goto done;
	}
	NNI_ASSERT(nni_aio_get_pipe(ep->aio) != NULL);

	// Attempt to allocate the parent pipe.  If this fails we'll
	// drop the connection (ENOMEM probably).
	rv = nni_ipc_pipe_init(&pipe, ep, nni_aio_get_pipe(ep->aio));

done:
	nni_aio_set_pipe(ep->aio, NULL);
	aio          = ep->user_aio;
	ep->user_aio = NULL;

	if ((aio != NULL) && (rv == 0)) {
		NNI_ASSERT(pipe != NULL);
		nni_aio_finish_pipe(aio, pipe);
		return;
	}

	if (pipe != NULL) {
		nni_ipc_pipe_fini(pipe);
	}
	if (aio != NULL) {
		NNI_ASSERT(rv != 0);
		nni_aio_finish_error(aio, rv);
	}
}

static void
nni_ipc_ep_cb(void *arg)
{
	nni_ipc_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	nni_ipc_ep_finish(ep);
	nni_mtx_unlock(&ep->mtx);
}

static void
nni_ipc_cancel_ep(nni_aio *aio, int rv)
{
	nni_ipc_ep *ep = aio->a_prov_data;

	NNI_ASSERT(rv != 0);
	nni_mtx_lock(&ep->mtx);
	if (ep->user_aio != aio) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	ep->user_aio = NULL;
	nni_mtx_unlock(&ep->mtx);

	nni_aio_cancel(ep->aio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
nni_ipc_ep_accept(void *arg, nni_aio *aio)
{
	nni_ipc_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	if ((rv = nni_aio_start(aio, nni_ipc_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	ep->user_aio = aio;

	nni_plat_ipc_ep_accept(ep->iep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static void
nni_ipc_ep_connect(void *arg, nni_aio *aio)
{
	nni_ipc_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	// If we can't start, then its dying and we can't report either.
	if ((rv = nni_aio_start(aio, nni_ipc_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	ep->user_aio = aio;

	nni_plat_ipc_ep_connect(ep->iep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static int
nni_ipc_ep_setopt(void *arg, int opt, const void *v, size_t sz)
{
	int         rv = NNG_ENOTSUP;
	nni_ipc_ep *ep = arg;

	if (opt == nng_optid_recvmaxsz) {
		nni_mtx_lock(&ep->mtx);
		rv = nni_setopt_size(&ep->rcvmax, v, sz, 0, NNI_MAXSZ);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
nni_ipc_ep_getopt(void *arg, int opt, void *v, size_t *szp)
{
	int         rv = NNG_ENOTSUP;
	nni_ipc_ep *ep = arg;

	if (opt == nng_optid_recvmaxsz) {
		nni_mtx_lock(&ep->mtx);
		rv = nni_getopt_size(ep->rcvmax, v, szp);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static nni_tran_pipe nni_ipc_pipe_ops = {
	.p_fini   = nni_ipc_pipe_fini,
	.p_start  = nni_ipc_pipe_start,
	.p_send   = nni_ipc_pipe_send,
	.p_recv   = nni_ipc_pipe_recv,
	.p_close  = nni_ipc_pipe_close,
	.p_peer   = nni_ipc_pipe_peer,
	.p_getopt = nni_ipc_pipe_getopt,
};

static nni_tran_ep nni_ipc_ep_ops = {
	.ep_init    = nni_ipc_ep_init,
	.ep_fini    = nni_ipc_ep_fini,
	.ep_connect = nni_ipc_ep_connect,
	.ep_bind    = nni_ipc_ep_bind,
	.ep_accept  = nni_ipc_ep_accept,
	.ep_close   = nni_ipc_ep_close,
	.ep_setopt  = nni_ipc_ep_setopt,
	.ep_getopt  = nni_ipc_ep_getopt,
};

// This is the IPC transport linkage, and should be the only global
// symbol in this entire file.
struct nni_tran nni_ipc_tran = {
	.tran_version = NNI_TRANSPORT_VERSION,
	.tran_scheme  = "ipc",
	.tran_ep      = &nni_ipc_ep_ops,
	.tran_pipe    = &nni_ipc_pipe_ops,
	.tran_init    = nni_ipc_tran_init,
	.tran_fini    = nni_ipc_tran_fini,
};
