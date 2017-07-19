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

// TCP transport.   Platform specific TCP operations must be
// supplied as well.

typedef struct nni_tcp_pipe nni_tcp_pipe;
typedef struct nni_tcp_ep   nni_tcp_ep;

// nni_tcp_pipe is one end of a TCP connection.
struct nni_tcp_pipe {
	const char *       addr;
	nni_plat_tcp_pipe *tpp;
	uint16_t           peer;
	uint16_t           proto;
	size_t             rcvmax;

	nni_aio *user_txaio;
	nni_aio *user_rxaio;
	nni_aio *user_negaio;

	uint8_t  txlen[sizeof(uint64_t)];
	uint8_t  rxlen[sizeof(uint64_t)];
	int      gottxhead;
	int      gotrxhead;
	int      wanttxhead;
	int      wantrxhead;
	nni_aio  txaio;
	nni_aio  rxaio;
	nni_aio  negaio;
	nni_msg *rxmsg;
	nni_mtx  mtx;
};

struct nni_tcp_ep {
	char             addr[NNG_MAXADDRLEN + 1];
	nni_plat_tcp_ep *tep;
	int              closed;
	uint16_t         proto;
	size_t           rcvmax;
	int              ipv4only;
	nni_aio          aio;
	nni_aio *        user_aio;
	nni_mtx          mtx;
};

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
	nni_tcp_pipe *pipe = arg;

	nni_aio_fini(&pipe->rxaio);
	nni_aio_fini(&pipe->txaio);
	nni_aio_fini(&pipe->negaio);
	if (pipe->tpp != NULL) {
		nni_plat_tcp_pipe_fini(pipe->tpp);
	}
	if (pipe->rxmsg) {
		nni_msg_free(pipe->rxmsg);
	}

	NNI_FREE_STRUCT(pipe);
}

static int
nni_tcp_pipe_init(nni_tcp_pipe **pipep, nni_tcp_ep *ep, void *tpp)
{
	nni_tcp_pipe *pipe;
	int           rv;

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&pipe->mtx)) != 0) {
		goto fail;
	}
	rv = nni_aio_init(&pipe->txaio, nni_tcp_pipe_send_cb, pipe);
	if (rv != 0) {
		goto fail;
	}
	rv = nni_aio_init(&pipe->rxaio, nni_tcp_pipe_recv_cb, pipe);
	if (rv != 0) {
		goto fail;
	}
	rv = nni_aio_init(&pipe->negaio, nni_tcp_pipe_nego_cb, pipe);
	if (rv != 0) {
		goto fail;
	}
	pipe->proto  = ep->proto;
	pipe->rcvmax = ep->rcvmax;
	pipe->tpp    = tpp;
	pipe->addr   = ep->addr;

	*pipep = pipe;
	return (0);

fail:
	nni_tcp_pipe_fini(pipe);
	return (rv);
}

static void
nni_tcp_cancel_nego(nni_aio *aio)
{
	nni_tcp_pipe *pipe = aio->a_prov_data;

	nni_mtx_lock(&pipe->mtx);
	pipe->user_negaio = NULL;
	nni_mtx_unlock(&pipe->mtx);

	nni_aio_cancel(&pipe->negaio, aio->a_result);
}

static void
nni_tcp_pipe_nego_cb(void *arg)
{
	nni_tcp_pipe *pipe = arg;
	nni_aio *     aio  = &pipe->negaio;
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
		aio->a_iov[0].iov_buf = &pipe->txlen[pipe->gottxhead];
		// send it down...
		nni_plat_tcp_pipe_send(pipe->tpp, aio);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	if (pipe->gotrxhead < pipe->wantrxhead) {
		aio->a_niov           = 1;
		aio->a_iov[0].iov_len = pipe->wantrxhead - pipe->gotrxhead;
		aio->a_iov[0].iov_buf = &pipe->rxlen[pipe->gotrxhead];
		nni_plat_tcp_pipe_recv(pipe->tpp, aio);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	// We have both sent and received the headers.  Lets check the
	// receive side header.
	if ((pipe->rxlen[0] != 0) || (pipe->rxlen[1] != 'S') ||
	    (pipe->rxlen[2] != 'P') || (pipe->rxlen[3] != 0) ||
	    (pipe->rxlen[6] != 0) || (pipe->rxlen[7] != 0)) {
		rv = NNG_EPROTO;
		goto done;
	}

	NNI_GET16(&pipe->rxlen[4], pipe->peer);

done:
	if ((aio = pipe->user_negaio) != NULL) {
		pipe->user_negaio = NULL;
		nni_aio_finish(aio, rv, 0);
	}
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_tcp_pipe_send_cb(void *arg)
{
	nni_tcp_pipe *pipe = arg;
	int           rv;
	nni_aio *     aio;
	size_t        len;

	nni_mtx_lock(&pipe->mtx);
	if ((aio = pipe->user_txaio) == NULL) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	pipe->user_txaio = NULL;

	if ((rv = nni_aio_result(&pipe->txaio)) != 0) {
		len = 0;
	} else {
		len = nni_msg_len(aio->a_msg);
		nni_msg_free(aio->a_msg);
		aio->a_msg = NULL;
	}
	nni_aio_finish(aio, 0, len);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_tcp_pipe_recv_cb(void *arg)
{
	nni_tcp_pipe *pipe = arg;
	nni_aio *     aio;
	int           rv;

	nni_mtx_lock(&pipe->mtx);

	aio = pipe->user_rxaio;
	if (aio == NULL) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	if ((rv = nni_aio_result(&pipe->rxaio)) != 0) {
		// Error on receive.  This has to cause an error back
		// to the user.  Also, if we had allocated an rxmsg, lets
		// toss it.
		if (pipe->rxmsg != NULL) {
			nni_msg_free(pipe->rxmsg);
			pipe->rxmsg = NULL;
		}
		pipe->user_rxaio = NULL;
		nni_aio_finish(aio, rv, 0);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	// If we don't have a message yet, we were reading the TCP message
	// header, which is just the length.  This tells us the size of the
	// message to allocate and how much more to expect.
	if (pipe->rxmsg == NULL) {
		uint64_t len;
		// We should have gotten a message header.
		NNI_GET64(pipe->rxlen, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if (len > pipe->rcvmax) {
			pipe->user_rxaio = NULL;
			nni_aio_finish(aio, NNG_EMSGSIZE, 0);
			nni_mtx_unlock(&pipe->mtx);
			return;
		}

		if ((rv = nng_msg_alloc(&pipe->rxmsg, (size_t) len)) != 0) {
			pipe->user_rxaio = NULL;
			nni_aio_finish(aio, rv, 0);
			nni_mtx_unlock(&pipe->mtx);
			return;
		}

		// Submit the rest of the data for a read -- we want to
		// read the entire message now.
		pipe->rxaio.a_iov[0].iov_buf = nni_msg_body(pipe->rxmsg);
		pipe->rxaio.a_iov[0].iov_len = nni_msg_len(pipe->rxmsg);
		pipe->rxaio.a_niov           = 1;

		nni_plat_tcp_pipe_recv(pipe->tpp, &pipe->rxaio);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	// Otherwise we got a message read completely.  Let the user know the
	// good news.
	pipe->user_rxaio = NULL;
	aio->a_msg       = pipe->rxmsg;
	pipe->rxmsg      = NULL;
	nni_aio_finish(aio, 0, nni_msg_len(aio->a_msg));
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_tcp_cancel_tx(nni_aio *aio)
{
	nni_tcp_pipe *pipe = aio->a_prov_data;

	nni_mtx_lock(&pipe->mtx);
	pipe->user_txaio = NULL;
	nni_mtx_unlock(&pipe->mtx);

	// cancel the underlying operation.
	nni_aio_cancel(&pipe->txaio, aio->a_result);
}

static void
nni_tcp_pipe_send(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *pipe = arg;
	nni_msg *     msg  = aio->a_msg;
	uint64_t      len;

	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	nni_mtx_lock(&pipe->mtx);

	if (nni_aio_start(aio, nni_tcp_cancel_tx, pipe) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	pipe->user_txaio = aio;

	NNI_PUT64(pipe->txlen, len);

	pipe->txaio.a_iov[0].iov_buf = pipe->txlen;
	pipe->txaio.a_iov[0].iov_len = sizeof(pipe->txlen);
	pipe->txaio.a_iov[1].iov_buf = nni_msg_header(msg);
	pipe->txaio.a_iov[1].iov_len = nni_msg_header_len(msg);
	pipe->txaio.a_iov[2].iov_buf = nni_msg_body(msg);
	pipe->txaio.a_iov[2].iov_len = nni_msg_len(msg);
	pipe->txaio.a_niov           = 3;

	nni_plat_tcp_pipe_send(pipe->tpp, &pipe->txaio);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_tcp_cancel_rx(nni_aio *aio)
{
	nni_tcp_pipe *pipe = aio->a_prov_data;

	nni_mtx_lock(&pipe->mtx);
	pipe->user_rxaio = NULL;
	nni_mtx_unlock(&pipe->mtx);

	// cancel the underlying operation.
	nni_aio_cancel(&pipe->rxaio, aio->a_result);
}

static void
nni_tcp_pipe_recv(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *pipe = arg;

	nni_mtx_lock(&pipe->mtx);

	if (nni_aio_start(aio, nni_tcp_cancel_rx, pipe) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	pipe->user_rxaio = aio;

	NNI_ASSERT(pipe->rxmsg == NULL);

	// Schedule a read of the TCP header.
	pipe->rxaio.a_iov[0].iov_buf = pipe->rxlen;
	pipe->rxaio.a_iov[0].iov_len = sizeof(pipe->rxlen);
	pipe->rxaio.a_niov           = 1;

	nni_plat_tcp_pipe_recv(pipe->tpp, &pipe->rxaio);
	nni_mtx_unlock(&pipe->mtx);
}

static uint16_t
nni_tcp_pipe_peer(void *arg)
{
	nni_tcp_pipe *pipe = arg;

	return (pipe->peer);
}

static int
nni_tcp_pipe_getopt(void *arg, int option, void *buf, size_t *szp)
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

static int
nni_tcp_parse_pair(char *pair, char **hostp, char **servp)
{
	char *host, *serv, *end;

	if (pair[0] == '[') {
		host = pair + 1;
		// IP address enclosed ... for IPv6 usually.
		if ((end = strchr(host, ']')) == NULL) {
			return (NNG_EADDRINVAL);
		}
		*end = '\0';
		serv = end + 1;
		if (*serv == ':') {
			serv++;
		} else if (serv != '\0') {
			return (NNG_EADDRINVAL);
		}
	} else {
		host = pair;
		serv = strchr(host, ':');
		if (serv != NULL) {
			*serv = '\0';
			serv++;
		}
	}
	if (hostp != NULL) {
		if ((strlen(host) == 0) || (strcmp(host, "*") == 0)) {
			*hostp = NULL;
		} else {
			*hostp = host;
		}
	}
	if (servp != NULL) {
		if (strlen(serv) == 0) {
			*servp = NULL;
		} else {
			*servp = serv;
		}
	}
	// Stash the port in big endian (network) byte order.
	return (0);
}

// Note that the url *must* be in a modifiable buffer.
int
nni_tcp_parse_url(
    char *url, char **host1, char **serv1, char **host2, char **serv2)
{
	char *h1;
	int   rv;

	if (strncmp(url, "tcp://", strlen("tcp://")) != 0) {
		return (NNG_EADDRINVAL);
	}
	url += strlen("tcp://");
	if ((h1 = strchr(url, ';')) != 0) {
		// For these we want the second part first, because
		// the "primary" address is the remote address, and the
		// "secondary" is the local (bind) address.  This is only
		// used for dial side.
		*h1 = '\0';
		h1++;
		if (((rv = nni_tcp_parse_pair(h1, host1, serv1)) != 0) ||
		    ((rv = nni_tcp_parse_pair(url, host2, serv2)) != 0)) {
			return (rv);
		}
	} else {
		if (host2 != NULL) {
			*host2 = NULL;
		}
		if (serv2 != NULL) {
			*serv2 = NULL;
		}
		if ((rv = nni_tcp_parse_pair(url, host1, serv1)) != 0) {
			return (rv);
		}
	}
	return (0);
}

static void
nni_tcp_pipe_start(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *pipe = arg;

	nni_mtx_lock(&pipe->mtx);
	pipe->txlen[0] = 0;
	pipe->txlen[1] = 'S';
	pipe->txlen[2] = 'P';
	pipe->txlen[3] = 0;
	NNI_PUT16(&pipe->txlen[4], pipe->proto);
	NNI_PUT16(&pipe->txlen[6], 0);

	pipe->user_negaio             = aio;
	pipe->gotrxhead               = 0;
	pipe->gottxhead               = 0;
	pipe->wantrxhead              = 8;
	pipe->wanttxhead              = 8;
	pipe->negaio.a_niov           = 1;
	pipe->negaio.a_iov[0].iov_len = 8;
	pipe->negaio.a_iov[0].iov_buf = &pipe->txlen[0];
	if (nni_aio_start(aio, nni_tcp_cancel_nego, pipe) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	nni_plat_tcp_pipe_send(pipe->tpp, &pipe->negaio);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_tcp_ep_fini(void *arg)
{
	nni_tcp_ep *ep = arg;

	if (ep->tep != NULL) {
		nni_plat_tcp_ep_fini(ep->tep);
	}
	nni_aio_fini(&ep->aio);
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static int
nni_tcp_ep_init(void **epp, const char *url, nni_sock *sock, int mode)
{
	nni_tcp_ep *ep;
	int         rv;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_mtx_init(&ep->mtx)) != 0) ||
	    ((rv = nni_aio_init(&ep->aio, nni_tcp_ep_cb, ep)) != 0) ||
	    ((rv = nni_plat_tcp_ep_init(&ep->tep, url, mode)) != 0)) {
		nni_tcp_ep_fini(ep);
		return (rv);
	}
	ep->closed = 0;
	ep->proto  = nni_sock_proto(sock);
	ep->rcvmax = nni_sock_rcvmaxsz(sock);
	(void) snprintf(ep->addr, sizeof(ep->addr), "%s", url);

	*epp = ep;
	return (0);
}

static void
nni_tcp_ep_close(void *arg)
{
	nni_tcp_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	ep->closed = 1;
	nni_plat_tcp_ep_close(ep->tep);
	nni_mtx_unlock(&ep->mtx);
}

static int
nni_tcp_ep_bind(void *arg)
{
	nni_tcp_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		return (NNG_ECLOSED);
	}

	rv = nni_plat_tcp_ep_listen(ep->tep);
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void
nni_tcp_ep_finish(nni_tcp_ep *ep)
{
	nni_aio *     aio;
	int           rv;
	nni_tcp_pipe *pipe = NULL;

	if ((rv = nni_aio_result(&ep->aio)) != 0) {
		goto done;
	}
	NNI_ASSERT(ep->aio.a_pipe != NULL);

	// Attempt to allocate the parent pipe.  If this fails we'll
	// drop the connection (ENOMEM probably).
	rv = nni_tcp_pipe_init(&pipe, ep, ep->aio.a_pipe);

done:
	ep->aio.a_pipe = NULL;
	aio            = ep->user_aio;
	ep->user_aio   = NULL;

	if ((aio == NULL) || (nni_aio_finish_pipe(aio, rv, pipe) != 0)) {
		if (pipe != NULL) {
			nni_tcp_pipe_fini(pipe);
		}
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
nni_tcp_cancel_ep(nni_aio *aio)
{
	nni_tcp_ep *ep = aio->a_prov_data;

	nni_mtx_lock(&ep->mtx);
	ep->user_aio = NULL;
	nni_mtx_unlock(&ep->mtx);

	nni_aio_cancel(&ep->aio, aio->a_result);
}

static void
nni_tcp_ep_accept(void *arg, nni_aio *aio)
{
	nni_tcp_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	if (ep->closed) {
		nni_aio_finish(aio, NNG_ECLOSED, 0);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	ep->user_aio = aio;

	if ((rv = nni_aio_start(aio, nni_tcp_cancel_ep, ep)) != 0) {
		ep->user_aio = NULL;
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	nni_plat_tcp_ep_accept(ep->tep, &ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static void
nni_tcp_ep_connect(void *arg, nni_aio *aio)
{
	nni_tcp_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_aio_finish(aio, NNG_ECLOSED, 0);
		nni_mtx_unlock(&ep->mtx);
	}
	NNI_ASSERT(ep->user_aio == NULL);
	ep->user_aio = aio;

	// If we can't start, then its dying and we can't report either,
	if ((rv = nni_aio_start(aio, nni_tcp_cancel_ep, ep)) != 0) {
		ep->user_aio = NULL;
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	nni_plat_tcp_ep_connect(ep->tep, &ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static nni_tran_pipe nni_tcp_pipe_ops = {
	.p_fini   = nni_tcp_pipe_fini,
	.p_start  = nni_tcp_pipe_start,
	.p_send   = nni_tcp_pipe_send,
	.p_recv   = nni_tcp_pipe_recv,
	.p_close  = nni_tcp_pipe_close,
	.p_peer   = nni_tcp_pipe_peer,
	.p_getopt = nni_tcp_pipe_getopt,
};

static nni_tran_ep nni_tcp_ep_ops = {
	.ep_init    = nni_tcp_ep_init,
	.ep_fini    = nni_tcp_ep_fini,
	.ep_connect = nni_tcp_ep_connect,
	.ep_bind    = nni_tcp_ep_bind,
	.ep_accept  = nni_tcp_ep_accept,
	.ep_close   = nni_tcp_ep_close,
	.ep_setopt  = NULL,
	.ep_getopt  = NULL,
};

// This is the TCP transport linkage, and should be the only global
// symbol in this entire file.
struct nni_tran nni_tcp_tran = {
	.tran_scheme = "tcp",
	.tran_ep     = &nni_tcp_ep_ops,
	.tran_pipe   = &nni_tcp_pipe_ops,
	.tran_init   = nni_tcp_tran_init,
	.tran_fini   = nni_tcp_tran_fini,
};
