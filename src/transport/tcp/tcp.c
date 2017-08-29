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
	char             addr[NNG_MAXADDRLEN + 1];
	nni_plat_tcp_ep *tep;
	uint16_t         proto;
	size_t           rcvmax;
	nni_duration     linger;
	int              ipv4only;
	nni_aio *        aio;
	nni_aio *        user_aio;
	nni_mtx          mtx;
};

static void nni_tcp_pipe_send_cb(void *);
static void nni_tcp_pipe_recv_cb(void *);
static void nni_tcp_pipe_nego_cb(void *);
static void nni_tcp_ep_cb(void *arg);

static int
nni_tcp_tran_chkopt(int o, const void *data, size_t sz)
{
	if (o == nng_optid_recvmaxsz) {
		return (nni_chkopt_size(data, sz, 0, NNI_MAXSZ));
	}
	if (o == nng_optid_linger) {
		return (nni_chkopt_usec(data, sz));
	}
	return (NNG_ENOTSUP);
}

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

	p->proto  = ep->proto;
	p->rcvmax = ep->rcvmax;
	p->tpp    = tpp;
	p->addr   = ep->addr;

	*pipep = p;
	return (0);
}

static void
nni_tcp_cancel_nego(nni_aio *aio, int rv)
{
	nni_tcp_pipe *p = aio->a_prov_data;

	nni_mtx_lock(&p->mtx);
	if (p->user_negaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_negaio = NULL;
	nni_mtx_unlock(&p->mtx);

	nni_aio_cancel(p->negaio, rv);
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
		aio->a_niov           = 1;
		aio->a_iov[0].iov_len = p->wanttxhead - p->gottxhead;
		aio->a_iov[0].iov_buf = &p->txlen[p->gottxhead];
		// send it down...
		nni_plat_tcp_pipe_send(p->tpp, aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		aio->a_niov           = 1;
		aio->a_iov[0].iov_len = p->wantrxhead - p->gotrxhead;
		aio->a_iov[0].iov_buf = &p->rxlen[p->gotrxhead];
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
	size_t        len;

	nni_mtx_lock(&p->mtx);
	if ((aio = p->user_txaio) == NULL) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_txaio = NULL;

	if ((rv = nni_aio_result(p->txaio)) != 0) {
		len = 0;
	} else {
		len = nni_msg_len(aio->a_msg);
		nni_msg_free(nni_aio_get_msg(aio));
		nni_aio_set_msg(aio, NULL);
	}
	nni_aio_finish(aio, 0, len);
	nni_mtx_unlock(&p->mtx);
}

static void
nni_tcp_pipe_recv_cb(void *arg)
{
	nni_tcp_pipe *p = arg;
	nni_aio *     aio;
	int           rv;
	nni_msg *     msg;

	nni_mtx_lock(&p->mtx);

	aio = p->user_rxaio;
	if (aio == NULL) {
		nni_mtx_unlock(&p->mtx);
		return;
	}

	if ((rv = nni_aio_result(p->rxaio)) != 0) {
		// Error on receive.  This has to cause an error back
		// to the user.  Also, if we had allocated an rxmsg, lets
		// toss it.
		if (p->rxmsg != NULL) {
			nni_msg_free(p->rxmsg);
			p->rxmsg = NULL;
		}
		p->user_rxaio = NULL;
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	// If we don't have a message yet, we were reading the TCP message
	// header, which is just the length.  This tells us the size of the
	// message to allocate and how much more to expect.
	if (p->rxmsg == NULL) {
		nni_aio *rxaio;
		uint64_t len;
		// We should have gotten a message header.
		NNI_GET64(p->rxlen, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if (len > p->rcvmax) {
			p->user_rxaio = NULL;
			nni_aio_finish_error(aio, NNG_EMSGSIZE);
			nni_mtx_unlock(&p->mtx);
			return;
		}

		if ((rv = nng_msg_alloc(&p->rxmsg, (size_t) len)) != 0) {
			p->user_rxaio = NULL;
			nni_aio_finish_error(aio, rv);
			nni_mtx_unlock(&p->mtx);
			return;
		}

		// Submit the rest of the data for a read -- we want to
		// read the entire message now.
		rxaio                   = p->rxaio;
		rxaio->a_iov[0].iov_buf = nni_msg_body(p->rxmsg);
		rxaio->a_iov[0].iov_len = nni_msg_len(p->rxmsg);
		rxaio->a_niov           = 1;

		nni_plat_tcp_pipe_recv(p->tpp, rxaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	// We read a message completely.  Let the user know the good news.
	p->user_rxaio = NULL;
	msg           = p->rxmsg;
	p->rxmsg      = NULL;
	nni_aio_finish_msg(aio, msg);
	nni_mtx_unlock(&p->mtx);
}

static void
nni_tcp_cancel_tx(nni_aio *aio, int rv)
{
	nni_tcp_pipe *p = aio->a_prov_data;

	nni_mtx_lock(&p->mtx);
	if (p->user_txaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_txaio = NULL;
	nni_mtx_unlock(&p->mtx);

	// cancel the underlying operation.
	nni_aio_cancel(p->txaio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
nni_tcp_pipe_send(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *p   = arg;
	nni_msg *     msg = nni_aio_get_msg(aio);
	uint64_t      len;
	nni_aio *     txaio;

	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	nni_mtx_lock(&p->mtx);

	if (nni_aio_start(aio, nni_tcp_cancel_tx, p) != 0) {
		nni_mtx_unlock(&p->mtx);
		return;
	}

	p->user_txaio = aio;

	NNI_PUT64(p->txlen, len);

	txaio                   = p->txaio;
	txaio->a_iov[0].iov_buf = p->txlen;
	txaio->a_iov[0].iov_len = sizeof(p->txlen);
	txaio->a_iov[1].iov_buf = nni_msg_header(msg);
	txaio->a_iov[1].iov_len = nni_msg_header_len(msg);
	txaio->a_iov[2].iov_buf = nni_msg_body(msg);
	txaio->a_iov[2].iov_len = nni_msg_len(msg);
	txaio->a_niov           = 3;

	nni_plat_tcp_pipe_send(p->tpp, txaio);
	nni_mtx_unlock(&p->mtx);
}

static void
nni_tcp_cancel_rx(nni_aio *aio, int rv)
{
	nni_tcp_pipe *p = aio->a_prov_data;

	nni_mtx_lock(&p->mtx);
	if (p->user_rxaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_rxaio = NULL;
	nni_mtx_unlock(&p->mtx);

	// cancel the underlying operation.
	nni_aio_cancel(p->rxaio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
nni_tcp_pipe_recv(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *p = arg;
	nni_aio *     rxaio;

	nni_mtx_lock(&p->mtx);

	if (nni_aio_start(aio, nni_tcp_cancel_rx, p) != 0) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_rxaio = aio;

	NNI_ASSERT(p->rxmsg == NULL);

	// Schedule a read of the TCP header.
	rxaio                   = p->rxaio;
	rxaio->a_iov[0].iov_buf = p->rxlen;
	rxaio->a_iov[0].iov_len = sizeof(p->rxlen);
	rxaio->a_niov           = 1;

	nni_plat_tcp_pipe_recv(p->tpp, rxaio);
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
nni_tcp_pipe_peer(void *arg)
{
	nni_tcp_pipe *p = arg;

	return (p->peer);
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
		} else if (*serv != '\0') {
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
	if ((strlen(host) == 0) || (strcmp(host, "*") == 0)) {
		*hostp = NULL;
	} else {
		*hostp = host;
	}
	if (strlen(serv) == 0) {
		*servp = NULL;
	} else {
		*servp = serv;
	}
	// Stash the port in big endian (network) byte order.
	return (0);
}

// Note that the url *must* be in a modifiable buffer.
int
nni_tcp_parse_url(char *url, char **lhost, char **lserv, char **rhost,
    char **rserv, int mode)
{
	char *h1;
	int   rv;

	if (strncmp(url, "tcp://", strlen("tcp://")) != 0) {
		return (NNG_EADDRINVAL);
	}
	url += strlen("tcp://");
	if ((mode == NNI_EP_MODE_DIAL) && ((h1 = strchr(url, ';')) != 0)) {
		// The local address is the first part, the remote address
		// is the second part.
		*h1 = '\0';
		h1++;
		if (((rv = nni_tcp_parse_pair(h1, rhost, rserv)) != 0) ||
		    ((rv = nni_tcp_parse_pair(url, lhost, lserv)) != 0)) {
			return (rv);
		}
		if ((*rserv == NULL) || (*rhost == NULL)) {
			// We have to know where to connect to!
			return (NNG_EADDRINVAL);
		}
	} else if (mode == NNI_EP_MODE_DIAL) {
		*lhost = NULL;
		*lserv = NULL;
		if ((rv = nni_tcp_parse_pair(url, rhost, rserv)) != 0) {
			return (rv);
		}
		if ((*rserv == NULL) || (*rhost == NULL)) {
			// We have to know where to connect to!
			return (NNG_EADDRINVAL);
		}
	} else {
		NNI_ASSERT(mode == NNI_EP_MODE_LISTEN);
		*rhost = NULL;
		*rserv = NULL;
		if ((rv = nni_tcp_parse_pair(url, lhost, lserv)) != 0) {
			return (rv);
		}
		// We have to have a port to listen on!
		if (*lserv == NULL) {
			return (NNG_EADDRINVAL);
		}
	}
	return (0);
}

static void
nni_tcp_pipe_start(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *p = arg;
	nni_aio *     negaio;

	nni_mtx_lock(&p->mtx);
	p->txlen[0] = 0;
	p->txlen[1] = 'S';
	p->txlen[2] = 'P';
	p->txlen[3] = 0;
	NNI_PUT16(&p->txlen[4], p->proto);
	NNI_PUT16(&p->txlen[6], 0);

	p->user_negaio           = aio;
	p->gotrxhead             = 0;
	p->gottxhead             = 0;
	p->wantrxhead            = 8;
	p->wanttxhead            = 8;
	negaio                   = p->negaio;
	negaio->a_niov           = 1;
	negaio->a_iov[0].iov_len = 8;
	negaio->a_iov[0].iov_buf = &p->txlen[0];
	if (nni_aio_start(aio, nni_tcp_cancel_nego, p) != 0) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
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
nni_tcp_ep_init(void **epp, const char *url, nni_sock *sock, int mode)
{
	nni_tcp_ep * ep;
	int          rv;
	char         buf[NNG_MAXADDRLEN + 1];
	char *       rhost;
	char *       rserv;
	char *       lhost;
	char *       lserv;
	nni_sockaddr rsa, lsa;
	nni_aio *    aio;
	int          passive;

	// Make a copy of the url (to allow for destructive operations)
	if (nni_strlcpy(buf, url, sizeof(buf)) >= sizeof(buf)) {
		return (NNG_EADDRINVAL);
	}

	// Parse the URLs first.
	rv = nni_tcp_parse_url(buf, &lhost, &lserv, &rhost, &rserv, mode);
	if (rv != 0) {
		return (rv);
	}
	passive = (mode == NNI_EP_MODE_DIAL ? 0 : 1);

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		return (rv);
	}

	// XXX: arguably we could defer this part to the point we do a bind
	// or connect!

	if ((rhost != NULL) || (rserv != NULL)) {
		aio->a_addr = &rsa;
		nni_plat_tcp_resolv(rhost, rserv, NNG_AF_UNSPEC, passive, aio);
		nni_aio_wait(aio);
		if ((rv = nni_aio_result(aio)) != 0) {
			nni_aio_fini(aio);
			return (rv);
		}
	} else {
		rsa.s_un.s_family = NNG_AF_UNSPEC;
	}

	if ((lhost != NULL) || (lserv != NULL)) {
		aio->a_addr = &lsa;
		nni_plat_tcp_resolv(lhost, lserv, NNG_AF_UNSPEC, passive, aio);
		nni_aio_wait(aio);
		if ((rv = nni_aio_result(aio)) != 0) {
			nni_aio_fini(aio);
			return (rv);
		}
	} else {
		lsa.s_un.s_family = NNG_AF_UNSPEC;
	}
	nni_aio_fini(aio);

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (nni_strlcpy(ep->addr, url, sizeof(ep->addr)) >= sizeof(ep->addr)) {
		NNI_FREE_STRUCT(ep);
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_plat_tcp_ep_init(&ep->tep, &lsa, &rsa, mode)) != 0) {
		NNI_FREE_STRUCT(ep);
		return (rv);
	}

	nni_mtx_init(&ep->mtx);
	if ((rv = nni_aio_init(&ep->aio, nni_tcp_ep_cb, ep)) != 0) {
		nni_tcp_ep_fini(ep);
		return (rv);
	}
	ep->proto = nni_sock_proto(sock);

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

	if ((rv = nni_aio_result(ep->aio)) != 0) {
		goto done;
	}
	NNI_ASSERT(nni_aio_get_pipe(ep->aio) != NULL);

	// Attempt to allocate the parent pipe.  If this fails we'll
	// drop the connection (ENOMEM probably).
	rv = nni_tcp_pipe_init(&pipe, ep, nni_aio_get_pipe(ep->aio));

done:
	nni_aio_set_pipe(ep->aio, NULL);
	aio          = ep->user_aio;
	ep->user_aio = NULL;

	if ((aio != NULL) && (rv == 0)) {
		nni_aio_finish_pipe(aio, pipe);
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
	nni_tcp_ep *ep = aio->a_prov_data;

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
nni_tcp_ep_accept(void *arg, nni_aio *aio)
{
	nni_tcp_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	if ((rv = nni_aio_start(aio, nni_tcp_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	ep->user_aio = aio;

	nni_plat_tcp_ep_accept(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static void
nni_tcp_ep_connect(void *arg, nni_aio *aio)
{
	nni_tcp_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	// If we can't start, then its dying and we can't report either.
	if ((rv = nni_aio_start(aio, nni_tcp_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	ep->user_aio = aio;

	nni_plat_tcp_ep_connect(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static int
nni_tcp_ep_setopt(void *arg, int opt, const void *v, size_t sz)
{
	int         rv = NNG_ENOTSUP;
	nni_tcp_ep *ep = arg;

	if (opt == nng_optid_recvmaxsz) {
		nni_mtx_lock(&ep->mtx);
		rv = nni_setopt_size(&ep->rcvmax, v, sz, 0, NNI_MAXSZ);
		nni_mtx_unlock(&ep->mtx);

	} else if (opt == nng_optid_linger) {
		nni_mtx_lock(&ep->mtx);
		rv = nni_setopt_usec(&ep->linger, v, sz);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
nni_tcp_ep_getopt(void *arg, int opt, void *v, size_t *szp)
{
	int         rv = NNG_ENOTSUP;
	nni_tcp_ep *ep = arg;

	if (opt == nng_optid_recvmaxsz) {
		nni_mtx_lock(&ep->mtx);
		rv = nni_getopt_size(ep->rcvmax, v, szp);
		nni_mtx_unlock(&ep->mtx);

	} else if (opt == nng_optid_linger) {
		nni_mtx_lock(&ep->mtx);
		rv = nni_getopt_usec(ep->linger, v, szp);
		nni_mtx_unlock(&ep->mtx);
	}
	// XXX: add address properties
	return (rv);
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
	.ep_setopt  = nni_tcp_ep_setopt,
	.ep_getopt  = nni_tcp_ep_getopt,
};

// This is the TCP transport linkage, and should be the only global
// symbol in this entire file.
struct nni_tran nni_tcp_tran = {
	.tran_version = NNI_TRANSPORT_VERSION,
	.tran_scheme  = "tcp",
	.tran_ep      = &nni_tcp_ep_ops,
	.tran_pipe    = &nni_tcp_pipe_ops,
	.tran_chkopt  = nni_tcp_tran_chkopt,
	.tran_init    = nni_tcp_tran_init,
	.tran_fini    = nni_tcp_tran_fini,
};
