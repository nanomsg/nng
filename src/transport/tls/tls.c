//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "core/nng_impl.h"

#include "supplemental/tls/tls.h"
#include "tls.h"

// TLS over TCP transport.   Platform specific TCP operations must be
// supplied as well, and uses the supplemental TLS v1.2 code.  It is not
// an accident that this very closely resembles the TCP transport itself.

typedef struct nni_tls_pipe nni_tls_pipe;
typedef struct nni_tls_ep   nni_tls_ep;

// nni_tls_pipe is one end of a TLS connection.
struct nni_tls_pipe {
	nni_plat_tcp_pipe *tcp;
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
	nni_tls *tls;
};

struct nni_tls_ep {
	nni_plat_tcp_ep *tep;
	uint16_t         proto;
	size_t           rcvmax;
	nni_duration     linger;
	int              ipv4only;
	int              authmode;
	nni_aio *        aio;
	nni_aio *        user_aio;
	nni_mtx          mtx;
	nng_tls_config * cfg;
	nni_url *        url;
};

static void nni_tls_pipe_send_cb(void *);
static void nni_tls_pipe_recv_cb(void *);
static void nni_tls_pipe_nego_cb(void *);
static void nni_tls_ep_cb(void *arg);

static int
nni_tls_tran_init(void)
{
	return (0);
}

static void
nni_tls_tran_fini(void)
{
}

static void
nni_tls_pipe_close(void *arg)
{
	nni_tls_pipe *p = arg;

	nni_tls_close(p->tls);
}

static void
nni_tls_pipe_fini(void *arg)
{
	nni_tls_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negaio);

	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);
	nni_aio_fini(p->negaio);

	if (p->tls != NULL) {
		nni_tls_fini(p->tls);
	}
	nni_msg_free(p->rxmsg);
	NNI_FREE_STRUCT(p);
}

static int
nni_tls_pipe_init(nni_tls_pipe **pipep, nni_tls_ep *ep, void *tpp)
{
	nni_tls_pipe *     p;
	nni_plat_tcp_pipe *tcp = tpp;
	int                rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	if (((rv = nni_tls_init(&p->tls, ep->cfg, tcp)) != 0) ||
	    ((rv = nni_aio_init(&p->txaio, nni_tls_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, nni_tls_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negaio, nni_tls_pipe_nego_cb, p)) != 0)) {
		nni_tls_pipe_fini(p);
		return (rv);
	}

	p->proto  = ep->proto;
	p->rcvmax = ep->rcvmax;
	p->tcp    = tcp;

	*pipep = p;
	return (0);
}

static void
nni_tls_cancel_nego(nni_aio *aio, int rv)
{
	nni_tls_pipe *p = aio->a_prov_data;

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
nni_tls_pipe_nego_cb(void *arg)
{
	nni_tls_pipe *p   = arg;
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
		nni_tls_send(p->tls, aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		aio->a_niov           = 1;
		aio->a_iov[0].iov_len = p->wantrxhead - p->gotrxhead;
		aio->a_iov[0].iov_buf = &p->rxlen[p->gotrxhead];
		nni_tls_recv(p->tls, aio);
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
nni_tls_pipe_send_cb(void *arg)
{
	nni_tls_pipe *p = arg;
	int           rv;
	nni_aio *     aio;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     txaio = p->txaio;

	nni_mtx_lock(&p->mtx);
	if ((aio = p->user_txaio) == NULL) {
		nni_mtx_unlock(&p->mtx);
		return;
	}

	if ((rv = nni_aio_result(txaio)) != 0) {
		p->user_txaio = NULL;
		nni_mtx_unlock(&p->mtx);
		msg = nni_aio_get_msg(aio);
		nni_aio_set_msg(aio, NULL);
		nni_msg_free(msg);
		nni_aio_finish_error(aio, rv);
		return;
	}

	n = nni_aio_count(txaio);
	while (n) {
		NNI_ASSERT(txaio->a_niov != 0);
		if (txaio->a_iov[0].iov_len > n) {
			txaio->a_iov[0].iov_len -= n;
			txaio->a_iov[0].iov_buf += n;
			break;
		}
		n -= txaio->a_iov[0].iov_len;
		for (int i = 0; i < txaio->a_niov; i++) {
			txaio->a_iov[i] = txaio->a_iov[i + 1];
		}
		txaio->a_niov--;
	}
	if ((txaio->a_niov != 0) && (txaio->a_iov[0].iov_len != 0)) {
		nni_tls_send(p->tls, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	nni_mtx_unlock(&p->mtx);
	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish(aio, 0, n);
}

static void
nni_tls_pipe_recv_cb(void *arg)
{
	nni_tls_pipe *p = arg;
	nni_aio *     aio;
	int           rv;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     rxaio = p->rxaio;

	nni_mtx_lock(&p->mtx);

	if ((aio = p->user_rxaio) == NULL) {
		// Canceled.
		nni_mtx_unlock(&p->mtx);
		return;
	}

	if ((rv = nni_aio_result(p->rxaio)) != 0) {
		goto recv_error;
	}

	n = nni_aio_count(p->rxaio);
	while (n) {
		NNI_ASSERT(rxaio->a_niov != 0);
		if (rxaio->a_iov[0].iov_len > n) {
			rxaio->a_iov[0].iov_len -= n;
			rxaio->a_iov[0].iov_buf += n;
			break;
		}
		n -= rxaio->a_iov[0].iov_len;
		rxaio->a_niov--;
		for (int i = 0; i < rxaio->a_niov; i++) {
			rxaio->a_iov[i] = rxaio->a_iov[i + 1];
		}
	}
	// Was this a partial read?  If so then resubmit for the rest.
	if ((rxaio->a_niov != 0) && (rxaio->a_iov[0].iov_len != 0)) {
		nni_tls_recv(p->tls, rxaio);
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

		if ((rv = nng_msg_alloc(&p->rxmsg, (size_t) len)) != 0) {
			goto recv_error;
		}

		// Submit the rest of the data for a read -- we want to
		// read the entire message now.
		if (len != 0) {
			rxaio->a_iov[0].iov_buf = nni_msg_body(p->rxmsg);
			rxaio->a_iov[0].iov_len = (size_t) len;
			rxaio->a_niov           = 1;

			nni_tls_recv(p->tls, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// We read a message completely.  Let the user know the good news.
	p->user_rxaio = NULL;
	msg           = p->rxmsg;
	p->rxmsg      = NULL;
	nni_mtx_unlock(&p->mtx);
	nni_aio_finish_msg(aio, msg);
	return;

recv_error:
	p->user_rxaio = NULL;
	msg           = p->rxmsg;
	p->rxmsg      = NULL;
	nni_mtx_unlock(&p->mtx);
	nni_msg_free(msg);
	nni_aio_finish_error(aio, rv);
}

static void
nni_tls_cancel_tx(nni_aio *aio, int rv)
{
	nni_tls_pipe *p = aio->a_prov_data;

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
nni_tls_pipe_send(void *arg, nni_aio *aio)
{
	nni_tls_pipe *p   = arg;
	nni_msg *     msg = nni_aio_get_msg(aio);
	uint64_t      len;
	nni_aio *     txaio;
	int           niov;

	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	nni_mtx_lock(&p->mtx);

	if (nni_aio_start(aio, nni_tls_cancel_tx, p) != 0) {
		nni_mtx_unlock(&p->mtx);
		return;
	}

	p->user_txaio = aio;

	NNI_PUT64(p->txlen, len);

	niov                       = 0;
	txaio                      = p->txaio;
	txaio->a_iov[niov].iov_buf = p->txlen;
	txaio->a_iov[niov].iov_len = sizeof(p->txlen);
	niov++;
	if (nni_msg_header_len(msg) > 0) {
		txaio->a_iov[niov].iov_buf = nni_msg_header(msg);
		txaio->a_iov[niov].iov_len = nni_msg_header_len(msg);
		niov++;
	}
	if (nni_msg_len(msg) > 0) {
		txaio->a_iov[niov].iov_buf = nni_msg_body(msg);
		txaio->a_iov[niov].iov_len = nni_msg_len(msg);
		niov++;
	}
	txaio->a_niov = niov;

	nni_tls_send(p->tls, txaio);
	nni_mtx_unlock(&p->mtx);
}

static void
nni_tls_cancel_rx(nni_aio *aio, int rv)
{
	nni_tls_pipe *p = aio->a_prov_data;

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
nni_tls_pipe_recv(void *arg, nni_aio *aio)
{
	nni_tls_pipe *p = arg;
	nni_aio *     rxaio;

	nni_mtx_lock(&p->mtx);

	if (nni_aio_start(aio, nni_tls_cancel_rx, p) != 0) {
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

	nni_tls_recv(p->tls, rxaio);
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
nni_tls_pipe_peer(void *arg)
{
	nni_tls_pipe *p = arg;

	return (p->peer);
}

static int
nni_tls_pipe_getopt_locaddr(void *arg, void *v, size_t *szp)
{
	nni_tls_pipe *p = arg;
	int           rv;
	nng_sockaddr  sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_tls_sockname(p->tls, &sa)) == 0) {
		rv = nni_getopt_sockaddr(&sa, v, szp);
	}
	return (rv);
}

static int
nni_tls_pipe_getopt_remaddr(void *arg, void *v, size_t *szp)
{
	nni_tls_pipe *p = arg;
	int           rv;
	nng_sockaddr  sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_tls_peername(p->tls, &sa)) == 0) {
		rv = nni_getopt_sockaddr(&sa, v, szp);
	}
	return (rv);
}

static void
nni_tls_pipe_start(void *arg, nni_aio *aio)
{
	nni_tls_pipe *p = arg;
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
	if (nni_aio_start(aio, nni_tls_cancel_nego, p) != 0) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_tls_send(p->tls, negaio);
	nni_mtx_unlock(&p->mtx);
}

static void
nni_tls_ep_fini(void *arg)
{
	nni_tls_ep *ep = arg;

	nni_aio_stop(ep->aio);
	if (ep->tep != NULL) {
		nni_plat_tcp_ep_fini(ep->tep);
	}
	if (ep->cfg) {
		nni_tls_config_fini(ep->cfg);
	}
	nni_aio_fini(ep->aio);
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static int
nni_tls_ep_init(void **epp, nni_url *url, nni_sock *sock, int mode)
{
	nni_tls_ep *      ep;
	int               rv;
	char *            host;
	char *            serv;
	nni_sockaddr      rsa, lsa;
	nni_aio *         aio;
	int               passive;
	nng_tls_mode      tlsmode;
	nng_tls_auth_mode authmode;

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

	if (mode == NNI_EP_MODE_DIAL) {
		passive           = 0;
		tlsmode           = NNG_TLS_MODE_CLIENT;
		authmode          = NNG_TLS_AUTH_MODE_REQUIRED;
		lsa.s_un.s_family = NNG_AF_UNSPEC;
		aio->a_addr       = &rsa;
		if ((host == NULL) || (serv == NULL)) {
			nni_aio_fini(aio);
			return (NNG_EADDRINVAL);
		}
	} else {
		passive           = 1;
		tlsmode           = NNG_TLS_MODE_SERVER;
		authmode          = NNG_TLS_AUTH_MODE_NONE;
		rsa.s_un.s_family = NNG_AF_UNSPEC;
		aio->a_addr       = &lsa;
	}

	// XXX: arguably we could defer this part to the point we do a bind
	// or connect!
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

	if (((rv = nni_plat_tcp_ep_init(&ep->tep, &lsa, &rsa, mode)) != 0) ||
	    ((rv = nni_tls_config_init(&ep->cfg, tlsmode)) != 0) ||
	    ((rv = nng_tls_config_auth_mode(ep->cfg, authmode)) != 0) ||
	    ((rv = nni_aio_init(&ep->aio, nni_tls_ep_cb, ep)) != 0)) {
		nni_tls_ep_fini(ep);
		return (rv);
	}
	if ((tlsmode == NNG_TLS_MODE_CLIENT) && (host != NULL)) {
		if ((rv = nng_tls_config_server_name(ep->cfg, host)) != 0) {
			nni_tls_ep_fini(ep);
			return (rv);
		}
	}
	ep->proto    = nni_sock_proto(sock);
	ep->authmode = authmode;

	*epp = ep;
	return (0);
}

static void
nni_tls_ep_close(void *arg)
{
	nni_tls_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	nni_plat_tcp_ep_close(ep->tep);
	nni_mtx_unlock(&ep->mtx);

	nni_aio_stop(ep->aio);
}

static int
nni_tls_ep_bind(void *arg)
{
	nni_tls_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_plat_tcp_ep_listen(ep->tep);
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void
nni_tls_ep_finish(nni_tls_ep *ep)
{
	nni_aio *     aio;
	int           rv;
	nni_tls_pipe *pipe = NULL;

	if ((rv = nni_aio_result(ep->aio)) != 0) {
		goto done;
	}
	NNI_ASSERT(nni_aio_get_pipe(ep->aio) != NULL);

	// Attempt to allocate the parent pipe.  If this fails we'll
	// drop the connection (ENOMEM probably).
	rv = nni_tls_pipe_init(&pipe, ep, nni_aio_get_pipe(ep->aio));

done:
	nni_aio_set_pipe(ep->aio, NULL);
	aio          = ep->user_aio;
	ep->user_aio = NULL;

	if ((aio != NULL) && (rv == 0)) {
		nni_aio_finish_pipe(aio, pipe);
		return;
	}
	if (pipe != NULL) {
		nni_tls_pipe_fini(pipe);
	}
	if (aio != NULL) {
		NNI_ASSERT(rv != 0);
		nni_aio_finish_error(aio, rv);
	}
}

static void
nni_tls_ep_cb(void *arg)
{
	nni_tls_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	nni_tls_ep_finish(ep);
	nni_mtx_unlock(&ep->mtx);
}

static void
nni_tls_cancel_ep(nni_aio *aio, int rv)
{
	nni_tls_ep *ep = aio->a_prov_data;

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
nni_tls_ep_accept(void *arg, nni_aio *aio)
{
	nni_tls_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	if ((rv = nni_aio_start(aio, nni_tls_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	ep->user_aio = aio;

	nni_plat_tcp_ep_accept(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static void
nni_tls_ep_connect(void *arg, nni_aio *aio)
{
	nni_tls_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);

	// If we can't start, then its dying and we can't report either.
	if ((rv = nni_aio_start(aio, nni_tls_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	ep->user_aio = aio;

	nni_plat_tcp_ep_connect(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static int
nni_tls_ep_setopt_recvmaxsz(void *arg, const void *v, size_t sz)
{
	nni_tls_ep *ep = arg;
	if (ep == NULL) {
		return (nni_chkopt_size(v, sz, 0, NNI_MAXSZ));
	}
	return (nni_setopt_size(&ep->rcvmax, v, sz, 0, NNI_MAXSZ));
}

static int
nni_tls_ep_getopt_recvmaxsz(void *arg, void *v, size_t *szp)
{
	nni_tls_ep *ep = arg;
	return (nni_getopt_size(ep->rcvmax, v, szp));
}

static int
nni_tls_ep_setopt_linger(void *arg, const void *v, size_t sz)
{
	nni_tls_ep *ep = arg;
	if (ep == NULL) {
		return (nni_chkopt_ms(v, sz));
	}
	return (nni_setopt_ms(&ep->linger, v, sz));
}

static int
nni_tls_ep_getopt_linger(void *arg, void *v, size_t *szp)
{
	nni_tls_ep *ep = arg;
	return (nni_getopt_ms(ep->linger, v, szp));
}

static int
tls_setopt_config(void *arg, const void *data, size_t sz)
{
	nni_tls_ep *    ep = arg;
	nng_tls_config *cfg, *old;

	if (sz != sizeof(cfg)) {
		return (NNG_EINVAL);
	}
	memcpy(&cfg, data, sz);
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	if (ep == NULL) {
		return (0);
	}
	old = ep->cfg;
	nni_tls_config_hold(cfg);
	ep->cfg = cfg;
	if (old != NULL) {
		nni_tls_config_fini(old);
	}
	return (0);
}

static int
tls_getopt_config(void *arg, void *v, size_t *szp)
{
	nni_tls_ep *ep = arg;
	return (nni_getopt_ptr(ep->cfg, v, szp));
}

static int
tls_setopt_ca_file(void *arg, const void *v, size_t sz)
{
	nni_tls_ep *ep = arg;

	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}
	if (ep == NULL) {
		return (0);
	}
	return (nng_tls_config_ca_file(ep->cfg, v));
}

static int
tls_setopt_auth_mode(void *arg, const void *v, size_t sz)
{
	nni_tls_ep *ep = arg;
	int         mode;
	int         rv;

	rv = nni_setopt_int(
	    &mode, v, sz, NNG_TLS_AUTH_MODE_NONE, NNG_TLS_AUTH_MODE_REQUIRED);
	if ((rv != 0) || (ep == NULL)) {
		return (rv);
	}
	return (nng_tls_config_auth_mode(ep->cfg, mode));
}

static int
tls_setopt_server_name(void *arg, const void *v, size_t sz)
{
	nni_tls_ep *ep = arg;

	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}
	if (ep == NULL) {
		return (0);
	}
	return (nng_tls_config_server_name(ep->cfg, v));
}

static int
tls_setopt_cert_key_file(void *arg, const void *v, size_t sz)
{
	nni_tls_ep *ep = arg;

	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}
	if (ep == NULL) {
		return (0);
	}
	return (nng_tls_config_cert_key_file(ep->cfg, v, NULL));
}

static int
tls_getopt_verified(void *arg, void *v, size_t *szp)
{
	nni_tls_pipe *p = arg;

	return (nni_getopt_int(nni_tls_verified(p->tls) ? 1 : 0, v, szp));
}

static nni_tran_pipe_option nni_tls_pipe_options[] = {
	{ NNG_OPT_LOCADDR, nni_tls_pipe_getopt_locaddr },
	{ NNG_OPT_REMADDR, nni_tls_pipe_getopt_remaddr },
	{ NNG_OPT_TLS_VERIFIED, tls_getopt_verified },
	// terminate list
	{ NULL, NULL }
};

static nni_tran_pipe nni_tls_pipe_ops = {
	.p_fini    = nni_tls_pipe_fini,
	.p_start   = nni_tls_pipe_start,
	.p_send    = nni_tls_pipe_send,
	.p_recv    = nni_tls_pipe_recv,
	.p_close   = nni_tls_pipe_close,
	.p_peer    = nni_tls_pipe_peer,
	.p_options = nni_tls_pipe_options,
};

static nni_tran_ep_option nni_tls_ep_options[] = {
	{
	    .eo_name   = NNG_OPT_RECVMAXSZ,
	    .eo_getopt = nni_tls_ep_getopt_recvmaxsz,
	    .eo_setopt = nni_tls_ep_setopt_recvmaxsz,
	},
	{
	    .eo_name   = NNG_OPT_LINGER,
	    .eo_getopt = nni_tls_ep_getopt_linger,
	    .eo_setopt = nni_tls_ep_setopt_linger,
	},
	{
	    .eo_name   = NNG_OPT_TLS_CONFIG,
	    .eo_getopt = tls_getopt_config,
	    .eo_setopt = tls_setopt_config,
	},
	{
	    .eo_name   = NNG_OPT_TLS_CERT_KEY_FILE,
	    .eo_getopt = NULL,
	    .eo_setopt = tls_setopt_cert_key_file,
	},
	{
	    .eo_name   = NNG_OPT_TLS_CA_FILE,
	    .eo_getopt = NULL,
	    .eo_setopt = tls_setopt_ca_file,
	},
	{
	    .eo_name   = NNG_OPT_TLS_AUTH_MODE,
	    .eo_getopt = NULL,
	    .eo_setopt = tls_setopt_auth_mode,
	},
	{
	    .eo_name   = NNG_OPT_TLS_SERVER_NAME,
	    .eo_getopt = NULL,
	    .eo_setopt = tls_setopt_server_name,
	},
	// terminate list
	{ NULL, NULL, NULL },
};

static nni_tran_ep nni_tls_ep_ops = {
	.ep_init    = nni_tls_ep_init,
	.ep_fini    = nni_tls_ep_fini,
	.ep_connect = nni_tls_ep_connect,
	.ep_bind    = nni_tls_ep_bind,
	.ep_accept  = nni_tls_ep_accept,
	.ep_close   = nni_tls_ep_close,
	.ep_options = nni_tls_ep_options,
};

static nni_tran nni_tls_tran = {
	.tran_version = NNI_TRANSPORT_VERSION,
	.tran_scheme  = "tls+tcp",
	.tran_ep      = &nni_tls_ep_ops,
	.tran_pipe    = &nni_tls_pipe_ops,
	.tran_init    = nni_tls_tran_init,
	.tran_fini    = nni_tls_tran_fini,
};

int
nng_tls_register(void)
{
	return (nni_tran_register(&nni_tls_tran));
}
