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
#include "supplemental/tls/tls_api.h"
#include "tls.h"

// TLS over TCP transport.   Platform specific TCP operations must be
// supplied as well, and uses the supplemental TLS v1.2 code.  It is not
// an accident that this very closely resembles the TCP transport itself.

typedef struct tls_pipe tls_pipe;
typedef struct tls_ep   tls_ep;

// tls_pipe is one end of a TLS connection.
struct tls_pipe {
	nni_plat_tcp_pipe *tcp;
	uint16_t           peer;
	uint16_t           proto;
	size_t             rcvmax;
	bool               nodelay;
	bool               keepalive;

	nni_list sendq;
	nni_list recvq;
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

struct tls_ep {
	nni_plat_tcp_ep *tep;
	uint16_t         proto;
	size_t           rcvmax;
	int              authmode;
	nni_aio *        aio;
	nni_aio *        user_aio;
	nni_mtx          mtx;
	nng_tls_config * cfg;
	nng_sockaddr     bsa;
	nni_url *        url;
	int              mode;
	bool             nodelay;
	bool             keepalive;
};

static void tls_pipe_dorecv(tls_pipe *);
static void tls_pipe_dosend(tls_pipe *, nni_aio *);
static void tls_pipe_send_cb(void *);
static void tls_pipe_recv_cb(void *);
static void tls_pipe_nego_cb(void *);
static void tls_ep_cb(void *arg);

static int
tls_tran_init(void)
{
	return (0);
}

static void
tls_tran_fini(void)
{
}

static void
tls_pipe_close(void *arg)
{
	tls_pipe *p = arg;

	nni_aio_close(p->rxaio);
	nni_aio_close(p->txaio);
	nni_aio_close(p->negaio);

	nni_tls_close(p->tls);
}

static void
tls_pipe_stop(void *arg)
{
	tls_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negaio);
}

static void
tls_pipe_fini(void *arg)
{
	tls_pipe *p = arg;

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
tls_pipe_init(tls_pipe **pipep, tls_ep *ep, void *tpp)
{
	tls_pipe *         p;
	nni_plat_tcp_pipe *tcp = tpp;
	int                rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	if (((rv = nni_tls_init(&p->tls, ep->cfg, tcp)) != 0) ||
	    ((rv = nni_aio_init(&p->txaio, tls_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, tls_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negaio, tls_pipe_nego_cb, p)) != 0)) {
		tls_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);

	p->proto     = ep->proto;
	p->rcvmax    = ep->rcvmax;
	p->tcp       = tcp;
	p->keepalive = ep->keepalive;
	p->nodelay   = ep->nodelay;

	*pipep = p;
	return (0);
}

static void
tls_cancel_nego(nni_aio *aio, int rv)
{
	tls_pipe *p = nni_aio_get_prov_data(aio);

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
tls_pipe_nego_cb(void *arg)
{
	tls_pipe *p   = arg;
	nni_aio * aio = p->negaio;
	int       rv;

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
		nni_aio_set_iov(aio, 1, &iov);
		// send it down...
		nni_tls_send(p->tls, aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
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
	if (rv == 0) {
		// These can fail. Note that the TLS stack automatically
		// starts out in NODELAY to make the handshake performant.
		(void) nni_tls_set_nodelay(p->tls, p->nodelay);
		(void) nni_tls_set_keepalive(p->tls, p->keepalive);
	}
	if ((aio = p->user_negaio) != NULL) {
		p->user_negaio = NULL;
		nni_aio_finish(aio, rv, 0);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
tls_pipe_send_cb(void *arg)
{
	tls_pipe *p = arg;
	int       rv;
	nni_aio * aio;
	size_t    n;
	nni_msg * msg;
	nni_aio * txaio = p->txaio;

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
		nni_tls_send(p->tls, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	if (!nni_list_empty(&p->sendq)) {
		tls_pipe_dosend(p, nni_list_first(&p->sendq));
	}
	nni_mtx_unlock(&p->mtx);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_synch(aio, 0, n);
}

static void
tls_pipe_recv_cb(void *arg)
{
	tls_pipe *p = arg;
	nni_aio * aio;
	int       rv;
	size_t    n;
	nni_msg * msg;
	nni_aio * rxaio = p->rxaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->recvq);

	if ((rv = nni_aio_result(p->rxaio)) != 0) {
		goto recv_error;
	}

	n = nni_aio_count(rxaio);
	nni_aio_iov_advance(rxaio, n);
	if (nni_aio_iov_count(rxaio) > 0) {
		// Was this a partial read?  If so then resubmit for the rest.
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

			nni_tls_recv(p->tls, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// We read a message completely.  Let the user know the good news.
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	if (!nni_list_empty(&p->recvq)) {
		tls_pipe_dorecv(p);
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
tls_cancel_tx(nni_aio *aio, int rv)
{
	tls_pipe *p = nni_aio_get_prov_data(aio);

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
tls_pipe_dosend(tls_pipe *p, nni_aio *aio)
{
	nni_aio *txaio;
	nni_msg *msg;
	int      niov;
	nni_iov  iov[3];
	uint64_t len;

	msg = nni_aio_get_msg(aio);
	len = nni_msg_len(msg) + nni_msg_header_len(msg);

	NNI_PUT64(p->txlen, len);

	txaio             = p->txaio;
	niov              = 0;
	iov[niov].iov_buf = p->txlen;
	iov[niov].iov_len = sizeof(p->txlen);
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
	nni_tls_send(p->tls, txaio);
}

static void
tls_pipe_send(void *arg, nni_aio *aio)
{
	tls_pipe *p = arg;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tls_cancel_tx, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		tls_pipe_dosend(p, aio);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
tls_cancel_rx(nni_aio *aio, int rv)
{
	tls_pipe *p = nni_aio_get_prov_data(aio);

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
tls_pipe_dorecv(tls_pipe *p)
{
	nni_aio *rxaio;
	nni_iov  iov;
	NNI_ASSERT(p->rxmsg == NULL);

	// Schedule a read of the IPC header.
	rxaio       = p->rxaio;
	iov.iov_buf = p->rxlen;
	iov.iov_len = sizeof(p->rxlen);
	nni_aio_set_iov(rxaio, 1, &iov);

	nni_tls_recv(p->tls, rxaio);
}

static void
tls_pipe_recv(void *arg, nni_aio *aio)
{
	tls_pipe *p = arg;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tls_cancel_rx, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_aio_list_append(&p->recvq, aio);
	if (nni_list_first(&p->recvq) == aio) {
		tls_pipe_dorecv(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
tls_pipe_peer(void *arg)
{
	tls_pipe *p = arg;

	return (p->peer);
}

static int
tls_pipe_get_locaddr(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_pipe *   p = arg;
	int          rv;
	nni_sockaddr sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_tls_sockname(p->tls, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, t);
	}
	return (rv);
}

static int
tls_pipe_get_remaddr(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_pipe *   p = arg;
	int          rv;
	nni_sockaddr sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_tls_peername(p->tls, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, t);
	}
	return (rv);
}

static int
tls_pipe_get_keepalive(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_pipe *p = arg;
	return (nni_copyout_bool(p->keepalive, v, szp, t));
}

static int
tls_pipe_get_nodelay(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_pipe *p = arg;
	return (nni_copyout_bool(p->nodelay, v, szp, t));
}

static void
tls_pipe_start(void *arg, nni_aio *aio)
{
	tls_pipe *p = arg;
	nni_aio * negaio;
	nni_iov   iov;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tls_cancel_nego, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
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
	nni_tls_send(p->tls, negaio);
	nni_mtx_unlock(&p->mtx);
}

static void
tls_ep_fini(void *arg)
{
	tls_ep *ep = arg;

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
tls_ep_init(void **epp, nni_url *url, nni_sock *sock, int mode)
{
	tls_ep *          ep;
	int               rv;
	char *            host;
	char *            serv;
	nni_sockaddr      rsa, lsa;
	nni_aio *         aio;
	int               passive;
	nng_tls_mode      tlsmode;
	nng_tls_auth_mode authmode;
	uint16_t          af;

	if (strcmp(url->u_scheme, "tls+tcp") == 0) {
		af = NNG_AF_UNSPEC;
	} else if (strcmp(url->u_scheme, "tls+tcp4") == 0) {
		af = NNG_AF_INET;
	} else if (strcmp(url->u_scheme, "tls+tcp6") == 0) {
		af = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}

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
		passive      = 0;
		tlsmode      = NNG_TLS_MODE_CLIENT;
		authmode     = NNG_TLS_AUTH_MODE_REQUIRED;
		lsa.s_family = af;
		nni_aio_set_input(aio, 0, &rsa);
		if ((host == NULL) || (serv == NULL)) {
			nni_aio_fini(aio);
			return (NNG_EADDRINVAL);
		}
	} else {
		passive      = 1;
		tlsmode      = NNG_TLS_MODE_SERVER;
		authmode     = NNG_TLS_AUTH_MODE_NONE;
		rsa.s_family = af;
		nni_aio_set_input(aio, 0, &lsa);
	}

	// XXX: arguably we could defer this part to the point we do a bind
	// or connect!
	nni_plat_tcp_resolv(host, serv, af, passive, aio);
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
	ep->url       = url;
	ep->keepalive = false;
	ep->nodelay   = true;

	if (((rv = nni_plat_tcp_ep_init(&ep->tep, &lsa, &rsa, mode)) != 0) ||
	    ((rv = nni_tls_config_init(&ep->cfg, tlsmode)) != 0) ||
	    ((rv = nng_tls_config_auth_mode(ep->cfg, authmode)) != 0) ||
	    ((rv = nni_aio_init(&ep->aio, tls_ep_cb, ep)) != 0)) {
		tls_ep_fini(ep);
		return (rv);
	}
	if ((tlsmode == NNG_TLS_MODE_CLIENT) && (host != NULL)) {
		if ((rv = nng_tls_config_server_name(ep->cfg, host)) != 0) {
			tls_ep_fini(ep);
			return (rv);
		}
	}
	ep->proto    = nni_sock_proto_id(sock);
	ep->authmode = authmode;

	*epp = ep;
	return (0);
}

static int
tls_dialer_init(void **epp, nni_url *url, nni_sock *sock)
{
	return (tls_ep_init(epp, url, sock, NNI_EP_MODE_DIAL));
}

static int
tls_listener_init(void **epp, nni_url *url, nni_sock *sock)
{
	return (tls_ep_init(epp, url, sock, NNI_EP_MODE_LISTEN));
}

static void
tls_ep_close(void *arg)
{
	tls_ep *ep = arg;

	nni_aio_close(ep->aio);

	nni_mtx_lock(&ep->mtx);
	nni_plat_tcp_ep_close(ep->tep);
	nni_mtx_unlock(&ep->mtx);
}

static int
tls_ep_bind(void *arg)
{
	tls_ep *ep = arg;
	int     rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_plat_tcp_ep_listen(ep->tep, &ep->bsa);
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void
tls_ep_finish(tls_ep *ep)
{
	nni_aio * aio;
	int       rv;
	tls_pipe *pipe = NULL;

	if ((rv = nni_aio_result(ep->aio)) != 0) {
		goto done;
	}
	NNI_ASSERT(nni_aio_get_output(ep->aio, 0) != NULL);

	// Attempt to allocate the parent pipe.  If this fails we'll
	// drop the connection (ENOMEM probably).
	rv = tls_pipe_init(&pipe, ep, nni_aio_get_output(ep->aio, 0));

done:
	aio          = ep->user_aio;
	ep->user_aio = NULL;

	if ((aio != NULL) && (rv == 0)) {
		nni_aio_set_output(aio, 0, pipe);
		nni_aio_finish(aio, 0, 0);
		return;
	}
	if (pipe != NULL) {
		tls_pipe_fini(pipe);
	}
	if (aio != NULL) {
		NNI_ASSERT(rv != 0);
		nni_aio_finish_error(aio, rv);
	}
}

static void
tls_ep_cb(void *arg)
{
	tls_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	tls_ep_finish(ep);
	nni_mtx_unlock(&ep->mtx);
}

static void
tls_cancel_ep(nni_aio *aio, int rv)
{
	tls_ep *ep = nni_aio_get_prov_data(aio);

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
tls_ep_accept(void *arg, nni_aio *aio)
{
	tls_ep *ep = arg;
	int     rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);
	if ((rv = nni_aio_schedule(aio, tls_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ep->user_aio = aio;
	nni_plat_tcp_ep_accept(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static void
tls_ep_connect(void *arg, nni_aio *aio)
{
	tls_ep *ep = arg;
	int     rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	NNI_ASSERT(ep->user_aio == NULL);
	if ((rv = nni_aio_schedule(aio, tls_cancel_ep, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
	}
	ep->user_aio = aio;
	nni_plat_tcp_ep_connect(ep->tep, ep->aio);
	nni_mtx_unlock(&ep->mtx);
}

static int
tls_ep_chk_bool(const void *v, size_t sz, nni_opt_type t)
{
	return (nni_copyin_bool(NULL, v, sz, t));
}

static int
tls_ep_set_nodelay(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tls_ep *ep = arg;
	bool    val;
	int     rv;
	if ((rv = nni_copyin_bool(&val, v, sz, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		ep->nodelay = val;
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tls_ep_get_nodelay(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_ep *ep = arg;
	int     rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_bool(ep->nodelay, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tls_ep_set_keepalive(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tls_ep *ep = arg;
	bool    val;
	int     rv;
	if ((rv = nni_copyin_bool(&val, v, sz, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		ep->keepalive = val;
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tls_ep_get_keepalive(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_ep *ep = arg;
	int     rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_bool(ep->keepalive, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tls_dialer_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_ep *ep = arg;

	return (nni_copyout_str(ep->url->u_rawurl, v, szp, t));
}

static int
tls_listener_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_ep *ep = arg;
	char    ustr[128];
	char    ipstr[48];  // max for IPv6 addresses including []
	char    portstr[6]; // max for 16-bit port

	nni_plat_tcp_ntop(&ep->bsa, ipstr, portstr);
	snprintf(ustr, sizeof(ustr), "tls+tcp://%s:%s", ipstr, portstr);
	return (nni_copyout_str(ustr, v, szp, t));
}

static int
tls_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tls_ep *ep = arg;
	size_t  val;
	int     rv;

	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tls_ep_chk_recvmaxsz(const void *v, size_t sz, nni_opt_type t)
{
	return (nni_copyin_size(NULL, v, sz, 0, NNI_MAXSZ, t));
}

static int
tls_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_ep *ep = arg;
	int     rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tls_ep_chk_config(const void *data, size_t sz, nni_opt_type t)
{
	void *v;
	int   rv;
	if (((rv = nni_copyin_ptr(&v, data, sz, t)) == 0) && (v == NULL)) {
		rv = NNG_EINVAL;
	}
	return (rv);
}

static int
tls_ep_set_config(void *arg, const void *data, size_t sz, nni_opt_type t)
{
	tls_ep *        ep = arg;
	nng_tls_config *cfg, *old;
	int             rv;

	if ((rv = nni_copyin_ptr((void **) &cfg, data, sz, t)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	nni_mtx_lock(&ep->mtx);
	old = ep->cfg;
	nni_tls_config_hold(cfg);
	ep->cfg = cfg;
	nni_mtx_unlock(&ep->mtx);
	if (old != NULL) {
		nni_tls_config_fini(old);
	}
	return (0);
}

static int
tls_ep_get_config(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_ep *ep = arg;
	int     rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_ptr(ep->cfg, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tls_ep_chk_string(const void *v, size_t sz, nni_opt_type t)
{
	if ((t != NNI_TYPE_OPAQUE) && (t != NNI_TYPE_STRING)) {
		return (NNG_EBADTYPE);
	}
	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}
	return (0);
}

static int
tls_ep_set_ca_file(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tls_ep *ep = arg;
	int     rv;

	if ((rv = tls_ep_chk_string(v, sz, t)) == 0) {
		rv = nng_tls_config_ca_file(ep->cfg, v);
	}
	return (rv);
}

static int
tls_ep_chk_auth_mode(const void *v, size_t sz, nni_opt_type t)
{
	return (nni_copyin_int(NULL, v, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t));
}

static int
tls_ep_set_auth_mode(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tls_ep *ep = arg;
	int     mode;
	int     rv;

	rv = nni_copyin_int(&mode, v, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t);
	if (rv == 0) {
		rv = nng_tls_config_auth_mode(ep->cfg, mode);
	}
	return (rv);
}

static int
tls_ep_set_server_name(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tls_ep *ep = arg;
	int     rv;

	if ((rv = tls_ep_chk_string(v, sz, t)) == 0) {
		rv = nng_tls_config_server_name(ep->cfg, v);
	}
	return (rv);
}

static int
tls_ep_set_cert_key_file(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tls_ep *ep = arg;
	int     rv;

	if ((rv = tls_ep_chk_string(v, sz, t)) == 0) {
		nni_mtx_lock(&ep->mtx);
		rv = nng_tls_config_cert_key_file(ep->cfg, v, NULL);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static int
tls_pipe_get_verified(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tls_pipe *p = arg;

	return (nni_copyout_bool(nni_tls_verified(p->tls), v, szp, t));
}

static nni_tran_option tls_pipe_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = tls_pipe_get_locaddr,
	},
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = tls_pipe_get_remaddr,
	},
	{
	    .o_name = NNG_OPT_TLS_VERIFIED,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tls_pipe_get_verified,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tls_pipe_get_keepalive,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tls_pipe_get_nodelay,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_pipe_ops tls_pipe_ops = {
	.p_fini    = tls_pipe_fini,
	.p_start   = tls_pipe_start,
	.p_stop    = tls_pipe_stop,
	.p_send    = tls_pipe_send,
	.p_recv    = tls_pipe_recv,
	.p_close   = tls_pipe_close,
	.p_peer    = tls_pipe_peer,
	.p_options = tls_pipe_options,
};

static nni_tran_option tls_dialer_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = tls_ep_get_recvmaxsz,
	    .o_set  = tls_ep_set_recvmaxsz,
	    .o_chk  = tls_ep_chk_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_type = NNI_TYPE_STRING,
	    .o_get  = tls_dialer_get_url,
	},
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_type = NNI_TYPE_POINTER,
	    .o_get  = tls_ep_get_config,
	    .o_set  = tls_ep_set_config,
	    .o_chk  = tls_ep_chk_config,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tls_ep_set_cert_key_file,
	    .o_chk  = tls_ep_chk_string,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tls_ep_set_ca_file,
	    .o_chk  = tls_ep_chk_string,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_type = NNI_TYPE_INT32, // enum really
	    .o_set  = tls_ep_set_auth_mode,
	    .o_chk  = tls_ep_chk_auth_mode,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tls_ep_set_server_name,
	    .o_chk  = tls_ep_chk_string,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tls_ep_get_nodelay,
	    .o_set  = tls_ep_set_nodelay,
	    .o_chk  = tls_ep_chk_bool,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tls_ep_get_keepalive,
	    .o_set  = tls_ep_set_keepalive,
	    .o_chk  = tls_ep_chk_bool,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_option tls_listener_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = tls_ep_get_recvmaxsz,
	    .o_set  = tls_ep_set_recvmaxsz,
	    .o_chk  = tls_ep_chk_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_type = NNI_TYPE_STRING,
	    .o_get  = tls_listener_get_url,
	},
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_type = NNI_TYPE_POINTER,
	    .o_get  = tls_ep_get_config,
	    .o_set  = tls_ep_set_config,
	    .o_chk  = tls_ep_chk_config,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tls_ep_set_cert_key_file,
	    .o_chk  = tls_ep_chk_string,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tls_ep_set_ca_file,
	    .o_chk  = tls_ep_chk_string,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_type = NNI_TYPE_INT32, // enum really
	    .o_set  = tls_ep_set_auth_mode,
	    .o_chk  = tls_ep_chk_auth_mode,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_type = NNI_TYPE_STRING,
	    .o_set  = tls_ep_set_server_name,
	    .o_chk  = tls_ep_chk_string,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tls_ep_get_nodelay,
	    .o_set  = tls_ep_set_nodelay,
	    .o_chk  = tls_ep_chk_bool,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tls_ep_get_keepalive,
	    .o_set  = tls_ep_set_keepalive,
	    .o_chk  = tls_ep_chk_bool,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_dialer_ops tls_dialer_ops = {
	.d_init    = tls_dialer_init,
	.d_fini    = tls_ep_fini,
	.d_connect = tls_ep_connect,
	.d_close   = tls_ep_close,
	.d_options = tls_dialer_options,
};

static nni_tran_listener_ops tls_listener_ops = {
	.l_init    = tls_listener_init,
	.l_fini    = tls_ep_fini,
	.l_bind    = tls_ep_bind,
	.l_accept  = tls_ep_accept,
	.l_close   = tls_ep_close,
	.l_options = tls_listener_options,
};

static nni_tran tls_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tls+tcp",
	.tran_dialer   = &tls_dialer_ops,
	.tran_listener = &tls_listener_ops,
	.tran_pipe     = &tls_pipe_ops,
	.tran_init     = tls_tran_init,
	.tran_fini     = tls_tran_fini,
};

static nni_tran tls4_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tls+tcp4",
	.tran_dialer   = &tls_dialer_ops,
	.tran_listener = &tls_listener_ops,
	.tran_pipe     = &tls_pipe_ops,
	.tran_init     = tls_tran_init,
	.tran_fini     = tls_tran_fini,
};

static nni_tran tls6_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tls+tcp6",
	.tran_dialer   = &tls_dialer_ops,
	.tran_listener = &tls_listener_ops,
	.tran_pipe     = &tls_pipe_ops,
	.tran_init     = tls_tran_init,
	.tran_fini     = tls_tran_fini,
};

int
nng_tls_register(void)
{
	int rv;
	if (((rv = nni_tran_register(&tls_tran)) != 0) ||
	    ((rv = nni_tran_register(&tls4_tran)) != 0) ||
	    ((rv = nni_tran_register(&tls6_tran)) != 0)) {
		return (rv);
	}
	return (0);
}
