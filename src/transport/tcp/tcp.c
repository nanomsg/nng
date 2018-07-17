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

typedef struct tcptran_pipe     tcptran_pipe;
typedef struct tcptran_dialer   tcptran_dialer;
typedef struct tcptran_listener tcptran_listener;

// tcp_pipe is one end of a TCP connection.
struct tcptran_pipe {
	nni_tcp_conn *conn;
	uint16_t      peer;
	uint16_t      proto;
	size_t        rcvmax;
	bool          nodelay;
	bool          keepalive;

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

struct tcptran_dialer {
	nni_tcp_dialer *dialer;
	uint16_t        proto;
	uint16_t        af;
	size_t          rcvmax;
	bool            nodelay;
	bool            keepalive;
	bool            resolving;
	nng_sockaddr    sa;
	nni_aio *       aio;
	nni_aio *       user_aio;
	nni_url *       url;
	nni_mtx         mtx;
};

struct tcptran_listener {
	nni_tcp_listener *listener;
	uint16_t          proto;
	size_t            rcvmax;
	bool              nodelay;
	bool              keepalive;
	nni_aio *         aio;
	nni_aio *         user_aio;
	nni_url *         url;
	nng_sockaddr      sa;
	nng_sockaddr      bsa; // bound addr
	nni_mtx           mtx;
};

static void tcptran_pipe_send_start(tcptran_pipe *);
static void tcptran_pipe_recv_start(tcptran_pipe *);
static void tcptran_pipe_send_cb(void *);
static void tcptran_pipe_recv_cb(void *);
static void tcptran_pipe_nego_cb(void *);
static void tcptran_dialer_cb(void *arg);
static void tcptran_listener_cb(void *arg);

static int
tcptran_init(void)
{
	return (0);
}

static void
tcptran_fini(void)
{
}

static void
tcptran_pipe_close(void *arg)
{
	tcptran_pipe *p = arg;

	nni_aio_close(p->rxaio);
	nni_aio_close(p->txaio);
	nni_aio_close(p->negaio);

	nni_tcp_conn_close(p->conn);
}

static void
tcptran_pipe_stop(void *arg)
{
	tcptran_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negaio);
}

static void
tcptran_pipe_fini(void *arg)
{
	tcptran_pipe *p = arg;

	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);
	nni_aio_fini(p->negaio);
	if (p->conn != NULL) {
		nni_tcp_conn_fini(p->conn);
	}
	nni_msg_free(p->rxmsg);
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static int
tcptran_pipe_init(tcptran_pipe **pipep, void *conn)
{
	tcptran_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_init(&p->txaio, tcptran_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, tcptran_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negaio, tcptran_pipe_nego_cb, p)) != 0)) {
		tcptran_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);

	p->conn = conn;
	*pipep  = p;
	return (0);
}

static void
tcptran_pipe_nego_cancel(nni_aio *aio, int rv)
{
	tcptran_pipe *p = nni_aio_get_prov_data(aio);

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
tcptran_pipe_nego_cb(void *arg)
{
	tcptran_pipe *p   = arg;
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
		nni_tcp_conn_send(p->conn, aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nni_tcp_conn_recv(p->conn, aio);
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
tcptran_pipe_send_cb(void *arg)
{
	tcptran_pipe *p = arg;
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
		nni_tcp_conn_send(p->conn, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	nni_aio_list_remove(aio);
	tcptran_pipe_send_start(p);

	nni_mtx_unlock(&p->mtx);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_synch(aio, 0, n);
}

static void
tcptran_pipe_recv_cb(void *arg)
{
	tcptran_pipe *p = arg;
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
		nni_tcp_conn_recv(p->conn, rxaio);
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
			nni_tcp_conn_recv(p->conn, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// We read a message completely.  Let the user know the good news.
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	if (!nni_list_empty(&p->recvq)) {
		tcptran_pipe_recv_start(p);
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
tcptran_pipe_send_cancel(nni_aio *aio, int rv)
{
	tcptran_pipe *p = nni_aio_get_prov_data(aio);

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
tcptran_pipe_send_start(tcptran_pipe *p)
{
	nni_aio *aio;
	nni_aio *txaio;
	nni_msg *msg;
	int      niov;
	nni_iov  iov[3];
	uint64_t len;

	if ((aio = nni_list_first(&p->sendq)) == NULL) {
		return;
	}

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
	nni_tcp_conn_send(p->conn, txaio);
}

static void
tcptran_pipe_send(void *arg, nni_aio *aio)
{
	tcptran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tcptran_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		tcptran_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
tcptran_pipe_recv_cancel(nni_aio *aio, int rv)
{
	tcptran_pipe *p = nni_aio_get_prov_data(aio);

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
tcptran_pipe_recv_start(tcptran_pipe *p)
{
	nni_aio *rxaio;
	nni_iov  iov;
	NNI_ASSERT(p->rxmsg == NULL);

	// Schedule a read of the IPC header.
	rxaio       = p->rxaio;
	iov.iov_buf = p->rxlen;
	iov.iov_len = sizeof(p->rxlen);
	nni_aio_set_iov(rxaio, 1, &iov);

	nni_tcp_conn_recv(p->conn, rxaio);
}

static void
tcptran_pipe_recv(void *arg, nni_aio *aio)
{
	tcptran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tcptran_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_list_append(&p->recvq, aio);
	if (nni_list_first(&p->recvq) == aio) {
		tcptran_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
tcptran_pipe_peer(void *arg)
{
	tcptran_pipe *p = arg;

	return (p->peer);
}

static int
tcptran_pipe_get_locaddr(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_pipe *p = arg;
	int           rv;
	nni_sockaddr  sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_tcp_conn_sockname(p->conn, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, t);
	}
	return (rv);
}

static int
tcptran_pipe_get_remaddr(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_pipe *p = arg;
	int           rv;
	nni_sockaddr  sa;

	memset(&sa, 0, sizeof(sa));
	if ((rv = nni_tcp_conn_peername(p->conn, &sa)) == 0) {
		rv = nni_copyout_sockaddr(&sa, v, szp, t);
	}
	return (rv);
}

static int
tcptran_pipe_get_keepalive(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_pipe *p = arg;
	return (nni_copyout_bool(p->keepalive, v, szp, t));
}

static int
tcptran_pipe_get_nodelay(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_pipe *p = arg;
	return (nni_copyout_bool(p->nodelay, v, szp, t));
}

static void
tcptran_pipe_start(void *arg, nni_aio *aio)
{
	tcptran_pipe *p = arg;
	nni_aio *     negaio;
	nni_iov       iov;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tcptran_pipe_nego_cancel, p)) != 0) {
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
	nni_tcp_conn_send(p->conn, negaio);
	nni_mtx_unlock(&p->mtx);
}

static void
tcptran_dialer_fini(void *arg)
{
	tcptran_dialer *d = arg;

	nni_aio_stop(d->aio);
	if (d->dialer != NULL) {
		nni_tcp_dialer_fini(d->dialer);
	}
	nni_aio_fini(d->aio);
	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

static void
tcptran_dialer_close(void *arg)
{
	tcptran_dialer *d = arg;

	nni_aio_close(d->aio);
	nni_tcp_dialer_close(d->dialer);
}

static int
tcptran_dialer_init(void **dp, nni_url *url, nni_sock *sock)
{
	tcptran_dialer *d;
	int             rv;
	uint16_t        af;

	if (strcmp(url->u_scheme, "tcp") == 0) {
		af = NNG_AF_UNSPEC;
	} else if (strcmp(url->u_scheme, "tcp4") == 0) {
		af = NNG_AF_INET;
	} else if (strcmp(url->u_scheme, "tcp6") == 0) {
		af = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL) || (strlen(url->u_hostname) == 0) ||
	    (strlen(url->u_port) == 0)) {
		return (NNG_EADDRINVAL);
	}

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&d->mtx);

	if (((rv = nni_tcp_dialer_init(&d->dialer)) != 0) ||
	    ((rv = nni_aio_init(&d->aio, tcptran_dialer_cb, d)) != 0)) {
		tcptran_dialer_fini(d);
		return (rv);
	}

	d->url       = url;
	d->proto     = nni_sock_proto_id(sock);
	d->nodelay   = true;
	d->keepalive = false;
	d->af        = af;

	*dp = d;
	return (0);
}

static void
tcptran_dialer_cb(void *arg)
{
	tcptran_dialer *d = arg;
	tcptran_pipe *  p;
	nni_tcp_conn *  conn;
	nni_aio *       aio;
	int             rv;

	nni_mtx_lock(&d->mtx);
	aio = d->user_aio;
	rv  = nni_aio_result(d->aio);

	if (aio == NULL) {
		nni_mtx_unlock(&d->mtx);
		if ((rv == 0) && !d->resolving) {
			conn = nni_aio_get_output(d->aio, 0);
			nni_tcp_conn_fini(conn);
		}
		return;
	}

	if (rv != 0) {
		d->user_aio = NULL;
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (d->resolving) {
		// Name resolution complete.  Now go to next step.
		d->resolving = false;
		nni_tcp_dialer_dial(d->dialer, &d->sa, d->aio);
		nni_mtx_unlock(&d->mtx);
		return;
	}

	d->user_aio = NULL;
	conn        = nni_aio_get_output(d->aio, 0);
	NNI_ASSERT(conn != NULL);
	if ((rv = tcptran_pipe_init(&p, conn)) != 0) {
		nni_mtx_unlock(&d->mtx);
		nni_tcp_conn_fini(conn);
		nni_aio_finish_error(aio, rv);
		return;
	}

	p->proto     = d->proto;
	p->rcvmax    = d->rcvmax;
	p->nodelay   = d->nodelay;
	p->keepalive = d->keepalive;
	nni_mtx_unlock(&d->mtx);

	(void) nni_tcp_conn_set_nodelay(conn, p->nodelay);
	(void) nni_tcp_conn_set_keepalive(conn, p->keepalive);

	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
}

static void
tcptran_dialer_cancel(nni_aio *aio, int rv)
{
	tcptran_dialer *d = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&d->mtx);
	if (d->user_aio != aio) {
		nni_mtx_unlock(&d->mtx);
		return;
	}
	d->user_aio = NULL;
	nni_mtx_unlock(&d->mtx);

	nni_aio_abort(d->aio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
tcptran_dialer_connect(void *arg, nni_aio *aio)
{
	tcptran_dialer *d = arg;
	int             rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&d->mtx);
	NNI_ASSERT(d->user_aio == NULL);

	if ((rv = nni_aio_schedule(aio, tcptran_dialer_cancel, d)) != 0) {
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	d->user_aio = aio;

	d->resolving = true;

	// Start the name resolution.  Callback will see resolving, and then
	// switch to doing actual connect.
	nni_aio_set_input(d->aio, 0, &d->sa);
	nni_tcp_resolv(d->url->u_hostname, d->url->u_port, d->af, 0, d->aio);
	nni_mtx_unlock(&d->mtx);
}

static int
tcptran_dialer_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_dialer *d = arg;

	return (nni_copyout_str(d->url->u_rawurl, v, szp, t));
}

static int
tcptran_dialer_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_dialer *d = arg;
	int             rv;

	nni_mtx_lock(&d->mtx);
	rv = nni_copyout_size(d->rcvmax, v, szp, t);
	nni_mtx_unlock(&d->mtx);
	return (rv);
}

static int
tcptran_dialer_set_recvmaxsz(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tcptran_dialer *d = arg;
	size_t          val;
	int             rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_mtx_lock(&d->mtx);
		d->rcvmax = val;
		nni_mtx_unlock(&d->mtx);
	}
	return (rv);
}

static int
tcptran_dialer_get_nodelay(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_dialer *d = arg;
	int             rv;
	nni_mtx_lock(&d->mtx);
	rv = nni_copyout_bool(d->nodelay, v, szp, t);
	nni_mtx_unlock(&d->mtx);
	return (rv);
}

static int
tcptran_dialer_set_nodelay(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tcptran_dialer *d = arg;
	bool            val;
	int             rv;
	if ((rv = nni_copyin_bool(&val, v, sz, t)) == 0) {
		nni_mtx_lock(&d->mtx);
		d->nodelay = val;
		nni_mtx_unlock(&d->mtx);
	}
	return (rv);
}

static int
tcptran_dialer_get_keepalive(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_dialer *d = arg;
	return (nni_copyout_bool(d->keepalive, v, szp, t));
}

static int
tcptran_dialer_set_keepalive(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tcptran_dialer *d = arg;
	bool            val;
	int             rv;
	if ((rv = nni_copyin_bool(&val, v, sz, t)) == 0) {
		nni_mtx_lock(&d->mtx);
		d->keepalive = val;
		nni_mtx_unlock(&d->mtx);
	}
	return (rv);
}

static void
tcptran_listener_fini(void *arg)
{
	tcptran_listener *l = arg;

	nni_aio_stop(l->aio);
	if (l->listener != NULL) {
		nni_tcp_listener_fini(l->listener);
	}
	nni_aio_fini(l->aio);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

static int
tcptran_listener_init(void **lp, nni_url *url, nni_sock *sock)
{
	tcptran_listener *l;
	int               rv;
	char *            host;
	nni_aio *         aio;
	uint16_t          af;

	if (strcmp(url->u_scheme, "tcp") == 0) {
		af = NNG_AF_UNSPEC;
	} else if (strcmp(url->u_scheme, "tcp4") == 0) {
		af = NNG_AF_INET;
	} else if (strcmp(url->u_scheme, "tcp6") == 0) {
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

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&l->mtx);
	l->url = url;

	if (strlen(url->u_hostname) == 0) {
		host = NULL;
	} else {
		host = url->u_hostname;
	}

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		tcptran_listener_fini(l);
		return (rv);
	}

	// XXX: We are doing lookup at listener initialization.  There is
	// a valid argument that this should be done at bind time, but that
	// would require making bind asynchronous.  In some ways this would
	// be worse than the cost of just waiting here.  We always recommend
	// using local IP addresses rather than names when possible.

	nni_aio_set_input(aio, 0, &l->sa);

	nni_tcp_resolv(host, url->u_port, af, 1, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_fini(aio);

	if (rv != 0) {
		tcptran_listener_fini(l);
		return (rv);
	}

	if (((rv = nni_tcp_listener_init(&l->listener)) != 0) ||
	    ((rv = nni_aio_init(&l->aio, tcptran_listener_cb, l)) != 0)) {
		tcptran_listener_fini(l);
		return (rv);
	}

	l->proto     = nni_sock_proto_id(sock);
	l->nodelay   = true;
	l->keepalive = false;
	l->bsa       = l->sa;

	*lp = l;
	return (0);
}

static void
tcptran_listener_close(void *arg)
{
	tcptran_listener *l = arg;

	nni_aio_close(l->aio);
	nni_tcp_listener_close(l->listener);
}

static int
tcptran_listener_bind(void *arg)
{
	tcptran_listener *l = arg;
	int               rv;

	nni_mtx_lock(&l->mtx);
	l->bsa = l->sa;
	rv     = nni_tcp_listener_listen(l->listener, &l->bsa);
	nni_mtx_unlock(&l->mtx);

	return (rv);
}

static void
tcptran_listener_cb(void *arg)
{
	tcptran_listener *l = arg;
	nni_aio *         aio;
	int               rv;
	tcptran_pipe *    p = NULL;
	nni_tcp_conn *    conn;

	nni_mtx_lock(&l->mtx);
	rv          = nni_aio_result(l->aio);
	aio         = l->user_aio;
	l->user_aio = NULL;

	if (aio == NULL) {
		nni_mtx_unlock(&l->mtx);
		if (rv == 0) {
			conn = nni_aio_get_output(l->aio, 0);
			nni_tcp_conn_fini(conn);
		}
		return;
	}

	if (rv != 0) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	conn = nni_aio_get_output(l->aio, 0);

	NNI_ASSERT(conn != NULL);
	if ((rv = tcptran_pipe_init(&p, conn)) != 0) {
		nni_mtx_unlock(&l->mtx);
		nni_tcp_conn_fini(conn);
		nni_aio_finish_error(aio, rv);
		return;
	}

	p->proto     = l->proto;
	p->rcvmax    = l->rcvmax;
	p->nodelay   = l->nodelay;
	p->keepalive = l->keepalive;
	nni_mtx_unlock(&l->mtx);

	(void) nni_tcp_conn_set_nodelay(conn, p->nodelay);
	(void) nni_tcp_conn_set_keepalive(conn, p->keepalive);

	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
}

static void
tcptran_listener_cancel(nni_aio *aio, int rv)
{
	tcptran_listener *l = nni_aio_get_prov_data(aio);

	nni_mtx_lock(&l->mtx);
	if (l->user_aio != aio) {
		nni_mtx_unlock(&l->mtx);
		return;
	}
	l->user_aio = NULL;
	nni_mtx_unlock(&l->mtx);

	nni_aio_abort(l->aio, rv);
	nni_aio_finish_error(aio, rv);
}

static void
tcptran_listener_accept(void *arg, nni_aio *aio)
{
	tcptran_listener *l = arg;
	int               rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&l->mtx);
	NNI_ASSERT(l->user_aio == NULL);

	if ((rv = nni_aio_schedule(aio, tcptran_listener_cancel, l)) != 0) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	l->user_aio = aio;

	nni_tcp_listener_accept(l->listener, l->aio);
	nni_mtx_unlock(&l->mtx);
}

static int
tcptran_listener_set_nodelay(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tcptran_listener *l = arg;
	bool              val;
	int               rv;
	if ((rv = nni_copyin_bool(&val, v, sz, t)) == 0) {
		nni_mtx_lock(&l->mtx);
		l->nodelay = val;
		nni_mtx_unlock(&l->mtx);
	}
	return (rv);
}

static int
tcptran_listener_get_nodelay(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_listener *l = arg;
	int               rv;
	nni_mtx_lock(&l->mtx);
	rv = nni_copyout_bool(l->nodelay, v, szp, t);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}

static int
tcptran_listener_set_recvmaxsz(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tcptran_listener *l = arg;
	size_t            val;
	int               rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_mtx_lock(&l->mtx);
		l->rcvmax = val;
		nni_mtx_unlock(&l->mtx);
	}
	return (rv);
}

static int
tcptran_listener_set_keepalive(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tcptran_listener *l = arg;
	bool              val;
	int               rv;
	if ((rv = nni_copyin_bool(&val, v, sz, t)) == 0) {
		nni_mtx_lock(&l->mtx);
		l->keepalive = val;
		nni_mtx_unlock(&l->mtx);
	}
	return (rv);
}

static int
tcptran_listener_get_keepalive(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_listener *l = arg;
	int               rv;
	nni_mtx_lock(&l->mtx);
	rv = nni_copyout_bool(l->keepalive, v, szp, t);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}

static int
tcptran_listener_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_listener *l = arg;
	char              ustr[128];
	char              ipstr[48];  // max for IPv6 addresses including []
	char              portstr[6]; // max for 16-bit port

	nni_ntop(&l->bsa, ipstr, portstr);
	snprintf(ustr, sizeof(ustr), "tcp://%s:%s", ipstr, portstr);
	return (nni_copyout_str(ustr, v, szp, t));
}

static int
tcptran_listener_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_listener *l = arg;
	int               rv;

	nni_mtx_lock(&l->mtx);
	rv = nni_copyout_size(l->rcvmax, v, szp, t);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}

static int
tcptran_listener_get_locaddr(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	tcptran_listener *l = arg;
	int               rv;

	nni_mtx_lock(&l->mtx);
	rv = nni_copyout_sockaddr(&l->bsa, buf, szp, t);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}

static int
tcptran_check_bool(const void *v, size_t sz, nni_opt_type t)
{
	return (nni_copyin_bool(NULL, v, sz, t));
}

static int
tcptran_check_recvmaxsz(const void *v, size_t sz, nni_opt_type t)
{
	return (nni_copyin_size(NULL, v, sz, 0, NNI_MAXSZ, t));
}

static nni_tran_option tcptran_pipe_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = tcptran_pipe_get_locaddr,
	},
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = tcptran_pipe_get_remaddr,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tcptran_pipe_get_keepalive,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tcptran_pipe_get_nodelay,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_pipe_ops tcptran_pipe_ops = {
	.p_fini    = tcptran_pipe_fini,
	.p_start   = tcptran_pipe_start,
	.p_stop    = tcptran_pipe_stop,
	.p_send    = tcptran_pipe_send,
	.p_recv    = tcptran_pipe_recv,
	.p_close   = tcptran_pipe_close,
	.p_peer    = tcptran_pipe_peer,
	.p_options = tcptran_pipe_options,
};

static nni_tran_option tcptran_dialer_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = tcptran_dialer_get_recvmaxsz,
	    .o_set  = tcptran_dialer_set_recvmaxsz,
	    .o_chk  = tcptran_check_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_type = NNI_TYPE_STRING,
	    .o_get  = tcptran_dialer_get_url,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tcptran_dialer_get_nodelay,
	    .o_set  = tcptran_dialer_set_nodelay,
	    .o_chk  = tcptran_check_bool,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tcptran_dialer_get_keepalive,
	    .o_set  = tcptran_dialer_set_keepalive,
	    .o_chk  = tcptran_check_bool,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_option tcptran_listener_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = tcptran_listener_get_recvmaxsz,
	    .o_set  = tcptran_listener_set_recvmaxsz,
	    .o_chk  = tcptran_check_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = tcptran_listener_get_locaddr,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_type = NNI_TYPE_STRING,
	    .o_get  = tcptran_listener_get_url,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tcptran_listener_get_nodelay,
	    .o_set  = tcptran_listener_set_nodelay,
	    .o_chk  = tcptran_check_bool,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_type = NNI_TYPE_BOOL,
	    .o_get  = tcptran_listener_get_keepalive,
	    .o_set  = tcptran_listener_set_keepalive,
	    .o_chk  = tcptran_check_bool,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_dialer_ops tcptran_dialer_ops = {
	.d_init    = tcptran_dialer_init,
	.d_fini    = tcptran_dialer_fini,
	.d_connect = tcptran_dialer_connect,
	.d_close   = tcptran_dialer_close,
	.d_options = tcptran_dialer_options,
};

static nni_tran_listener_ops tcptran_listener_ops = {
	.l_init    = tcptran_listener_init,
	.l_fini    = tcptran_listener_fini,
	.l_bind    = tcptran_listener_bind,
	.l_accept  = tcptran_listener_accept,
	.l_close   = tcptran_listener_close,
	.l_options = tcptran_listener_options,
};

static nni_tran tcp_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tcp",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
};

static nni_tran tcp4_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tcp4",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
};

static nni_tran tcp6_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tcp6",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
};

int
nng_tcp_register(void)
{
	int rv;
	if (((rv = nni_tran_register(&tcp_tran)) != 0) ||
	    ((rv = nni_tran_register(&tcp4_tran)) != 0) ||
	    ((rv = nni_tran_register(&tcp6_tran)) != 0)) {
		return (rv);
	}
	return (0);
}
