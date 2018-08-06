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

typedef struct ipctran_pipe     ipctran_pipe;
typedef struct ipctran_dialer   ipctran_dialer;
typedef struct ipctran_listener ipctran_listener;

// ipc_pipe is one end of an IPC connection.
struct ipctran_pipe {
	nni_ipc_conn *conn;
	uint16_t      peer;
	uint16_t      proto;
	size_t        rcvmax;
	nni_sockaddr  sa;

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

struct ipctran_dialer {
	nni_sockaddr    sa;
	nni_ipc_dialer *dialer;
	uint16_t        proto;
	size_t          rcvmax;
	nni_aio *       aio;
	nni_aio *       user_aio;
	nni_mtx         mtx;
};

struct ipctran_listener {
	nni_sockaddr      sa;
	nni_ipc_listener *listener;
	uint16_t          proto;
	size_t            rcvmax;
	nni_aio *         aio;
	nni_aio *         user_aio;
	nni_mtx           mtx;
};

static void ipctran_pipe_send_start(ipctran_pipe *);
static void ipctran_pipe_recv_start(ipctran_pipe *);
static void ipctran_pipe_send_cb(void *);
static void ipctran_pipe_recv_cb(void *);
static void ipctran_pipe_nego_cb(void *);
static void ipctran_dialer_cb(void *);
static void ipctran_listener_cb(void *);

static int
ipctran_init(void)
{
	return (0);
}

static void
ipctran_fini(void)
{
}

static void
ipctran_pipe_close(void *arg)
{
	ipctran_pipe *p = arg;

	nni_aio_close(p->rxaio);
	nni_aio_close(p->txaio);
	nni_aio_close(p->negaio);

	nni_ipc_conn_close(p->conn);
}

static void
ipctran_pipe_stop(void *arg)
{
	ipctran_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negaio);
}

static void
ipctran_pipe_fini(void *arg)
{
	ipctran_pipe *p = arg;

	nni_aio_fini(p->rxaio);
	nni_aio_fini(p->txaio);
	nni_aio_fini(p->negaio);
	if (p->conn != NULL) {
		nni_ipc_conn_fini(p->conn);
	}
	if (p->rxmsg) {
		nni_msg_free(p->rxmsg);
	}
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static int
ipctran_pipe_init(ipctran_pipe **pipep, void *conn)
{
	ipctran_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_init(&p->txaio, ipctran_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->rxaio, ipctran_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->negaio, ipctran_pipe_nego_cb, p)) != 0)) {
		ipctran_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->sendq);
	nni_aio_list_init(&p->recvq);

	p->conn = conn;
#if 0
	p->proto              = ep->proto;
	p->rcvmax             = ep->rcvmax;
	p->sa.s_ipc.sa_family = NNG_AF_IPC;
	p->sa                 = ep->sa;
#endif
	*pipep = p;
	return (0);
}

static void
ipctran_pipe_nego_cancel(nni_aio *aio, int rv)
{
	ipctran_pipe *p = nni_aio_get_prov_data(aio);

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
ipctran_pipe_nego_cb(void *arg)
{
	ipctran_pipe *p   = arg;
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
		iov.iov_buf = &p->txhead[p->gottxhead];
		nni_aio_set_iov(aio, 1, &iov);
		// send it down...
		nni_ipc_conn_send(p->conn, aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxhead[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nni_ipc_conn_recv(p->conn, aio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// We have both sent and received the headers.  Lets check the
	// receive side header.
	if ((p->rxhead[0] != 0) || (p->rxhead[1] != 'S') ||
	    (p->rxhead[2] != 'P') || (p->rxhead[3] != 0) ||
	    (p->rxhead[6] != 0) || (p->rxhead[7] != 0)) {
		rv = NNG_EPROTO;
		goto done;
	}

	NNI_GET16(&p->rxhead[4], p->peer);

done:
	if ((aio = p->user_negaio) != NULL) {
		p->user_negaio = NULL;
		nni_aio_finish(aio, rv, 0);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ipctran_pipe_send_cb(void *arg)
{
	ipctran_pipe *p = arg;
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
	if (nni_aio_iov_count(txaio) != 0) {
		nni_ipc_conn_send(p->conn, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	nni_aio_list_remove(aio);
	ipctran_pipe_send_start(p);

	nni_mtx_unlock(&p->mtx);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_synch(aio, 0, n);
}

static void
ipctran_pipe_recv_cb(void *arg)
{
	ipctran_pipe *p = arg;
	nni_aio *     aio;
	int           rv;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     rxaio = p->rxaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->recvq);

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
		nni_ipc_conn_recv(p->conn, rxaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	// If we don't have a message yet, we were reading the message
	// header, which is just the length.  This tells us the size of the
	// message to allocate and how much more to expect.
	if (p->rxmsg == NULL) {
		uint64_t len;

		// Check to make sure we got msg type 1.
		if (p->rxhead[0] != 1) {
			rv = NNG_EPROTO;
			goto recv_error;
		}

		// We should have gotten a message header.
		NNI_GET64(p->rxhead + 1, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if ((len > p->rcvmax) && (p->rcvmax > 0)) {
			rv = NNG_EMSGSIZE;
			goto recv_error;
		}

		// Note that all IO on this pipe is blocked behind this
		// allocation.  We could possibly look at using a separate
		// lock for the read side in the future, so that we allow
		// transmits to proceed normally.  In practice this is
		// unlikely to be much of an issue though.
		if ((rv = nni_msg_alloc(&p->rxmsg, (size_t) len)) != 0) {
			goto recv_error;
		}

		if (len != 0) {
			nni_iov iov;
			// Submit the rest of the data for a read -- we want to
			// read the entire message now.
			iov.iov_buf = nni_msg_body(p->rxmsg);
			iov.iov_len = (size_t) len;

			nni_aio_set_iov(rxaio, 1, &iov);
			nni_ipc_conn_recv(p->conn, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// Otherwise we got a message read completely.  Let the user know the
	// good news.

	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	if (!nni_list_empty(&p->recvq)) {
		ipctran_pipe_recv_start(p);
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
ipctran_pipe_send_cancel(nni_aio *aio, int rv)
{
	ipctran_pipe *p = nni_aio_get_prov_data(aio);

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
ipctran_pipe_send_start(ipctran_pipe *p)
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

	p->txhead[0] = 1; // message type, 1.
	NNI_PUT64(p->txhead + 1, len);

	txaio          = p->txaio;
	niov           = 0;
	iov[0].iov_buf = p->txhead;
	iov[0].iov_len = sizeof(p->txhead);
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
	nni_ipc_conn_send(p->conn, txaio);
}

static void
ipctran_pipe_send(void *arg, nni_aio *aio)
{
	ipctran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, ipctran_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		ipctran_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ipctran_pipe_recv_cancel(nni_aio *aio, int rv)
{
	ipctran_pipe *p = nni_aio_get_prov_data(aio);

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
ipctran_pipe_recv_start(ipctran_pipe *p)
{
	nni_aio *rxaio;
	nni_iov  iov;
	NNI_ASSERT(p->rxmsg == NULL);

	// Schedule a read of the IPC header.
	rxaio       = p->rxaio;
	iov.iov_buf = p->rxhead;
	iov.iov_len = sizeof(p->rxhead);
	nni_aio_set_iov(rxaio, 1, &iov);

	nni_ipc_conn_recv(p->conn, rxaio);
}

static void
ipctran_pipe_recv(void *arg, nni_aio *aio)
{
	ipctran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);

	if ((rv = nni_aio_schedule(aio, ipctran_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_list_append(&p->recvq, aio);
	if (nni_list_first(&p->recvq) == aio) {
		ipctran_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ipctran_pipe_start(void *arg, nni_aio *aio)
{
	ipctran_pipe *p = arg;
	nni_aio *     negaio;
	nni_iov       iov;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, ipctran_pipe_nego_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->txhead[0] = 0;
	p->txhead[1] = 'S';
	p->txhead[2] = 'P';
	p->txhead[3] = 0;
	NNI_PUT16(&p->txhead[4], p->proto);
	NNI_PUT16(&p->txhead[6], 0);

	p->user_negaio = aio;
	p->gotrxhead   = 0;
	p->gottxhead   = 0;
	p->wantrxhead  = 8;
	p->wanttxhead  = 8;
	negaio         = p->negaio;
	iov.iov_len    = 8;
	iov.iov_buf    = &p->txhead[0];
	nni_aio_set_iov(negaio, 1, &iov);
	nni_ipc_conn_send(p->conn, negaio);
	nni_mtx_unlock(&p->mtx);
}

static uint16_t
ipctran_pipe_peer(void *arg)
{
	ipctran_pipe *p = arg;

	return (p->peer);
}

static int
ipctran_pipe_get_addr(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipctran_pipe *p = arg;
	return (nni_copyout_sockaddr(&p->sa, buf, szp, t));
}

static int
ipctran_pipe_get_peer_uid(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipctran_pipe *p = arg;
	uint64_t      id;
	int           rv;
	if ((rv = nni_ipc_conn_get_peer_uid(p->conn, &id)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipctran_pipe_get_peer_gid(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipctran_pipe *p = arg;
	uint64_t      id;
	int           rv;
	if ((rv = nni_ipc_conn_get_peer_gid(p->conn, &id)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipctran_pipe_get_peer_pid(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipctran_pipe *p = arg;
	uint64_t      id;
	int           rv;
	if ((rv = nni_ipc_conn_get_peer_pid(p->conn, &id)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipctran_pipe_get_peer_zoneid(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipctran_pipe *p = arg;
	uint64_t      id;
	int           rv;
	if ((rv = nni_ipc_conn_get_peer_zoneid(p->conn, &id)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static void
ipctran_dialer_fini(void *arg)
{
	ipctran_dialer *d = arg;

	nni_aio_stop(d->aio);
	if (d->dialer != NULL) {
		nni_ipc_dialer_fini(d->dialer);
	}
	nni_aio_fini(d->aio);
	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

static void
ipctran_dialer_close(void *arg)
{
	ipctran_dialer *d = arg;

	nni_aio_close(d->aio);
	nni_ipc_dialer_close(d->dialer);
}

static int
ipctran_dialer_init(void **dp, nni_url *url, nni_sock *sock)
{
	ipctran_dialer *d;
	int             rv;
	size_t          sz;

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&d->mtx);

	sz                    = sizeof(d->sa.s_ipc.sa_path);
	d->sa.s_ipc.sa_family = NNG_AF_IPC;

	if (nni_strlcpy(d->sa.s_ipc.sa_path, url->u_path, sz) >= sz) {
		ipctran_dialer_fini(d);
		return (NNG_EADDRINVAL);
	}

	if (((rv = nni_ipc_dialer_init(&d->dialer)) != 0) ||
	    ((rv = nni_aio_init(&d->aio, ipctran_dialer_cb, d)) != 0)) {
		ipctran_dialer_fini(d);
		return (rv);
	}

	d->proto = nni_sock_proto_id(sock);

	*dp = d;
	return (0);
}

static void
ipctran_dialer_cb(void *arg)
{
	ipctran_dialer *d = arg;
	ipctran_pipe *  p;
	nni_ipc_conn *  conn;
	nni_aio *       aio;
	int             rv;

	nni_mtx_lock(&d->mtx);
	aio = d->user_aio;
	rv  = nni_aio_result(d->aio);

	if (aio == NULL) {
		nni_mtx_unlock(&d->mtx);
		if (rv == 0) {
			conn = nni_aio_get_output(d->aio, 0);
			nni_ipc_conn_fini(conn);
		}
		return;
	}

	if (rv != 0) {
		d->user_aio = NULL;
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	d->user_aio = NULL;
	conn        = nni_aio_get_output(d->aio, 0);
	NNI_ASSERT(conn != NULL);
	if ((rv = ipctran_pipe_init(&p, conn)) != 0) {
		nni_mtx_unlock(&d->mtx);
		nni_ipc_conn_fini(conn);
		nni_aio_finish_error(aio, rv);
		return;
	}

	p->proto  = d->proto;
	p->rcvmax = d->rcvmax;
	p->sa     = d->sa;
	nni_mtx_unlock(&d->mtx);

	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
}

static void
ipctran_dialer_cancel(nni_aio *aio, int rv)
{
	ipctran_dialer *d = nni_aio_get_prov_data(aio);

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
ipctran_dialer_connect(void *arg, nni_aio *aio)
{
	ipctran_dialer *d = arg;
	int             rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&d->mtx);
	NNI_ASSERT(d->user_aio == NULL);

	if ((rv = nni_aio_schedule(aio, ipctran_dialer_cancel, d)) != 0) {
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	d->user_aio = aio;

	nni_ipc_dialer_dial(d->dialer, &d->sa, d->aio);
	nni_mtx_unlock(&d->mtx);
}

static int
ipctran_dialer_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	ipctran_dialer *d = arg;
	int             rv;
	nni_mtx_lock(&d->mtx);
	rv = nni_copyout_size(d->rcvmax, v, szp, t);
	nni_mtx_unlock(&d->mtx);
	return (rv);
}

static int
ipctran_dialer_set_recvmaxsz(
    void *arg, const void *v, size_t sz, nni_opt_type t)
{
	ipctran_dialer *d = arg;
	size_t          val;
	int             rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_mtx_lock(&d->mtx);
		d->rcvmax = val;
		nni_mtx_unlock(&d->mtx);
	}
	return (rv);
}

static void
ipctran_listener_fini(void *arg)
{
	ipctran_listener *l = arg;

	nni_aio_stop(l->aio);
	if (l->listener != NULL) {
		nni_ipc_listener_fini(l->listener);
	}
	nni_aio_fini(l->aio);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

static int
ipctran_listener_init(void **lp, nni_url *url, nni_sock *sock)
{
	ipctran_listener *l;
	int               rv;
	size_t            sz;

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&l->mtx);

	sz                    = sizeof(l->sa.s_ipc.sa_path);
	l->sa.s_ipc.sa_family = NNG_AF_IPC;

	if (nni_strlcpy(l->sa.s_ipc.sa_path, url->u_path, sz) >= sz) {
		ipctran_listener_fini(l);
		return (NNG_EADDRINVAL);
	}

	if (((rv = nni_ipc_listener_init(&l->listener)) != 0) ||
	    ((rv = nni_aio_init(&l->aio, ipctran_listener_cb, l)) != 0)) {
		ipctran_listener_fini(l);
		return (rv);
	}

	l->proto = nni_sock_proto_id(sock);

	*lp = l;
	return (0);
}

static void
ipctran_listener_close(void *arg)
{
	ipctran_listener *l = arg;

	nni_aio_close(l->aio);
	nni_ipc_listener_close(l->listener);
}

static int
ipctran_listener_bind(void *arg)
{
	ipctran_listener *l = arg;
	int               rv;

	nni_mtx_lock(&l->mtx);
	rv = nni_ipc_listener_listen(l->listener, &l->sa);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}

static void
ipctran_listener_cb(void *arg)
{
	ipctran_listener *l = arg;
	nni_aio *         aio;
	int               rv;
	ipctran_pipe *    p = NULL;
	nni_ipc_conn *    conn;

	nni_mtx_lock(&l->mtx);
	rv          = nni_aio_result(l->aio);
	aio         = l->user_aio;
	l->user_aio = NULL;

	if (aio == NULL) {
		nni_mtx_unlock(&l->mtx);
		if (rv == 0) {
			conn = nni_aio_get_output(l->aio, 0);
			nni_ipc_conn_fini(conn);
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

	// Attempt to allocate the parent pipe.  If this fails we'll
	// drop the connection (ENOMEM probably).
	if ((rv = ipctran_pipe_init(&p, conn)) != 0) {
		nni_mtx_unlock(&l->mtx);
		nni_ipc_conn_fini(conn);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->proto  = l->proto;
	p->rcvmax = l->rcvmax;
	p->sa     = l->sa;
	nni_mtx_unlock(&l->mtx);

	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
}

static void
ipctran_listener_cancel(nni_aio *aio, int rv)
{
	ipctran_listener *l = nni_aio_get_prov_data(aio);

	NNI_ASSERT(rv != 0);
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
ipctran_listener_accept(void *arg, nni_aio *aio)
{
	ipctran_listener *l = arg;
	int               rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&l->mtx);
	NNI_ASSERT(l->user_aio == NULL);

	if ((rv = nni_aio_schedule(aio, ipctran_listener_cancel, l)) != 0) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	l->user_aio = aio;

	nni_ipc_listener_accept(l->listener, l->aio);
	nni_mtx_unlock(&l->mtx);
}

static int
ipctran_listener_set_recvmaxsz(
    void *arg, const void *data, size_t sz, nni_opt_type t)
{
	ipctran_listener *l = arg;
	size_t            val;
	int               rv;

	if ((rv = nni_copyin_size(&val, data, sz, 0, NNI_MAXSZ, t)) == 0) {
		nni_mtx_lock(&l->mtx);
		l->rcvmax = val;
		nni_mtx_unlock(&l->mtx);
	}
	return (rv);
}

static int
ipctran_listener_get_recvmaxsz(
    void *arg, void *data, size_t *szp, nni_opt_type t)
{
	ipctran_listener *l = arg;
	int               rv;
	nni_mtx_lock(&l->mtx);
	rv = nni_copyout_size(l->rcvmax, data, szp, t);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}

static int
ipctran_listener_get_locaddr(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	ipctran_listener *l = arg;
	int               rv;

	nni_mtx_lock(&l->mtx);
	rv = nni_copyout_sockaddr(&l->sa, buf, szp, t);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}

static int
ipctran_check_recvmaxsz(const void *data, size_t sz, nni_opt_type t)
{
	return (nni_copyin_size(NULL, data, sz, 0, NNI_MAXSZ, t));
}

static int
ipctran_listener_set_perms(
    void *arg, const void *data, size_t sz, nni_opt_type t)
{
	ipctran_listener *l = arg;
	int               val;
	int               rv;

	// Probably we could further limit this -- most systems don't have
	// meaningful chmod beyond the lower 9 bits.
	if ((rv = nni_copyin_int(&val, data, sz, 0, 0x7FFFFFFF, t)) == 0) {
		nni_mtx_lock(&l->mtx);
		rv = nni_ipc_listener_set_permissions(l->listener, val);
		nni_mtx_unlock(&l->mtx);
	}
	return (rv);
}

static int
ipctran_check_perms(const void *data, size_t sz, nni_opt_type t)
{
	return (nni_copyin_int(NULL, data, sz, 0, 0x7FFFFFFF, t));
}

static int
ipctran_listener_set_sec_desc(
    void *arg, const void *data, size_t sz, nni_opt_type t)
{
	ipctran_listener *l = arg;
	void *            ptr;
	int               rv;

	if ((rv = nni_copyin_ptr(&ptr, data, sz, t)) == 0) {
		nni_mtx_lock(&l->mtx);
		rv =
		    nni_ipc_listener_set_security_descriptor(l->listener, ptr);
		nni_mtx_unlock(&l->mtx);
	}
	return (rv);
}

static int
ipctran_check_sec_desc(const void *data, size_t sz, nni_opt_type t)
{
	return (nni_copyin_ptr(NULL, data, sz, t));
}

static nni_tran_option ipctran_pipe_options[] = {
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = ipctran_pipe_get_addr,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = ipctran_pipe_get_addr,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_UID,
	    .o_type = NNI_TYPE_UINT64,
	    .o_get  = ipctran_pipe_get_peer_uid,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_GID,
	    .o_type = NNI_TYPE_UINT64,
	    .o_get  = ipctran_pipe_get_peer_gid,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_PID,
	    .o_type = NNI_TYPE_UINT64,
	    .o_get  = ipctran_pipe_get_peer_pid,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_ZONEID,
	    .o_type = NNI_TYPE_UINT64,
	    .o_get  = ipctran_pipe_get_peer_zoneid,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_pipe_ops ipctran_pipe_ops = {
	.p_fini    = ipctran_pipe_fini,
	.p_start   = ipctran_pipe_start,
	.p_stop    = ipctran_pipe_stop,
	.p_send    = ipctran_pipe_send,
	.p_recv    = ipctran_pipe_recv,
	.p_close   = ipctran_pipe_close,
	.p_peer    = ipctran_pipe_peer,
	.p_options = ipctran_pipe_options,
};

static nni_tran_option ipctran_dialer_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = ipctran_dialer_get_recvmaxsz,
	    .o_set  = ipctran_dialer_set_recvmaxsz,
	    .o_chk  = ipctran_check_recvmaxsz,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_option ipctran_listener_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_type = NNI_TYPE_SIZE,
	    .o_get  = ipctran_listener_get_recvmaxsz,
	    .o_set  = ipctran_listener_set_recvmaxsz,
	    .o_chk  = ipctran_check_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_type = NNI_TYPE_SOCKADDR,
	    .o_get  = ipctran_listener_get_locaddr,
	},
	{
	    .o_name = NNG_OPT_IPC_SECURITY_DESCRIPTOR,
	    .o_type = NNI_TYPE_POINTER,
	    .o_get  = NULL,
	    .o_set  = ipctran_listener_set_sec_desc,
	    .o_chk  = ipctran_check_sec_desc,
	},
	{
	    .o_name = NNG_OPT_IPC_PERMISSIONS,
	    .o_type = NNI_TYPE_INT32,
	    .o_get  = NULL,
	    .o_set  = ipctran_listener_set_perms,
	    .o_chk  = ipctran_check_perms,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_dialer_ops ipctran_dialer_ops = {
	.d_init    = ipctran_dialer_init,
	.d_fini    = ipctran_dialer_fini,
	.d_connect = ipctran_dialer_connect,
	.d_close   = ipctran_dialer_close,
	.d_options = ipctran_dialer_options,
};

static nni_tran_listener_ops ipctran_listener_ops = {
	.l_init    = ipctran_listener_init,
	.l_fini    = ipctran_listener_fini,
	.l_bind    = ipctran_listener_bind,
	.l_accept  = ipctran_listener_accept,
	.l_close   = ipctran_listener_close,
	.l_options = ipctran_listener_options,
};

static nni_tran ipc_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "ipc",
	.tran_dialer   = &ipctran_dialer_ops,
	.tran_listener = &ipctran_listener_ops,
	.tran_pipe     = &ipctran_pipe_ops,
	.tran_init     = ipctran_init,
	.tran_fini     = ipctran_fini,
};

int
nng_ipc_register(void)
{
	return (nni_tran_register(&ipc_tran));
}
