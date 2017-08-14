//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <string.h>

// Socket implementation.

static nni_list    nni_sock_list;
static nni_idhash *nni_sock_hash;
static nni_mtx     nni_sock_lk;

uint32_t
nni_sock_id(nni_sock *s)
{
	return (s->s_id);
}

// nni_sock_sendq and nni_sock_recvq are called by the protocol to obtain
// the upper read and write queues.
nni_msgq *
nni_sock_sendq(nni_sock *s)
{
	return (s->s_uwq);
}

nni_msgq *
nni_sock_recvq(nni_sock *s)
{
	return (s->s_urq);
}

int
nni_sock_find(nni_sock **sockp, uint32_t id)
{
	int       rv;
	nni_sock *s;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	nni_mtx_lock(&nni_sock_lk);
	if ((rv = nni_idhash_find(nni_sock_hash, id, (void **) &s)) == 0) {
		if (s->s_closed) {
			rv = NNG_ECLOSED;
		} else {
			s->s_refcnt++;
			*sockp = s;
		}
	}
	nni_mtx_unlock(&nni_sock_lk);

	return (rv);
}

void
nni_sock_rele(nni_sock *s)
{
	nni_mtx_lock(&s->s_mx);
	s->s_refcnt--;
	if (s->s_closing) {
		nni_cv_wake(&s->s_cv);
	}
	nni_mtx_unlock(&s->s_mx);
}

int
nni_sock_pipe_start(nni_sock *s, nni_pipe *pipe)
{
	void *pdata = nni_pipe_get_proto_data(pipe);
	int   rv;

	NNI_ASSERT(s != NULL);
	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		// We're closing, bail out.
		rv = NNG_ECLOSED;
	} else if (nni_pipe_peer(pipe) != s->s_peer_id.p_id) {
		// Peer protocol mismatch.
		rv = NNG_EPROTO;
	} else {
		// Protocol can reject for other reasons.
		rv = s->s_pipe_ops.pipe_start(pdata);
	}
	nni_mtx_unlock(&s->s_mx);
	return (0);
}

int
nni_sock_pipe_init(nni_sock *s, nni_pipe *p, void **datap)
{
	return (s->s_pipe_ops.pipe_init(datap, p, s->s_data));
}

void
nni_sock_pipe_fini(nni_sock *s, void *data)
{
	if (data != NULL) {
		s->s_pipe_ops.pipe_fini(data);
	}
}

int
nni_sock_pipe_add(nni_sock *s, nni_pipe *p)
{
	int   rv;
	void *pdata;

	if ((rv = s->s_pipe_ops.pipe_init(&pdata, p, s->s_data)) != 0) {
		return (rv);
	}
	nni_pipe_set_proto_data(p, pdata);

	// Initialize protocol pipe data.
	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	nni_list_append(&s->s_pipes, p);

	// Start the initial negotiation I/O...
	nni_pipe_start(p);

	nni_mtx_unlock(&s->s_mx);
	return (0);
}

void
nni_sock_pipe_remove(nni_sock *sock, nni_pipe *pipe)
{
	void *pdata;

	pdata = nni_pipe_get_proto_data(pipe);

	if (pdata != NULL) {
		nni_mtx_lock(&sock->s_mx);
		sock->s_pipe_ops.pipe_stop(pdata);
		if (nni_list_active(&sock->s_pipes, pipe)) {
			nni_list_remove(&sock->s_pipes, pipe);
			if (sock->s_closing &&
			    nni_list_empty(&sock->s_pipes)) {
				nni_cv_wake(&sock->s_cv);
			}
		}
		sock->s_pipe_ops.pipe_fini(pdata);
		nni_pipe_set_proto_data(pipe, NULL);
		nni_mtx_unlock(&sock->s_mx);
	}
}

void
nni_sock_lock(nni_sock *sock)
{
	nni_mtx_lock(&sock->s_mx);
}

void
nni_sock_unlock(nni_sock *sock)
{
	nni_mtx_unlock(&sock->s_mx);
}

static void
nni_sock_cansend_cb(void *arg)
{
	nni_notify *notify = arg;
	nni_sock *  sock   = notify->n_sock;

	if (nni_aio_result(&notify->n_aio) != 0) {
		return;
	}

	notify->n_func(&sock->s_send_ev, notify->n_arg);
}

static void
nni_sock_canrecv_cb(void *arg)
{
	nni_notify *notify = arg;
	nni_sock *  sock   = notify->n_sock;

	if (nni_aio_result(&notify->n_aio) != 0) {
		return;
	}

	notify->n_func(&sock->s_recv_ev, notify->n_arg);
}

nni_notify *
nni_sock_notify(nni_sock *sock, int type, nng_notify_func fn, void *arg)
{
	nni_notify *notify;
	int         rv;

	if ((notify = NNI_ALLOC_STRUCT(notify)) == NULL) {
		return (NULL);
	}

	notify->n_func = fn;
	notify->n_arg  = arg;
	notify->n_type = type;
	notify->n_sock = sock;

	switch (type) {
	case NNG_EV_CAN_RCV:
		rv = nni_aio_init(&notify->n_aio, nni_sock_canrecv_cb, notify);
		if (rv != 0) {
			goto fail;
		}
		nni_msgq_aio_notify_get(sock->s_urq, &notify->n_aio);
		break;
	case NNG_EV_CAN_SND:
		rv = nni_aio_init(&notify->n_aio, nni_sock_cansend_cb, notify);
		if (rv != 0) {
			goto fail;
		}
		nni_msgq_aio_notify_put(sock->s_uwq, &notify->n_aio);
		break;
	default:
		rv = NNG_ENOTSUP;
		goto fail;
		break;
	}

	return (notify);

fail:
	nni_aio_fini(&notify->n_aio);
	NNI_FREE_STRUCT(notify);
	return (NULL);
}

void
nni_sock_unnotify(nni_sock *sock, nni_notify *notify)
{
	nni_aio_fini(&notify->n_aio);
	NNI_FREE_STRUCT(notify);
}

static void
nni_sock_destroy(nni_sock *s)
{
	if (s == NULL) {
		return;
	}

	// Close any open notification pipes.
	if (s->s_recv_fd.sn_init) {
		nni_plat_pipe_close(s->s_recv_fd.sn_wfd, s->s_recv_fd.sn_rfd);
	}
	if (s->s_send_fd.sn_init) {
		nni_plat_pipe_close(s->s_send_fd.sn_wfd, s->s_send_fd.sn_rfd);
	}

	// The protocol needs to clean up its state.
	if (s->s_data != NULL) {
		s->s_sock_ops.sock_fini(s->s_data);
	}

	nni_ev_fini(&s->s_send_ev);
	nni_ev_fini(&s->s_recv_ev);
	nni_msgq_fini(s->s_urq);
	nni_msgq_fini(s->s_uwq);
	nni_cv_fini(&s->s_cv);
	nni_mtx_fini(&s->s_mx);
	NNI_FREE_STRUCT(s);
}

static int
nni_sock_create(nni_sock **sp, const nni_proto *proto)
{
	int       rv;
	nni_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	s->s_linger          = 0;
	s->s_sndtimeo        = -1;
	s->s_rcvtimeo        = -1;
	s->s_closing         = 0;
	s->s_reconn          = NNI_SECOND;
	s->s_reconnmax       = 0;
	s->s_rcvmaxsz        = 1024 * 1024; // 1 MB by default
	s->s_id              = 0;
	s->s_refcnt          = 0;
	s->s_send_fd.sn_init = 0;
	s->s_recv_fd.sn_init = 0;
	s->s_self_id         = proto->proto_self;
	s->s_peer_id         = proto->proto_peer;
	s->s_flags           = proto->proto_flags;
	s->s_sock_ops        = *proto->proto_sock_ops;
	s->s_pipe_ops        = *proto->proto_pipe_ops;

	NNI_ASSERT(s->s_sock_ops.sock_open != NULL);
	NNI_ASSERT(s->s_sock_ops.sock_close != NULL);

	NNI_ASSERT(s->s_pipe_ops.pipe_start != NULL);
	NNI_ASSERT(s->s_pipe_ops.pipe_stop != NULL);

	NNI_LIST_NODE_INIT(&s->s_node);
	nni_pipe_sock_list_init(&s->s_pipes);
	nni_ep_list_init(&s->s_eps);

	if (((rv = nni_mtx_init(&s->s_mx)) != 0) ||
	    ((rv = nni_cv_init(&s->s_cv, &s->s_mx)) != 0) ||
	    ((rv = nni_ev_init(&s->s_recv_ev, NNG_EV_CAN_RCV, s)) != 0) ||
	    ((rv = nni_ev_init(&s->s_send_ev, NNG_EV_CAN_SND, s)) != 0) ||
	    ((rv = nni_msgq_init(&s->s_uwq, 0)) != 0) ||
	    ((rv = nni_msgq_init(&s->s_urq, 0)) != 0) ||
	    ((rv = s->s_sock_ops.sock_init(&s->s_data, s)) != 0)) {
		nni_sock_destroy(s);
		return (rv);
	}
	*sp = s;
	return (rv);
}

int
nni_sock_sys_init(void)
{
	int rv;

	NNI_LIST_INIT(&nni_sock_list, nni_sock, s_node);
	if (((rv = nni_idhash_init(&nni_sock_hash)) != 0) ||
	    ((rv = nni_mtx_init(&nni_sock_lk)) != 0)) {
		nni_sock_sys_fini();
	} else {
		nni_idhash_set_limits(nni_sock_hash, 1, 0x7fffffff, 1);
	}
	return (rv);
}

void
nni_sock_sys_fini(void)
{
	nni_idhash_fini(nni_sock_hash);
	nni_sock_hash = NULL;
	nni_mtx_fini(&nni_sock_lk);
}

int
nni_sock_open(nni_sock **sockp, const nni_proto *proto)
{
	nni_sock *s = NULL;
	int       rv;

	if (proto->proto_version != NNI_PROTOCOL_VERSION) {
		// unsupported protocol version
		return (NNG_ENOTSUP);
	}

	if (((rv = nni_init()) != 0) ||
	    ((rv = nni_sock_create(&s, proto)) != 0)) {
		nni_sock_destroy(s);
		return (rv);
	}

	nni_mtx_lock(&nni_sock_lk);
	if ((rv = nni_idhash_alloc(nni_sock_hash, &s->s_id, s)) != 0) {
		nni_sock_destroy(s);
	} else {
		nni_list_append(&nni_sock_list, s);
		s->s_sock_ops.sock_open(s->s_data);
		*sockp = s;
	}
	nni_mtx_unlock(&nni_sock_lk);

	return (rv);
}

// nni_sock_shutdown shuts down the socket; after this point no further
// access to the socket will function, and any threads blocked in entry
// points will be woken (and the functions they are blocked in will return
// NNG_ECLOSED.)
int
nni_sock_shutdown(nni_sock *sock)
{
	nni_pipe *pipe;
	nni_ep *  ep;
	nni_ep *  nep;
	nni_time  linger;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	// Mark us closing, so no more EPs or changes can occur.
	sock->s_closing = 1;

	// Special optimization; if there are no pipes connected,
	// then there is no reason to linger since there's nothing that
	// could possibly send this data out.
	if (nni_list_first(&sock->s_pipes) == NULL) {
		linger = NNI_TIME_ZERO;
	} else {
		linger = nni_clock() + sock->s_linger;
	}

	// Close the EPs. This prevents new connections from forming but
	// but allows existing ones to drain.
	NNI_LIST_FOREACH (&sock->s_eps, ep) {
		nni_ep_shutdown(ep);
	}
	nni_mtx_unlock(&sock->s_mx);

	// We drain the upper write queue.  This is just like closing it,
	// except that the protocol gets a chance to get the messages and
	// push them down to the transport.  This operation can *block*
	// until the linger time has expired.
	nni_msgq_drain(sock->s_uwq, linger);

	// Generally, unless the protocol is blocked trying to perform
	// writes (e.g. a slow reader on the other side), it should be
	// trying to shut things down.  We wait to give it
	// a chance to do so gracefully.
	nni_mtx_lock(&sock->s_mx);
	while (nni_list_first(&sock->s_pipes) != NULL) {
		if (nni_cv_until(&sock->s_cv, linger) == NNG_ETIMEDOUT) {
			break;
		}
	}

	// At this point, we've done everything we politely can to give
	// the protocol a chance to flush its write side.  Now its time
	// to be a little more insistent.

	// Close the upper queues immediately.  This can happen
	// safely while we hold the lock.
	nni_msgq_close(sock->s_urq);
	nni_msgq_close(sock->s_uwq);

	// Go through the endpoint list, attempting to close them.
	// We might already have a close in progress, in which case
	// we skip past it; it will be removed from another thread.
	nep = nni_list_first(&sock->s_eps);
	while ((ep = nep) != NULL) {
		nep = nni_list_next(&sock->s_eps, nep);

		if (nni_ep_hold(ep) == 0) {
			nni_mtx_unlock(&sock->s_mx);
			nni_ep_close(ep);
			nni_mtx_lock(&sock->s_mx);
		}
	}

	// For each pipe, arrange for it to teardown hard.
	NNI_LIST_FOREACH (&sock->s_pipes, pipe) {
		nni_pipe_stop(pipe);
	}

	// We have to wait for *both* endpoints and pipes to be removed.
	while ((!nni_list_empty(&sock->s_pipes)) ||
	    (!nni_list_empty(&sock->s_eps))) {
		nni_cv_wait(&sock->s_cv);
	}

	sock->s_sock_ops.sock_close(sock->s_data);

	nni_cv_wake(&sock->s_cv);

	NNI_ASSERT(nni_list_first(&sock->s_pipes) == NULL);

	nni_mtx_unlock(&sock->s_mx);

	// At this point, there are no threads blocked inside of us
	// that are referencing socket state.  User code should call
	// nng_close to release the last resources.
	return (0);
}

// nni_sock_close shuts down the socket, then releases any resources
// associated with it.  It is a programmer error to reference the socket
// after this function is called, as the pointer may reference invalid
// memory or other objects.
void
nni_sock_close(nni_sock *s)
{
	// Shutdown everything if not already done.  This operation
	// is idempotent.
	nni_sock_shutdown(s);

	nni_mtx_lock(&nni_sock_lk);
	if (s->s_closed) {
		// Some other thread called close.  All we need to do is
		// drop our reference count.
		nni_mtx_unlock(&nni_sock_lk);
		nni_sock_rele(s);
		return;
	}
	s->s_closed = 1;
	nni_idhash_remove(nni_sock_hash, s->s_id);

	// We might have been removed from the list already, e.g. by
	// nni_sock_closeall.  This is idempotent.
	nni_list_node_remove(&s->s_node);

	nni_mtx_unlock(&nni_sock_lk);

	// Wait for all other references to drop.  Note that we
	// have a reference already (from our caller).
	nni_mtx_lock(&s->s_mx);
	while ((s->s_refcnt > 1) || (!nni_list_empty(&s->s_pipes)) ||
	    (!nni_list_empty(&s->s_eps))) {
		nni_cv_wait(&s->s_cv);
	}
	nni_mtx_unlock(&s->s_mx);

	nni_sock_destroy(s);
}

void
nni_sock_closeall(void)
{
	nni_sock *s;

	for (;;) {
		nni_mtx_lock(&nni_sock_lk);
		if ((s = nni_list_first(&nni_sock_list)) == NULL) {
			nni_mtx_unlock(&nni_sock_lk);
			return;
		}
		// Bump the reference count.  The close call below will
		// drop it.
		s->s_refcnt++;
		nni_list_node_remove(&s->s_node);
		nni_mtx_unlock(&nni_sock_lk);
		nni_sock_close(s);
	}
}

int
nni_sock_sendmsg(nni_sock *sock, nni_msg *msg, nni_time expire)
{
	int rv;
	int besteffort;

	// Senderr is typically set by protocols when the state machine
	// indicates that it is no longer valid to send a message.  E.g.
	// a REP socket with no REQ pending.
	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	if ((rv = sock->s_senderr) != 0) {
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}
	besteffort = sock->s_besteffort;

	if (sock->s_sock_ops.sock_sfilter != NULL) {
		msg = sock->s_sock_ops.sock_sfilter(sock->s_data, msg);
	}
	nni_mtx_unlock(&sock->s_mx);

	if (msg == NULL) {
		return (0);
	}

	if (besteffort) {
		// BestEffort mode -- if we cannot handle the message due to
		// backpressure, we just throw it away, and don't complain.
		expire = NNI_TIME_ZERO;
	}
	if (sock->s_send_fd.sn_init) {
		nni_plat_pipe_clear(sock->s_send_fd.sn_rfd);
	}
	rv = nni_msgq_put_until(sock->s_uwq, msg, expire);
	if (besteffort && (rv == NNG_ETIMEDOUT)) {
		// Pretend this worked... it didn't, but pretend.
		nni_msg_free(msg);
		return (0);
	}
	return (rv);
}

int
nni_sock_recvmsg(nni_sock *sock, nni_msg **msgp, nni_time expire)
{
	int      rv;
	nni_msg *msg;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	if ((rv = sock->s_recverr) != 0) {
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}
	nni_mtx_unlock(&sock->s_mx);

	if (sock->s_recv_fd.sn_init) {
		nni_plat_pipe_clear(sock->s_recv_fd.sn_rfd);
	}

	for (;;) {
		rv = nni_msgq_get_until(sock->s_urq, &msg, expire);
		if (rv != 0) {
			return (rv);
		}
		if (sock->s_sock_ops.sock_rfilter != NULL) {
			nni_mtx_lock(&sock->s_mx);
			msg = sock->s_sock_ops.sock_rfilter(sock->s_data, msg);
			nni_mtx_unlock(&sock->s_mx);
		}
		if (msg != NULL) {
			break;
		}
		// Protocol dropped the message; try again.
	}

	*msgp = msg;
	return (0);
}

// nni_sock_protocol returns the socket's 16-bit protocol number.
uint16_t
nni_sock_proto(nni_sock *sock)
{
	return (sock->s_self_id.p_id);
}

uint16_t
nni_sock_peer(nni_sock *sock)
{
	return (sock->s_peer_id.p_id);
}

nni_duration
nni_sock_linger(nni_sock *sock)
{
	return (sock->s_linger);
}

size_t
nni_sock_rcvmaxsz(nni_sock *sock)
{
	return (sock->s_rcvmaxsz);
}

void
nni_sock_reconntimes(nni_sock *sock, nni_duration *rcur, nni_duration *rmax)
{
	// These two values are linked, so get them atomically.
	nni_mtx_lock(&sock->s_mx);
	*rcur = sock->s_reconn;
	*rmax = sock->s_reconnmax ? sock->s_reconnmax : sock->s_reconn;
	nni_mtx_unlock(&sock->s_mx);
}

int
nni_sock_ep_add(nni_sock *sock, nni_ep *ep)
{
	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	nni_list_append(&sock->s_eps, ep);
	nni_mtx_unlock(&sock->s_mx);
	return (0);
}

void
nni_sock_ep_remove(nni_sock *sock, nni_ep *ep)
{
	nni_mtx_lock(&sock->s_mx);
	if (nni_list_active(&sock->s_eps, ep)) {
		nni_list_remove(&sock->s_eps, ep);
		if ((sock->s_closed) && (nni_list_empty(&sock->s_eps))) {
			nni_cv_wake(&sock->s_cv);
		}
	}
	nni_mtx_unlock(&sock->s_mx);
}

void
nni_sock_recverr(nni_sock *sock, int err)
{
	sock->s_recverr = err;
}

void
nni_sock_senderr(nni_sock *sock, int err)
{
	sock->s_senderr = err;
}

int
nni_sock_setopt(nni_sock *sock, int opt, const void *val, size_t size)
{
	int rv = NNG_ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	if (sock->s_sock_ops.sock_setopt != NULL) {
		rv =
		    sock->s_sock_ops.sock_setopt(sock->s_data, opt, val, size);
		if (rv != NNG_ENOTSUP) {
			nni_mtx_unlock(&sock->s_mx);
			return (rv);
		}
	}
	switch (opt) {
	case NNG_OPT_LINGER:
		rv = nni_setopt_duration(&sock->s_linger, val, size);
		break;
	case NNG_OPT_SNDTIMEO:
		rv = nni_setopt_duration(&sock->s_sndtimeo, val, size);
		break;
	case NNG_OPT_RCVTIMEO:
		rv = nni_setopt_duration(&sock->s_rcvtimeo, val, size);
		break;
	case NNG_OPT_RECONN_TIME:
		rv = nni_setopt_duration(&sock->s_reconn, val, size);
		break;
	case NNG_OPT_RECONN_MAXTIME:
		rv = nni_setopt_duration(&sock->s_reconnmax, val, size);
		break;
	case NNG_OPT_SNDBUF:
		rv = nni_setopt_buf(sock->s_uwq, val, size);
		break;
	case NNG_OPT_RCVBUF:
		rv = nni_setopt_buf(sock->s_urq, val, size);
		break;
	case NNG_OPT_RCVMAXSZ:
		rv = nni_setopt_size(
		    &sock->s_rcvmaxsz, val, size, 0, NNI_MAXSZ);
		break;
	}
	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}

int
nni_sock_getopt(nni_sock *sock, int opt, void *val, size_t *sizep)
{
	int rv = NNG_ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	if (sock->s_sock_ops.sock_getopt != NULL) {
		rv = sock->s_sock_ops.sock_getopt(
		    sock->s_data, opt, val, sizep);
		if (rv != NNG_ENOTSUP) {
			nni_mtx_unlock(&sock->s_mx);
			return (rv);
		}
	}

	switch (opt) {
	case NNG_OPT_LINGER:
		rv = nni_getopt_duration(&sock->s_linger, val, sizep);
		break;
	case NNG_OPT_SNDTIMEO:
		rv = nni_getopt_duration(&sock->s_sndtimeo, val, sizep);
		break;
	case NNG_OPT_RCVTIMEO:
		rv = nni_getopt_duration(&sock->s_rcvtimeo, val, sizep);
		break;
	case NNG_OPT_RECONN_TIME:
		rv = nni_getopt_duration(&sock->s_reconn, val, sizep);
		break;
	case NNG_OPT_RECONN_MAXTIME:
		rv = nni_getopt_duration(&sock->s_reconnmax, val, sizep);
		break;
	case NNG_OPT_SNDBUF:
		rv = nni_getopt_buf(sock->s_uwq, val, sizep);
		break;
	case NNG_OPT_RCVBUF:
		rv = nni_getopt_buf(sock->s_urq, val, sizep);
		break;
	case NNG_OPT_RCVMAXSZ:
		rv = nni_getopt_size(&sock->s_rcvmaxsz, val, sizep);
		break;
	case NNG_OPT_SNDFD:
		rv = nni_getopt_fd(
		    sock, &sock->s_send_fd, NNG_EV_CAN_SND, val, sizep);
		break;
	case NNG_OPT_RCVFD:
		rv = nni_getopt_fd(
		    sock, &sock->s_recv_fd, NNG_EV_CAN_RCV, val, sizep);
		break;
	}
	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}
