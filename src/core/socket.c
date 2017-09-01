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

typedef struct nni_sockopt {
	nni_list_node node;
	int           opt;
	size_t        sz;
	void *        data;
} nni_sockopt;

struct nni_socket {
	nni_list_node s_node;
	nni_mtx       s_mx;
	nni_cv        s_cv;
	nni_cv        s_close_cv;

	uint64_t s_id;
	uint32_t s_flags;
	unsigned s_refcnt; // protected by global lock
	void *   s_data;   // Protocol private

	nni_msgq *s_uwq; // Upper write queue
	nni_msgq *s_urq; // Upper read queue

	nni_proto_id s_self_id;
	nni_proto_id s_peer_id;

	nni_proto_pipe_ops s_pipe_ops;
	nni_proto_sock_ops s_sock_ops;

	// XXX: options
	nni_duration s_linger;    // linger time
	nni_duration s_sndtimeo;  // send timeout
	nni_duration s_rcvtimeo;  // receive timeout
	nni_duration s_reconn;    // reconnect time
	nni_duration s_reconnmax; // max reconnect time
	size_t       s_rcvmaxsz;  // max receive size
	nni_list     s_options;   // opts not handled by sock/proto

	nni_list s_eps;   // active endpoints
	nni_list s_pipes; // active pipes

	int s_ep_pend;    // EP dial/listen in progress
	int s_closing;    // Socket is closing
	int s_closed;     // Socket closed, protected by global lock
	int s_besteffort; // Best effort mode delivery
	int s_senderr;    // Protocol state machine use
	int s_recverr;    // Protocol state machine use

	nni_event s_recv_ev; // Event for readability
	nni_event s_send_ev; // Event for sendability

	nni_notifyfd s_send_fd;
	nni_notifyfd s_recv_fd;
};

static void
nni_free_opt(nni_sockopt *opt)
{
	nni_free(opt->data, opt->sz);
	NNI_FREE_STRUCT(opt);
}

uint32_t
nni_sock_id(nni_sock *s)
{
	return ((uint32_t) s->s_id);
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
	nni_mtx_lock(&nni_sock_lk);
	s->s_refcnt--;
	if (s->s_closed && (s->s_refcnt < 2)) {
		nni_cv_wake(&s->s_close_cv);
	}
	nni_mtx_unlock(&nni_sock_lk);
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
	return (rv);
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

	if (nni_aio_result(notify->n_aio) != 0) {
		return;
	}

	notify->n_func(&sock->s_send_ev, notify->n_arg);
}

static void
nni_sock_canrecv_cb(void *arg)
{
	nni_notify *notify = arg;
	nni_sock *  sock   = notify->n_sock;

	if (nni_aio_result(notify->n_aio) != 0) {
		return;
	}

	notify->n_func(&sock->s_recv_ev, notify->n_arg);
}

nni_notify *
nni_sock_notify(nni_sock *sock, int type, nng_notify_func fn, void *arg)
{
	nni_notify *notify;

	if ((notify = NNI_ALLOC_STRUCT(notify)) == NULL) {
		return (NULL);
	}

	notify->n_func = fn;
	notify->n_arg  = arg;
	notify->n_type = type;
	notify->n_sock = sock;

	switch (type) {
	case NNG_EV_CAN_RCV:
		nni_aio_init(&notify->n_aio, nni_sock_canrecv_cb, notify);
		nni_msgq_aio_notify_get(sock->s_urq, notify->n_aio);
		break;
	case NNG_EV_CAN_SND:
		nni_aio_init(&notify->n_aio, nni_sock_cansend_cb, notify);
		nni_msgq_aio_notify_put(sock->s_uwq, notify->n_aio);
		break;
	default:
		NNI_FREE_STRUCT(notify);
		return (NULL);
	}

	return (notify);
}

void
nni_sock_unnotify(nni_sock *sock, nni_notify *notify)
{
	nni_aio_fini(notify->n_aio);
	NNI_FREE_STRUCT(notify);
}

static void
nni_sock_destroy(nni_sock *s)
{
	nni_sockopt *sopt;

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

	while ((sopt = nni_list_first(&s->s_options)) != NULL) {
		nni_list_remove(&s->s_options, sopt);
		nni_free_opt(sopt);
	}

	// This exists to silence a false positive in helgrind.
	nni_mtx_lock(&s->s_mx);
	nni_mtx_unlock(&s->s_mx);

	nni_ev_fini(&s->s_send_ev);
	nni_ev_fini(&s->s_recv_ev);
	nni_msgq_fini(s->s_urq);
	nni_msgq_fini(s->s_uwq);
	nni_cv_fini(&s->s_close_cv);
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
	s->s_sndtimeo        = NNI_TIME_NEVER;
	s->s_rcvtimeo        = NNI_TIME_NEVER;
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
	NNI_LIST_INIT(&s->s_options, nni_sockopt, node);
	nni_pipe_sock_list_init(&s->s_pipes);
	nni_ep_list_init(&s->s_eps);
	nni_mtx_init(&s->s_mx);
	nni_cv_init(&s->s_cv, &s->s_mx);
	nni_cv_init(&s->s_close_cv, &nni_sock_lk);
	nni_ev_init(&s->s_recv_ev, NNG_EV_CAN_RCV, s);
	nni_ev_init(&s->s_send_ev, NNG_EV_CAN_SND, s);

	if (((rv = nni_msgq_init(&s->s_uwq, 0)) != 0) ||
	    ((rv = nni_msgq_init(&s->s_urq, 0)) != 0) ||
	    ((rv = s->s_sock_ops.sock_init(&s->s_data, s)) != 0) ||
	    ((rv = nni_sock_setopt(s, nng_optid_linger, &s->s_linger,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, nng_optid_sendtimeo, &s->s_sndtimeo,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, nng_optid_recvtimeo, &s->s_rcvtimeo,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, nng_optid_reconnmint, &s->s_reconn,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, nng_optid_reconnmaxt, &s->s_reconnmax,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, nng_optid_recvmaxsz, &s->s_rcvmaxsz,
	          sizeof(size_t))) != 0)) {
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
	nni_mtx_init(&nni_sock_lk);

	if ((rv = nni_idhash_init(&nni_sock_hash)) != 0) {
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

	// Wait for all other references to drop.  Note that we
	// have a reference already (from our caller).
	while (s->s_refcnt > 1) {
		nni_cv_wait(&s->s_close_cv);
	}
	nni_mtx_unlock(&nni_sock_lk);

	// Wait for pipe and eps to finish closing.
	nni_mtx_lock(&s->s_mx);
	while (
	    (!nni_list_empty(&s->s_pipes)) || (!nni_list_empty(&s->s_eps))) {
		nni_cv_wait(&s->s_cv);
	}
	nni_mtx_unlock(&s->s_mx);

	nni_sock_destroy(s);
}

void
nni_sock_closeall(void)
{
	nni_sock *s;

	if (nni_sock_hash == NULL) {
		return;
	}
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
nni_sock_sendmsg(nni_sock *sock, nni_msg *msg, int flags)
{
	int      rv;
	int      besteffort;
	nni_time expire;
	nni_time timeo = sock->s_sndtimeo;

	if ((flags == NNG_FLAG_NONBLOCK) || (timeo == 0)) {
		expire = NNI_TIME_ZERO;
	} else if (timeo == NNI_TIME_NEVER) {
		expire = NNI_TIME_NEVER;
	} else {
		expire = nni_clock();
		expire += timeo;
	}

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
nni_sock_recvmsg(nni_sock *sock, nni_msg **msgp, int flags)
{
	int      rv;
	nni_msg *msg;
	nni_time expire;
	nni_time timeo = sock->s_rcvtimeo;

	if ((flags == NNG_FLAG_NONBLOCK) || (timeo == 0)) {
		expire = NNI_TIME_ZERO;
	} else if (timeo == NNI_TIME_NEVER) {
		expire = NNI_TIME_NEVER;
	} else {
		expire = nni_clock();
		expire += timeo;
	}

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
nni_sock_ep_add(nni_sock *s, nni_ep *ep)
{
	nni_sockopt *sopt;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}
	NNI_LIST_FOREACH (&s->s_options, sopt) {
		int rv;
		rv = nni_ep_setopt(ep, sopt->opt, sopt->data, sopt->sz, 0);
		if ((rv != 0) && (rv != NNG_ENOTSUP)) {
			nni_mtx_unlock(&s->s_mx);
			return (rv);
		}
	}
	nni_list_append(&s->s_eps, ep);
	nni_mtx_unlock(&s->s_mx);
	return (0);
}

void
nni_sock_ep_remove(nni_sock *sock, nni_ep *ep)
{
	nni_mtx_lock(&sock->s_mx);
	if (nni_list_active(&sock->s_eps, ep)) {
		nni_list_remove(&sock->s_eps, ep);
		if ((sock->s_closing) && (nni_list_empty(&sock->s_eps))) {
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
nni_sock_setopt(nni_sock *s, int opt, const void *val, size_t size)
{
	int          rv = NNG_ENOTSUP;
	nni_ep *     ep;
	int          commits = 0;
	nni_sockopt *optv;
	nni_sockopt *oldv = NULL;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}
	if (s->s_sock_ops.sock_setopt != NULL) {
		rv = s->s_sock_ops.sock_setopt(s->s_data, opt, val, size);
		if (rv != NNG_ENOTSUP) {
			nni_mtx_unlock(&s->s_mx);
			return (rv);
		}
	}

	// Some options do not go down to transports.  Handle them
	// directly.
	if (opt == nng_optid_reconnmint) {
		rv = nni_setopt_usec(&s->s_reconn, val, size);
	} else if (opt == nng_optid_reconnmaxt) {
		rv = nni_setopt_usec(&s->s_reconnmax, val, size);
	} else if (opt == nng_optid_sendbuf) {
		rv = nni_setopt_buf(s->s_uwq, val, size);
	} else if (opt == nng_optid_recvbuf) {
		rv = nni_setopt_buf(s->s_urq, val, size);
	} else if ((opt == nng_optid_sendfd) || (opt == nng_optid_recvfd) ||
	    (opt == nng_optid_locaddr) || (opt == nng_optid_remaddr)) {
		// these options can be read, but cannot be set
		rv = NNG_EINVAL;
	}

	nni_mtx_unlock(&s->s_mx);

	// If the option was already handled one way or the other,
	if (rv != NNG_ENOTSUP) {
		return (rv);
	}

	// Validation of transport options.  This is stateless, so
	// transports should not fail to set an option later if they
	// passed it here.
	rv = nni_tran_chkopt(opt, val, size);

	// Also check a few generic things.  We do this if no transport
	// check was found, or even if a transport rejected one of the
	// settings.
	if ((rv == NNG_ENOTSUP) || (rv == 0)) {
		if ((opt == nng_optid_linger) ||
		    (opt == nng_optid_sendtimeo) ||
		    (opt == nng_optid_recvtimeo)) {
			rv = nni_chkopt_usec(val, size);
		} else if (opt == nng_optid_recvmaxsz) {
			// just a sanity test on the size; it also ensures that
			// a size can be set even with no transport configured.
			rv = nni_chkopt_size(val, size, 0, NNI_MAXSZ);
		}
	}

	if (rv != 0) {
		return (rv);
	}

	// Prepare a copy of the sockoption.
	if ((optv = NNI_ALLOC_STRUCT(optv)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((optv->data = nni_alloc(size)) == NULL) {
		NNI_FREE_STRUCT(optv);
		return (NNG_ENOMEM);
	}
	memcpy(optv->data, val, size);
	optv->opt = opt;
	optv->sz  = size;
	NNI_LIST_NODE_INIT(&optv->node);

	nni_mtx_lock(&s->s_mx);
	NNI_LIST_FOREACH (&s->s_options, oldv) {
		if (oldv->opt == opt) {
			if ((oldv->sz != size) ||
			    (memcmp(oldv->data, val, size) != 0)) {
				break;
			}

			// The values are the same.  This is a no-op.
			nni_mtx_unlock(&s->s_mx);
			nni_free_opt(optv);
			return (0);
		}
	}

	// Apply the options.  Failure to set any option on any transport
	// (other than ENOTSUP) stops the operation altogether.  Its
	// important that transport wide checks properly pre-validate.
	NNI_LIST_FOREACH (&s->s_eps, ep) {
		int x;
		x = nni_ep_setopt(ep, opt, optv->data, size, 0);
		if (x != NNG_ENOTSUP) {
			if ((rv = x) != 0) {
				nni_mtx_unlock(&s->s_mx);
				nni_free_opt(optv);
				return (rv);
			}
		}
	}

	// For some options, which also have an impact on the socket
	// behavior, we save a local value.  Note that the transport
	// will already have had a chance to veto this.

	if (opt == nng_optid_linger) {
		rv = nni_setopt_usec(&s->s_linger, val, size);
	} else if (opt == nng_optid_sendtimeo) {
		rv = nni_setopt_usec(&s->s_sndtimeo, val, size);
	} else if (opt == nng_optid_recvtimeo) {
		rv = nni_setopt_usec(&s->s_rcvtimeo, val, size);
	}

	if (rv == 0) {
		// Remove and toss the old value, we are using a new one.
		if (oldv != NULL) {
			nni_list_remove(&s->s_options, oldv);
			nni_free_opt(oldv);
		}

		// Insert our new value.  This permits it to be compared
		// against later, and for new endpoints to automatically
		// receive these values,
		nni_list_append(&s->s_options, optv);
	} else {
		nni_free_opt(optv);
	}

	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

int
nni_sock_getopt(nni_sock *s, int opt, void *val, size_t *szp)
{
	int          rv = NNG_ENOTSUP;
	nni_sockopt *sopt;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}
	if (s->s_sock_ops.sock_getopt != NULL) {
		rv = s->s_sock_ops.sock_getopt(s->s_data, opt, val, szp);
		if (rv != NNG_ENOTSUP) {
			nni_mtx_unlock(&s->s_mx);
			return (rv);
		}
	}

	// Options that are handled by socket core, and never
	// passed down.
	if (opt == nng_optid_sendbuf) {
		rv = nni_getopt_buf(s->s_uwq, val, szp);
	} else if (opt == nng_optid_recvbuf) {
		rv = nni_getopt_buf(s->s_urq, val, szp);
	} else if (opt == nng_optid_sendfd) {
		rv = nni_getopt_fd(s, &s->s_send_fd, NNG_EV_CAN_SND, val, szp);
	} else if (opt == nng_optid_recvfd) {
		rv = nni_getopt_fd(s, &s->s_recv_fd, NNG_EV_CAN_RCV, val, szp);
	} else if (opt == nng_optid_reconnmint) {
		rv = nni_getopt_usec(&s->s_reconn, val, szp);
	} else if (opt == nng_optid_reconnmaxt) {
		rv = nni_getopt_usec(&s->s_reconnmax, val, szp);
	} else {
		NNI_LIST_FOREACH (&s->s_options, sopt) {
			if (sopt->opt == opt) {
				size_t sz = sopt->sz;
				if (sopt->sz > *szp) {
					sz = *szp;
				}
				*szp = sopt->sz;
				memcpy(val, sopt->data, sz);
				rv = 0;
				break;
			}
		}
	}
	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

uint32_t
nni_sock_flags(nni_sock *sock)
{
	return (sock->s_flags);
}
