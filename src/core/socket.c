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

static nni_objhash *nni_socks = NULL;

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
	nni_sock *sock;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_objhash_find(nni_socks, id, (void **) &sock)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&sock->s_mx);
	if ((sock->s_closed) || (sock->s_data == NULL)) {
		nni_objhash_unref(nni_socks, id);
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	nni_mtx_unlock(&sock->s_mx);

	if (sockp != NULL) {
		*sockp = sock;
	}

	return (0);
}

void
nni_sock_rele(nni_sock *sock)
{
	nni_objhash_unref(nni_socks, sock->s_id);
}

static int
nni_sock_pipe_start(nni_pipe *pipe)
{
	nni_sock *sock  = pipe->p_sock;
	void *    pdata = nni_pipe_get_proto_data(pipe);
	int       rv;

	NNI_ASSERT(sock != NULL);
	if (sock->s_closing) {
		// We're closing, bail out.
		return (NNG_ECLOSED);
	}
	if (nni_pipe_peer(pipe) != sock->s_peer) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}
	if ((rv = sock->s_pipe_ops.pipe_start(pdata)) != 0) {
		// Protocol rejection for other reasons.
		// E.g. pair and already have active connected partner.
		return (rv);
	}
	return (0);
}

static void
nni_sock_pipe_start_cb(void *arg)
{
	nni_pipe *pipe = arg;
	nni_aio * aio  = &pipe->p_start_aio;

	if (nni_aio_result(aio) != 0) {
		// Failed I/O during start, abort everything.
		nni_pipe_stop(pipe);
		return;
	}
	if (nni_sock_pipe_start(pipe) != 0) {
		nni_pipe_stop(pipe);
		return;
	}
}

int
nni_sock_pipe_add(nni_sock *sock, nni_ep *ep, nni_pipe *pipe)
{
	int rv;

	// Initialize protocol pipe data.
	nni_mtx_lock(&sock->s_mx);
	nni_mtx_lock(&ep->ep_mtx);

	if ((sock->s_closing) || (ep->ep_closed)) {
		nni_mtx_unlock(&ep->ep_mtx);
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	rv = nni_aio_init(&pipe->p_start_aio, nni_sock_pipe_start_cb, pipe);
	if (rv != 0) {
		nni_mtx_unlock(&ep->ep_mtx);
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}

	rv = sock->s_pipe_ops.pipe_init(
	    &pipe->p_proto_data, pipe, sock->s_data);
	if (rv != 0) {
		nni_mtx_unlock(&ep->ep_mtx);
		nni_mtx_lock(&sock->s_mx);
		return (rv);
	}
	// Save the protocol destructor.
	pipe->p_proto_dtor = sock->s_pipe_ops.pipe_fini;
	pipe->p_sock       = sock;
	pipe->p_ep         = ep;

	nni_list_append(&sock->s_pipes, pipe);
	nni_list_append(&ep->ep_pipes, pipe);

	// Start the initial negotiation I/O...
	if (pipe->p_tran_ops.p_start == NULL) {
		if (nni_sock_pipe_start(pipe) != 0) {
			nni_pipe_stop(pipe);
		}
	} else {
		pipe->p_tran_ops.p_start(
		    pipe->p_tran_data, &pipe->p_start_aio);
	}

	nni_mtx_unlock(&ep->ep_mtx);
	nni_mtx_unlock(&sock->s_mx);
	return (0);
}

int
nni_sock_pipe_ready(nni_sock *sock, nni_pipe *pipe)
{
	int   rv;
	void *pdata = nni_pipe_get_proto_data(pipe);

	nni_mtx_lock(&sock->s_mx);

	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	if (nni_pipe_peer(pipe) != sock->s_peer) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_EPROTO);
	}

	if ((rv = sock->s_pipe_ops.pipe_start(pdata)) != 0) {
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}

	nni_mtx_unlock(&sock->s_mx);

	return (0);
}

void
nni_sock_pipe_remove(nni_sock *sock, nni_pipe *pipe)
{
	void *pdata;

	pdata = nni_pipe_get_proto_data(pipe);

	// Stop any pending negotiation.
	nni_aio_stop(&pipe->p_start_aio);

	nni_mtx_lock(&sock->s_mx);
	if ((sock->s_pipe_ops.pipe_stop == NULL) || (pdata == NULL)) {
		nni_mtx_unlock(&sock->s_mx);
		return;
	}

	sock->s_pipe_ops.pipe_stop(pdata);
	if (nni_list_active(&sock->s_pipes, pipe)) {
		nni_list_remove(&sock->s_pipes, pipe);
		if (sock->s_closing && nni_list_empty(&sock->s_pipes)) {
			nni_cv_wake(&sock->s_cv);
		}
	}
	nni_mtx_unlock(&sock->s_mx);
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

static nni_msg *
nni_sock_nullfilter(void *arg, nni_msg *mp)
{
	NNI_ARG_UNUSED(arg);
	return (mp);
}

static int
nni_sock_nullgetopt(void *arg, int num, void *data, size_t *szp)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(num);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(szp);
	return (NNG_ENOTSUP);
}

static int
nni_sock_nullsetopt(void *arg, int num, const void *data, size_t sz)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(num);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(sz);
	return (NNG_ENOTSUP);
}

static void
nni_sock_nullop(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static int
nni_sock_nullstartpipe(void *arg)
{
	NNI_ARG_UNUSED(arg);

	return (0);
}

static void *
nni_sock_ctor(uint32_t id)
{
	int       rv;
	nni_sock *sock;

	if ((sock = NNI_ALLOC_STRUCT(sock)) == NULL) {
		return (NULL);
	}
	// s_protocol, s_peer, and s_flags undefined as yet.
	sock->s_linger    = 0;
	sock->s_sndtimeo  = -1;
	sock->s_rcvtimeo  = -1;
	sock->s_closing   = 0;
	sock->s_reconn    = NNI_SECOND;
	sock->s_reconnmax = 0;
	sock->s_rcvmaxsz  = 1024 * 1024; // 1 MB by default
	sock->s_id        = id;

	nni_pipe_sock_list_init(&sock->s_pipes);

	nni_ep_list_init(&sock->s_eps);

	sock->s_send_fd.sn_init = 0;
	sock->s_recv_fd.sn_init = 0;

	if (((rv = nni_mtx_init(&sock->s_mx)) != 0) ||
	    ((rv = nni_cv_init(&sock->s_cv, &sock->s_mx)) != 0)) {
		goto fail;
	}

	rv = nni_ev_init(&sock->s_recv_ev, NNG_EV_CAN_RCV, sock);
	if (rv != 0) {
		goto fail;
	}
	rv = nni_ev_init(&sock->s_send_ev, NNG_EV_CAN_SND, sock);
	if (rv != 0) {
		goto fail;
	}

	if (((rv = nni_msgq_init(&sock->s_uwq, 0)) != 0) ||
	    ((rv = nni_msgq_init(&sock->s_urq, 0)) != 0)) {
		goto fail;
	}

	return (sock);

fail:
	nni_ev_fini(&sock->s_send_ev);
	nni_ev_fini(&sock->s_recv_ev);
	nni_msgq_fini(sock->s_urq);
	nni_msgq_fini(sock->s_uwq);
	nni_cv_fini(&sock->s_cv);
	nni_mtx_fini(&sock->s_mx);
	NNI_FREE_STRUCT(sock);
	return (NULL);
}

static void
nni_sock_dtor(void *ptr)
{
	nni_sock *sock = ptr;

	// Close any open notification pipes.
	if (sock->s_recv_fd.sn_init) {
		nni_plat_pipe_close(
		    sock->s_recv_fd.sn_wfd, sock->s_recv_fd.sn_rfd);
	}
	if (sock->s_send_fd.sn_init) {
		nni_plat_pipe_close(
		    sock->s_send_fd.sn_wfd, sock->s_send_fd.sn_rfd);
	}

	// The protocol needs to clean up its state.
	if (sock->s_data != NULL) {
		sock->s_sock_ops.sock_fini(sock->s_data);
	}

	nni_ev_fini(&sock->s_send_ev);
	nni_ev_fini(&sock->s_recv_ev);
	nni_msgq_fini(sock->s_urq);
	nni_msgq_fini(sock->s_uwq);
	nni_cv_fini(&sock->s_cv);
	nni_mtx_fini(&sock->s_mx);
	NNI_FREE_STRUCT(sock);
}

int
nni_sock_sys_init(void)
{
	int rv;

	rv = nni_objhash_init(&nni_socks, nni_sock_ctor, nni_sock_dtor);

	return (rv);
}

void
nni_sock_sys_fini(void)
{
	nni_objhash_fini(nni_socks);
	nni_socks = NULL;
}

// nn_sock_open creates the underlying socket.
int
nni_sock_open(nni_sock **sockp, uint16_t pnum)
{
	nni_sock *          sock;
	nni_proto *         proto;
	int                 rv;
	nni_proto_sock_ops *sops;
	nni_proto_pipe_ops *pops;
	uint32_t            sockid;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((proto = nni_proto_find(pnum)) == NULL) {
		return (NNG_ENOTSUP);
	}

	rv = nni_objhash_alloc(nni_socks, &sockid, (void **) &sock);
	if (rv != 0) {
		return (rv);
	}

	// We make a copy of the protocol operations.
	sock->s_protocol = proto->proto_self;
	sock->s_peer     = proto->proto_peer;
	sock->s_flags    = proto->proto_flags;
	sock->s_sock_ops = *proto->proto_sock_ops;

	sops = &sock->s_sock_ops;
	if (sops->sock_sfilter == NULL) {
		sops->sock_sfilter = nni_sock_nullfilter;
	}
	if (sops->sock_rfilter == NULL) {
		sops->sock_rfilter = nni_sock_nullfilter;
	}
	if (sops->sock_getopt == NULL) {
		sops->sock_getopt = nni_sock_nullgetopt;
	}
	if (sops->sock_setopt == NULL) {
		sops->sock_setopt = nni_sock_nullsetopt;
	}
	if (sops->sock_close == NULL) {
		sops->sock_close = nni_sock_nullop;
	}
	if (sops->sock_open == NULL) {
		sops->sock_open = nni_sock_nullop;
	}
	sock->s_pipe_ops = *proto->proto_pipe_ops;
	pops             = &sock->s_pipe_ops;
	if (pops->pipe_start == NULL) {
		pops->pipe_start = nni_sock_nullstartpipe;
	}
	if (pops->pipe_stop == NULL) {
		pops->pipe_stop = nni_sock_nullop;
	}

	if ((rv = sops->sock_init(&sock->s_data, sock)) != 0) {
		nni_objhash_unref(nni_socks, sockid);
		return (rv);
	}

	sops->sock_open(sock->s_data);

	*sockp = sock;
	return (0);
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
		nni_ep_close(ep);
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

	// For each ep, arrange for it to teardown hard.
	NNI_LIST_FOREACH (&sock->s_eps, ep) {
		nni_ep_stop(ep);
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

void
nni_sock_ep_remove(nni_sock *sock, nni_ep *ep)
{
	nni_pipe *pipe;
	// If we're not on the list, then nothing to do.  Be idempotent.
	// Note that if the ep is not on a list, then we assume that we have
	// exclusive access.  Therefore the check for being active need not
	// be locked.
	if ((sock == NULL) || (!nni_list_active(&sock->s_eps, ep))) {
		return;
	}

	// This is done under the endpoints lock, although the remove
	// is done under that as well, we also make sure that we hold
	// the socket lock in the remove step.
	nni_mtx_lock(&ep->ep_mtx);
	NNI_LIST_FOREACH (&ep->ep_pipes, pipe) {
		nni_pipe_stop(pipe);
	}
	while (!nni_list_empty(&ep->ep_pipes)) {
		nni_cv_wait(&ep->ep_cv);
	}
	nni_mtx_unlock(&ep->ep_mtx);

	nni_mtx_lock(&sock->s_mx);
	nni_list_remove(&sock->s_eps, ep);
	if ((sock->s_closing) && (nni_list_empty(&sock->s_eps))) {
		nni_cv_wake(&sock->s_cv);
	}
	nni_mtx_unlock(&sock->s_mx);
}

// nni_sock_close shuts down the socket, then releases any resources
// associated with it.  It is a programmer error to reference the socket
// after this function is called, as the pointer may reference invalid
// memory or other objects.
void
nni_sock_close(nni_sock *sock)
{
	// Shutdown everything if not already done.  This operation
	// is idempotent.
	nni_sock_shutdown(sock);

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closed) {
		nni_mtx_unlock(&sock->s_mx);
		return;
	}
	sock->s_closed = 1;
	nni_mtx_unlock(&sock->s_mx);

	// At this point nothing else should be referencing us.
	// As with UNIX close, it is a gross error for the caller
	// to have concurrent threads using this.  We've taken care to
	// ensure that any active consumers have been stopped, but if
	// user code attempts to utilize the socket *after* this point,
	// the results may be tragic.

	// Unreference twice. First drops the reference our caller
	// acquired to start the open, and the second (blocking) one
	// is the reference created for us at socket creation.

	nni_objhash_unref(nni_socks, sock->s_id);
	nni_objhash_unref_wait(nni_socks, sock->s_id);
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

	msg = sock->s_sock_ops.sock_sfilter(sock->s_data, msg);
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
	if (besteffort && (rv == NNG_EAGAIN)) {
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
		nni_mtx_lock(&sock->s_mx);
		msg = sock->s_sock_ops.sock_rfilter(sock->s_data, msg);
		nni_mtx_unlock(&sock->s_mx);
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
	return (sock->s_protocol);
}

uint16_t
nni_sock_peer(nni_sock *sock)
{
	return (sock->s_peer);
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
nni_sock_dial(nni_sock *sock, const char *addr, nni_ep **epp, int flags)
{
	nni_ep *ep;
	int     rv;

	nni_mtx_lock(&sock->s_mx);
	if ((rv = nni_ep_create(&ep, sock, addr, NNI_EP_MODE_DIAL)) != 0) {
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}
	nni_list_append(&sock->s_eps, ep);
	// Put a hold on the endpoint, for now.
	nni_mtx_lock(&ep->ep_mtx);
	ep->ep_refcnt++;
	ep->ep_started = 1;
	nni_mtx_unlock(&ep->ep_mtx);
	nni_mtx_unlock(&sock->s_mx);

	if ((rv = nni_ep_dial(ep, flags)) != 0) {
		nni_ep_stop(ep);
	} else if (epp != NULL) {
		*epp = ep;
	}

	// Drop our endpoint hold.
	nni_mtx_lock(&ep->ep_mtx);
	if (rv != 0) {
		ep->ep_started = 0;
	}
	ep->ep_refcnt--;
	nni_cv_wake(&ep->ep_cv);
	nni_mtx_unlock(&ep->ep_mtx);

	return (rv);
}

int
nni_sock_listen(nni_sock *sock, const char *addr, nni_ep **epp, int flags)
{
	nni_ep *ep;
	int     rv;

	nni_mtx_lock(&sock->s_mx);
	if ((rv = nni_ep_create(&ep, sock, addr, NNI_EP_MODE_LISTEN)) != 0) {
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}

	nni_list_append(&sock->s_eps, ep);
	nni_mtx_lock(&ep->ep_mtx);
	ep->ep_refcnt++;
	ep->ep_started = 1;
	nni_mtx_unlock(&ep->ep_mtx);
	nni_mtx_unlock(&sock->s_mx);

	if ((rv = nni_ep_listen(ep, flags)) != 0) {
		nni_ep_stop(ep);
	} else if (epp != NULL) {
		*epp = ep;
	}

	// Drop our endpoint hold.
	nni_mtx_lock(&ep->ep_mtx);
	if (rv != 0) {
		ep->ep_started = 0;
	}
	ep->ep_refcnt--;
	nni_cv_wake(&ep->ep_cv);
	nni_mtx_unlock(&ep->ep_mtx);

	return (rv);
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
	rv = sock->s_sock_ops.sock_setopt(sock->s_data, opt, val, size);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
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
	rv = sock->s_sock_ops.sock_getopt(sock->s_data, opt, val, sizep);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
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
