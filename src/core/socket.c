//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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
nni_sock_hold(nni_sock **sockp, uint32_t id)
{
	int rv;
	nni_sock *sock;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_objhash_find(nni_socks, id, (void **) &sock)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&sock->s_mx);
	if ((sock->s_closed) || (sock->s_data == NULL)) {
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


int
nni_sock_pipe_add(nni_sock *sock, nni_pipe *pipe)
{
	int rv;
	void *pdata;

	rv = sock->s_pipe_ops.pipe_init(&pdata, pipe, sock->s_data);
	if (rv != 0) {
		return (rv);
	}

	// XXX: place a hold on the socket.

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		sock->s_pipe_ops.pipe_fini(pdata);
		return (NNG_ECLOSED);
	}
	nni_pipe_set_proto_data(pipe, pdata);
	nni_list_append(&sock->s_pipes, pipe);
	nni_mtx_unlock(&sock->s_mx);
	return (0);
}


int
nni_sock_pipe_ready(nni_sock *sock, nni_pipe *pipe)
{
	int rv;
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
nni_sock_pipe_closed(nni_sock *sock, nni_pipe *pipe)
{
	nni_ep *ep;
	void *pdata = nni_pipe_get_proto_data(pipe);

	nni_mtx_lock(&sock->s_mx);

	// NB: nni_list_remove doesn't really care *which* list the pipe
	// is on, and so if the pipe is already on the idle list these
	// two statements are effectively a no-op.
	nni_list_remove(&sock->s_pipes, pipe);
	if (nni_list_first(&sock->s_pipes) == NULL) {
		nni_cv_wake(&sock->s_cv);
	}

	sock->s_pipe_ops.pipe_stop(pdata);

	// Notify the endpoint that the pipe has closed.
	if (((ep = pipe->p_ep) != NULL) && ((ep->ep_pipe == pipe))) {
		ep->ep_pipe = NULL;
		nni_cv_wake(&ep->ep_cv);
	}
	nni_mtx_unlock(&sock->s_mx);
}


void
nni_sock_pipe_rem(nni_sock *sock, nni_pipe *pipe)
{
	nni_ep *ep;
	void *pdata = nni_pipe_get_proto_data(pipe);

	nni_mtx_lock(&sock->s_mx);

	if (nni_list_active(&sock->s_pipes, pipe)) {
		nni_list_remove(&sock->s_pipes, pipe);
	}

	if (pdata != NULL) {
		sock->s_pipe_ops.pipe_fini(pdata);
	}

	// XXX: Move this to a seperate ep-specific API.
	// Notify the endpoint that the pipe has closed - if not already done.
	if (((ep = pipe->p_ep) != NULL) && ((ep->ep_pipe == pipe))) {
		ep->ep_pipe = NULL;
		nni_cv_wake(&ep->ep_cv);
	}
	nni_cv_wake(&sock->s_cv);
	nni_mtx_unlock(&sock->s_mx);

	// XXX release the hold on the pipe
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
	nni_sock *sock = notify->n_sock;

	if (nni_aio_result(&notify->n_aio) != 0) {
		return;
	}

	notify->n_func(&sock->s_send_ev, notify->n_arg);
}


static void
nni_sock_canrecv_cb(void *arg)
{
	nni_notify *notify = arg;
	nni_sock *sock = notify->n_sock;

	if (nni_aio_result(&notify->n_aio) != 0) {
		return;
	}

	notify->n_func(&sock->s_recv_ev, notify->n_arg);
}


nni_notify *
nni_sock_notify(nni_sock *sock, int type, nng_notify_func fn, void *arg)
{
	nni_notify *notify;
	int rv;

	if ((notify = NNI_ALLOC_STRUCT(notify)) == NULL) {
		return (NULL);
	}

	notify->n_func = fn;
	notify->n_arg = arg;
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
	switch (notify->n_type) {
	case NNG_EV_CAN_RCV:
		nni_msgq_aio_cancel(sock->s_urq, &notify->n_aio);
		break;
	case NNG_EV_CAN_SND:
		nni_msgq_aio_cancel(sock->s_uwq, &notify->n_aio);
		break;
	default:
		return;
	}
	nni_aio_fini(&notify->n_aio);
	NNI_FREE_STRUCT(notify);
}


nni_mtx *
nni_sock_mtx(nni_sock *sock)
{
	return (&sock->s_mx);
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
	int rv;
	nni_sock *sock;

	if ((sock = NNI_ALLOC_STRUCT(sock)) == NULL) {
		return (NULL);
	}
	// s_protocol, s_peer, and s_flags undefined as yet.
	sock->s_linger = 0;
	sock->s_sndtimeo = -1;
	sock->s_rcvtimeo = -1;
	sock->s_closing = 0;
	sock->s_reconn = NNI_SECOND;
	sock->s_reconnmax = 0;
	sock->s_rcvmaxsz = 1024 * 1024; // 1 MB by default
	sock->s_id = id;

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
		nni_plat_pipe_close(sock->s_recv_fd.sn_wfd,
		    sock->s_recv_fd.sn_rfd);
	}
	if (sock->s_send_fd.sn_init) {
		nni_plat_pipe_close(sock->s_send_fd.sn_wfd,
		    sock->s_send_fd.sn_rfd);
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
	nni_sock *sock;
	nni_proto *proto;
	int rv;
	nni_proto_sock_ops *sops;
	nni_proto_pipe_ops *pops;
	uint32_t sockid;

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
	sock->s_peer = proto->proto_peer;
	sock->s_flags = proto->proto_flags;
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
	pops = &sock->s_pipe_ops;
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
	nni_ep *ep;
	nni_time linger;
	int i;

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

	// Stop all EPS.
	while ((ep = nni_list_first(&sock->s_eps)) != NULL) {
		nni_mtx_unlock(&sock->s_mx);
		nni_ep_close(ep);
		nni_mtx_lock(&sock->s_mx);
	}

	// For each pipe, close the underlying transport.  Also move it
	// to the idle list so we won't keep looping.
	while ((pipe = nni_list_first(&sock->s_pipes)) != NULL) {
		nni_mtx_unlock(&sock->s_mx);
		nni_pipe_close(pipe);
		nni_mtx_lock(&sock->s_mx);
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


// nni_sock_add_ep adds a newly created endpoint to the socket.  The
// caller must hold references on the sock and the ep, and not be holding
// the socket lock.  The ep acquires a reference against the sock,
// which will be dropped later by nni_sock_rem_ep.  The endpoint must not
// already be associated with a socket.  (Note, the ep holds the reference
// on the socket, not the other way around.)
int
nni_sock_add_ep(nni_sock *sock, nni_ep *ep)
{
	int rv;

	if ((rv = nni_sock_hold(NULL, sock->s_id)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		nni_sock_rele(sock);
		return (NNG_ECLOSED);
	}
	nni_list_append(&sock->s_eps, ep);
	nni_mtx_unlock(&sock->s_mx);
	return (0);
}


void
nni_sock_rem_ep(nni_sock *sock, nni_ep *ep)
{
	nni_mtx_lock(&sock->s_mx);
	// If we're not on the list, then nothing to do.  Be idempotent.
	if (!nni_list_active(&sock->s_eps, ep)) {
		nni_mtx_unlock(&sock->s_mx);
		return;
	}
	nni_list_remove(&sock->s_eps, ep);
	nni_mtx_unlock(&sock->s_mx);

	// Drop the reference the EP acquired in add_ep.
	nni_sock_rele(sock);
}


// nni_sock_close shuts down the socket, then releases any resources
// associated with it.  It is a programmer error to reference the socket
// after this function is called, as the pointer may reference invalid
// memory or other objects.
void
nni_sock_close(nni_sock *sock)
{
	int i;
	nni_notify *notify;

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
	int rv;
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
	int rv;

	if ((rv = nni_ep_create(&ep, sock, addr)) != 0) {
		return (rv);
	}

	if ((rv = nni_ep_dial(ep, flags)) != 0) {
		nni_ep_close(ep);
	} else if (epp != NULL) {
		*epp = ep;
	}

	return (rv);
}


int
nni_sock_listen(nni_sock *sock, const char *addr, nni_ep **epp, int flags)
{
	nni_ep *ep;
	int rv;

	if ((rv = nni_ep_create(&ep, sock, addr)) != 0) {
		return (rv);
	}

	if ((rv = nni_ep_listen(ep, flags)) != 0) {
		nni_ep_close(ep);
	} else if (epp != NULL) {
		*epp = ep;
	}

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
		rv = nni_setopt_size(&sock->s_rcvmaxsz, val, size, 0,
			NNI_MAXSZ);
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
		rv = nni_getopt_fd(sock, &sock->s_send_fd, NNG_EV_CAN_SND,
			val, sizep);
		break;
	case NNG_OPT_RCVFD:
		rv = nni_getopt_fd(sock, &sock->s_recv_fd, NNG_EV_CAN_RCV,
			val, sizep);
		break;
	}
	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}
