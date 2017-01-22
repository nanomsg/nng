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
	nni_mtx_lock(nni_idlock);
	rv = nni_idhash_find(nni_sockets, id, (void **) &sock);
	if ((rv != 0) || (sock->s_closed)) {
		nni_mtx_unlock(nni_idlock);
		return (NNG_ECLOSED);
	}
	sock->s_refcnt++;
	nni_mtx_unlock(nni_idlock);
	*sockp = sock;

	return (0);
}


void
nni_sock_rele(nni_sock *sock)
{
	nni_mtx_lock(nni_idlock);
	sock->s_refcnt--;
	if ((sock->s_closed) && (sock->s_refcnt == 1)) {
		nni_cv_wake(&sock->s_refcv);
	}
	nni_mtx_unlock(nni_idlock);
}


// nni_sock_hold_close is a special hold acquired by the nng_close
// function.  This waits until it has exclusive access, and then marks
// the socket unusuable by anything else.
int
nni_sock_hold_close(nni_sock **sockp, uint32_t id)
{
	int rv;
	nni_sock *sock;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	nni_mtx_lock(nni_idlock);
	rv = nni_idhash_find(nni_sockets, id, (void **) &sock);
	if (rv != 0) {
		nni_mtx_unlock(nni_idlock);
		return (NNG_ECLOSED);
	}
	sock->s_closed = 1;
	sock->s_refcnt++;
	while (sock->s_refcnt != 1) {
		nni_cv_wait(&sock->s_refcv);
	}
	nni_mtx_unlock(nni_idlock);
	*sockp = sock;

	return (0);
}


// XXX: don't expose the upper queues to protocols, because we need to
// trap on activity in those queues!

// Because we have to call back into the socket, and possibly also the proto,
// and wait for threads to terminate, we do this in a special thread.  The
// assumption is that closing is always a "fast" operation.
static void
nni_reaper(void *arg)
{
	nni_sock *sock = arg;

	for (;;) {
		nni_pipe *pipe;
		nni_ep *ep;

		nni_mtx_lock(&sock->s_mx);
		if ((pipe = nni_list_first(&sock->s_reaps)) != NULL) {
			nni_list_remove(&sock->s_reaps, pipe);
			if (pipe->p_id != 0) {
				nni_mtx_lock(nni_idlock);
				nni_idhash_remove(nni_pipes, pipe->p_id);
				nni_mtx_unlock(nni_idlock);
			}

			if (((ep = pipe->p_ep) != NULL) &&
			    ((ep->ep_pipe == pipe))) {
				ep->ep_pipe = NULL;
				nni_cv_wake(&ep->ep_cv);
			}

			// Remove the pipe from the protocol.  Protocols may
			// keep lists of pipes for managing their topologies.
			// Note that if a protocol has rejected the pipe, it
			// won't have any data.
			if (pipe->p_active) {
				sock->s_pipe_ops.pipe_rem(pipe->p_proto_data);
			}
			nni_mtx_unlock(&sock->s_mx);

			// XXX: also publish event...

			// There should be no references left to this pipe.
			// The various threads will have shutdown, except
			// the threads that this waits for.
			nni_pipe_destroy(pipe);
			continue;
		}

		if ((sock->s_reapexit) &&
		    (nni_list_first(&sock->s_reaps) == NULL) &&
		    (nni_list_first(&sock->s_pipes) == NULL)) {
			nni_mtx_unlock(&sock->s_mx);
			break;
		}

		nni_cv_wait(&sock->s_cv);
		nni_mtx_unlock(&sock->s_mx);
	}
}


static void
nni_sock_urq_notify(nni_msgq *mq, int flags, void *arg)
{
	nni_sock *sock = arg;

	if ((flags & NNI_MSGQ_NOTIFY_CANGET) == 0) {
		return; // No interest in writability of read queue.
	}
	nni_mtx_lock(&sock->s_mx);
	nni_ev_submit(&sock->s_recv_ev);
	nni_mtx_unlock(&sock->s_mx);
}


static void
nni_sock_uwq_notify(nni_msgq *mq, int flags, void *arg)
{
	nni_sock *sock = arg;

	if ((flags & NNI_MSGQ_NOTIFY_CANPUT) == 0) {
		return; // No interest in readability of write queue.
	}
	nni_mtx_lock(&sock->s_mx);
	nni_ev_submit(&sock->s_send_ev);
	nni_mtx_unlock(&sock->s_mx);
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
nni_sock_nulladdpipe(void *arg)
{
	NNI_ARG_UNUSED(arg);

	return (0);
}


// nn_sock_open creates the underlying socket.
int
nni_sock_open(nni_sock **sockp, uint16_t pnum)
{
	nni_sock *sock;
	nni_proto *proto;
	int rv;
	int i;
	nni_proto_sock_ops *sops;
	nni_proto_pipe_ops *pops;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((proto = nni_proto_find(pnum)) == NULL) {
		return (NNG_ENOTSUP);
	}
	if ((sock = NNI_ALLOC_STRUCT(sock)) == NULL) {
		return (NNG_ENOMEM);
	}

	// We make a copy of the protocol operations.
	sock->s_protocol = proto->proto_self;
	sock->s_peer = proto->proto_peer;
	sock->s_flags = proto->proto_flags;
	sock->s_linger = 0;
	sock->s_sndtimeo = -1;
	sock->s_rcvtimeo = -1;
	sock->s_closing = 0;
	sock->s_reconn = NNI_SECOND;
	sock->s_reconnmax = NNI_SECOND;
	sock->s_reapexit = 0;
	NNI_LIST_INIT(&sock->s_pipes, nni_pipe, p_node);
	NNI_LIST_INIT(&sock->s_reaps, nni_pipe, p_node);
	NNI_LIST_INIT(&sock->s_eps, nni_ep, ep_node);
	NNI_LIST_INIT(&sock->s_notify, nni_notify, n_node);
	NNI_LIST_INIT(&sock->s_events, nni_event, e_node);
	sock->s_send_fd.sn_init = 0;
	sock->s_recv_fd.sn_init = 0;

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
	sock->s_pipe_ops = *proto->proto_pipe_ops;
	pops = &sock->s_pipe_ops;
	if (pops->pipe_add == NULL) {
		pops->pipe_add = nni_sock_nulladdpipe;
	}
	if (pops->pipe_rem == NULL) {
		pops->pipe_rem = nni_sock_nullop;
	}

	if (((rv = nni_mtx_init(&sock->s_mx)) != 0) ||
	    ((rv = nni_mtx_init(&sock->s_notify_mx)) != 0) ||
	    ((rv = nni_cv_init(&sock->s_cv, &sock->s_mx)) != 0) ||
	    ((rv = nni_cv_init(&sock->s_notify_cv, &sock->s_mx)) != 0)) {
		goto fail;
	}

	if ((rv = nni_cv_init(&sock->s_refcv, nni_idlock)) != 0) {
		goto fail;
	}

	rv = nni_ev_init(&sock->s_recv_ev, NNG_EV_CAN_RECV, sock);
	if (rv != 0) {
		goto fail;
	}
	rv = nni_ev_init(&sock->s_send_ev, NNG_EV_CAN_SEND, sock);
	if (rv != 0) {
		goto fail;
	}

	if (((rv = nni_thr_init(&sock->s_reaper, nni_reaper, sock)) != 0) ||
	    ((rv = nni_thr_init(&sock->s_notifier, nni_notifier, sock)) != 0)) {
		goto fail;
	}

	if (((rv = nni_msgq_init(&sock->s_uwq, 0)) != 0) ||
	    ((rv = nni_msgq_init(&sock->s_urq, 0)) != 0)) {
		goto fail;
	}

	nni_mtx_lock(nni_idlock);
	rv = nni_idhash_alloc(nni_sockets, &sock->s_id, sock);
	nni_mtx_unlock(nni_idlock);
	if (rv != 0) {
		goto fail;
	}

	// Caller always gets the socket held.
	sock->s_refcnt = 1;

	if ((rv = sops->sock_init(&sock->s_data, sock)) != 0) {
		goto fail;
	}

	// NB: If worker functions are null, then the thread initialization
	// turns into a NOP, and no actual thread will be started.
	for (i = 0; i < NNI_MAXWORKERS; i++) {
		nni_worker fn = sops->sock_worker[i];
		rv = nni_thr_init(&sock->s_worker_thr[i], fn, sock->s_data);
		if (rv != 0) {
			goto fail;
		}
	}

	for (i = 0; i < NNI_MAXWORKERS; i++) {
		nni_thr_run(&sock->s_worker_thr[i]);
	}

	nni_msgq_notify(sock->s_urq, nni_sock_urq_notify, sock);
	nni_msgq_notify(sock->s_uwq, nni_sock_uwq_notify, sock);

	nni_thr_run(&sock->s_reaper);
	nni_thr_run(&sock->s_notifier);
	*sockp = sock;
	return (0);

fail:
	sock->s_sock_ops.sock_fini(sock->s_data);

	// And we need to clean up *our* state.
	for (i = 0; i < NNI_MAXWORKERS; i++) {
		nni_thr_fini(&sock->s_worker_thr[i]);
	}
	if (sock->s_id != 0) {
		nni_mtx_lock(nni_idlock);
		nni_idhash_remove(nni_sockets, sock->s_id);
		if (nni_idhash_count(nni_sockets) == 0) {
			nni_idhash_reclaim(nni_pipes);
			nni_idhash_reclaim(nni_endpoints);
			nni_idhash_reclaim(nni_sockets);
		}
		nni_mtx_unlock(nni_idlock);
	}
	nni_thr_fini(&sock->s_notifier);
	nni_thr_fini(&sock->s_reaper);
	nni_ev_fini(&sock->s_send_ev);
	nni_ev_fini(&sock->s_recv_ev);
	nni_msgq_fini(sock->s_urq);
	nni_msgq_fini(sock->s_uwq);
	nni_cv_fini(&sock->s_refcv);
	nni_cv_fini(&sock->s_notify_cv);
	nni_cv_fini(&sock->s_cv);
	nni_mtx_fini(&sock->s_notify_mx);
	nni_mtx_fini(&sock->s_mx);
	NNI_FREE_STRUCT(sock);
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

	// Stop all EPS.  We're going to do this first, since we know
	// we're closing.
	while ((ep = nni_list_first(&sock->s_eps)) != NULL) {
		nni_mtx_unlock(&sock->s_mx);
		nni_ep_close(ep);
		nni_mtx_lock(&sock->s_mx);
	}

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

	// For each pipe, close the underlying transport, and move it to
	// deathrow (the reaplist).
	while ((pipe = nni_list_first(&sock->s_pipes)) != NULL) {
		if (pipe->p_tran_data != NULL) {
			pipe->p_tran_ops.pipe_close(pipe->p_tran_data);
		}
		pipe->p_reap = 1;
		nni_list_remove(&sock->s_pipes, pipe);
		nni_list_append(&sock->s_reaps, pipe);
	}

	sock->s_sock_ops.sock_close(sock->s_data);

	sock->s_reapexit = 1;
	nni_cv_wake(&sock->s_notify_cv);
	nni_cv_wake(&sock->s_cv);
	nni_mtx_unlock(&sock->s_mx);

	// Wait for the threads to exit.
	for (i = 0; i < NNI_MAXWORKERS; i++) {
		nni_thr_wait(&sock->s_worker_thr[i]);
	}
	nni_thr_wait(&sock->s_notifier);
	nni_thr_wait(&sock->s_reaper);

	// At this point, there are no threads blocked inside of us
	// that are referencing socket state.  User code should call
	// nng_close to release the last resources.
	return (0);
}


// nni_sock_close shuts down the socket, then releases any resources
// associated with it.  It is a programmer error to reference the socket
// after this function is called, as the pointer may reference invalid
// memory or other objects.  The socket should have been acquired with
// nni_sock_hold_close().
void
nni_sock_close(nni_sock *sock)
{
	int i;
	nni_notify *notify;

	// Shutdown everything if not already done.  This operation
	// is idempotent.
	nni_sock_shutdown(sock);

	// At this point nothing else should be referencing us.
	// As with UNIX close, it is a gross error for the caller
	// to have concurrent threads using this.  We've taken care to
	// ensure that any active consumers have been stopped, but if
	// user code attempts to utilize the socket *after* this point,
	// the results may be tragic.

	nni_mtx_lock(nni_idlock);
	nni_idhash_remove(nni_sockets, sock->s_id);
	if (nni_idhash_count(nni_sockets) == 0) {
		nni_idhash_reclaim(nni_pipes);
		nni_idhash_reclaim(nni_endpoints);
		nni_idhash_reclaim(nni_sockets);
	}

	nni_mtx_unlock(nni_idlock);

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
	sock->s_sock_ops.sock_fini(sock->s_data);

	// And we need to clean up *our* state.
	for (i = 0; i < NNI_MAXWORKERS; i++) {
		nni_thr_fini(&sock->s_worker_thr[i]);
	}
	while ((notify = nni_list_first(&sock->s_notify)) != NULL) {
		nni_list_remove(&sock->s_notify, notify);
		NNI_FREE_STRUCT(notify);
	}
	nni_thr_fini(&sock->s_notifier);
	nni_thr_fini(&sock->s_reaper);
	nni_msgq_fini(sock->s_urq);
	nni_msgq_fini(sock->s_uwq);
	nni_ev_fini(&sock->s_send_ev);
	nni_ev_fini(&sock->s_recv_ev);
	nni_cv_fini(&sock->s_refcv);
	nni_cv_fini(&sock->s_notify_cv);
	nni_cv_fini(&sock->s_cv);
	nni_mtx_fini(&sock->s_notify_mx);
	nni_mtx_fini(&sock->s_mx);
	NNI_FREE_STRUCT(sock);
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
	int rv = ENOTSUP;

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
	}
	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}


int
nni_sock_getopt(nni_sock *sock, int opt, void *val, size_t *sizep)
{
	int rv = ENOTSUP;

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
	case NNG_OPT_SENDFD:
		rv = nni_getopt_fd(sock, &sock->s_send_fd, NNG_EV_CAN_SEND,
			val, sizep);
		break;
	case NNG_OPT_RECVFD:
		rv = nni_getopt_fd(sock, &sock->s_recv_fd, NNG_EV_CAN_RECV,
			val, sizep);
		break;
	}
	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}
