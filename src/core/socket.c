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
				pipe->p_proto_ops.pipe_rem(pipe->p_proto_data);
			}
			nni_mtx_unlock(&sock->s_mx);

			// XXX: also publish event...
			nni_pipe_destroy(pipe);
			continue;
		}

		if ((sock->s_closing) &&
		    (nni_list_first(&sock->s_reaps) == NULL) &&
		    (nni_list_first(&sock->s_pipes) == NULL)) {
			nni_mtx_unlock(&sock->s_mx);
			break;
		}

		nni_cv_wait(&sock->s_cv);
		nni_mtx_unlock(&sock->s_mx);
	}
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


// nn_sock_open creates the underlying socket.
int
nni_sock_open(nni_sock **sockp, uint16_t pnum)
{
	nni_sock *sock;
	nni_proto *proto;
	int rv;

	if ((proto = nni_proto_find(pnum)) == NULL) {
		return (NNG_ENOTSUP);
	}
	if ((sock = NNI_ALLOC_STRUCT(sock)) == NULL) {
		return (NNG_ENOMEM);
	}

	// We make a copy of the protocol operations.
	sock->s_proto = *proto;
	sock->s_linger = 0;
	sock->s_sndtimeo = -1;
	sock->s_rcvtimeo = -1;
	sock->s_closing = 0;
	sock->s_reconn = NNI_SECOND;
	sock->s_reconnmax = NNI_SECOND;
	NNI_LIST_INIT(&sock->s_pipes, nni_pipe, p_node);
	NNI_LIST_INIT(&sock->s_reaps, nni_pipe, p_node);
	NNI_LIST_INIT(&sock->s_eps, nni_ep, ep_node);

	if ((rv = nni_mtx_init(&sock->s_mx)) != 0) {
		NNI_FREE_STRUCT(sock);
		return (rv);
	}
	if ((rv = nni_cv_init(&sock->s_cv, &sock->s_mx)) != 0) {
		nni_mtx_fini(&sock->s_mx);
		NNI_FREE_STRUCT(sock);
		return (rv);
	}

	if ((rv = nni_thr_init(&sock->s_reaper, nni_reaper, sock)) != 0) {
		nni_cv_fini(&sock->s_cv);
		nni_mtx_fini(&sock->s_mx);
		NNI_FREE_STRUCT(sock);
		return (rv);
	}

	if ((rv = nni_msgq_init(&sock->s_uwq, 0)) != 0) {
		nni_thr_fini(&sock->s_reaper);
		nni_cv_fini(&sock->s_cv);
		nni_mtx_fini(&sock->s_mx);
		NNI_FREE_STRUCT(sock);
		return (rv);
	}
	if ((rv = nni_msgq_init(&sock->s_urq, 0)) != 0) {
		nni_msgq_fini(sock->s_uwq);
		nni_thr_fini(&sock->s_reaper);
		nni_cv_fini(&sock->s_cv);
		nni_mtx_fini(&sock->s_mx);
		NNI_FREE_STRUCT(sock);
		return (rv);
	}

	if ((rv = sock->s_proto.proto_init(&sock->s_data, sock)) != 0) {
		nni_msgq_fini(sock->s_urq);
		nni_msgq_fini(sock->s_uwq);
		nni_thr_fini(&sock->s_reaper);
		nni_cv_fini(&sock->s_cv);
		nni_mtx_fini(&sock->s_mx);
		NNI_FREE_STRUCT(sock);
		return (rv);
	}
	if (sock->s_proto.proto_send_filter == NULL) {
		sock->s_proto.proto_send_filter = nni_sock_nullfilter;
	}
	if (sock->s_proto.proto_recv_filter == NULL) {
		sock->s_proto.proto_recv_filter = nni_sock_nullfilter;
	}
	if (sock->s_proto.proto_getopt == NULL) {
		sock->s_proto.proto_getopt = nni_sock_nullgetopt;
	}
	if (sock->s_proto.proto_setopt == NULL) {
		sock->s_proto.proto_setopt = nni_sock_nullsetopt;
	}
	nni_thr_run(&sock->s_reaper);
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

	// Close the upper read queue immediately.  This can happen
	// safely while we hold the lock.
	nni_msgq_close(sock->s_urq);

	// Go through and schedule close on all pipes.
	while ((pipe = nni_list_first(&sock->s_pipes)) != NULL) {
		nni_mtx_unlock(&sock->s_mx);
		nni_pipe_close(pipe);
		nni_mtx_lock(&sock->s_mx);
	}

	nni_cv_wake(&sock->s_cv);
	nni_mtx_unlock(&sock->s_mx);

	// Wait for the reaper to exit.
	nni_thr_wait(&sock->s_reaper);

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
nni_sock_close(nni_sock *sock)
{
	// Shutdown everything if not already done.  This operation
	// is idempotent.
	nni_sock_shutdown(sock);

	// At this point nothing else should be referencing us.
	// As with UNIX close, it is a gross error for the caller
	// to have concurrent threads using this.  We've taken care to
	// ensure that any active consumers have been stopped, but if
	// user code attempts to utilize the socket *after* this point,
	// the results may be tragic.

	// The protocol needs to clean up its state.
	sock->s_proto.proto_fini(sock->s_data);

	// And we need to clean up *our* state.
	nni_thr_fini(&sock->s_reaper);
	nni_msgq_fini(sock->s_urq);
	nni_msgq_fini(sock->s_uwq);
	nni_cv_fini(&sock->s_cv);
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
	nni_mtx_unlock(&sock->s_mx);

	msg = sock->s_proto.proto_send_filter(sock->s_data, msg);
	if (msg == NULL) {
		return (0);
	}

	if (besteffort) {
		// BestEffort mode -- if we cannot handle the message due to
		// backpressure, we just throw it away, and don't complain.
		expire = NNI_TIME_ZERO;
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

	for (;;) {
		rv = nni_msgq_get_until(sock->s_urq, &msg, expire);
		if (rv != 0) {
			return (rv);
		}
		msg = sock->s_proto.proto_recv_filter(sock->s_data, msg);
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
	return (sock->s_proto.proto_self);
}


uint16_t
nni_sock_peer(nni_sock *sock)
{
	return (sock->s_proto.proto_peer);
}


int
nni_sock_dial(nni_sock *sock, const char *addr, nni_ep **epp, int flags)
{
	nni_ep *ep;
	int rv;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	if ((rv = nni_ep_create(&ep, sock, addr)) != 0) {
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}
	nni_list_append(&sock->s_eps, ep);
	nni_mtx_unlock(&sock->s_mx);

	rv = nni_ep_dial(ep, flags);
	if (rv != 0) {
		nni_ep_close(ep);
	} else {
		if (epp != NULL) {
			*epp = ep;
		}
	}

	return (rv);
}


int
nni_sock_listen(nni_sock *sock, const char *addr, nni_ep **epp, int flags)
{
	nni_ep *ep;
	int rv;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}

	if ((rv = nni_ep_create(&ep, sock, addr)) != 0) {
		nni_mtx_unlock(&sock->s_mx);
		return (rv);
	}
	nni_list_append(&sock->s_eps, ep);
	nni_mtx_unlock(&sock->s_mx);

	rv = nni_ep_listen(ep, flags);
	if (rv != 0) {
		nni_ep_close(ep);
	} else {
		if (epp != NULL) {
			*epp = ep;
		}
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
	size_t rsz;
	void *ptr;
	int rv = ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	rv = sock->s_proto.proto_setopt(sock->s_data, opt, val, size);
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
	size_t rsz;
	void *ptr;
	int rv = ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	rv = sock->s_proto.proto_getopt(sock->s_data, opt, val, sizep);
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
	}
	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}
