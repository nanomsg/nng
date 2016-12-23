//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

// Socket implementation.

// nni_socket_sendq and nni_socket_recvq are called by the protocol to obtain
// the upper read and write queues.
nni_msgqueue *
nni_socket_sendq(nni_socket *s)
{
	return (s->s_uwq);
}


nni_msgqueue *
nni_socket_recvq(nni_socket *s)
{
	return (s->s_urq);
}


// nn_socket_create creates the underlying socket.
int
nni_socket_create(nni_socket **sockp, uint16_t proto)
{
	nni_socket *sock;
	nni_protocol *ops;
	int rv;

	if ((ops = nni_protocol_find(proto)) == NULL) {
		return (NNG_ENOTSUP);
	}
	if ((sock = nni_alloc(sizeof (*sock))) == NULL) {
		return (NNG_ENOMEM);
	}
	sock->s_ops = *ops;

	if ((rv = nni_mutex_init(&sock->s_mx)) != 0) {
		nni_free(sock, sizeof (*sock));
		return (rv);
	}
	if ((rv = nni_cond_init(&sock->s_cv, &sock->s_mx)) != 0) {
		nni_mutex_fini(&sock->s_mx);
		nni_free(sock, sizeof (*sock));
		return (rv);
	}

	NNI_LIST_INIT(&sock->s_pipes, nni_pipe, p_sock_node);
	NNI_LIST_INIT(&sock->s_eps, nni_endpt, ep_sock_node);
	NNI_LIST_INIT(&sock->s_reap_eps, nni_endpt, ep_sock_node);

	if ((rv = sock->s_ops.proto_create(&sock->s_data, sock)) != 0) {
		nni_cond_fini(&sock->s_cv);
		nni_mutex_fini(&sock->s_mx);
		nni_free(sock, sizeof (*sock));
		return (rv);
	}
	*sockp = sock;
	return (0);
}


// nni_socket_close closes the underlying socket.
int
nni_socket_close(nni_socket *sock)
{
	nni_pipe *pipe;
	nni_endpt *ep;
	nni_time linger;


	nni_mutex_enter(&sock->s_mx);
	// Mark us closing, so no more EPs or changes can occur.
	sock->s_closing = 1;

	// Stop all EPS.  We're going to do this first, since we know
	// we're closing.
	NNI_LIST_FOREACH (&sock->s_eps, ep) {
		nni_endpt_close(ep);
	}
	nni_mutex_exit(&sock->s_mx);

	// XXX: TODO: add socket linger timeout to this, from socket option.
	linger = nni_clock();

	// We drain the upper write queue.  This is just like closing it,
	// except that the protocol gets a chance to get the messages and
	// push them down to the transport.  This operation can *block*
	// until the linger time has expired.
	nni_msgqueue_drain(sock->s_uwq, linger);

	// Generally, unless the protocol is blocked trying to perform
	// writes (e.g. a slow reader on the other side), it should be
	// trying to shut things down -- the normal flow is for it to
	// close pipes and call nni_sock_rem_pipe().  We wait to give it
	// a chance to do so gracefully.
	nni_mutex_enter(&sock->s_mx);
	while (nni_list_first(&sock->s_pipes) != NULL) {
		if (nni_cond_waituntil(&sock->s_cv, linger) == NNG_ETIMEDOUT) {
			break;
		}
	}

	// At this point, we've done everything we politely can to give
	// the protocol a chance to flush its write side.  Now its time
	// to be a little more insistent.

	// Close the upper read queue immediately.  This can happen
	// safely while we hold the lock.
	nni_msgqueue_close(sock->s_urq);

	// Go through and close all the pipes.
	nni_mutex_enter(&sock->s_mx);
	NNI_LIST_FOREACH (&sock->s_pipes, pipe) {
		nni_pipe_close(pipe);
	}

	// At this point, the protocols should have all their operations
	// failing, if they have any remaining, and they should be returning
	// any pipes back to us very quickly.  We'll wait for them to finish,
	// as it MUST occur shortly.
	while (nni_list_first(&sock->s_pipes) != NULL) {
		nni_cond_wait(&sock->s_cv);
	}

	// We signaled the endpoints to shutdown and cleanup.  We just
	// need to wait for them to finish.
	while ((ep = nni_list_first(&sock->s_eps)) != NULL) {
		nni_cond_wait(&sock->s_cv);
	}
	nni_mutex_exit(&sock->s_mx);

	// At this point nothing else should be referencing us.

	// The protocol needs to clean up its state.
	sock->s_ops.proto_destroy(&sock->s_data);

	// And we need to clean up *our* state.
	nni_cond_fini(&sock->s_cv);
	nni_mutex_fini(&sock->s_mx);
	nni_free(sock, sizeof (*sock));

	return (0);
}


int
nni_socket_sendmsg(nni_socket *sock, nni_msg *msg, nni_duration tmout)
{
	int rv;
	int besteffort;
	nni_time expire;

	if (tmout > 0) {
		expire = nni_clock() + tmout;
	} else if (tmout < 0) {
		expire = NNI_TIME_NEVER;
	} else {
		expire = NNI_TIME_ZERO;
	}

	// Senderr is typically set by protocols when the state machine
	// indicates that it is no longer valid to send a message.  E.g.
	// a REP socket with no REQ pending.
	nni_mutex_enter(&sock->s_mx);
	if (sock->s_closing) {
		nni_mutex_exit(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	if ((rv = sock->s_senderr) != 0) {
		nni_mutex_exit(&sock->s_mx);
		return (rv);
	}
	besteffort = sock->s_besteffort;
	nni_mutex_exit(&sock->s_mx);

	if (sock->s_ops.proto_send_filter != NULL) {
		msg = sock->s_ops.proto_send_filter(sock->s_data, msg);
		if (msg == NULL) {
			return (0);
		}
	}

	if (besteffort) {
		// BestEffort mode -- if we cannot handle the message due to
		// backpressure, we just throw it away, and don't complain.
		expire = NNI_TIME_ZERO;
	}
	rv = nni_msgqueue_put_until(sock->s_uwq, msg, expire);
	if (besteffort && (rv == NNG_EAGAIN)) {
		// Pretend this worked... it didn't, but pretend.
		nni_msg_free(msg);
		return (0);
	}
	return (rv);
}


int
nni_socket_recvmsg(nni_socket *sock, nni_msg **msgp, nni_duration tmout)
{
	int rv;
	nni_time expire;
	nni_msg *msg;

	if (tmout > 0) {
		expire = nni_clock() + tmout;
	} else if (tmout < 0) {
		expire = NNI_TIME_NEVER;
	} else {
		expire = NNI_TIME_ZERO;
	}

	nni_mutex_enter(&sock->s_mx);
	if (sock->s_closing) {
		nni_mutex_exit(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	if ((rv = sock->s_recverr) != 0) {
		nni_mutex_exit(&sock->s_mx);
		return (rv);
	}
	nni_mutex_exit(&sock->s_mx);

	for (;;) {
		rv = nni_msgqueue_get_until(sock->s_urq, &msg, expire);
		if (rv != 0) {
			return (rv);
		}
		msg = sock->s_ops.proto_recv_filter(sock->s_data, msg);
		if (msg != NULL) {
			break;
		}
		// Protocol dropped the message; try again.
	}

	*msgp = msg;
	return (0);
}


// nni_socket_protocol returns the socket's 16-bit protocol number.
uint16_t
nni_socket_proto(nni_socket *sock)
{
	return (sock->s_ops.proto_self);
}


// nni_socket_rem_pipe removes the pipe from the socket.  This is often
// called by the protocol when a pipe is removed due to close.
void
nni_socket_rem_pipe(nni_socket *sock, nni_pipe *pipe)
{
	nni_mutex_enter(&sock->s_mx);
	if (pipe->p_sock != sock) {
		nni_mutex_exit(&sock->s_mx);
	}

	// Remove the pipe from the protocol.  Protocols may
	// keep lists of pipes for managing their topologies.
	sock->s_ops.proto_rem_pipe(sock->s_data, pipe);

	// Now remove it from our own list.
	nni_list_remove(&sock->s_pipes, pipe);
	pipe->p_sock = NULL;
	// XXX: TODO: Redial
	// XXX: also publish event...
	// if (pipe->p_ep != NULL) {
	//	nn_endpt_rem_pipe(pipe->p_ep, pipe)
	// }

	nni_pipe_destroy(pipe);

	// If we're closing, wake the socket if we finished draining.
	if (sock->s_closing && (nni_list_first(&sock->s_pipes) == NULL)) {
		nni_cond_broadcast(&sock->s_cv);
	}
	nni_mutex_exit(&sock->s_mx);
}


int
nni_socket_add_pipe(nni_socket *sock, nni_pipe *pipe)
{
	int rv;

	nni_mutex_enter(&sock->s_mx);
	if (sock->s_closing) {
		nni_mutex_exit(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	if ((rv = sock->s_ops.proto_add_pipe(sock->s_data, pipe)) != 0) {
		nni_mutex_exit(&sock->s_mx);
		return (rv);
	}
	nni_list_append(&sock->s_pipes, pipe);

	// Add the pipe to its endpoint list.
	nni_mutex_enter(&pipe->p_ep->ep_mx);
	nni_list_append(&pipe->p_ep->ep_pipes, pipe);
	nni_mutex_exit(&pipe->p_ep->ep_mx);

	pipe->p_sock = sock;
	// XXX: Publish event
	nni_mutex_exit(&sock->s_mx);
	return (0);
}


static void
nni_socket_dialer(void *arg)
{
	nni_endpt *ep = arg;
	nni_socket *sock = ep->ep_sock;
	nni_pipe *pipe;
	int rv;

	for (;;) {
		nni_mutex_enter(&ep->ep_mx);
		while ((!ep->ep_close) &&
		    (nni_list_first(&ep->ep_pipes) != NULL)) {
			nni_cond_wait(&ep->ep_cv);
		}
		if (ep->ep_close) {
			nni_mutex_exit(&ep->ep_mx);
			break;
		}
		nni_mutex_exit(&ep->ep_mx);

		pipe = NULL;

		if (((rv = nni_endpt_dial(ep, &pipe)) != 0) ||
		    ((rv = nni_socket_add_pipe(sock, pipe)) != 0)) {
			if (rv == NNG_ECLOSED) {
				break;
			}
			if (pipe != NULL) {
				nni_pipe_destroy(pipe);
			}
			// XXX: Publish connection error event...
			// XXX: Inject a wait for reconnect...
			continue;
		}
	}
}


int
nni_socket_dial(nni_socket *sock, nni_endpt *ep)
{
	int rv = 0;

	nni_mutex_enter(&sock->s_mx);
	nni_mutex_enter(&ep->ep_mx);
	if ((ep->ep_dialer != NULL) || (ep->ep_listener != NULL)) {
		rv = NNG_EBUSY;
		goto out;
	}
	if (ep->ep_sock != sock) {	// Should never happen
		rv = NNG_EINVAL;
		goto out;
	}
	if (sock->s_closing) {
		rv = NNG_ECLOSED;
		goto out;
	}
	if (nni_thread_create(&ep->ep_dialer, nni_socket_dialer, ep) != 0) {
		rv = NNG_ENOMEM;
		goto out;
	}
	nni_list_append(&sock->s_eps, ep);
out:
	nni_mutex_exit(&ep->ep_mx);
	nni_mutex_exit(&sock->s_mx);

	return (rv);
}
