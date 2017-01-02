//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <string.h>

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


// Because we have to call back into the socket, and possibly also the proto,
// and wait for threads to terminate, we do this in a special thread.  The
// assumption is that closing is always a "fast" operation.
static void
nni_reaper(void *arg)
{
	nni_socket *sock = arg;

	for (;;) {
		nni_pipe *pipe;
		nni_endpt *ep;

		nni_mutex_enter(&sock->s_mx);
		if ((pipe = nni_list_first(&sock->s_reaps)) != NULL) {
			nni_list_remove(&sock->s_reaps, pipe);

			if (((ep = pipe->p_ep) != NULL) &&
			    ((ep->ep_pipe == pipe))) {
				ep->ep_pipe = NULL;
				nni_cond_broadcast(&ep->ep_cv);
			}
			nni_mutex_exit(&sock->s_mx);

			// This should already have been done.
			if (pipe->p_trandata != NULL) {
				pipe->p_ops.p_close(pipe->p_trandata);
			}

			// Remove the pipe from the protocol.  Protocols may
			// keep lists of pipes for managing their topologies.
			// Note that if a protocol has rejected the pipe, it
			// won't have any data.
			if (pipe->p_active) {
				sock->s_ops.proto_rem_pipe(sock->s_data,
				    pipe->p_pdata);
			}

			// XXX: also publish event...
			nni_pipe_destroy(pipe);
			continue;
		}

		if ((sock->s_closing) &&
		    (nni_list_first(&sock->s_reaps) == NULL) &&
		    (nni_list_first(&sock->s_pipes) == NULL)) {
			nni_mutex_exit(&sock->s_mx);
			break;
		}

		nni_cond_wait(&sock->s_cv);
		nni_mutex_exit(&sock->s_mx);
	}
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
	sock->s_linger = 0;
	sock->s_sndtimeo = -1;
	sock->s_rcvtimeo = -1;
	sock->s_closing = 0;
	sock->s_reconn = NNI_SECOND;
	sock->s_reconnmax = NNI_SECOND;
	NNI_LIST_INIT(&sock->s_pipes, nni_pipe, p_node);
	NNI_LIST_INIT(&sock->s_reaps, nni_pipe, p_node);
	NNI_LIST_INIT(&sock->s_eps, nni_endpt, ep_node);

	if ((rv = nni_mutex_init(&sock->s_mx)) != 0) {
		nni_free(sock, sizeof (*sock));
		return (rv);
	}
	if ((rv = nni_cond_init(&sock->s_cv, &sock->s_mx)) != 0) {
		nni_mutex_fini(&sock->s_mx);
		nni_free(sock, sizeof (*sock));
		return (rv);
	}

	if ((rv = nni_thr_init(&sock->s_reaper, nni_reaper, sock)) != 0) {
		nni_cond_fini(&sock->s_cv);
		nni_mutex_fini(&sock->s_mx);
		nni_free(sock, sizeof (*sock));
		return (rv);
	}

	if ((rv = nni_msgqueue_create(&sock->s_uwq, 0)) != 0) {
		nni_thr_fini(&sock->s_reaper);
		nni_cond_fini(&sock->s_cv);
		nni_mutex_fini(&sock->s_mx);
		nni_free(sock, sizeof (*sock));
		return (rv);
	}
	if ((rv = nni_msgqueue_create(&sock->s_urq, 0)) != 0) {
		nni_msgqueue_destroy(sock->s_uwq);
		nni_thr_fini(&sock->s_reaper);
		nni_cond_fini(&sock->s_cv);
		nni_mutex_fini(&sock->s_mx);
		nni_free(sock, sizeof (*sock));
		return (rv);
	}

	if ((rv = sock->s_ops.proto_create(&sock->s_data, sock)) != 0) {
		nni_msgqueue_destroy(sock->s_urq);
		nni_msgqueue_destroy(sock->s_uwq);
		nni_thr_fini(&sock->s_reaper);
		nni_cond_fini(&sock->s_cv);
		nni_mutex_fini(&sock->s_mx);
		nni_free(sock, sizeof (*sock));
		return (rv);
	}
	nni_thr_run(&sock->s_reaper);
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
	nni_thread *reaper;

	nni_mutex_enter(&sock->s_mx);
	// Mark us closing, so no more EPs or changes can occur.
	sock->s_closing = 1;

	// Stop all EPS.  We're going to do this first, since we know
	// we're closing.
	while ((ep = nni_list_first(&sock->s_eps)) != NULL) {
		nni_mutex_exit(&sock->s_mx);
		nni_endpt_close(ep);
		nni_mutex_enter(&sock->s_mx);
	}

	// Special optimization; if there are no pipes connected,
	// then there is no reason to linger since there's nothing that
	// could possibly send this data out.
	if (nni_list_first(&sock->s_pipes) == NULL) {
		linger = NNI_TIME_ZERO;
	} else {
		linger = nni_clock() + sock->s_linger;
	}
	nni_mutex_exit(&sock->s_mx);


	// We drain the upper write queue.  This is just like closing it,
	// except that the protocol gets a chance to get the messages and
	// push them down to the transport.  This operation can *block*
	// until the linger time has expired.
	nni_msgqueue_drain(sock->s_uwq, linger);

	// Generally, unless the protocol is blocked trying to perform
	// writes (e.g. a slow reader on the other side), it should be
	// trying to shut things down.  We wait to give it
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

	// Go through and schedule close on all pipes.
	while ((pipe = nni_list_first(&sock->s_pipes)) != NULL) {
		nni_list_remove(&sock->s_pipes, pipe);
		pipe->p_reap = 1;
		nni_list_append(&sock->s_reaps, pipe);
	}

	nni_cond_broadcast(&sock->s_cv);
	nni_mutex_exit(&sock->s_mx);

	// Wait for the reaper to exit.
	nni_thr_fini(&sock->s_reaper);

	// At this point nothing else should be referencing us.
	// The protocol needs to clean up its state.
	sock->s_ops.proto_destroy(sock->s_data);

	// And we need to clean up *our* state.
	nni_msgqueue_destroy(sock->s_urq);
	nni_msgqueue_destroy(sock->s_uwq);
	nni_cond_fini(&sock->s_cv);
	nni_mutex_fini(&sock->s_mx);
	nni_free(sock, sizeof (*sock));
	return (0);
}


int
nni_socket_sendmsg(nni_socket *sock, nni_msg *msg, nni_time expire)
{
	int rv;
	int besteffort;

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
nni_socket_recvmsg(nni_socket *sock, nni_msg **msgp, nni_time expire)
{
	int rv;
	nni_msg *msg;

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
		if (sock->s_ops.proto_recv_filter != NULL) {
			msg = sock->s_ops.proto_recv_filter(sock->s_data, msg);
		}
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


int
nni_socket_dial(nni_socket *sock, const char *addr, nni_endpt **epp, int flags)
{
	nni_endpt *ep;
	int rv;

	if ((rv = nni_endpt_create(&ep, sock, addr)) != 0) {
		return (rv);
	}
	rv = nni_endpt_dial(ep, flags);
	if (rv != 0) {
		nni_endpt_close(ep);
	} else {
		if (epp != NULL) {
			*epp = ep;
		}
	}
	return (rv);
}


int
nni_socket_listen(nni_socket *sock, const char *addr, nni_endpt **epp,
    int flags)
{
	nni_endpt *ep;
	int rv;

	if ((rv = nni_endpt_create(&ep, sock, addr)) != 0) {
		return (rv);
	}
	rv = nni_endpt_listen(ep, flags);
	if (rv != 0) {
		nni_endpt_close(ep);
	} else {
		if (epp != NULL) {
			*epp = ep;
		}
	}
	return (rv);
}


void
nni_socket_recverr(nni_socket *sock, int err)
{
	sock->s_recverr = err;
}


void
nni_socket_senderr(nni_socket *sock, int err)
{
	sock->s_senderr = err;
}


int
nni_socket_setopt(nni_socket *sock, int opt, const void *val, size_t size)
{
	size_t rsz;
	void *ptr;
	int rv = ENOTSUP;

	nni_mutex_enter(&sock->s_mx);
	if (sock->s_ops.proto_setopt != NULL) {
		rv = sock->s_ops.proto_setopt(sock->s_data, opt, val, size);
		if (rv != NNG_ENOTSUP) {
			nni_mutex_exit(&sock->s_mx);
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
	}
	nni_mutex_exit(&sock->s_mx);
	return (rv);
}


int
nni_socket_getopt(nni_socket *sock, int opt, void *val, size_t *sizep)
{
	size_t rsz;
	void *ptr;
	int rv = ENOTSUP;

	nni_mutex_enter(&sock->s_mx);
	if (sock->s_ops.proto_getopt != NULL) {
		rv = sock->s_ops.proto_getopt(sock->s_data, opt, val, sizep);
		if (rv != NNG_ENOTSUP) {
			nni_mutex_exit(&sock->s_mx);
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
	}
	nni_mutex_exit(&sock->s_mx);
	return (rv);
}
