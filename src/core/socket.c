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
			nni_mutex_exit(&sock->s_mx);

			// This should already have been done.
			pipe->p_ops.p_close(pipe->p_trandata);

			// Remove the pipe from the protocol.  Protocols may
			// keep lists of pipes for managing their topologies.
			// Note that if a protocol has rejected the pipe, it
			// won't have any data.
			if (pipe->p_protdata != NULL) {
				sock->s_ops.proto_rem_pipe(sock->s_data,
				    pipe->p_protdata);
			}

			// If pipe was a connected (dialer) pipe,
			// then let the endpoint know so it can try to
			// reestablish the connection.
			if ((ep = pipe->p_ep) != NULL) {
				ep->ep_pipe = NULL;
				pipe->p_ep = NULL;
				nni_mutex_enter(&ep->ep_mx);
				nni_cond_signal(&ep->ep_cv);
				nni_mutex_exit(&ep->ep_mx);
			}

			// XXX: also publish event...
			nni_pipe_destroy(pipe);
			continue;
		}

		if (sock->s_reaper == NULL) {
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

	if ((rv = nni_mutex_init(&sock->s_mx)) != 0) {
		nni_free(sock, sizeof (*sock));
		return (rv);
	}
	if ((rv = nni_cond_init(&sock->s_cv, &sock->s_mx)) != 0) {
		nni_mutex_fini(&sock->s_mx);
		nni_free(sock, sizeof (*sock));
		return (rv);
	}

	NNI_LIST_INIT(&sock->s_pipes, nni_pipe, p_node);
	NNI_LIST_INIT(&sock->s_reaps, nni_pipe, p_node);
	NNI_LIST_INIT(&sock->s_eps, nni_endpt, ep_node);

	if ((rv = nni_thread_create(&sock->s_reaper, nni_reaper, sock)) != 0) {
		goto fail;
	}

	if (((rv = nni_msgqueue_create(&sock->s_uwq, 0)) != 0) ||
	    ((rv = nni_msgqueue_create(&sock->s_urq, 0)) != 0)) {
		goto fail;
	}

	if ((rv = sock->s_ops.proto_create(&sock->s_data, sock)) != 0) {
		goto fail;
	}
	*sockp = sock;
	return (0);

fail:
	if (sock->s_urq != NULL) {
		nni_msgqueue_destroy(sock->s_urq);
	}
	if (sock->s_uwq != NULL) {
		nni_msgqueue_destroy(sock->s_uwq);
	}
	if (sock->s_reaper != NULL) {
		nni_thread *reap = sock->s_reaper;
		nni_mutex_enter(&sock->s_mx);
		sock->s_reaper = NULL;
		nni_cond_broadcast(&sock->s_cv);
		nni_mutex_exit(&sock->s_mx);
		nni_thread_reap(reap);
	}
	nni_cond_fini(&sock->s_cv);
	nni_mutex_fini(&sock->s_mx);
	nni_free(sock, sizeof (*sock));
	return (rv);
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
	NNI_LIST_FOREACH (&sock->s_eps, ep) {
		nni_endpt_close(ep);
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

	// Go through and schedule close on all pipes.
	while ((pipe = nni_list_first(&sock->s_pipes)) != NULL) {
		nni_list_remove(&sock->s_pipes, pipe);
		pipe->p_active = 0;
		pipe->p_reap = 1;
		nni_list_append(&sock->s_reaps, pipe);
	}

	// Tell the reaper it's done once it finishes. Also kick it off.
	reaper = sock->s_reaper;
	sock->s_reaper = NULL;
	nni_cond_broadcast(&sock->s_cv);

	// We already told the endpoints to shutdown.  We just
	// need to reap them now.
	while ((ep = nni_list_first(&sock->s_eps)) != NULL) {
		nni_list_remove(&sock->s_eps, ep);
		nni_mutex_exit(&sock->s_mx);

		nni_endpt_destroy(ep);
		nni_mutex_enter(&sock->s_mx);
	}
	nni_mutex_exit(&sock->s_mx);

	// Wait for the reaper to exit.
	nni_thread_reap(reaper);

	// At this point nothing else should be referencing us.
	// The protocol needs to clean up its state.
	sock->s_ops.proto_destroy(sock->s_data);

	// And we need to clean up *our* state.
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


int
nni_socket_add_pipe(nni_socket *sock, nni_pipe *pipe)
{
	int rv;

	nni_mutex_enter(&sock->s_mx);
	if (sock->s_closing) {
		nni_mutex_exit(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	rv = sock->s_ops.proto_add_pipe(sock->s_data, pipe, &pipe->p_protdata);
	if (rv != 0) {
		pipe->p_reap = 1;
		nni_list_append(&sock->s_reaps, pipe);
		nni_cond_broadcast(&sock->s_cv);
		nni_mutex_exit(&sock->s_mx);
		return (rv);
	}
	nni_list_append(&sock->s_pipes, pipe);
	pipe->p_active = 1;

	// XXX: Publish event
	nni_mutex_exit(&sock->s_mx);
	return (0);
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
		nni_endpt_destroy(ep);
	} else {
		if (epp != NULL) {
			*epp = ep;
		}
		nni_mutex_enter(&sock->s_mx);
		nni_list_append(&sock->s_eps, ep);
		nni_mutex_exit(&sock->s_mx);
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
		nni_endpt_destroy(ep);
	} else {
		if (epp != NULL) {
			*epp = ep;
		}
		nni_mutex_enter(&sock->s_mx);
		nni_list_append(&sock->s_eps, ep);
		nni_mutex_exit(&sock->s_mx);
	}
	return (rv);
}


static int
nni_setopt_duration(nni_duration *ptr, const void *val, size_t size)
{
	nni_duration dur;

	if (size != sizeof (*ptr)) {
		return (NNG_EINVAL);
	}
	memcpy(&dur, val, sizeof (dur));
	if (dur < -1) {
		return (-EINVAL);
	}
	*ptr = dur;
	return (0);
}


static int
nni_getopt_duration(nni_duration *ptr, void *val, size_t *sizep)
{
	size_t sz = sizeof (nni_duration);

	if (sz > *sizep) {
		sz = *sizep;
	}
	*sizep = sizeof (nni_duration);
	memcpy(val, ptr, sz);
	return (0);
}


static int
nni_setopt_buf(nni_msgqueue *mq, const void *val, size_t sz)
{
	int len;

	if (sz < sizeof (len)) {
		return (NNG_EINVAL);
	}
	memcpy(&len, val, sizeof (len));
	if (len < 0) {
		return (NNG_EINVAL);
	}
	return (nni_msgqueue_resize(mq, len));
}


static int
nni_getopt_buf(nni_msgqueue *mq, void *val, size_t *sizep)
{
	int len = nni_msgqueue_cap(mq);

	int sz = *sizep;

	if (sz > sizeof (len)) {
		sz = sizeof (len);
	}
	memcpy(val, &len, sz);
	*sizep = sizeof (len);
	return (0);
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
