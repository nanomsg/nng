/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "core/nng_impl.h"

/*
 * Socket implementation.
 */

/*
 * nni_socket_sendq and nni_socket_recvq are called by the protocol to obtain
 * the upper read and write queues.
 */
nni_msgqueue_t
nni_socket_sendq(nni_socket_t s)
{
	return (s->s_uwq);
}

nni_msgqueue_t
nni_socket_recvq(nni_socket_t s)
{
	return (s->s_urq);
}

int
nni_socket_create(nni_socket_t *sockp, uint16_t proto)
{
        nni_socket_t sock;
        struct nni_protocol *ops;
        int rv;

        if ((ops = nni_protocol_find(proto)) == NULL) {
        	return (NNG_ENOTSUP);
        }
        if ((sock = nni_alloc(sizeof (*sock))) == NULL) {
        	return (NNG_ENOMEM);
        }
        sock->s_ops = *ops;

        NNI_LIST_INIT(&sock->s_pipes, struct nng_pipe, p_sock_node);
        //NNI_LIST_INIT(&sock->s_eps, nni_endpt_t, ep_node);

        if ((rv = sock->s_ops.proto_create(&sock->s_data, sock)) != 0) {
        	nni_free(sock, sizeof (*sock));
        	return (rv);

        }
        *sockp = sock;
	return (0);
}

int
nni_socket_close(nni_socket_t sock)
{
	nni_pipe_t pipe;
	nni_endpt_t ep;

	nni_msgqueue_close(sock->s_urq);
	/* XXX: drain this? */
	nni_msgqueue_close(sock->s_uwq);

	nni_mutex_enter(sock->s_mx);
	NNI_LIST_FOREACH(&sock->s_eps, ep) {
		#if 0
		nni_ep_stop(ep);
		// OR....
		nni_mutex_enter(ep->ep_mx);
		ep->ep_stop = 1;
		nni_cond_broadcast(ep->ep_cond);
		nni_mutex_exit(ep->ep_mx);
		#endif
		break;	/* REMOVE ME */
	}
	nni_mutex_exit(sock->s_mx);
	/* XXX: close endpoints - no new pipes made... */

	/* XXX: protocol shutdown */

	/*
	 * Paths to pipe close:
	 *
	 * - user calls nng_pipe_close()
	 * - protocol calls pipe_close() after underlying close
	 * - socket calls pipe close due to socket_close (here)
	 */

	/* XXX: close remaining pipes */
	while ((pipe = nni_list_first(&sock->s_pipes)) != NULL) {
		nni_list_remove(&sock->s_pipes, pipe);
		/* XXX: nni_pipe_destroy */
	}

	/* XXX: wait for workers to cease activity */
	while ((ep = nni_list_first(&sock->s_eps)) != NULL) {
		nni_list_remove(&sock->s_eps, ep);
		/* XXX: nni_ep_destroy(ep); */
	}

	return (0);
}

int
nni_socket_sendmsg(nni_socket_t sock, nni_msg_t msg, int tmout)
{
	int rv;
	int besteffort;

	/*
	 * Senderr is typically set by protocols when the state machine
	 * indicates that it is no longer valid to send a message.  E.g.
	 * a REP socket with no REQ pending.
	 */
	nni_mutex_enter(sock->s_mx);
	if ((rv = sock->s_senderr) != 0) {
		nni_mutex_exit(sock->s_mx);
		return (rv);
	}
	besteffort = sock->s_besteffort;
	nni_mutex_exit(sock->s_mx);

	if (sock->s_ops.proto_send_filter != NULL) {
		msg = sock->s_ops.proto_send_filter(sock->s_data, msg);
		if (msg == NULL) {
			return (0);
		}
	}

	if (besteffort) {
		/*
                 * BestEffort mode -- if we cannot handle the message due to
                 * backpressure, we just throw it away, and don't complain.
		 */
		tmout = 0;
	}
	rv = nni_msgqueue_put(sock->s_uwq, msg, tmout);
	if (besteffort && (rv == NNG_EAGAIN)) {
		/* Pretend this worked... it didn't, but pretend. */
		nni_msg_free(msg);
		return (0);
	}
	return (rv);
}

uint16_t
nni_socket_protocol(nni_socket_t sock)
{
        return (sock->s_ops.proto_self);
}

void
nni_socket_remove_pipe(nni_socket_t sock, nni_pipe_t pipe)
{
	nni_mutex_enter(sock->s_mx);
	if (pipe->p_sock != sock) {
		nni_mutex_exit(sock->s_mx);
	}
	/*
	 * Remove the pipe from the protocol.  Protocols may
	 * keep lists of pipes for managing their topologies.
	 */
	sock->s_ops.proto_remove_pipe(sock->s_data, pipe);

	/* Now remove it from our own list */
	nni_list_remove(&sock->s_pipes, pipe);
	pipe->p_sock = NULL;
	// XXX: Redial
	// XXX: also publish event...
	//if (pipe->p_ep != NULL) {
	//	nn_endpt_remove_pipe(pipe->p_ep, pipe)
	//}
	nni_mutex_exit(sock->s_mx);
}

int
nni_socket_add_pipe(nni_socket_t sock, nni_pipe_t pipe)
{
	int rv;
	nni_mutex_enter(sock->s_mx);
	if ((rv = sock->s_ops.proto_add_pipe(sock->s_data, pipe)) != 0) {
		nni_mutex_exit(sock->s_mx);
		return (rv);
	}
	nni_list_append(&sock->s_pipes, pipe);
	pipe->p_sock = sock;
	/* XXX: Publish event */
	nni_mutex_exit(sock->s_mx);
	return (0);
}
