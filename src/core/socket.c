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

struct nng_socket {
	nni_mutex_t	s_mx;

	nni_msgqueue_t	s_uwq;	/* Upper write queue. */
	nni_msgqueue_t	s_urq;	/* Upper read queue. */

	struct nni_protocol s_ops;

	void		*s_data; /* Protocol private. */

	/* options */

	nni_list_t	s_eps;
	nni_list_t	s_pipes;

	int		s_besteffort;	/* Best effort mode delivery. */
	int		s_senderr;	/* Protocol state machine use. */
};

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

        nni_pipe_list_init(&sock->s_pipes);
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

	nni_msgqueue_close(sock->s_urq);
	/* XXX: drain this? */
	nni_msgqueue_close(sock->s_uwq);

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
		/* XXX: call nni_pipe_close, then nni_pipe_destroy */
	}

	/* XXX: wait for workers to cease activity */

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
