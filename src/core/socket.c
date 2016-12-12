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

#include "../nng.h"

#include "nng_impl.h"

/*
 * Socket implementation.
 */

struct nng_socket {
	int		s_proto;
	nni_mutex_t	s_mx;

	nni_msgqueue_t	s_uwq;	/* Upper write queue. */
	nni_msgqueue_t	s_urq;	/* Upper read queue. */

	/* uwq */
	/* urq */
	/* options */
	/* pipes */
	/* endpoints */

	int		s_besteffort;	/* Best effort mode delivery. */
	int		s_senderr;	/* Protocol state machine use. */
};

int
nng_socket_create(nng_socket_t *sockp, int proto)
{
	return (NNG_EAGAIN);	/* XXX: IMPLEMENT ME */
}

int
nng_socket_close(nng_socket_t sock)
{
	nni_msgqueue_close(sock->s_urq);
	/* XXX: drain this? */
	nni_msgqueue_close(sock->s_uwq);

	/* XXX: close endpoints - no new pipes made... */

	/* XXX: protocol shutdown */

	/* XXX: close remaining pipes */

	/* XXX: wait for workers to cease activity */

	return (0);
}

int
nng_socket_sendmsg(nng_socket_t sock, nng_msg_t msg, int tmout)
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

#if 0
	if (s.ops.p_sendhook != NULL) {
		if ((rv = s.ops.p_sendhook(sock->s_proto, msg)) != 0) {
			nng_msg_free(msg);
			return (0);
		}
	}
#endif

	if (besteffort) {
		/*
		 * BestEffort mode -- if we cannot handle the message due
		 * to backpressure, we just throw it away, and don't complain.
		 */
		tmout = 0;
	}
	rv = nni_msgqueue_put(sock->s_uwq, msg, tmout);
	if (besteffort && (rv == NNG_EAGAIN)) {
		/* Pretend this worked... it didn't, but pretend. */
		nng_msg_free(msg);
		return (0);
	}
	return (rv);
}
