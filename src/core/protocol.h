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

#ifndef CORE_PROTOCOL_H
#define CORE_PROTOCOL_H

/*
 * Protocol implementation details.  Protocols must implement the
 * interfaces in this file.
 */

struct nni_protocol {

	/*
	 * Protocol information.
	 */
	uint16_t	proto_self;	/* our 16-bit protocol ID */
	uint16_t	proto_peer;	/* who we peer with (protocol ID) */

	/*
	 * Create protocol instance data, which will be stored on the socket.
	 */
	int (*proto_create)(void **, nng_socket_t);

	/*
	 * Destroy the protocol instance.
	 */
	void (*proto_destroy)(void *);

	/*
	 * Shutdown the protocol instance, including giving time to
	 * drain any outbound frames (linger).  The protocol is not
	 * required to honor the linger.
	 */
	void (*proto_shutdown)(void *, uint64_t);

	/*
	 * Add and remove pipes.  These are called as connections are
	 * created or destroyed.
	 */
	int (*proto_add_pipe)(void *, nng_pipe_t);
	int (*proto_remove_pipe)(void *, nng_pipe_t);

	/*
	 * Option manipulation.  These may be NULL.
	 */
	int (*proto_setopt)(void *, int, const void *, size_t);
	int (*proto_getopt)(void *, int, void **, size_t *);

	/*
	 * Receive filter.  This may be NULL, but if it isn't, then
	 * messages coming into the system are routed here just before
	 * being delivered to the application.  To drop the message,
	 * the protocol should return NULL, otherwise the message
	 * (possibly modified).
	 */
	nng_msg_t (*proto_recv_filter)(void *, nng_msg_t);

	/*
	 * Send filter.  This may be NULL, but if it isn't, then
	 * messages here are filtered just after they come from the 
	 * application.
	 */
	nng_msg_t (*proto_send_filter)(void *, nng_msg_t);
};

/*
 * These are socket methods that protocol operations can
 * reasonably expect to call.
 */

/*
 * nni_socket_sendq obtains the upper writeq.  The protocol should
 * recieve messages from this, and place them on the appropriate
 * pipe.
 */
extern nni_msgqueue_t nni_socket_sendq(nng_socket_t);

/*
 * nni_socket_recvq obtains the upper readq.  The protocol should
 * inject incoming messages from pipes to it.
 */
extern nni_msgqueue_t nni_socket_recvq(nng_socket_t);

/*
 * nni_socket_recv_err sets an error code to be returned to clients
 * rather than waiting for a message.  Set it to 0 to resume normal
 * receive operation.
 */
extern void nni_socket_recv_err(nng_socket_t, int);

/*
 * nni_socket_send_err sets an error code to be returned to clients
 * when they try to send, so that they don't have to timeout waiting
 * for their message to be accepted for send. Set it to 0 to resume
 * normal send operations.
 */
extern void nni_socket_send_err(nng_socket_t, int);

/*
 * Pipe operations that protocols use.
 */
extern int nni_pipe_recv(nng_pipe_t, nng_msg_t *);
extern int nni_pipe_send(nng_pipe_t, nng_msg_t);
extern uint32_t nni_pipe_id(nng_pipe_t);
extern uint32_t nni_pipe_close(nng_pipe_t);

#endif /* CORE_PROTOCOL_H */
