/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#ifndef CORE_PROTOCOL_H
#define CORE_PROTOCOL_H

/*
 * Protocol implementation details.  Protocols must implement the
 * interfaces in this file.  Note that implementing new protocols is
 * not necessarily intended to be a trivial task.  The protocol developer
 * must understand the nature of nng, as they are responsible for handling
 * most of the logic.  The protocol generally does most of the work for
 * locking, and calls into the transport's pipe functions to do actual
 * work, and the pipe functions generally assume no locking is needed.
 * As a consequence, most of the concurrency in nng exists in the protocol
 * implementations.
 *
 * Pipe operations may block, or even reenter the protoccol entry points
 * (for example nni_pipe_close() causes the protocols proto_remove_pipe
 * entry point to be called), so it is very important that protocols do
 * not hold any locks across calls to pipe functions.
 */

struct nni_protocol {
        /*
         * Protocol information.
         */
        uint16_t        proto_self;     /* our 16-bit protocol ID */
        uint16_t        proto_peer;     /* who we peer with (protocol ID) */
        const char *    proto_name;     /* string version of our name */

        /*
         * Create protocol instance data, which will be stored on the socket.
         */
        int             (*proto_create)(void **, nni_socket_t);

        /*
         * Destroy the protocol instance.
         */
        void            (*proto_destroy)(void *);

        /*
         * Shutdown the protocol instance, including giving time to
         * drain any outbound frames (linger).  The protocol is not
         * required to honor the linger.
         */
        void            (*proto_shutdown)(void *, uint64_t);

        /*
         * Add and remove pipes.  These are called as connections are
         * created or destroyed.
         */
        int             (*proto_add_pipe)(void *, nni_pipe_t);
        int             (*proto_remove_pipe)(void *, nni_pipe_t);

        /*
         * Option manipulation.  These may be NULL.
         */
        int             (*proto_setopt)(void *, int, const void *, size_t);
        int             (*proto_getopt)(void *, int, void *, size_t *);

        /*
         * Receive filter.  This may be NULL, but if it isn't, then
         * messages coming into the system are routed here just before
         * being delivered to the application.  To drop the message,
         * the protocol should return NULL, otherwise the message
         * (possibly modified).
         */
        nng_msg_t       (*proto_recv_filter)(void *, nni_msg_t);

        /*
         * Send filter.  This may be NULL, but if it isn't, then
         * messages here are filtered just after they come from the
         * application.
         */
        nng_msg_t       (*proto_send_filter)(void *, nni_msg_t);
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
extern nni_msgqueue_t nni_socket_sendq(nni_socket_t);

/*
 * nni_socket_recvq obtains the upper readq.  The protocol should
 * inject incoming messages from pipes to it.
 */
extern nni_msgqueue_t nni_socket_recvq(nni_socket_t);

/*
 * nni_socket_recv_err sets an error code to be returned to clients
 * rather than waiting for a message.  Set it to 0 to resume normal
 * receive operation.
 */
extern void nni_socket_recv_err(nni_socket_t, int);

/*
 * nni_socket_send_err sets an error code to be returned to clients
 * when they try to send, so that they don't have to timeout waiting
 * for their message to be accepted for send. Set it to 0 to resume
 * normal send operations.
 */
extern void nni_socket_send_err(nni_socket_t, int);

/*
 * These functions are not used by protocols, but rather by the socket
 * core implementation. The lookups can be used by transports as well.
 */
extern struct nni_protocol *nni_protocol_find(uint16_t);
extern const char *nni_protocol_name(uint16_t);
extern uint16_t nni_protocol_number(const char *);

#endif /* CORE_PROTOCOL_H */
