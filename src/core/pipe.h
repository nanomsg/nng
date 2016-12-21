/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#ifndef CORE_PIPE_H
#define CORE_PIPE_H

/*
 * NB: This structure is supplied here for use by the CORE. Use of this library
 * OUSIDE of the core is STRICTLY VERBOTEN.  NO DIRECT ACCESS BY PROTOCOLS OR
 * TRANSPORTS.
 */

#include "core/transport.h"

struct nng_pipe {
	uint32_t		p_id;
	struct nni_pipe_ops	p_ops;
	void *			p_tran;
	nni_list_node_t		p_sock_node;
	nni_socket_t		p_sock;
	nni_list_node_t		p_ep_node;
	nni_endpt_t		p_ep;
};


/*
 * Pipe operations that protocols use.
 */
extern int nni_pipe_recv(nni_pipe_t, nng_msg_t *);
extern int nni_pipe_send(nni_pipe_t, nng_msg_t);
extern uint32_t nni_pipe_id(nni_pipe_t);
extern void nni_pipe_close(nni_pipe_t);

/*
 * Used only by the socket core - as we don't wish to expose the details
 * of the pipe structure outside of pipe.c.
 */
extern int nni_pipe_create(nni_pipe_t *, struct nni_transport *);

extern void nni_pipe_destroy(nni_pipe_t);

#endif /* CORE_PIPE_H */
