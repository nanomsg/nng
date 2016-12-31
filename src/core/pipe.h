//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_PIPE_H
#define CORE_PIPE_H

// NB: This structure is supplied here for use by the CORE. Use of this
// OUSIDE of the core is STRICTLY VERBOTEN.  NO DIRECT ACCESS BY PROTOCOLS OR
// TRANSPORTS.

#include "core/transport.h"

struct nng_pipe {
	uint32_t		p_id;
	struct nni_pipe_ops	p_ops;
	void *			p_trandata;
	void *			p_pdata;        // protocol specific data
	size_t			p_psize;        // size of protocol data
	nni_list_node		p_node;
	nni_socket *		p_sock;
	nni_endpt *		p_ep;
	int			p_reap;
	int			p_active;
	int			p_abort;
	nni_mutex		p_mx;
	nni_cond		p_cv;
	void			(*p_send)(void *);
	void			(*p_recv)(void *);
	nni_thread *		p_send_thr;
	nni_thread *		p_recv_thr;
};

// Pipe operations that protocols use.
extern int nni_pipe_recv(nni_pipe *, nng_msg **);
extern int nni_pipe_send(nni_pipe *, nng_msg *);
extern uint32_t nni_pipe_id(nni_pipe *);
extern void nni_pipe_close(nni_pipe *);

// Used only by the socket core - as we don't wish to expose the details
// of the pipe structure outside of pipe.c.
extern int nni_pipe_create(nni_pipe **, nni_endpt *);

extern void nni_pipe_destroy(nni_pipe *);

extern int nni_pipe_start(nni_pipe *);
extern int nni_pipe_getopt(nni_pipe *, int, void *, size_t *sizep);

#endif // CORE_PIPE_H
