//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_ENDPT_H
#define CORE_ENDPT_H

#include "core/transport.h"

// NB: This structure is supplied here for use by the CORE. Use of this
// OUSIDE of the core is STRICTLY VERBOTEN.  NO DIRECT ACCESS BY PROTOCOLS
// OR TRANSPORTS.
struct nng_endpt {
	struct nni_endpt_ops	ep_ops;
	void *			ep_data;	// Transport private
	nni_list_node		ep_sock_node;	// Per socket list
	nni_socket *		ep_sock;
	char			ep_addr[NNG_MAXADDRLEN];
	nni_thread *		ep_dialer;
	nni_thread *		ep_listener;
	int			ep_close;
	nni_mutex		ep_mx;
	nni_cond		ep_cv;
	nni_list		ep_pipes;	// Active list of pipes
};

extern int nni_endpt_create(nni_endpt **, nni_socket *, const char *);
extern void nni_endpt_destroy(nni_endpt *);
extern int nni_endpt_dial(nni_endpt *, nni_pipe **);
extern int nni_endpt_listen(nni_endpt *);
extern int nni_endpt_accept(nni_endpt *, nni_pipe **);
extern void nni_endpt_close(nni_endpt *);

#endif // CORE_ENDPT_H
