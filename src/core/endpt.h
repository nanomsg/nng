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
	nni_endpt_ops	ep_ops;
	void *		ep_data;                // Transport private
	nni_list_node	ep_node;                // Per socket list
	nni_socket *	ep_sock;
	char		ep_addr[NNG_MAXADDRLEN];
	nni_thr		ep_thr;
	int		ep_mode;
	int		ep_close;       // full shutdown
	int		ep_bound;       // true if we bound locally
	nni_cond	ep_cv;
	nni_pipe *	ep_pipe;        // Connected pipe (dialers only)
};

#define NNI_EP_MODE_IDLE	0
#define NNI_EP_MODE_DIAL	1
#define NNI_EP_MODE_LISTEN	2

extern int nni_endpt_create(nni_endpt **, nni_socket *, const char *);
extern int nni_endpt_accept(nni_endpt *, nni_pipe **);
extern void nni_endpt_close(nni_endpt *);
extern int nni_endpt_dial(nni_endpt *, int);
extern int nni_endpt_listen(nni_endpt *, int);

#endif // CORE_ENDPT_H
