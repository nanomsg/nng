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
struct nng_endpoint {
	nni_tran_ep	ep_ops;
	nni_tran *	ep_tran;
	void *		ep_data;                // Transport private
	nni_list_node	ep_node;                // Per socket list
	nni_sock *	ep_sock;
	char		ep_addr[NNG_MAXADDRLEN];
	nni_thr		ep_thr;
	int		ep_mode;
	int		ep_close;       // full shutdown
	int		ep_bound;       // true if we bound locally
	nni_cv		ep_cv;
	nni_pipe *	ep_pipe;        // Connected pipe (dialers only)
};

#define NNI_EP_MODE_IDLE	0
#define NNI_EP_MODE_DIAL	1
#define NNI_EP_MODE_LISTEN	2

extern int nni_ep_create(nni_ep **, nni_sock *, const char *);
extern int nni_ep_accept(nni_ep *, nni_pipe **);
extern void nni_ep_close(nni_ep *);
extern int nni_ep_dial(nni_ep *, int);
extern int nni_ep_listen(nni_ep *, int);

#endif // CORE_ENDPT_H
