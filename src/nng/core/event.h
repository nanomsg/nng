//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_EVENT_H
#define CORE_EVENT_H

#include "core/defs.h"
#include "core/list.h"

struct nng_event {
	int       e_type;
	nni_sock *e_sock;
	nni_ep *  e_ep;
	nni_pipe *e_pipe;
};

struct nng_notify {
	nng_notify_func n_func;
	void *          n_arg;
	int             n_type;
	nni_sock *      n_sock;
	nni_aio *       n_aio;
};

extern void nni_ev_init(nni_event *, int, nni_sock *);
extern void nni_ev_fini(nni_event *);

#endif // CORE_EVENT_H
