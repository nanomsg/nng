//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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
	int		e_type;
	nni_sock *	e_sock;
	nni_ep *	e_ep;
	nni_pipe *	e_pipe;

	int		e_done;         // true when notify thr is finished
	int		e_pending;      // true if event is queued
	nni_cv		e_cv;           // signaled when e_done is noted
	nni_list_node	e_node;         // location on the socket list
};

struct nng_notify {
	nni_list_node	n_node;
	nng_notify_func n_func;
	void *		n_arg;
	int		n_mask;
};

#endif // CORE_EVENT_H
