//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdlib.h>
#include <string.h>

void
nni_ev_init(nni_event *event, int type, nni_sock *sock)
{
	memset(event, 0, sizeof(*event));
	event->e_type = type;
	event->e_sock = sock;
}

void
nni_ev_fini(nni_event *event)
{
	NNI_ARG_UNUSED(event);
}
