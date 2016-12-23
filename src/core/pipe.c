//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

// This file contains functions relating to pipes.
//
// Operations on pipes (to the transport) are generally blocking operations,
// performed in the context of the protocol.

// nni_pipe_id returns the 32-bit pipe id, which can be used in backtraces.
uint32_t
nni_pipe_id(nni_pipe * p)
{
	return (p->p_id);
}


int
nni_pipe_send(nni_pipe * p, nng_msg *msg)
{
	return (p->p_ops.p_send(p->p_tran, msg));
}


int
nni_pipe_recv(nni_pipe * p, nng_msg **msgp)
{
	return (p->p_ops.p_recv(p->p_tran, msgp));
}


// nni_pipe_close closes the underlying connection.  It is expected that
// subsequent attempts receive or send (including any waiting receive) will
// simply return NNG_ECLOSED.
void
nni_pipe_close(nni_pipe * p)
{
	p->p_ops.p_close(p->p_tran);
}


uint16_t
nni_pipe_peer(nni_pipe * p)
{
	return (p->p_ops.p_peer(p->p_tran));
}


void
nni_pipe_destroy(nni_pipe * p)
{
	p->p_ops.p_destroy(p->p_tran);
	nni_free(p, sizeof (*p));
}
