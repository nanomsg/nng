/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "core/nng_impl.h"

/*
 * This file contains functions relating to pipes.
 *
 * Operations on pipes (to the transport) are generally blocking operations,
 * performed in the context of the protocol.
 */

/* nni_pipe_id returns the 32-bit pipe id, which can be used in backtraces. */
uint32_t
nni_pipe_id(nni_pipe_t p)
{
        return (p->p_id);
}

int
nni_pipe_send(nni_pipe_t p, nng_msg_t msg)
{
        return (p->p_ops.p_send(p->p_tran, msg));
}

int
nni_pipe_recv(nni_pipe_t p, nng_msg_t *msgp)
{
        return (p->p_ops.p_recv(p->p_tran, msgp));
}

/*
 * nni_pipe_close closes the underlying connection.  It is expected that
 * subsequent attempts receive or send (including any waiting receive) will
 * simply return NNG_ECLOSED.
 */
void
nni_pipe_close(nni_pipe_t p)
{
        p->p_ops.p_close(p->p_tran);
}

uint16_t
nni_pipe_peer(nni_pipe_t p)
{
        return (p->p_ops.p_peer(p->p_tran));
}

void
nni_pipe_destroy(nni_pipe_t p)
{
	p->p_ops.p_destroy(p->p_tran);
	nni_free(p, sizeof (*p));
}
