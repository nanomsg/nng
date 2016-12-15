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

#ifndef CORE_ENDPT_H
#define CORE_ENDPT_H

#include "core/transport.h"

/*
 * NB: This structure is supplied here for use by the CORE. Use of this library
 * OUSIDE of the core is STRICTLY VERBOTEN.  NO DIRECT ACCESS BY PROTOCOLS OR
 * TRANSPORTS.
 */

struct nng_endpt {
        struct nni_endpt_ops    ep_ops;
        void                    *ep_tran;
        nni_list_node_t         ep_sock_node;
        nni_socket_t		ep_sock;
        const char		*ep_addr;
        nni_thread_t		ep_dialer;
        nni_thread_t		ep_listener;
        int			ep_close;
        nni_mutex_t		ep_mx;
        nni_cond_t		ep_cv;
};

/*
 * This file contains definitions for endpoints.
 */

int nni_endpt_create(nni_endpt_t *, nni_socket_t, const char  *);
void nni_endpt_destroy(nni_endpt_t);
int nni_endpt_dial(nni_endpt_t, nni_pipe_t *);
int nni_endpt_listen(nni_endpt_t);
int nni_endpt_accept(nni_endpt_t, nni_pipe_t *);
int nni_endpt_close(nni_endpt_t);

#endif /* CORE_ENDPT_H */