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

#ifndef CORE_SOCKET_H
#define CORE_SOCKET_H

/*
 * NB: This structure is supplied here for use by the CORE. Use of this library
 * OUSIDE of the core is STRICTLY VERBOTEN.  NO DIRECT ACCESS BY PROTOCOLS OR
 * TRANSPORTS.
 */

struct nng_socket {
	nni_mutex_t	s_mx;

	nni_msgqueue_t	s_uwq;	/* Upper write queue. */
	nni_msgqueue_t	s_urq;	/* Upper read queue. */

	struct nni_protocol s_ops;

	void		*s_data; /* Protocol private. */

	/* options */

	nni_list_t	s_eps;
	nni_list_t	s_pipes;

	int		s_besteffort;	/* Best effort mode delivery. */
	int		s_senderr;	/* Protocol state machine use. */
};

/*
 * Internally used socket API.  Again, this stuff is not part of our public
 * API.
 */

extern int nni_socket_create(nni_socket_t *, uint16_t);
extern int nni_socket_close(nni_socket_t);
extern int nni_socket_add_pipe(nni_socket_t, nni_pipe_t);
extern void nni_socket_remove_pipe(nni_socket_t, nni_pipe_t);
extern uint16_t nni_socket_protocol(nni_socket_t);
extern int nni_socket_setopt(nni_socket_t, int, const void *, size_t);
extern int nni_socket_getopt(nni_socket_t, int, void *, size_t *);

#endif	/* CORE_SOCKET_H */
