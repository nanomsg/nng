//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_SOCKET_H
#define CORE_SOCKET_H

// NB: This structure is supplied here for use by the CORE. Use of this library
// OUSIDE of the core is STRICTLY VERBOTEN.  NO DIRECT ACCESS BY PROTOCOLS OR
// TRANSPORTS.
struct nng_socket {
	nni_mutex	s_mx;
	nni_cond	s_cv;

	nni_msgqueue *	s_uwq;          // Upper write queue
	nni_msgqueue *	s_urq;          // Upper read queue

	nni_protocol	s_ops;

	void *		s_data;         // Protocol private

	// XXX: options
	nni_duration	s_linger;

	nni_list	s_eps;                  // active endpoints
	nni_list	s_pipes;                // pipes for this socket

	int		s_closing;              // Socket is closing
	int		s_besteffort;           // Best effort mode delivery
	int		s_senderr;              // Protocol state machine use
	int		s_recverr;              // Protocol state machine use

	uint32_t	s_nextid;               // Next Pipe ID.
};

extern int nni_socket_create(nni_socket **, uint16_t);
extern int nni_socket_close(nni_socket *);
extern int nni_socket_add_pipe(nni_socket *, nni_pipe *, int);
extern void nni_socket_rem_pipe(nni_socket *, nni_pipe *);
extern uint16_t nni_socket_proto(nni_socket *);
extern int nni_socket_setopt(nni_socket *, int, const void *, size_t);
extern int nni_socket_getopt(nni_socket *, int, void *, size_t *);

#endif  // CORE_SOCKET_H
