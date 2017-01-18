//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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
	nni_mtx			s_mx;
	nni_cv			s_cv;

	nni_msgq *		s_uwq;  // Upper write queue
	nni_msgq *		s_urq;  // Upper read queue

	uint16_t		s_protocol;
	uint16_t		s_peer;

	nni_proto_pipe_ops	s_pipe_ops;
	nni_proto_sock_ops	s_sock_ops;

	void *			s_data; // Protocol private

	// XXX: options
	nni_duration		s_linger;       // linger time
	nni_duration		s_sndtimeo;     // send timeout
	nni_duration		s_rcvtimeo;     // receive timeout
	nni_duration		s_reconn;       // reconnect time
	nni_duration		s_reconnmax;    // max reconnect time

	nni_list		s_eps;          // active endpoints
	nni_list		s_pipes;        // pipes for this socket
	nni_list		s_events;       // pending events
	nni_list		s_notify;       // event watchers
	nni_cv			s_notify_cv;    // wakes notify thread
	nni_mtx			s_notify_mx;    // protects s_notify list

	nni_list		s_reaps;        // pipes to reap
	nni_thr			s_reaper;
	nni_thr			s_notifier;
	nni_thr			s_worker_thr[NNI_MAXWORKERS];

	int			s_ep_pend;      // EP dial/listen in progress
	int			s_closing;      // Socket is closing
	int			s_reapexit;     // Shutdown the reaper
	int			s_besteffort;   // Best effort mode delivery
	int			s_senderr;      // Protocol state machine use
	int			s_recverr;      // Protocol state machine use

	nni_event		s_recv_ev;      // Event for readability
	nni_event		s_send_ev;      // Event for sendability

	uint32_t		s_nextid;       // Next Pipe ID.
};

extern int nni_sock_open(nni_sock **, uint16_t);
extern void nni_sock_close(nni_sock *);
extern int nni_sock_shutdown(nni_sock *);
extern uint16_t nni_sock_proto(nni_sock *);
extern uint16_t nni_sock_peer(nni_sock *);
extern int nni_sock_setopt(nni_sock *, int, const void *, size_t);
extern int nni_sock_getopt(nni_sock *, int, void *, size_t *);
extern int nni_sock_recvmsg(nni_sock *, nni_msg **, nni_time);
extern int nni_sock_sendmsg(nni_sock *, nni_msg *, nni_time);
extern int nni_sock_dial(nni_sock *, const char *, nni_ep **, int);
extern int nni_sock_listen(nni_sock *, const char *, nni_ep **, int);

// Set error codes for applications.  These are only ever
// called from the filter functions in protocols, and thus
// already have the socket lock held.
extern void nni_sock_recverr(nni_sock *, int);
extern void nni_sock_senderr(nni_sock *, int);

// These are socket methods that protocol operations can expect to call.
// Note that each of these should be called without any locks held, since
// the socket can reenter the protocol.

// nni_socket_sendq obtains the upper writeq.  The protocol should
// recieve messages from this, and place them on the appropriate pipe.
extern nni_msgq *nni_sock_sendq(nni_sock *);

// nni_socket_recvq obtains the upper readq.  The protocol should
// inject incoming messages from pipes to it.
extern nni_msgq *nni_sock_recvq(nni_sock *);

// nni_sock_mtx obtains the socket mutex.  This is for protocols to use
// from separate threads; they must not hold the lock for extended periods.
// Additionally, this can only be acquired from separate threads.  The
// synchronous entry points (excluding the send/recv thread workers) will
// be called with this lock already held.  We expose the mutex directly
// here so that protocols can use it to initialize condvars.
extern nni_mtx *nni_sock_mtx(nni_sock *);

#endif  // CORE_SOCKET_H
