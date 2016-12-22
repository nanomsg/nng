//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// Pair protocol.  The PAIR protocol is a simple 1:1 messaging pattern.
// While a peer is connected to the server, all other peer connection
// attempts are discarded.

// An nni_pair_sock is our per-socket protocol private structure.
typedef struct nni_pair_sock {
	nni_socket_t	sock;
	nni_mutex_t	mx;
	nni_pipe_t	pipe;
	nni_msgqueue_t	uwq;
	nni_msgqueue_t	urq;
} nni_pair_sock;

// An nni_pair_pipe is our per-pipe protocol private structure.  We keep
// one of these even though in theory we'd only have a single underlying
// pipe.  The separate data structure is more like other protocols that do
// manage multiple pipes.
typedef struct nni_pair_pipe {
	nni_pipe_t	pipe;
	nni_pair_sock * pair;
	int		good;
	nni_thread_t	sthr;
	nni_thread_t	rthr;
	int		sigclose;
} nni_pair_pipe;

static void nni_pair_receiver(void *);
static void nni_pair_sender(void *);

static int
nni_pair_create(void **pairp, nni_socket_t sock)
{
	nni_pair_sock *pair;
	int rv;

	if ((pair = nni_alloc(sizeof (*pair))) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mutex_create(&pair->mx)) != 0) {
		nni_free(pair, sizeof (*pair));
		return (rv);
	}
	pair->sock = sock;
	pair->uwq = nni_socket_sendq(sock);
	pair->urq = nni_socket_recvq(sock);
	*pairp = pair;
	return (0);
}


static void
nni_pair_destroy(void *arg)
{
	nni_pair_sock *pair = arg;

	// If we had any worker threads that we have not unregistered,
	// this wold be the time to shut them all down.  We don't, because
	// the socket already shut us down, and we don't have any other
	// threads that run.
	nni_mutex_destroy(pair->mx);
	nni_free(pair, sizeof (*pair));
}


static void
nni_pair_shutdown(void *arg)
{
	nni_pair_sock *pair = arg;
	nni_pipe_t pipe;

	// This just causes the protocol to close its various pipes.
	// The draining logic, if any, will have been performed in the
	// upper layer socket.
	//
	// Closing the pipes is intended to cause the receiver on them
	// to notice the failure, and ultimately call back into the socket
	// to unregister them.  The socket can use this to wait for a clean
	// shutdown of all pipe workers.
	nni_mutex_enter(pair->mx);
	pipe = pair->pipe;
	pair->pipe = NULL;
	nni_mutex_exit(pair->mx);

	nni_pipe_close(pipe);
}


static int
nni_pair_add_pipe(void *arg, nni_pipe_t pipe)
{
	nni_pair_sock *pair = arg;
	nni_pair_pipe *pp;
	int rv;

	pp = nni_alloc(sizeof (*pp));
	pp->pipe = pipe;
	pp->good = 0;
	pp->sigclose = 0;
	pp->sthr = NULL;
	pp->rthr = NULL;

	nni_mutex_enter(pair->mx);
	if (pair->pipe != NULL) {
		// Already have a peer, denied.
		nni_mutex_exit(pair->mx);
		nni_free(pp, sizeof (*pp));
		return (NNG_EBUSY);
	}
	if ((rv = nni_thread_create(&pp->rthr, nni_pair_receiver, pp)) != 0) {
		nni_mutex_exit(pair->mx);
		return (rv);
	}
	if ((rv = nni_thread_create(&pp->sthr, nni_pair_sender, pp)) != 0) {
		nni_mutex_exit(pair->mx);
		return (rv);
	}
	pp->good = 1;
	pair->pipe = pipe;
	nni_mutex_exit(pair->mx);
	return (NNG_EINVAL);
}


static int
nni_pair_rem_pipe(void *arg, nni_pipe_t pipe)
{
	nni_pair_pipe *pp = arg;
	nni_pair_sock *pair = pp->pair;

	if (pp->sthr) {
		(void) nni_thread_reap(pp->sthr);
	}
	if (pp->rthr) {
		(void) nni_thread_reap(pp->rthr);
	}
	nni_mutex_enter(pair->mx);
	if (pair->pipe != pipe) {
		nni_mutex_exit(pair->mx);
		return (NNG_EINVAL);
	}
	nni_mutex_exit(pair->mx);
	return (NNG_EINVAL);
}


static void
nni_pair_sender(void *arg)
{
	nni_pair_pipe *pp = arg;
	nni_pair_sock *pair = pp->pair;
	nni_msgqueue_t uwq = pair->uwq;
	nni_msgqueue_t urq = pair->urq;
	nni_pipe_t pipe = pp->pipe;
	nni_msg_t msg;
	int rv;

	nni_mutex_enter(pair->mx);
	if (!pp->good) {
		nni_mutex_exit(pair->mx);
		return;
	}
	nni_mutex_exit(pair->mx);


	for (;;) {
		rv = nni_msgqueue_get_sig(uwq, &msg, -1, &pp->sigclose);
		if (rv != 0) {
			break;
		}
		rv = nni_pipe_send(pipe, msg);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgqueue_signal(urq, &pp->sigclose);
	nni_pipe_close(pipe);
	nni_socket_rem_pipe(pair->sock, pipe);
}


static void
nni_pair_receiver(void *arg)
{
	nni_pair_pipe *pp = arg;
	nni_pair_sock *pair = pp->pair;
	nni_msgqueue_t urq = pair->urq;
	nni_msgqueue_t uwq = pair->uwq;
	nni_pipe_t pipe = pp->pipe;
	nni_msg_t msg;
	int rv;

	nni_mutex_enter(pair->mx);
	if (!pp->good) {
		nni_mutex_exit(pair->mx);
		return;
	}
	nni_mutex_exit(pair->mx);

	for (;;) {
		rv = nni_pipe_recv(pipe, &msg);
		if (rv != 0) {
			break;
		}
		rv = nni_msgqueue_put_sig(urq, msg, -1, &pp->sigclose);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgqueue_signal(uwq, &pp->sigclose);
	nni_pipe_close(pipe);
	nni_socket_rem_pipe(pair->sock, pipe);
}


static int
nni_pair_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	return (NNG_ENOTSUP);
}


static int
nni_pair_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	return (NNG_ENOTSUP);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
struct nni_protocol nni_pair_protocol = {
	NNG_PROTO_PAIR,         // proto_self
	NNG_PROTO_PAIR,         // proto_peer
	"pair",
	nni_pair_create,
	nni_pair_destroy,
	nni_pair_shutdown,
	nni_pair_add_pipe,
	nni_pair_rem_pipe,
	nni_pair_setopt,
	nni_pair_getopt,
	NULL,                   // proto_recvfilter
	NULL,                   // proto_sendfilter
};
