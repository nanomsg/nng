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
	nni_socket *	sock;
	nni_pipe *	pipe;
	nni_mutex	mx;
	nni_msgqueue *	uwq;
	nni_msgqueue *	urq;
} nni_pair_sock;

// An nni_pair_pipe is our per-pipe protocol private structure.  We keep
// one of these even though in theory we'd only have a single underlying
// pipe.  The separate data structure is more like other protocols that do
// manage multiple pipes.
typedef struct nni_pair_pipe {
	nni_pipe *	pipe;
	nni_pair_sock * pair;
	int		good;
	nni_thread *	sthr;
	nni_thread *	rthr;
	int		sigclose;
} nni_pair_pipe;

static void nni_pair_receiver(void *);
static void nni_pair_sender(void *);

static int
nni_pair_create(void **pairp, nni_socket *sock)
{
	nni_pair_sock *pair;
	int rv;

	if ((pair = nni_alloc(sizeof (*pair))) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mutex_init(&pair->mx)) != 0) {
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
	nni_mutex_fini(&pair->mx);
	nni_free(pair, sizeof (*pair));
}


static int
nni_pair_add_pipe(void *arg, nni_pipe *pipe)
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

	nni_mutex_enter(&pair->mx);
	if (pair->pipe != NULL) {
		// Already have a peer, denied.
		nni_mutex_exit(&pair->mx);
		nni_free(pp, sizeof (*pp));
		return (NNG_EBUSY);
	}
	if ((rv = nni_thread_create(&pp->rthr, nni_pair_receiver, pp)) != 0) {
		nni_mutex_exit(&pair->mx);
		return (rv);
	}
	if ((rv = nni_thread_create(&pp->sthr, nni_pair_sender, pp)) != 0) {
		nni_mutex_exit(&pair->mx);
		return (rv);
	}
	pp->good = 1;
	pair->pipe = pipe;
	nni_mutex_exit(&pair->mx);
	return (NNG_EINVAL);
}


static int
nni_pair_rem_pipe(void *arg, nni_pipe *pipe)
{
	nni_pair_pipe *pp = arg;
	nni_pair_sock *pair = pp->pair;

	if (pp->sthr) {
		(void) nni_thread_reap(pp->sthr);
	}
	if (pp->rthr) {
		(void) nni_thread_reap(pp->rthr);
	}
	nni_mutex_enter(&pair->mx);
	if (pair->pipe != pipe) {
		nni_mutex_exit(&pair->mx);
		return (NNG_EINVAL);
	}
	nni_mutex_exit(&pair->mx);
	return (NNG_EINVAL);
}


static void
nni_pair_sender(void *arg)
{
	nni_pair_pipe *pp = arg;
	nni_pair_sock *pair = pp->pair;
	nni_msgqueue *uwq = pair->uwq;
	nni_msgqueue *urq = pair->urq;
	nni_pipe *pipe = pp->pipe;
	nni_msg *msg;
	int rv;

	nni_mutex_enter(&pair->mx);
	if (!pp->good) {
		nni_mutex_exit(&pair->mx);
		return;
	}
	nni_mutex_exit(&pair->mx);


	for (;;) {
		rv = nni_msgqueue_get_sig(uwq, &msg, &pp->sigclose);
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
	nni_msgqueue *urq = pair->urq;
	nni_msgqueue *uwq = pair->uwq;
	nni_pipe *pipe = pp->pipe;
	nni_msg *msg;
	int rv;

	nni_mutex_enter(&pair->mx);
	if (!pp->good) {
		nni_mutex_exit(&pair->mx);
		return;
	}
	nni_mutex_exit(&pair->mx);

	for (;;) {
		rv = nni_pipe_recv(pipe, &msg);
		if (rv != 0) {
			break;
		}
		rv = nni_msgqueue_put_sig(urq, msg, &pp->sigclose);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgqueue_signal(uwq, &pp->sigclose);
	nni_pipe_close(pipe);
	nni_socket_rem_pipe(pair->sock, pipe);
}


// TODO: probably we could replace these with NULL, since we have no
// protocol specific options?
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
	.proto_self		= NNG_PROTO_PAIR,
	.proto_peer		= NNG_PROTO_PAIR,
	.proto_name		= "pair",
	.proto_create		= nni_pair_create,
	.proto_destroy		= nni_pair_destroy,
	.proto_add_pipe		= nni_pair_add_pipe,
	.proto_rem_pipe		= nni_pair_rem_pipe,
	.proto_setopt		= nni_pair_setopt,
	.proto_getopt		= nni_pair_getopt,
	.proto_recv_filter	= NULL,
	.proto_send_filter	= NULL,
};
