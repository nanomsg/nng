//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// Pull protocol.  The PULL protocol is the "read" side of a pipeline.

typedef struct nni_pull_pipe	nni_pull_pipe;
typedef struct nni_pull_sock	nni_pull_sock;

static void nni_pull_putq_cb(void *);
static void nni_pull_recv_cb(void *);
static void nni_pull_recv(nni_pull_pipe *);
static void nni_pull_putq(nni_pull_pipe *, nni_msg *);

// An nni_pull_sock is our per-socket protocol private structure.
struct nni_pull_sock {
	nni_msgq *	urq;
	int		raw;
};

// An nni_pull_pipe is our per-pipe protocol private structure.
struct nni_pull_pipe {
	nni_pipe *	pipe;
	nni_pull_sock * pull;
	nni_aio		putq_aio;
	nni_aio		recv_aio;
};

static int
nni_pull_sock_init(void **pullp, nni_sock *sock)
{
	nni_pull_sock *pull;

	if ((pull = NNI_ALLOC_STRUCT(pull)) == NULL) {
		return (NNG_ENOMEM);
	}
	pull->raw = 0;
	pull->urq = nni_sock_recvq(sock);
	*pullp = pull;
	nni_sock_senderr(sock, NNG_ENOTSUP);
	return (0);
}


static void
nni_pull_sock_fini(void *arg)
{
	nni_pull_sock *pull = arg;

	if (pull != NULL) {
		NNI_FREE_STRUCT(pull);
	}
}


static int
nni_pull_pipe_init(void **ppp, nni_pipe *pipe, void *psock)
{
	nni_pull_pipe *pp;
	int rv;

	if ((pp = NNI_ALLOC_STRUCT(pp)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&pp->putq_aio, nni_pull_putq_cb, pp))) != 0) {
		NNI_FREE_STRUCT(pp);
		return (rv);
	}
	if (((rv = nni_aio_init(&pp->recv_aio, nni_pull_recv_cb, pp))) != 0) {
		nni_aio_fini(&pp->putq_aio);
		NNI_FREE_STRUCT(pp);
		return (rv);
	}
	pp->pipe = pipe;
	pp->pull = psock;
	*ppp = pp;
	return (0);
}


static void
nni_pull_pipe_fini(void *arg)
{
	nni_pull_pipe *pp = arg;

	if (pp != NULL) {
		nni_aio_fini(&pp->putq_aio);
		nni_aio_fini(&pp->recv_aio);
		NNI_FREE_STRUCT(pp);
	}
}


static int
nni_pull_pipe_start(void *arg)
{
	nni_pull_pipe *pp = arg;

	// Start the pending pull...
	nni_pipe_hold(pp->pipe);
	nni_pull_recv(pp);

	return (0);
}


static void
nni_pull_pipe_stop(void *arg)
{
	nni_pull_pipe *pp = arg;

	// Cancel any pending sendup.
	nni_msgq_aio_cancel(pp->pull->urq, &pp->putq_aio);
}


static void
nni_pull_recv_cb(void *arg)
{
	nni_pull_pipe *pp = arg;
	nni_aio *aio = &pp->recv_aio;
	nni_msg *msg;

	if (nni_aio_result(aio) != 0) {
		// Failed to get a message, probably the pipe is closed.
		nni_pipe_close(pp->pipe);
		nni_pipe_rele(pp->pipe);
		return;
	}

	// Got a message... start the put to send it up to the application.
	msg = aio->a_msg;
	aio->a_msg = NULL;
	nni_pull_putq(pp, msg);
}


static void
nni_pull_putq_cb(void *arg)
{
	nni_pull_pipe *pp = arg;
	nni_aio *aio = &pp->putq_aio;
	int rv;

	if (nni_aio_result(aio) != 0) {
		// If we failed to put, probably NNG_ECLOSED, nothing else
		// we can do.  Just close the pipe.
		nni_msg_free(aio->a_msg);
		aio->a_msg = NULL;
		nni_pipe_close(pp->pipe);
		nni_pipe_rele(pp->pipe);
		return;
	}

	nni_pull_recv(pp);
}


// nni_pull_recv is called to schedule a pending recv on the incoming pipe.
static void
nni_pull_recv(nni_pull_pipe *pp)
{
	// Schedule the aio with callback.
	if (nni_pipe_aio_recv(pp->pipe, &pp->recv_aio) != 0) {
		nni_pipe_close(pp->pipe);
		nni_pipe_rele(pp->pipe);
	}
}


// nni_pull_putq schedules a put operation to the user socket (sendup).
static void
nni_pull_putq(nni_pull_pipe *pp, nni_msg *msg)
{
	nni_pull_sock *pull = pp->pull;

	pp->putq_aio.a_msg = msg;

	nni_msgq_aio_put(pull->urq, &pp->putq_aio);
}


static int
nni_pull_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_pull_sock *pull = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_setopt_int(&pull->raw, buf, sz, 0, 1);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_pull_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_pull_sock *pull = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&pull->raw, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops nni_pull_pipe_ops = {
	.pipe_init	= nni_pull_pipe_init,
	.pipe_fini	= nni_pull_pipe_fini,
	.pipe_start	= nni_pull_pipe_start,
	.pipe_stop	= nni_pull_pipe_stop,
};

static nni_proto_sock_ops nni_pull_sock_ops = {
	.sock_init	= nni_pull_sock_init,
	.sock_fini	= nni_pull_sock_fini,
	.sock_setopt	= nni_pull_sock_setopt,
	.sock_getopt	= nni_pull_sock_getopt,
};

nni_proto nni_pull_proto = {
	.proto_self	= NNG_PROTO_PULL,
	.proto_peer	= NNG_PROTO_PUSH,
	.proto_name	= "pull",
	.proto_flags	= NNI_PROTO_FLAG_RCV,
	.proto_pipe_ops = &nni_pull_pipe_ops,
	.proto_sock_ops = &nni_pull_sock_ops,
};
