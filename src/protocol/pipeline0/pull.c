//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>

#include "core/nng_impl.h"
#include "nng/protocol/pipeline0/pull.h"

// Pull protocol.  The PULL protocol is the "read" side of a pipeline.

#ifndef NNI_PROTO_PULL_V0
#define NNI_PROTO_PULL_V0 NNI_PROTO(5, 1)
#endif

#ifndef NNI_PROTO_PUSH_V0
#define NNI_PROTO_PUSH_V0 NNI_PROTO(5, 0)
#endif

typedef struct pull0_pipe pull0_pipe;
typedef struct pull0_sock pull0_sock;

static void pull0_putq_cb(void *);
static void pull0_recv_cb(void *);
static void pull0_putq(pull0_pipe *, nni_msg *);

// pull0_sock is our per-socket protocol private structure.
struct pull0_sock {
	nni_msgq *urq;
	bool      raw;
};

// pull0_pipe is our per-pipe protocol private structure.
struct pull0_pipe {
	nni_pipe *  pipe;
	pull0_sock *pull;
	nni_aio *   putq_aio;
	nni_aio *   recv_aio;
};

static int
pull0_sock_init(void *arg, nni_sock *sock)
{
	pull0_sock *s = arg;

	s->urq = nni_sock_recvq(sock);
	return (0);
}

static void
pull0_sock_fini(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pull0_pipe_stop(void *arg)
{
	pull0_pipe *p = arg;

	nni_aio_stop(p->putq_aio);
	nni_aio_stop(p->recv_aio);
}

static void
pull0_pipe_fini(void *arg)
{
	pull0_pipe *p = arg;

	nni_aio_free(p->putq_aio);
	nni_aio_free(p->recv_aio);
}

static int
pull0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	pull0_pipe *p = arg;
	int         rv;

	if (((rv = nni_aio_alloc(&p->putq_aio, pull0_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->recv_aio, pull0_recv_cb, p)) != 0)) {
		pull0_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->pull = s;
	return (0);
}

static int
pull0_pipe_start(void *arg)
{
	pull0_pipe *p = arg;

	if (nni_pipe_peer(p->pipe) != NNI_PROTO_PUSH_V0) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	// Start the pending pull...
	nni_pipe_recv(p->pipe, p->recv_aio);

	return (0);
}

static void
pull0_pipe_close(void *arg)
{
	pull0_pipe *p = arg;

	nni_aio_close(p->putq_aio);
	nni_aio_close(p->recv_aio);
}

static void
pull0_recv_cb(void *arg)
{
	pull0_pipe *p   = arg;
	nni_aio *   aio = p->recv_aio;
	nni_msg *   msg;

	if (nni_aio_result(aio) != 0) {
		// Failed to get a message, probably the pipe is closed.
		nni_pipe_close(p->pipe);
		return;
	}

	// Got a message... start the put to send it up to the application.
	msg = nni_aio_get_msg(aio);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));
	nni_aio_set_msg(aio, NULL);
	pull0_putq(p, msg);
}

static void
pull0_putq_cb(void *arg)
{
	pull0_pipe *p   = arg;
	nni_aio *   aio = p->putq_aio;

	if (nni_aio_result(aio) != 0) {
		// If we failed to put, probably NNG_ECLOSED, nothing else
		// we can do.  Just close the pipe.
		nni_msg_free(nni_aio_get_msg(aio));
		nni_aio_set_msg(aio, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_pipe_recv(p->pipe, p->recv_aio);
}

// pull0_putq schedules a put operation to the user socket (sendup).
static void
pull0_putq(pull0_pipe *p, nni_msg *msg)
{
	pull0_sock *s = p->pull;

	nni_aio_set_msg(p->putq_aio, msg);

	nni_msgq_aio_put(s->urq, p->putq_aio);
}

static void
pull0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pull0_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pull0_sock_send(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static void
pull0_sock_recv(void *arg, nni_aio *aio)
{
	pull0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static nni_proto_pipe_ops pull0_pipe_ops = {
	.pipe_size  = sizeof(pull0_pipe),
	.pipe_init  = pull0_pipe_init,
	.pipe_fini  = pull0_pipe_fini,
	.pipe_start = pull0_pipe_start,
	.pipe_close = pull0_pipe_close,
	.pipe_stop  = pull0_pipe_stop,
};

static nni_option pull0_sock_options[] = {
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops pull0_sock_ops = {
	.sock_size    = sizeof(pull0_sock),
	.sock_init    = pull0_sock_init,
	.sock_fini    = pull0_sock_fini,
	.sock_open    = pull0_sock_open,
	.sock_close   = pull0_sock_close,
	.sock_send    = pull0_sock_send,
	.sock_recv    = pull0_sock_recv,
	.sock_options = pull0_sock_options,
};

static nni_proto pull0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PULL_V0, "pull" },
	.proto_peer     = { NNI_PROTO_PUSH_V0, "push" },
	.proto_flags    = NNI_PROTO_FLAG_RCV,
	.proto_pipe_ops = &pull0_pipe_ops,
	.proto_sock_ops = &pull0_sock_ops,
};

static nni_proto pull0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_PULL_V0, "pull" },
	.proto_peer     = { NNI_PROTO_PUSH_V0, "push" },
	.proto_flags    = NNI_PROTO_FLAG_RCV | NNI_PROTO_FLAG_RAW,
	.proto_pipe_ops = &pull0_pipe_ops,
	.proto_sock_ops = &pull0_sock_ops,
};

int
nng_pull0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pull0_proto));
}

int
nng_pull0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pull0_proto_raw));
}
