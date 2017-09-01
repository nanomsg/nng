//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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

typedef struct pull_pipe pull_pipe;
typedef struct pull_sock pull_sock;

static void pull_putq_cb(void *);
static void pull_recv_cb(void *);
static void pull_putq(pull_pipe *, nni_msg *);

// A pull_sock is our per-socket protocol private structure.
struct pull_sock {
	nni_msgq *urq;
	int       raw;
};

// A pull_pipe is our per-pipe protocol private structure.
struct pull_pipe {
	nni_pipe * pipe;
	pull_sock *pull;
	nni_aio *  putq_aio;
	nni_aio *  recv_aio;
};

static int
pull_sock_init(void **sp, nni_sock *sock)
{
	pull_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	s->raw = 0;
	s->urq = nni_sock_recvq(sock);
	*sp    = s;
	nni_sock_senderr(sock, NNG_ENOTSUP);
	return (0);
}

static void
pull_sock_fini(void *arg)
{
	pull_sock *s = arg;

	NNI_FREE_STRUCT(s);
}

static void
pull_pipe_fini(void *arg)
{
	pull_pipe *p = arg;

	nni_aio_fini(p->putq_aio);
	nni_aio_fini(p->recv_aio);
	NNI_FREE_STRUCT(p);
}

static int
pull_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	pull_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&p->putq_aio, pull_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->recv_aio, pull_recv_cb, p)) != 0)) {
		pull_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->pull = s;
	*pp     = p;
	return (0);
}

static int
pull_pipe_start(void *arg)
{
	pull_pipe *p = arg;

	// Start the pending pull...
	nni_pipe_recv(p->pipe, p->recv_aio);

	return (0);
}

static void
pull_pipe_stop(void *arg)
{
	pull_pipe *p = arg;

	nni_aio_stop(p->putq_aio);
	nni_aio_stop(p->recv_aio);
}

static void
pull_recv_cb(void *arg)
{
	pull_pipe *p   = arg;
	nni_aio *  aio = p->recv_aio;
	nni_msg *  msg;

	if (nni_aio_result(aio) != 0) {
		// Failed to get a message, probably the pipe is closed.
		nni_pipe_stop(p->pipe);
		return;
	}

	// Got a message... start the put to send it up to the application.
	msg = nni_aio_get_msg(aio);
	nni_aio_set_msg(aio, NULL);
	pull_putq(p, msg);
}

static void
pull_putq_cb(void *arg)
{
	pull_pipe *p   = arg;
	nni_aio *  aio = p->putq_aio;

	if (nni_aio_result(aio) != 0) {
		// If we failed to put, probably NNG_ECLOSED, nothing else
		// we can do.  Just close the pipe.
		nni_msg_free(nni_aio_get_msg(aio));
		nni_aio_set_msg(aio, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_pipe_recv(p->pipe, p->recv_aio);
}

// nni_pull_putq schedules a put operation to the user socket (sendup).
static void
pull_putq(pull_pipe *p, nni_msg *msg)
{
	pull_sock *s = p->pull;

	nni_aio_set_msg(p->putq_aio, msg);

	nni_msgq_aio_put(s->urq, p->putq_aio);
}

static void
pull_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pull_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static int
pull_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	pull_sock *s  = arg;
	int        rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
	}
	return (rv);
}

static int
pull_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	pull_sock *s  = arg;
	int        rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_getopt_int(&s->raw, buf, szp);
	}
	return (rv);
}

static nni_proto_pipe_ops pull_pipe_ops = {
	.pipe_init  = pull_pipe_init,
	.pipe_fini  = pull_pipe_fini,
	.pipe_start = pull_pipe_start,
	.pipe_stop  = pull_pipe_stop,
};

static nni_proto_sock_ops pull_sock_ops = {
	.sock_init   = pull_sock_init,
	.sock_fini   = pull_sock_fini,
	.sock_open   = pull_sock_open,
	.sock_close  = pull_sock_close,
	.sock_setopt = pull_sock_setopt,
	.sock_getopt = pull_sock_getopt,
};

static nni_proto pull_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_PULL_V0, "pull" },
	.proto_peer     = { NNG_PROTO_PUSH_V0, "push" },
	.proto_flags    = NNI_PROTO_FLAG_RCV,
	.proto_pipe_ops = &pull_pipe_ops,
	.proto_sock_ops = &pull_sock_ops,
};

int
nng_pull0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pull_proto));
}
