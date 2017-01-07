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

// An nni_pull_sock is our per-socket protocol private structure.
struct nni_pull_sock {
	nni_mtx		mx;
	nni_msgq *	urq;
	int		raw;
};

// An nni_pull_pipe is our per-pipe protocol private structure.
struct nni_pull_pipe {
	nni_pipe *	pipe;
	nni_pull_sock * pull;
};

static int
nni_pull_init(void **pullp, nni_sock *sock)
{
	nni_pull_sock *pull;
	int rv;

	if ((pull = NNI_ALLOC_STRUCT(pull)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&pull->mx)) != 0) {
		NNI_FREE_STRUCT(pull);
		return (rv);
	}
	pull->raw = 0;
	pull->urq = nni_sock_recvq(sock);
	*pullp = pull;
	nni_sock_senderr(sock, NNG_ENOTSUP);
	return (0);
}


static void
nni_pull_fini(void *arg)
{
	nni_pull_sock *pull = arg;

	nni_mtx_fini(&pull->mx);
	NNI_FREE_STRUCT(pull);
}


static int
nni_pull_pipe_init(void **ppp, nni_pipe *pipe, void *psock)
{
	nni_pull_pipe *pp;
	int rv;

	if ((pp = NNI_ALLOC_STRUCT(pp)) == NULL) {
		return (NNG_ENOMEM);
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

	NNI_FREE_STRUCT(pp);
}


static int
nni_pull_pipe_add(void *arg)
{
	nni_pull_pipe *pp = arg;

	if (nni_pipe_peer(pp->pipe) != NNG_PROTO_PUSH) {
		return (NNG_EPROTO);
	}
	return (0);
}


static void
nni_pull_pipe_rem(void *arg)
{
	NNI_ARG_UNUSED(arg);
}


static void
nni_pull_pipe_send(void *arg)
{
	NNI_ARG_UNUSED(arg);
}


static void
nni_pull_pipe_recv(void *arg)
{
	nni_pull_pipe *pp = arg;
	nni_pull_sock *pull = pp->pull;
	nni_msg *msg;

	for (;;) {
		if (nni_pipe_recv(pp->pipe, &msg) != 0) {
			break;
		}
		if (nni_msgq_put(pull->urq, msg) != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_pipe_close(pp->pipe);
}


static int
nni_pull_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_pull_sock *pull = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		nni_mtx_lock(&pull->mx);
		rv = nni_setopt_int(&pull->raw, buf, sz, 0, 1);
		nni_mtx_unlock(&pull->mx);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_pull_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_pull_sock *pull = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		nni_mtx_lock(&pull->mx);
		rv = nni_getopt_int(&pull->raw, buf, szp);
		nni_mtx_unlock(&pull->mx);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe nni_pull_proto_pipe = {
	.pipe_init	= nni_pull_pipe_init,
	.pipe_fini	= nni_pull_pipe_fini,
	.pipe_add	= nni_pull_pipe_add,
	.pipe_rem	= nni_pull_pipe_rem,
	.pipe_send	= nni_pull_pipe_send,
	.pipe_recv	= nni_pull_pipe_recv,
};

nni_proto nni_pull_proto = {
	.proto_self		= NNG_PROTO_PULL,
	.proto_peer		= NNG_PROTO_PUSH,
	.proto_name		= "pull",
	.proto_pipe		= &nni_pull_proto_pipe,
	.proto_init		= nni_pull_init,
	.proto_fini		= nni_pull_fini,
	.proto_setopt		= nni_pull_setopt,
	.proto_getopt		= nni_pull_getopt,
	.proto_recv_filter	= NULL,
	.proto_send_filter	= NULL,
};
