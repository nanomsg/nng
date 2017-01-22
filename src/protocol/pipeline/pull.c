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
	nni_msgq *	urq;
	int		raw;
};

// An nni_pull_pipe is our per-pipe protocol private structure.
struct nni_pull_pipe {
	nni_pipe *	pipe;
	nni_pull_sock * pull;
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

	if (pp != NULL) {
		NNI_FREE_STRUCT(pp);
	}
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
	.pipe_worker	= { nni_pull_pipe_recv },
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
	.proto_flags	= NNI_PROTO_FLAG_RECV,
	.proto_pipe_ops = &nni_pull_pipe_ops,
	.proto_sock_ops = &nni_pull_sock_ops,
};
