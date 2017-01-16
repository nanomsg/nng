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

// Publish protocol.  The PUB protocol simply sends messages out, as
// a broadcast.  It has nothing more sophisticated because it does not
// perform sender-side filtering.  Its best effort delivery, so anything
// that can't receive the message won't get one.

typedef struct nni_pub_pipe	nni_pub_pipe;
typedef struct nni_pub_sock	nni_pub_sock;

// An nni_pub_sock is our per-socket protocol private structure.
struct nni_pub_sock {
	nni_sock *	sock;
	nni_msgq *	uwq;
	int		raw;
	nni_list	pipes;
};

// An nni_pub_pipe is our per-pipe protocol private structure.
struct nni_pub_pipe {
	nni_pipe *	pipe;
	nni_pub_sock *	pub;
	nni_msgq *	sendq;
	nni_list_node	node;
	int		sigclose;
};

static int
nni_pub_sock_init(void **pubp, nni_sock *sock)
{
	nni_pub_sock *pub;

	if ((pub = NNI_ALLOC_STRUCT(pub)) == NULL) {
		return (NNG_ENOMEM);
	}
	pub->sock = sock;
	pub->raw = 0;
	NNI_LIST_INIT(&pub->pipes, nni_pub_pipe, node);

	pub->uwq = nni_sock_sendq(sock);

	*pubp = pub;
	nni_sock_recverr(sock, NNG_ENOTSUP);
	return (0);
}


static void
nni_pub_sock_fini(void *arg)
{
	nni_pub_sock *pub = arg;

	NNI_FREE_STRUCT(pub);
}


static int
nni_pub_pipe_init(void **ppp, nni_pipe *pipe, void *psock)
{
	nni_pub_pipe *pp;
	int rv;

	if ((pp = NNI_ALLOC_STRUCT(pp)) == NULL) {
		return (NNG_ENOMEM);
	}
	// XXX: consider making this depth tunable
	if ((rv = nni_msgq_init(&pp->sendq, 16)) != 0) {
		NNI_FREE_STRUCT(pp);
		return (rv);
	}
	pp->pipe = pipe;
	pp->pub = psock;
	pp->sigclose = 0;
	*ppp = pp;
	return (0);
}


static void
nni_pub_pipe_fini(void *arg)
{
	nni_pub_pipe *pp = arg;

	nni_msgq_fini(pp->sendq);
	NNI_FREE_STRUCT(pp);
}


static int
nni_pub_pipe_add(void *arg)
{
	nni_pub_pipe *pp = arg;
	nni_pub_sock *pub = pp->pub;

	if (nni_pipe_peer(pp->pipe) != NNG_PROTO_SUB) {
		return (NNG_EPROTO);
	}
	nni_list_append(&pub->pipes, pp);
	return (0);
}


static void
nni_pub_pipe_rem(void *arg)
{
	nni_pub_pipe *pp = arg;
	nni_pub_sock *pub = pp->pub;

	nni_list_remove(&pub->pipes, pp);
}


static void
nni_pub_sock_send(void *arg)
{
	nni_pub_sock *pub = arg;
	nni_msgq *uwq = pub->uwq;
	nni_msg *msg, *dup;
	nni_mtx *mx = nni_sock_mtx(pub->sock);

	for (;;) {
		nni_pub_pipe *pp;
		nni_pub_pipe *last;
		int rv;

		if ((rv = nni_msgq_get(uwq, &msg)) != 0) {
			break;
		}

		nni_mtx_lock(mx);
		last = nni_list_last(&pub->pipes);
		NNI_LIST_FOREACH (&pub->pipes, pp) {
			if (pp != last) {
				rv = nni_msg_dup(&dup, msg);
				if (rv != 0) {
					continue;
				}
			} else {
				dup = msg;
			}
			if ((rv = nni_msgq_tryput(pp->sendq, dup)) != 0) {
				nni_msg_free(dup);
			}
		}
		nni_mtx_unlock(mx);

		if (last == NULL) {
			nni_msg_free(msg);
		}
	}
}


static void
nni_pub_pipe_send(void *arg)
{
	nni_pub_pipe *pp = arg;
	nni_msgq *wq = pp->sendq;
	nni_pipe *pipe = pp->pipe;
	nni_msg *msg;
	int rv;

	for (;;) {
		rv = nni_msgq_get_sig(wq, &msg, &pp->sigclose);
		if (rv != 0) {
			break;
		}

		rv = nni_pipe_send(pipe, msg);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_pipe_close(pipe);
}


static void
nni_pub_pipe_recv(void *arg)
{
	nni_pub_pipe *pp = arg;
	nni_msgq *uwq = pp->pub->uwq;
	nni_pipe *pipe = pp->pipe;
	nni_msg *msg;
	int rv;

	// All we do is spin, waiting for the underlying transport to close.
	// We discard anything we happen to get.
	for (;;) {
		rv = nni_pipe_recv(pipe, &msg);
		if (rv != 0) {
			break;
		}
		nni_msg_free(msg);
	}

	nni_msgq_signal(uwq, &pp->sigclose);
	nni_msgq_signal(pp->sendq, &pp->sigclose);
	nni_pipe_close(pipe);
}


static int
nni_pub_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_pub_sock *pub = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_setopt_int(&pub->raw, buf, sz, 0, 1);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_pub_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_pub_sock *pub = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&pub->raw, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops nni_pub_pipe_ops = {
	.pipe_init	= nni_pub_pipe_init,
	.pipe_fini	= nni_pub_pipe_fini,
	.pipe_add	= nni_pub_pipe_add,
	.pipe_rem	= nni_pub_pipe_rem,
	.pipe_worker	= { nni_pub_pipe_send,
			    nni_pub_pipe_recv },
};

nni_proto_sock_ops nni_pub_sock_ops = {
	.sock_init	= nni_pub_sock_init,
	.sock_fini	= nni_pub_sock_fini,
	.sock_setopt	= nni_pub_sock_setopt,
	.sock_getopt	= nni_pub_sock_getopt,
	.sock_worker	= { nni_pub_sock_send },
};

nni_proto nni_pub_proto = {
	.proto_self	= NNG_PROTO_PUB,
	.proto_peer	= NNG_PROTO_SUB,
	.proto_name	= "pub",
	.proto_sock_ops = &nni_pub_sock_ops,
	.proto_pipe_ops = &nni_pub_pipe_ops,
};
