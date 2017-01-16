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

// Pair protocol.  The PAIR protocol is a simple 1:1 messaging pattern.
// While a peer is connected to the server, all other peer connection
// attempts are discarded.

typedef struct nni_pair_pipe	nni_pair_pipe;
typedef struct nni_pair_sock	nni_pair_sock;

// An nni_pair_sock is our per-socket protocol private structure.
struct nni_pair_sock {
	nni_sock *	nsock;
	nni_pair_pipe * ppipe;
	nni_msgq *	uwq;
	nni_msgq *	urq;
	int		raw;
};

// An nni_pair_pipe is our per-pipe protocol private structure.  We keep
// one of these even though in theory we'd only have a single underlying
// pipe.  The separate data structure is more like other protocols that do
// manage multiple pipes.
struct nni_pair_pipe {
	nni_pipe *	npipe;
	nni_pair_sock * psock;
	int		sigclose;
};

static void nni_pair_receiver(void *);
static void nni_pair_sender(void *);

static int
nni_pair_sock_init(void **sp, nni_sock *nsock)
{
	nni_pair_sock *psock;

	if ((psock = NNI_ALLOC_STRUCT(psock)) == NULL) {
		return (NNG_ENOMEM);
	}
	psock->nsock = nsock;
	psock->ppipe = NULL;
	psock->raw = 0;
	psock->uwq = nni_sock_sendq(nsock);
	psock->urq = nni_sock_recvq(nsock);
	*sp = psock;
	return (0);
}


static void
nni_pair_sock_fini(void *arg)
{
	nni_pair_sock *psock = arg;

	NNI_FREE_STRUCT(psock);
}


static int
nni_pair_pipe_init(void **pp, nni_pipe *npipe, void *psock)
{
	nni_pair_pipe *ppipe;

	if ((ppipe = NNI_ALLOC_STRUCT(ppipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	ppipe->npipe = npipe;
	ppipe->sigclose = 0;
	ppipe->psock = psock;
	*pp = ppipe;
	return (0);
}


static void
nni_pair_pipe_fini(void *arg)
{
	nni_pair_pipe *ppipe = arg;

	NNI_FREE_STRUCT(ppipe);
}


static int
nni_pair_pipe_add(void *arg)
{
	nni_pair_pipe *ppipe = arg;
	nni_pair_sock *psock = ppipe->psock;

	if (psock->ppipe != NULL) {
		return (NNG_EBUSY);      // Already have a peer, denied.
	}
	psock->ppipe = ppipe;
	return (0);
}


static void
nni_pair_pipe_rem(void *arg)
{
	nni_pair_pipe *ppipe = arg;
	nni_pair_sock *psock = ppipe->psock;

	if (psock->ppipe == ppipe) {
		psock->ppipe = NULL;
	}
}


static void
nni_pair_pipe_send(void *arg)
{
	nni_pair_pipe *ppipe = arg;
	nni_pair_sock *psock = ppipe->psock;
	nni_msgq *uwq = psock->uwq;
	nni_msgq *urq = psock->urq;
	nni_pipe *npipe = ppipe->npipe;
	nni_msg *msg;
	int rv;

	for (;;) {
		rv = nni_msgq_get_sig(uwq, &msg, &ppipe->sigclose);
		if (rv != 0) {
			break;
		}
		rv = nni_pipe_send(npipe, msg);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgq_signal(urq, &ppipe->sigclose);
	nni_pipe_close(npipe);
}


static void
nni_pair_pipe_recv(void *arg)
{
	nni_pair_pipe *ppipe = arg;
	nni_msgq *urq = ppipe->psock->urq;
	nni_msgq *uwq = ppipe->psock->uwq;
	nni_pipe *npipe = ppipe->npipe;
	nni_msg *msg;
	int rv;

	for (;;) {
		rv = nni_pipe_recv(npipe, &msg);
		if (rv != 0) {
			break;
		}
		rv = nni_msgq_put_sig(urq, msg, &ppipe->sigclose);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgq_signal(uwq, &ppipe->sigclose);
	nni_pipe_close(npipe);
}


static int
nni_pair_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_pair_sock *psock = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_setopt_int(&psock->raw, buf, sz, 0, 1);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_pair_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_pair_sock *psock = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&psock->raw, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.

static nni_proto_pipe_ops nni_pair_pipe_ops = {
	.pipe_init	= nni_pair_pipe_init,
	.pipe_fini	= nni_pair_pipe_fini,
	.pipe_add	= nni_pair_pipe_add,
	.pipe_rem	= nni_pair_pipe_rem,
	.pipe_worker	= { nni_pair_pipe_send,
			    nni_pair_pipe_recv },
};

static nni_proto_sock_ops nni_pair_sock_ops = {
	.sock_init	= nni_pair_sock_init,
	.sock_fini	= nni_pair_sock_fini,
	.sock_setopt	= nni_pair_sock_setopt,
	.sock_getopt	= nni_pair_sock_getopt,
};

nni_proto nni_pair_proto = {
	.proto_self	= NNG_PROTO_PAIR,
	.proto_peer	= NNG_PROTO_PAIR,
	.proto_name	= "pair",
	.proto_sock_ops = &nni_pair_sock_ops,
	.proto_pipe_ops = &nni_pair_pipe_ops,
};
