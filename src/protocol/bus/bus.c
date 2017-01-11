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

// Bus protocol.  The BUS protocol, each peer sends a message to its peers.
// However, bus protocols do not "forward" (absent a device).  So in order
// for each participant to receive the message, each sender must be connected
// to every other node in the network (full mesh).

typedef struct nni_bus_pipe	nni_bus_pipe;
typedef struct nni_bus_sock	nni_bus_sock;

// An nni_bus_sock is our per-socket protocol private structure.
struct nni_bus_sock {
	nni_sock *	nsock;
	int		raw;
	int		closing;
	nni_list	pipes;
};

// An nni_bus_pipe is our per-pipe protocol private structure.
struct nni_bus_pipe {
	nni_pipe *	npipe;
	nni_bus_sock *	psock;
	nni_msgq *	sendq;
	nni_list_node	node;
	int		sigclose;
};

static int
nni_bus_sock_init(void **sp, nni_sock *nsock)
{
	nni_bus_sock *psock;
	int rv;

	if ((psock = NNI_ALLOC_STRUCT(psock)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&psock->pipes, nni_bus_pipe, node);
	psock->nsock = nsock;
	psock->raw = 0;

	*sp = psock;
	nni_sock_recverr(nsock, NNG_ESTATE);
	return (0);
}


static void
nni_bus_sock_fini(void *arg)
{
	nni_bus_sock *psock = arg;

	NNI_FREE_STRUCT(psock);
}


static int
nni_bus_pipe_init(void **pp, nni_pipe *npipe, void *psock)
{
	nni_bus_pipe *ppipe;
	int rv;

	if ((ppipe = NNI_ALLOC_STRUCT(ppipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_NODE_INIT(&ppipe->node);
	// This depth could be tunable.
	if ((rv = nni_msgq_init(&ppipe->sendq, 16)) != 0) {
		NNI_FREE_STRUCT(ppipe);
		return (rv);
	}
	ppipe->npipe = npipe;
	ppipe->psock = psock;
	ppipe->sigclose = 0;
	*pp = ppipe;
	return (0);
}


static void
nni_bus_pipe_fini(void *arg)
{
	nni_bus_pipe *ppipe = arg;

	NNI_FREE_STRUCT(ppipe);
}


static int
nni_bus_pipe_add(void *arg)
{
	nni_bus_pipe *ppipe = arg;
	nni_bus_sock *psock = ppipe->psock;

	nni_list_append(&psock->pipes, ppipe);
	return (0);
}


static void
nni_bus_pipe_rem(void *arg)
{
	nni_bus_pipe *ppipe = arg;
	nni_bus_sock *psock = ppipe->psock;

	nni_list_remove(&psock->pipes, ppipe);
}


static void
nni_bus_pipe_sender(void *arg)
{
	nni_bus_pipe *ppipe = arg;
	nni_pipe *npipe = ppipe->npipe;
	nni_msgq *uwq = ppipe->sendq;
	nni_msgq *urq = nni_sock_recvq(ppipe->psock->nsock);
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
nni_bus_pipe_receiver(void *arg)
{
	nni_bus_pipe *ppipe = arg;
	nni_bus_sock *psock = ppipe->psock;
	nni_msgq *urq = nni_sock_recvq(psock->nsock);
	nni_msgq *uwq = nni_sock_sendq(psock->nsock);
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
	nni_msgq_signal(ppipe->sendq, &ppipe->sigclose);
	nni_pipe_close(npipe);
}


static int
nni_bus_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_bus_sock *psock = arg;
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
nni_bus_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_bus_sock *psock = arg;
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


static void
nni_bus_sock_sender(void *arg)
{
	nni_bus_sock *psock = arg;
	nni_msgq *uwq = nni_sock_sendq(psock->nsock);
	nni_mtx *mx = nni_sock_mtx(psock->nsock);
	nni_msg *msg, *dup;

	for (;;) {
		nni_bus_pipe *ppipe;
		nni_bus_pipe *last;
		int rv;

		if ((rv = nni_msgq_get(uwq, &msg)) != 0) {
			break;
		}

		nni_mtx_lock(mx);
		last = nni_list_last(&psock->pipes);
		NNI_LIST_FOREACH (&psock->pipes, ppipe) {
			if (ppipe != last) {
				rv = nni_msg_dup(&dup, msg);
				if (rv != 0) {
					continue;
				}
			} else {
				dup = msg;
			}
			if ((rv = nni_msgq_tryput(ppipe->sendq, dup)) != 0) {
				nni_msg_free(dup);
			}
		}
		nni_mtx_unlock(mx);

		if (last == NULL) {
			nni_msg_free(msg);
		}
	}
}


static nni_proto_pipe_ops nni_bus_pipe_ops = {
	.pipe_init	= nni_bus_pipe_init,
	.pipe_fini	= nni_bus_pipe_fini,
	.pipe_add	= nni_bus_pipe_add,
	.pipe_rem	= nni_bus_pipe_rem,
	.pipe_worker	= { nni_bus_pipe_sender,
			    nni_bus_pipe_receiver }
};

static nni_proto_sock_ops nni_bus_sock_ops = {
	.sock_init	= nni_bus_sock_init,
	.sock_fini	= nni_bus_sock_fini,
	.sock_setopt	= nni_bus_sock_setopt,
	.sock_getopt	= nni_bus_sock_getopt,
	.sock_worker	= { nni_bus_sock_sender },
};

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
nni_proto nni_bus_proto = {
	.proto_self	= NNG_PROTO_BUS,
	.proto_peer	= NNG_PROTO_BUS,
	.proto_name	= "bus",
	.proto_sock_ops = &nni_bus_sock_ops,
	.proto_pipe_ops = &nni_bus_pipe_ops,
};
