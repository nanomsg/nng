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

static void nni_bus_sock_getq(nni_bus_sock *);
static void nni_bus_pipe_getq(nni_bus_pipe *);
static void nni_bus_pipe_send(nni_bus_pipe *);
static void nni_bus_pipe_recv(nni_bus_pipe *);

static void nni_bus_sock_getq_cb(void *);
static void nni_bus_pipe_getq_cb(void *);
static void nni_bus_pipe_send_cb(void *);
static void nni_bus_pipe_recv_cb(void *);
static void nni_bus_pipe_putq_cb(void *);

// An nni_bus_sock is our per-socket protocol private structure.
struct nni_bus_sock {
	nni_sock *	nsock;
	int		raw;
	nni_aio		aio_getq;
	nni_list	pipes;
};

// An nni_bus_pipe is our per-pipe protocol private structure.
struct nni_bus_pipe {
	nni_pipe *	npipe;
	nni_bus_sock *	psock;
	nni_msgq *	sendq;
	nni_list_node	node;
	nni_aio		aio_getq;
	nni_aio		aio_recv;
	nni_aio		aio_send;
	nni_aio		aio_putq;
};

static int
nni_bus_sock_init(void **sp, nni_sock *nsock)
{
	nni_bus_sock *psock;
	int rv;

	if ((psock = NNI_ALLOC_STRUCT(psock)) == NULL) {
		return (NNG_ENOMEM);
	}
	rv = nni_aio_init(&psock->aio_getq, nni_bus_sock_getq_cb, psock);
	if (rv != 0) {
		NNI_FREE_STRUCT(psock);
		return (rv);
	}
	NNI_LIST_INIT(&psock->pipes, nni_bus_pipe, node);
	psock->nsock = nsock;
	psock->raw = 0;

	*sp = psock;
	return (0);
}


static void
nni_bus_sock_fini(void *arg)
{
	nni_bus_sock *psock = arg;

	if (psock != NULL) {
		nni_aio_fini(&psock->aio_getq);
		NNI_FREE_STRUCT(psock);
	}
}


static void
nni_bus_sock_open(void *arg)
{
	nni_bus_sock *psock = arg;

	nni_bus_sock_getq(psock);
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
	rv = nni_aio_init(&ppipe->aio_getq, nni_bus_pipe_getq_cb, ppipe);
	if (rv != 0) {
		nni_msgq_fini(ppipe->sendq);
		NNI_FREE_STRUCT(ppipe);
		return (rv);
	}
	rv = nni_aio_init(&ppipe->aio_send, nni_bus_pipe_send_cb, ppipe);
	if (rv != 0) {
		nni_aio_fini(&ppipe->aio_getq);
		nni_msgq_fini(ppipe->sendq);
		NNI_FREE_STRUCT(ppipe);
		return (rv);
	}
	rv = nni_aio_init(&ppipe->aio_recv, nni_bus_pipe_recv_cb, ppipe);
	if (rv != 0) {
		nni_aio_fini(&ppipe->aio_send);
		nni_aio_fini(&ppipe->aio_getq);
		nni_msgq_fini(ppipe->sendq);
		NNI_FREE_STRUCT(ppipe);
		return (rv);
	}
	rv = nni_aio_init(&ppipe->aio_putq, nni_bus_pipe_putq_cb, ppipe);
	if (rv != 0) {
		nni_aio_fini(&ppipe->aio_recv);
		nni_aio_fini(&ppipe->aio_send);
		nni_aio_fini(&ppipe->aio_getq);
		nni_msgq_fini(ppipe->sendq);
		NNI_FREE_STRUCT(ppipe);
		return (rv);
	}

	ppipe->npipe = npipe;
	ppipe->psock = psock;
	*pp = ppipe;
	return (0);
}


static void
nni_bus_pipe_fini(void *arg)
{
	nni_bus_pipe *ppipe = arg;

	if (ppipe != NULL) {
		nni_msgq_fini(ppipe->sendq);
		nni_aio_fini(&ppipe->aio_getq);
		nni_aio_fini(&ppipe->aio_send);
		nni_aio_fini(&ppipe->aio_recv);
		nni_aio_fini(&ppipe->aio_putq);
		NNI_FREE_STRUCT(ppipe);
	}
}


static int
nni_bus_pipe_start(void *arg)
{
	nni_bus_pipe *ppipe = arg;
	nni_bus_sock *psock = ppipe->psock;

	nni_list_append(&psock->pipes, ppipe);

	nni_pipe_hold(ppipe->npipe);
	nni_bus_pipe_recv(ppipe);
	nni_pipe_hold(ppipe->npipe);
	nni_bus_pipe_getq(ppipe);

	return (0);
}


static void
nni_bus_pipe_stop(void *arg)
{
	nni_bus_pipe *ppipe = arg;
	nni_bus_sock *psock = ppipe->psock;
	nni_sock *nsock = psock->nsock;

	if (nni_list_active(&psock->pipes, ppipe)) {
		nni_list_remove(&psock->pipes, ppipe);

		nni_msgq_close(ppipe->sendq);
		nni_msgq_aio_cancel(nni_sock_recvq(nsock), &ppipe->aio_putq);
	}
}


static void
nni_bus_pipe_getq_cb(void *arg)
{
	nni_bus_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_getq) != 0) {
		// closed?
		nni_pipe_close(ppipe->npipe);
		nni_pipe_rele(ppipe->npipe);
		return;
	}
	ppipe->aio_send.a_msg = ppipe->aio_getq.a_msg;
	ppipe->aio_getq.a_msg = NULL;

	nni_pipe_aio_send(ppipe->npipe, &ppipe->aio_send);
}


static void
nni_bus_pipe_send_cb(void *arg)
{
	nni_bus_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_send) != 0) {
		// closed?
		nni_msg_free(ppipe->aio_send.a_msg);
		ppipe->aio_send.a_msg = NULL;
		nni_pipe_close(ppipe->npipe);
		nni_pipe_rele(ppipe->npipe);
		return;
	}

	nni_bus_pipe_getq(ppipe);
}


static void
nni_bus_pipe_recv_cb(void *arg)
{
	nni_bus_pipe *ppipe = arg;
	nni_bus_sock *psock = ppipe->psock;
	nni_msg *msg;
	uint32_t id;

	if (nni_aio_result(&ppipe->aio_recv) != 0) {
		nni_pipe_close(ppipe->npipe);
		nni_pipe_rele(ppipe->npipe);
		return;
	}
	msg = ppipe->aio_recv.a_msg;
	id = nni_pipe_id(ppipe->npipe);

	if (nni_msg_prepend_header(msg, &id, 4) != 0) {
		// XXX: bump a nomemory stat
		nni_msg_free(msg);
		nni_pipe_close(ppipe->npipe);
		nni_pipe_rele(ppipe->npipe);
		return;
	}

	ppipe->aio_putq.a_msg = msg;
	nni_msgq_aio_put(nni_sock_recvq(psock->nsock), &ppipe->aio_putq);
}


static void
nni_bus_pipe_putq_cb(void *arg)
{
	nni_bus_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_putq) != 0) {
		nni_msg_free(ppipe->aio_putq.a_msg);
		ppipe->aio_putq.a_msg = NULL;
		nni_pipe_close(ppipe->npipe);
		nni_pipe_rele(ppipe->npipe);
		return;
	}

	// Wait for another recv.
	nni_bus_pipe_recv(ppipe);
}


static void
nni_bus_sock_getq_cb(void *arg)
{
	nni_bus_sock *psock = arg;
	nni_bus_pipe *ppipe;
	nni_bus_pipe *lpipe;
	nni_msgq *uwq = nni_sock_sendq(psock->nsock);
	nni_mtx *mx = nni_sock_mtx(psock->nsock);
	nni_msg *msg, *dup;
	uint32_t sender;

	if (nni_aio_result(&psock->aio_getq) != 0) {
		return;
	}

	msg = psock->aio_getq.a_msg;

	// The header being present indicates that the message
	// was received locally and we are rebroadcasting. (Device
	// is doing this probably.)  In this case grab the pipe
	// ID from the header, so we can exclude it.
	if (nni_msg_header_len(msg) >= 4) {
		memcpy(&sender, nni_msg_header(msg), 4);
		nni_msg_trim_header(msg, 4);
	} else {
		sender = 0;
	}

	nni_mtx_lock(mx);
	lpipe = nni_list_last(&psock->pipes);
	NNI_LIST_FOREACH (&psock->pipes, ppipe) {
		if (nni_pipe_id(ppipe->npipe) == sender) {
			continue;
		}
		if (ppipe != lpipe) {
			if (nni_msg_dup(&dup, msg) != 0) {
				continue;
			}
		} else {
			dup = msg;
		}
		if (nni_msgq_tryput(ppipe->sendq, dup) != 0) {
			nni_msg_free(dup);
		}
	}
	nni_mtx_unlock(mx);

	if (lpipe == NULL) {
		nni_msg_free(msg);
	}

	nni_bus_sock_getq(psock);
}


static void
nni_bus_sock_getq(nni_bus_sock *psock)
{
	nni_msgq_aio_get(nni_sock_sendq(psock->nsock), &psock->aio_getq);
}


static void
nni_bus_pipe_getq(nni_bus_pipe *ppipe)
{
	nni_msgq_aio_get(ppipe->sendq, &ppipe->aio_getq);
}


static void
nni_bus_pipe_recv(nni_bus_pipe *ppipe)
{
	nni_pipe_aio_recv(ppipe->npipe, &ppipe->aio_recv);
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


static nni_proto_pipe_ops nni_bus_pipe_ops = {
	.pipe_init	= nni_bus_pipe_init,
	.pipe_fini	= nni_bus_pipe_fini,
	.pipe_start	= nni_bus_pipe_start,
	.pipe_stop	= nni_bus_pipe_stop,
};

static nni_proto_sock_ops nni_bus_sock_ops = {
	.sock_init	= nni_bus_sock_init,
	.sock_fini	= nni_bus_sock_fini,
	.sock_open	= nni_bus_sock_open,
	.sock_setopt	= nni_bus_sock_setopt,
	.sock_getopt	= nni_bus_sock_getopt,
};

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
nni_proto nni_bus_proto = {
	.proto_self	= NNG_PROTO_BUS,
	.proto_peer	= NNG_PROTO_BUS,
	.proto_name	= "bus",
	.proto_flags	= NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &nni_bus_sock_ops,
	.proto_pipe_ops = &nni_bus_pipe_ops,
};
