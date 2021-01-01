//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdlib.h>

#include "core/nng_impl.h"
#include "nng/protocol/bus0/bus.h"

// Bus protocol.  The BUS protocol, each peer sends a message to its peers.
// However, bus protocols do not "forward" (absent a device).  So in order
// for each participant to receive the message, each sender must be connected
// to every other node in the network (full mesh).

#ifndef NNI_PROTO_BUS_V0
#define NNI_PROTO_BUS_V0 NNI_PROTO(7, 0)
#endif

typedef struct bus0_pipe bus0_pipe;
typedef struct bus0_sock bus0_sock;

static void bus0_sock_getq(bus0_sock *);
static void bus0_sock_send(void *, nni_aio *);
static void bus0_sock_recv(void *, nni_aio *);

static void bus0_pipe_getq(bus0_pipe *);
static void bus0_pipe_recv(bus0_pipe *);

static void bus0_sock_getq_cb(void *);
static void bus0_sock_getq_cb_raw(void *);
static void bus0_pipe_getq_cb(void *);
static void bus0_pipe_send_cb(void *);
static void bus0_pipe_recv_cb(void *);
static void bus0_pipe_putq_cb(void *);

// bus0_sock is our per-socket protocol private structure.
struct bus0_sock {
	nni_aio * aio_getq;
	nni_list  pipes;
	nni_mtx   mtx;
	nni_msgq *uwq;
	nni_msgq *urq;
	bool      raw;
};

// bus0_pipe is our per-pipe protocol private structure.
struct bus0_pipe {
	nni_pipe *    npipe;
	bus0_sock *   psock;
	nni_msgq *    sendq;
	nni_list_node node;
	nni_aio *     aio_getq;
	nni_aio *     aio_recv;
	nni_aio *     aio_send;
	nni_aio *     aio_putq;
	nni_mtx       mtx;
};

static void
bus0_sock_fini(void *arg)
{
	bus0_sock *s = arg;

	nni_aio_free(s->aio_getq);
	nni_mtx_fini(&s->mtx);
}

static int
bus0_sock_init(void *arg, nni_sock *nsock)
{
	bus0_sock *s = arg;
	int        rv;

	NNI_LIST_INIT(&s->pipes, bus0_pipe, node);
	nni_mtx_init(&s->mtx);
	if ((rv = nni_aio_alloc(&s->aio_getq, bus0_sock_getq_cb, s)) != 0) {
		bus0_sock_fini(s);
		return (rv);
	}
	s->uwq = nni_sock_sendq(nsock);
	s->urq = nni_sock_recvq(nsock);
	s->raw = false;

	return (0);
}

static int
bus0_sock_init_raw(void *arg, nni_sock *nsock)
{
	bus0_sock *s = arg;
	int        rv;

	NNI_LIST_INIT(&s->pipes, bus0_pipe, node);
	nni_mtx_init(&s->mtx);
	if ((rv = nni_aio_alloc(&s->aio_getq, bus0_sock_getq_cb_raw, s)) !=
	    0) {
		bus0_sock_fini(s);
		return (rv);
	}
	s->uwq = nni_sock_sendq(nsock);
	s->urq = nni_sock_recvq(nsock);
	s->raw = true;

	return (0);
}

static void
bus0_sock_open(void *arg)
{
	bus0_sock *s = arg;

	bus0_sock_getq(s);
}

static void
bus0_sock_close(void *arg)
{
	bus0_sock *s = arg;

	nni_aio_close(s->aio_getq);
}

static void
bus0_pipe_stop(void *arg)
{
	bus0_pipe *p = arg;

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_putq);
}

static void
bus0_pipe_fini(void *arg)
{
	bus0_pipe *p = arg;

	nni_aio_free(p->aio_getq);
	nni_aio_free(p->aio_send);
	nni_aio_free(p->aio_recv);
	nni_aio_free(p->aio_putq);
	nni_msgq_fini(p->sendq);
	nni_mtx_fini(&p->mtx);
}

static int
bus0_pipe_init(void *arg, nni_pipe *npipe, void *s)
{
	bus0_pipe *p = arg;
	int        rv;

	NNI_LIST_NODE_INIT(&p->node);
	nni_mtx_init(&p->mtx);
	if (((rv = nni_msgq_init(&p->sendq, 16)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_getq, bus0_pipe_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_send, bus0_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_recv, bus0_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->aio_putq, bus0_pipe_putq_cb, p)) != 0)) {
		bus0_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->psock = s;
	return (0);
}

static int
bus0_pipe_start(void *arg)
{
	bus0_pipe *p = arg;
	bus0_sock *s = p->psock;

	if (nni_pipe_peer(p->npipe) != NNI_PROTO_BUS_V0) {
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	nni_mtx_unlock(&s->mtx);

	bus0_pipe_recv(p);
	bus0_pipe_getq(p);

	return (0);
}

static void
bus0_pipe_close(void *arg)
{
	bus0_pipe *p = arg;
	bus0_sock *s = p->psock;

	nni_aio_close(p->aio_getq);
	nni_aio_close(p->aio_send);
	nni_aio_close(p->aio_recv);
	nni_aio_close(p->aio_putq);
	nni_msgq_close(p->sendq);

	nni_mtx_lock(&s->mtx);
	if (nni_list_active(&s->pipes, p)) {
		nni_list_remove(&s->pipes, p);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
bus0_pipe_getq_cb(void *arg)
{
	bus0_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		// closed?
		nni_pipe_close(p->npipe);
		return;
	}
	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->npipe, p->aio_send);
}

static void
bus0_pipe_send_cb(void *arg)
{
	bus0_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		// closed?
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	bus0_pipe_getq(p);
}

static void
bus0_pipe_recv_cb(void *arg)
{
	bus0_pipe *p = arg;
	bus0_sock *s = p->psock;
	nni_msg *  msg;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}
	msg = nni_aio_get_msg(p->aio_recv);

	if (s->raw) {
		nni_msg_header_append_u32(msg, nni_pipe_id(p->npipe));
	}

	nni_msg_set_pipe(msg, nni_pipe_id(p->npipe));
	nni_aio_set_msg(p->aio_putq, msg);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msgq_aio_put(s->urq, p->aio_putq);
}

static void
bus0_pipe_putq_cb(void *arg)
{
	bus0_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	// Wait for another recv.
	bus0_pipe_recv(p);
}

static void
bus0_sock_getq_cb(void *arg)
{
	bus0_sock *s = arg;
	bus0_pipe *p;
	bus0_pipe *lastp;
	nni_msg *  msg;
	nni_msg *  dup;

	if (nni_aio_result(s->aio_getq) != 0) {
		return;
	}

	msg = nni_aio_get_msg(s->aio_getq);

	// We ignore any headers present for cooked mode.
	nni_msg_header_clear(msg);

	nni_mtx_lock(&s->mtx);
	lastp = nni_list_last(&s->pipes);
	NNI_LIST_FOREACH (&s->pipes, p) {
		if (p != lastp) {
			if (nni_msg_dup(&dup, msg) != 0) {
				continue;
			}
		} else {
			dup = msg;
			msg = NULL;
		}
		if (nni_msgq_tryput(p->sendq, dup) != 0) {
			nni_msg_free(dup);
		}
	}
	nni_mtx_unlock(&s->mtx);
	nni_msg_free(msg);

	bus0_sock_getq(s);
}

static void
bus0_sock_getq_cb_raw(void *arg)
{
	bus0_sock *s = arg;
	bus0_pipe *p;
	nni_msg *  msg;
	uint32_t   sender;

	if (nni_aio_result(s->aio_getq) != 0) {
		return;
	}

	msg = nni_aio_get_msg(s->aio_getq);

	// The header being present indicates that the message
	// was received locally and we are rebroadcasting. (Device
	// is doing this probably.)  In this case grab the pipe
	// ID from the header, so we can exclude it.
	if (nni_msg_header_len(msg) >= 4) {
		sender = nni_msg_header_trim_u32(msg);
	} else {
		sender = 0;
	}

	nni_mtx_lock(&s->mtx);
	NNI_LIST_FOREACH (&s->pipes, p) {
		if (nni_pipe_id(p->npipe) == sender) {
			continue;
		}
		nni_msg_clone(msg);
		if (nni_msgq_tryput(p->sendq, msg) != 0) {
			nni_msg_free(msg);
		}
	}
	nni_mtx_unlock(&s->mtx);
	nni_msg_free(msg);

	bus0_sock_getq(s);
}

static void
bus0_sock_getq(bus0_sock *s)
{
	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
bus0_pipe_getq(bus0_pipe *p)
{
	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
bus0_pipe_recv(bus0_pipe *p)
{
	nni_pipe_recv(p->npipe, p->aio_recv);
}

static void
bus0_sock_send(void *arg, nni_aio *aio)
{
	bus0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static void
bus0_sock_recv(void *arg, nni_aio *aio)
{
	bus0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static nni_proto_pipe_ops bus0_pipe_ops = {
	.pipe_size  = sizeof(bus0_pipe),
	.pipe_init  = bus0_pipe_init,
	.pipe_fini  = bus0_pipe_fini,
	.pipe_start = bus0_pipe_start,
	.pipe_close = bus0_pipe_close,
	.pipe_stop  = bus0_pipe_stop,
};

static nni_option bus0_sock_options[] = {
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops bus0_sock_ops = {
	.sock_size    = sizeof(bus0_sock),
	.sock_init    = bus0_sock_init,
	.sock_fini    = bus0_sock_fini,
	.sock_open    = bus0_sock_open,
	.sock_close   = bus0_sock_close,
	.sock_send    = bus0_sock_send,
	.sock_recv    = bus0_sock_recv,
	.sock_options = bus0_sock_options,
};

static nni_proto_sock_ops bus0_sock_ops_raw = {
	.sock_size    = sizeof(bus0_sock),
	.sock_init    = bus0_sock_init_raw,
	.sock_fini    = bus0_sock_fini,
	.sock_open    = bus0_sock_open,
	.sock_close   = bus0_sock_close,
	.sock_send    = bus0_sock_send,
	.sock_recv    = bus0_sock_recv,
	.sock_options = bus0_sock_options,
};

static nni_proto bus0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_BUS_V0, "bus" },
	.proto_peer     = { NNI_PROTO_BUS_V0, "bus" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &bus0_sock_ops,
	.proto_pipe_ops = &bus0_pipe_ops,
};

static nni_proto bus0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_BUS_V0, "bus" },
	.proto_peer     = { NNI_PROTO_BUS_V0, "bus" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &bus0_sock_ops_raw,
	.proto_pipe_ops = &bus0_pipe_ops,
};

int
nng_bus0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &bus0_proto));
}

int
nng_bus0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &bus0_proto_raw));
}
