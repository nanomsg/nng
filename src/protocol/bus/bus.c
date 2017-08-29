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

// Bus protocol.  The BUS protocol, each peer sends a message to its peers.
// However, bus protocols do not "forward" (absent a device).  So in order
// for each participant to receive the message, each sender must be connected
// to every other node in the network (full mesh).

typedef struct bus_pipe bus_pipe;
typedef struct bus_sock bus_sock;

static void bus_sock_getq(bus_sock *);
static void bus_pipe_getq(bus_pipe *);
static void bus_pipe_send(bus_pipe *);
static void bus_pipe_recv(bus_pipe *);

static void bus_sock_getq_cb(void *);
static void bus_pipe_getq_cb(void *);
static void bus_pipe_send_cb(void *);
static void bus_pipe_recv_cb(void *);
static void bus_pipe_putq_cb(void *);

// A bus_sock is our per-socket protocol private structure.
struct bus_sock {
	nni_sock *nsock;
	int       raw;
	nni_aio * aio_getq;
	nni_list  pipes;
	nni_mtx   mtx;
};

// A bus_pipe is our per-pipe protocol private structure.
struct bus_pipe {
	nni_pipe *    npipe;
	bus_sock *    psock;
	nni_msgq *    sendq;
	nni_list_node node;
	nni_aio *     aio_getq;
	nni_aio *     aio_recv;
	nni_aio *     aio_send;
	nni_aio *     aio_putq;
	nni_mtx       mtx;
};

static void
bus_sock_fini(void *arg)
{
	bus_sock *s = arg;

	nni_aio_stop(s->aio_getq);
	nni_aio_fini(s->aio_getq);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static int
bus_sock_init(void **sp, nni_sock *nsock)
{
	bus_sock *s;
	int       rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&s->pipes, bus_pipe, node);
	nni_mtx_init(&s->mtx);
	if ((rv = nni_aio_init(&s->aio_getq, bus_sock_getq_cb, s)) != 0) {
		bus_sock_fini(s);
		return (rv);
	}
	s->nsock = nsock;
	s->raw   = 0;

	*sp = s;
	return (0);
}

static void
bus_sock_open(void *arg)
{
	bus_sock *s = arg;

	bus_sock_getq(s);
}

static void
bus_sock_close(void *arg)
{
	bus_sock *s = arg;

	nni_aio_cancel(s->aio_getq, NNG_ECLOSED);
}

static void
bus_pipe_fini(void *arg)
{
	bus_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_putq);
	nni_msgq_fini(p->sendq);
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static int
bus_pipe_init(void **pp, nni_pipe *npipe, void *s)
{
	bus_pipe *p;
	int       rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_NODE_INIT(&p->node);
	nni_mtx_init(&p->mtx);
	if (((rv = nni_msgq_init(&p->sendq, 16)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, bus_pipe_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, bus_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, bus_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, bus_pipe_putq_cb, p)) != 0)) {
		bus_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->psock = s;
	*pp      = p;
	return (0);
}

static int
bus_pipe_start(void *arg)
{
	bus_pipe *p = arg;
	bus_sock *s = p->psock;

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	nni_mtx_unlock(&s->mtx);

	bus_pipe_recv(p);
	bus_pipe_getq(p);

	return (0);
}

static void
bus_pipe_stop(void *arg)
{
	bus_pipe *p = arg;
	bus_sock *s = p->psock;

	nni_msgq_close(p->sendq);

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_putq);

	nni_mtx_lock(&s->mtx);
	if (nni_list_active(&s->pipes, p)) {
		nni_list_remove(&s->pipes, p);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
bus_pipe_getq_cb(void *arg)
{
	bus_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		// closed?
		nni_pipe_stop(p->npipe);
		return;
	}
	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->npipe, p->aio_send);
}

static void
bus_pipe_send_cb(void *arg)
{
	bus_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		// closed?
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->npipe);
		return;
	}

	bus_pipe_getq(p);
}

static void
bus_pipe_recv_cb(void *arg)
{
	bus_pipe *p = arg;
	bus_sock *s = p->psock;
	nni_msg * msg;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->npipe);
		return;
	}
	msg = nni_aio_get_msg(p->aio_recv);

	if (nni_msg_header_insert_u32(msg, nni_pipe_id(p->npipe)) != 0) {
		// XXX: bump a nomemory stat
		nni_msg_free(msg);
		nni_aio_set_msg(p->aio_recv, NULL);
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_aio_set_msg(p->aio_putq, msg);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msgq_aio_put(nni_sock_recvq(s->nsock), p->aio_putq);
}

static void
bus_pipe_putq_cb(void *arg)
{
	bus_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->npipe);
		return;
	}

	// Wait for another recv.
	bus_pipe_recv(p);
}

static void
bus_sock_getq_cb(void *arg)
{
	bus_sock *s = arg;
	bus_pipe *p;
	bus_pipe *lastp;
	nni_msgq *uwq = nni_sock_sendq(s->nsock);
	nni_msg * msg;
	nni_msg * dup;
	uint32_t  sender;

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
	lastp = nni_list_last(&s->pipes);
	NNI_LIST_FOREACH (&s->pipes, p) {
		if (nni_pipe_id(p->npipe) == sender) {
			continue;
		}
		if (p != lastp) {
			if (nni_msg_dup(&dup, msg) != 0) {
				continue;
			}
		} else {
			dup = msg;
		}
		if (nni_msgq_tryput(p->sendq, dup) != 0) {
			nni_msg_free(dup);
		}
	}
	nni_mtx_unlock(&s->mtx);

	if (lastp == NULL) {
		nni_msg_free(msg);
	}

	bus_sock_getq(s);
}

static void
bus_sock_getq(bus_sock *s)
{
	nni_msgq_aio_get(nni_sock_sendq(s->nsock), s->aio_getq);
}

static void
bus_pipe_getq(bus_pipe *p)
{
	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
bus_pipe_recv(bus_pipe *p)
{
	nni_pipe_recv(p->npipe, p->aio_recv);
}

static int
bus_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	bus_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
	}
	return (rv);
}

static int
bus_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	bus_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_getopt_int(s->raw, buf, szp);
	}
	return (rv);
}

static nni_proto_pipe_ops bus_pipe_ops = {
	.pipe_init  = bus_pipe_init,
	.pipe_fini  = bus_pipe_fini,
	.pipe_start = bus_pipe_start,
	.pipe_stop  = bus_pipe_stop,
};

static nni_proto_sock_ops bus_sock_ops = {
	.sock_init   = bus_sock_init,
	.sock_fini   = bus_sock_fini,
	.sock_open   = bus_sock_open,
	.sock_close  = bus_sock_close,
	.sock_setopt = bus_sock_setopt,
	.sock_getopt = bus_sock_getopt,
};

static nni_proto bus_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_BUS_V0, "bus" },
	.proto_peer     = { NNG_PROTO_BUS_V0, "bus" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &bus_sock_ops,
	.proto_pipe_ops = &bus_pipe_ops,
};

int
nng_bus0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &bus_proto));
}
