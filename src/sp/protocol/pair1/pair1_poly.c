//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>

#include "core/nng_impl.h"
#include "nng/protocol/pair1/pair.h"

// Pair1 poly-amorous mode.  The PAIRv1 protocol is normally a simple 1:1
// messaging pattern, but this mode offers the ability to use a best-effort
// multicast type of communication.  There are limitations, however.
// Most notably this does not interact well with nng_device type
// proxies, and there is no support for raw mode.

// THIS FEATURE IS DEPRECATED.  We discourage use in new applications.

#ifdef NNG_ENABLE_STATS
#define BUMP_STAT(x) nni_stat_inc(x, 1)
#else
#define BUMP_STAT(x)
#endif

typedef struct pair1poly_pipe pair1poly_pipe;
typedef struct pair1poly_sock pair1poly_sock;

static void pair1poly_sock_get_cb(void *);
static void pair1poly_pipe_send_cb(void *);
static void pair1poly_pipe_recv_cb(void *);
static void pair1poly_pipe_get_cb(void *);
static void pair1poly_pipe_put_cb(void *);
static void pair1poly_pipe_fini(void *);

// pair1poly_sock is our per-socket protocol private structure.
struct pair1poly_sock {
	nni_msgq      *uwq;
	nni_msgq      *urq;
	nni_sock      *sock;
	nni_atomic_int ttl;
	nni_mtx        mtx;
	nni_id_map     pipes;
	nni_list       plist;
	bool           started;
	nni_aio        aio_get;
	nni_stat_item  stat_poly;
	nni_stat_item  stat_raw;
	nni_stat_item  stat_reject_mismatch;
	nni_stat_item  stat_reject_already;
	nni_stat_item  stat_ttl_drop;
	nni_stat_item  stat_rx_malformed;
	nni_stat_item  stat_tx_malformed;
	nni_stat_item  stat_tx_drop;
};

// pair1poly_pipe is our per-pipe protocol private structure.
struct pair1poly_pipe {
	nni_pipe       *pipe;
	pair1poly_sock *pair;
	nni_msgq       *send_queue;
	nni_aio         aio_send;
	nni_aio         aio_recv;
	nni_aio         aio_get;
	nni_aio         aio_put;
	nni_list_node   node;
};

static void
pair1poly_sock_fini(void *arg)
{
	pair1poly_sock *s = arg;

	nni_aio_stop(&s->aio_get);
	nni_aio_fini(&s->aio_get);
	nni_id_map_fini(&s->pipes);
	nni_mtx_fini(&s->mtx);
}

#ifdef NNG_ENABLE_STATS
static void
pair1_add_sock_stat(
    pair1poly_sock *s, nni_stat_item *item, const nni_stat_info *info)
{
	nni_stat_init(item, info);
	nni_sock_add_stat(s->sock, item);
}
#endif

static void
pair1poly_sock_init(void *arg, nni_sock *sock)
{
	pair1poly_sock *s = arg;

	nni_id_map_init(&s->pipes, 0, 0, false);
	NNI_LIST_INIT(&s->plist, pair1poly_pipe, node);
	s->sock = sock;

	// Raw mode uses this.
	nni_mtx_init(&s->mtx);

	nni_aio_init(&s->aio_get, pair1poly_sock_get_cb, s);

#ifdef NNG_ENABLE_STATS
	static const nni_stat_info poly_info = {
		.si_name = "poly",
		.si_desc = "polyamorous mode?",
		.si_type = NNG_STAT_BOOLEAN,
	};
	static const nni_stat_info raw_info = {
		.si_name = "raw",
		.si_desc = "raw mode?",
		.si_type = NNG_STAT_BOOLEAN,
	};
	static const nni_stat_info mismatch_info = {
		.si_name   = "mismatch",
		.si_desc   = "pipes rejected (protocol mismatch)",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info already_info = {
		.si_name   = "already",
		.si_desc   = "pipes rejected (already connected)",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info ttl_drop_info = {
		.si_name   = "ttl_drop",
		.si_desc   = "messages dropped due to too many hops",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_MESSAGES,
		.si_atomic = true,
	};
	static const nni_stat_info tx_drop_info = {
		.si_name   = "tx_drop",
		.si_desc   = "messages dropped undeliverable",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_MESSAGES,
		.si_atomic = true,
	};
	static const nni_stat_info rx_malformed_info = {
		.si_name   = "rx_malformed",
		.si_desc   = "malformed messages received",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_MESSAGES,
		.si_atomic = true,
	};
	static const nni_stat_info tx_malformed_info = {
		.si_name   = "tx_malformed",
		.si_desc   = "malformed messages not sent",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_MESSAGES,
		.si_atomic = true,
	};

	pair1_add_sock_stat(s, &s->stat_poly, &poly_info);
	pair1_add_sock_stat(s, &s->stat_raw, &raw_info);
	pair1_add_sock_stat(s, &s->stat_reject_mismatch, &mismatch_info);
	pair1_add_sock_stat(s, &s->stat_reject_already, &already_info);
	pair1_add_sock_stat(s, &s->stat_ttl_drop, &ttl_drop_info);
	pair1_add_sock_stat(s, &s->stat_tx_drop, &tx_drop_info);
	pair1_add_sock_stat(s, &s->stat_rx_malformed, &rx_malformed_info);
	pair1_add_sock_stat(s, &s->stat_tx_malformed, &tx_malformed_info);

	nni_stat_set_bool(&s->stat_raw, false);
	nni_stat_set_bool(&s->stat_poly, true);
#endif

	s->uwq = nni_sock_sendq(sock);
	s->urq = nni_sock_recvq(sock);
	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);
}

static void
pair1poly_pipe_stop(void *arg)
{
	pair1poly_pipe *p = arg;

	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
	nni_aio_stop(&p->aio_put);
	nni_aio_stop(&p->aio_get);
}

static void
pair1poly_pipe_fini(void *arg)
{
	pair1poly_pipe *p = arg;

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_put);
	nni_aio_fini(&p->aio_get);
	nni_msgq_fini(p->send_queue);
}

static int
pair1poly_pipe_init(void *arg, nni_pipe *pipe, void *pair)
{
	pair1poly_pipe *p = arg;
	int             rv;

	nni_aio_init(&p->aio_send, pair1poly_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, pair1poly_pipe_recv_cb, p);
	nni_aio_init(&p->aio_get, pair1poly_pipe_get_cb, p);
	nni_aio_init(&p->aio_put, pair1poly_pipe_put_cb, p);

	if ((rv = nni_msgq_init(&p->send_queue, 2)) != 0) {
		pair1poly_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->pair = pair;

	return (0);
}

static int
pair1poly_pipe_start(void *arg)
{
	pair1poly_pipe *p = arg;
	pair1poly_sock *s = p->pair;
	uint32_t        id;
	int             rv;

	nni_mtx_lock(&s->mtx);
	if (nni_pipe_peer(p->pipe) != NNG_PAIR1_PEER) {
		// Peer protocol mismatch.
		nni_mtx_unlock(&s->mtx);
		BUMP_STAT(&s->stat_reject_mismatch);
		nng_log_warn("NNG-PEER-MISMATCH",
		    "Peer protocol mismatch: %d != %d, rejected.",
		    nni_pipe_peer(p->pipe), NNG_PAIR1_PEER);
		return (NNG_EPROTO);
	}

	id = nni_pipe_id(p->pipe);
	if ((rv = nni_id_set(&s->pipes, id, p)) != 0) {
		nni_mtx_unlock(&s->mtx);
		return (rv);
	}
	if (!s->started) {
		nni_msgq_aio_get(s->uwq, &s->aio_get);
	}
	nni_list_append(&s->plist, p);
	s->started = true;
	nni_mtx_unlock(&s->mtx);

	// Schedule a get.  In poly-amorous mode we get on the per pipe
	// send_queue, as the socket distributes to us. In monogamous mode
	// we bypass and get from the upper write queue directly (saving a
	// set of context switches).
	nni_msgq_aio_get(p->send_queue, &p->aio_get);

	// And the pipe read of course.
	nni_pipe_recv(p->pipe, &p->aio_recv);

	return (0);
}

static void
pair1poly_pipe_close(void *arg)
{
	pair1poly_pipe *p = arg;
	pair1poly_sock *s = p->pair;

	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);
	nni_aio_close(&p->aio_put);
	nni_aio_close(&p->aio_get);

	nni_mtx_lock(&s->mtx);
	nni_id_remove(&s->pipes, nni_pipe_id(p->pipe));
	nni_list_node_remove(&p->node);
	nni_mtx_unlock(&s->mtx);

	nni_msgq_close(p->send_queue);
}

static void
pair1poly_pipe_recv_cb(void *arg)
{
	pair1poly_pipe *p = arg;
	pair1poly_sock *s = p->pair;
	nni_msg        *msg;
	uint32_t        hdr;
	nni_pipe       *pipe = p->pipe;
	size_t          len;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);

	// Store the pipe ID.
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	// If the message is missing the hop count header, scrap it.
	if ((nni_msg_len(msg) < sizeof(uint32_t)) ||
	    ((hdr = nni_msg_trim_u32(msg)) > 0xff)) {
		BUMP_STAT(&s->stat_rx_malformed);
		nni_msg_free(msg);
		nni_pipe_close(pipe);
		return;
	}

	len = nni_msg_len(msg);

	// If we bounced too many times, discard the message, but
	// keep getting more.
	if ((int) hdr > nni_atomic_get(&s->ttl)) {
		BUMP_STAT(&s->stat_ttl_drop);
		nni_msg_free(msg);
		nni_pipe_recv(pipe, &p->aio_recv);
		return;
	}

	// Store the hop count in the header.
	nni_msg_header_append_u32(msg, hdr);

	// Send the message up.
	nni_aio_set_msg(&p->aio_put, msg);
	nni_sock_bump_rx(s->sock, len);
	nni_msgq_aio_put(s->urq, &p->aio_put);
}

static void
pair1poly_sock_get_cb(void *arg)
{
	pair1poly_pipe *p;
	pair1poly_sock *s = arg;
	nni_msg        *msg;
	uint32_t        id;

	if (nni_aio_result(&s->aio_get) != 0) {
		// Socket closing...
		return;
	}

	msg = nni_aio_get_msg(&s->aio_get);
	nni_aio_set_msg(&s->aio_get, NULL);

	p = NULL;
	nni_mtx_lock(&s->mtx);
	// If no pipe was requested, we look for any connected peer.
	if (((id = nni_msg_get_pipe(msg)) == 0) &&
	    (!nni_list_empty(&s->plist))) {
		p = nni_list_first(&s->plist);
	} else {
		p = nni_id_get(&s->pipes, id);
	}

	// Try a non-blocking send.  If this fails we just discard the
	// message.  We have to do this to avoid head-of-line blocking
	// for messages sent to other pipes.  Note that there is some
	// buffering in the send_queue.
	if ((p == NULL) || nni_msgq_tryput(p->send_queue, msg) != 0) {
		BUMP_STAT(&s->stat_tx_drop);
		nni_msg_free(msg);
	}

	nni_mtx_unlock(&s->mtx);
	nni_msgq_aio_get(s->uwq, &s->aio_get);
}

static void
pair1poly_pipe_put_cb(void *arg)
{
	pair1poly_pipe *p = arg;

	if (nni_aio_result(&p->aio_put) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_put));
		nni_aio_set_msg(&p->aio_put, NULL);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static void
pair1poly_pipe_get_cb(void *arg)
{
	pair1poly_pipe *p = arg;
	nni_msg        *msg;

	if (nni_aio_result(&p->aio_get) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_get);
	nni_aio_set_msg(&p->aio_get, NULL);

	// Cooked mode messages have no header, so we have to add one.
	// Strip off any previously existing header, such as when
	// replying to a message.
	nni_msg_header_clear(msg);

	// Insert the hop count header.
	nni_msg_header_append_u32(msg, 1);

	nni_aio_set_msg(&p->aio_send, msg);
	nni_pipe_send(p->pipe, &p->aio_send);
}

static void
pair1poly_pipe_send_cb(void *arg)
{
	pair1poly_pipe *p = arg;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_msgq_aio_get(p->send_queue, &p->aio_get);
}

static void
pair1poly_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pair1poly_sock_close(void *arg)
{
	pair1poly_sock *s = arg;
	nni_aio_close(&s->aio_get);
}

static int
pair1poly_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	pair1poly_sock *s = arg;
	int             rv;
	int             ttl;

	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}

	return (rv);
}

static int
pair1poly_get_max_ttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair1poly_sock *s = arg;
	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}

static int
pair1poly_get_poly(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	NNI_ARG_UNUSED(arg);
	return (nni_copyout_bool(true, buf, szp, t));
}

static void
pair1poly_sock_send(void *arg, nni_aio *aio)
{
	pair1poly_sock *s = arg;

	nni_sock_bump_tx(s->sock, nni_msg_len(nni_aio_get_msg(aio)));
	nni_msgq_aio_put(s->uwq, aio);
}

static void
pair1poly_sock_recv(void *arg, nni_aio *aio)
{
	pair1poly_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static nni_proto_pipe_ops pair1poly_pipe_ops = {
	.pipe_size  = sizeof(pair1poly_pipe),
	.pipe_init  = pair1poly_pipe_init,
	.pipe_fini  = pair1poly_pipe_fini,
	.pipe_start = pair1poly_pipe_start,
	.pipe_close = pair1poly_pipe_close,
	.pipe_stop  = pair1poly_pipe_stop,
};

static nni_option pair1poly_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = pair1poly_get_max_ttl,
	    .o_set  = pair1poly_set_max_ttl,
	},
	{
	    .o_name = NNG_OPT_PAIR1_POLY,
	    .o_get  = pair1poly_get_poly,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops pair1poly_sock_ops = {
	.sock_size    = sizeof(pair1poly_sock),
	.sock_init    = pair1poly_sock_init,
	.sock_fini    = pair1poly_sock_fini,
	.sock_open    = pair1poly_sock_open,
	.sock_close   = pair1poly_sock_close,
	.sock_recv    = pair1poly_sock_recv,
	.sock_send    = pair1poly_sock_send,
	.sock_options = pair1poly_sock_options,
};

static nni_proto pair1poly_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PAIR1_SELF, NNG_PAIR1_SELF_NAME },
	.proto_peer     = { NNG_PAIR1_PEER, NNG_PAIR1_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &pair1poly_sock_ops,
	.proto_pipe_ops = &pair1poly_pipe_ops,
};

int
nng_pair1_open_poly(nng_socket *sock)
{
	return (nni_proto_open(sock, &pair1poly_proto));
}
