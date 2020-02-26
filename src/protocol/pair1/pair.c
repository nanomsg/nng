//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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

// Pair protocol.  The PAIRv1 protocol is a simple 1:1 messaging pattern.

#define BUMP_STAT(x) nni_stat_inc_atomic(x, 1)

typedef struct pair1_pipe pair1_pipe;
typedef struct pair1_sock pair1_sock;

static void pair1_pipe_send_cb(void *);
static void pair1_pipe_recv_cb(void *);
static void pair1_pipe_get_cb(void *);
static void pair1_pipe_put_cb(void *);
static void pair1_pipe_fini(void *);

// pair1_sock is our per-socket protocol private structure.
struct pair1_sock {
	nni_msgq *     uwq;
	nni_msgq *     urq;
	nni_sock *     sock;
	bool           raw;
	nni_atomic_int ttl;
	nni_mtx        mtx;
	nni_idhash *   pipes;
	nni_list       plist;
	bool           started;
	nni_stat_item  stat_poly;
	nni_stat_item  stat_raw;
	nni_stat_item  stat_reject_mismatch;
	nni_stat_item  stat_reject_already;
	nni_stat_item  stat_ttl_drop;
	nni_stat_item  stat_rx_malformed;
	nni_stat_item  stat_tx_malformed;
	nni_stat_item  stat_tx_drop;
#ifdef NNG_TEST_LIB
	bool inject_header;
#endif
};

// pair1_pipe is our per-pipe protocol private structure.
struct pair1_pipe {
	nni_pipe *    pipe;
	pair1_sock *  pair;
	nni_aio       aio_send;
	nni_aio       aio_recv;
	nni_aio       aio_get;
	nni_aio       aio_put;
	nni_list_node node;
};

static void
pair1_sock_fini(void *arg)
{
	pair1_sock *s = arg;

	nni_idhash_fini(s->pipes);
	nni_mtx_fini(&s->mtx);
}

static int
pair1_sock_init_impl(void *arg, nni_sock *sock, bool raw)
{
	pair1_sock *s = arg;

	if (nni_idhash_init(&s->pipes) != 0) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&s->plist, pair1_pipe, node);

	// Raw mode uses this.
	nni_mtx_init(&s->mtx);

	nni_stat_init_bool(
	    &s->stat_poly, "polyamorous", "polyamorous mode?", false);
	nni_sock_add_stat(sock, &s->stat_poly);

	nni_stat_init_bool(&s->stat_raw, "raw", "raw mode?", raw);
	nni_sock_add_stat(sock, &s->stat_raw);

	nni_stat_init_atomic(&s->stat_reject_mismatch, "mismatch",
	    "pipes rejected (protocol mismatch)");
	nni_sock_add_stat(sock, &s->stat_reject_mismatch);

	nni_stat_init_atomic(&s->stat_reject_already, "already",
	    "pipes rejected (already connected)");
	nni_sock_add_stat(sock, &s->stat_reject_already);

	nni_stat_init_atomic(&s->stat_ttl_drop, "ttl_drop",
	    "messages dropped due to too many hops");
	nni_stat_set_unit(&s->stat_ttl_drop, NNG_UNIT_MESSAGES);
	nni_sock_add_stat(sock, &s->stat_ttl_drop);

	// This can only increment in polyamorous mode.
	nni_stat_init_atomic(
	    &s->stat_tx_drop, "tx_drop", "messages dropped undeliverable");
	nni_stat_set_unit(&s->stat_tx_drop, NNG_UNIT_MESSAGES);
	nni_sock_add_stat(sock, &s->stat_tx_drop);

	nni_stat_init_atomic(&s->stat_rx_malformed, "rx_malformed",
	    "malformed messages received");
	nni_stat_set_unit(&s->stat_rx_malformed, NNG_UNIT_MESSAGES);
	nni_sock_add_stat(sock, &s->stat_rx_malformed);

	nni_stat_init_atomic(&s->stat_tx_malformed, "tx_malformed",
	    "malformed messages not sent");
	nni_stat_set_unit(&s->stat_tx_malformed, NNG_UNIT_MESSAGES);
	if (raw) {
		// This stat only makes sense in raw mode.
		nni_sock_add_stat(sock, &s->stat_tx_malformed);
	}

	s->sock = sock;
	s->raw  = raw;
	s->uwq  = nni_sock_sendq(sock);
	s->urq  = nni_sock_recvq(sock);
	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);

	return (0);
}

static int
pair1_sock_init(void *arg, nni_sock *sock)
{
	return (pair1_sock_init_impl(arg, sock, false));
}

static int
pair1_sock_init_raw(void *arg, nni_sock *sock)
{
	return (pair1_sock_init_impl(arg, sock, true));
}

static void
pair1_pipe_stop(void *arg)
{
	pair1_pipe *p = arg;

	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
	nni_aio_stop(&p->aio_put);
	nni_aio_stop(&p->aio_get);
}

static void
pair1_pipe_fini(void *arg)
{
	pair1_pipe *p = arg;

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_put);
	nni_aio_fini(&p->aio_get);
}

static int
pair1_pipe_init(void *arg, nni_pipe *pipe, void *pair)
{
	pair1_pipe *p = arg;

	nni_aio_init(&p->aio_send, pair1_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, pair1_pipe_recv_cb, p);
	nni_aio_init(&p->aio_get, pair1_pipe_get_cb, p);
	nni_aio_init(&p->aio_put, pair1_pipe_put_cb, p);

	p->pipe = pipe;
	p->pair = pair;

	return (0);
}

static int
pair1_pipe_start(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->pair;
	uint32_t    id;
	int         rv;

	nni_mtx_lock(&s->mtx);
	if (nni_pipe_peer(p->pipe) != NNG_PAIR1_PEER) {
		nni_mtx_unlock(&s->mtx);
		BUMP_STAT(&s->stat_reject_mismatch);
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	id = nni_pipe_id(p->pipe);
	if ((rv = nni_idhash_insert(s->pipes, id, p)) != 0) {
		nni_mtx_unlock(&s->mtx);
		return (rv);
	}
	if (!nni_list_empty(&s->plist)) {
		nni_idhash_remove(s->pipes, id);
		nni_mtx_unlock(&s->mtx);
		BUMP_STAT(&s->stat_reject_already);
		return (NNG_EBUSY);
	}
	nni_list_append(&s->plist, p);
	s->started = true;
	nni_mtx_unlock(&s->mtx);

	// Schedule a get.
	nni_msgq_aio_get(s->uwq, &p->aio_get);

	// And the pipe read of course.
	nni_pipe_recv(p->pipe, &p->aio_recv);

	return (0);
}

static void
pair1_pipe_close(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->pair;

	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);
	nni_aio_close(&p->aio_put);
	nni_aio_close(&p->aio_get);

	nni_mtx_lock(&s->mtx);
	nni_idhash_remove(s->pipes, nni_pipe_id(p->pipe));
	nni_list_node_remove(&p->node);
	nni_mtx_unlock(&s->mtx);
}

static void
pair1_pipe_recv_cb(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->pair;
	nni_msg *   msg;
	uint32_t    hdr;
	nni_pipe *  pipe = p->pipe;
	size_t      len;

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
pair1_pipe_put_cb(void *arg)
{
	pair1_pipe *p = arg;

	if (nni_aio_result(&p->aio_put) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_put));
		nni_aio_set_msg(&p->aio_put, NULL);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static void
pair1_pipe_get_cb(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->pair;
	nni_msg *   msg;
	uint32_t    hops;

	if (nni_aio_result(&p->aio_get) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_get);
	nni_aio_set_msg(&p->aio_get, NULL);

	// Raw mode messages have the header already formed, with a hop count.
	// Cooked mode messages have no header so we have to add one.
	if (s->raw) {
		if ((nni_msg_header_len(msg) != sizeof(uint32_t)) ||
		    ((hops = nni_msg_header_trim_u32(msg)) > 254)) {
			BUMP_STAT(&s->stat_tx_malformed);
			nni_msg_free(msg);
			nni_msgq_aio_get(s->uwq, &p->aio_get);
			return;
		}
#if NNG_TEST_LIB
	} else if (s->inject_header) {
		nni_aio_set_msg(&p->aio_send, msg);
		nni_pipe_send(p->pipe, &p->aio_send);
		return;
#endif
	} else {
		// Strip off any previously existing header, such as when
		// replying to messages.
		nni_msg_header_clear(msg);
		hops = 0;
	}

	hops++;

	// Insert the hops header.
	nni_msg_header_append_u32(msg, hops);

	nni_aio_set_msg(&p->aio_send, msg);
	nni_pipe_send(p->pipe, &p->aio_send);
}

static void
pair1_pipe_send_cb(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->pair;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_msgq_aio_get(s->uwq, &p->aio_get);
}

static void
pair1_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pair1_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static int
pair1_sock_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	pair1_sock *s = arg;
	int         rv;
	int         ttl;

	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}

	return (rv);
}

static int
pair1_sock_get_max_ttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair1_sock *s = arg;
	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}


#ifdef NNG_TEST_LIB
static int
pair1_set_test_inject_header(void *arg, const void *buf, size_t sz, nni_type t)
{
	pair1_sock *s = arg;
	int         rv;
	nni_mtx_lock(&s->mtx);
	rv = nni_copyin_bool(&s->inject_header, buf, sz, t);
	nni_mtx_unlock(&s->mtx);
	return (rv);
}
#endif

static void
pair1_sock_send(void *arg, nni_aio *aio)
{
	pair1_sock *s = arg;

	nni_sock_bump_tx(s->sock, nni_msg_len(nni_aio_get_msg(aio)));
	nni_msgq_aio_put(s->uwq, aio);
}

static void
pair1_sock_recv(void *arg, nni_aio *aio)
{
	pair1_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static nni_proto_pipe_ops pair1_pipe_ops = {
	.pipe_size  = sizeof(pair1_pipe),
	.pipe_init  = pair1_pipe_init,
	.pipe_fini  = pair1_pipe_fini,
	.pipe_start = pair1_pipe_start,
	.pipe_close = pair1_pipe_close,
	.pipe_stop  = pair1_pipe_stop,
};

static nni_option pair1_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = pair1_sock_get_max_ttl,
	    .o_set  = pair1_sock_set_max_ttl,
	},
#ifdef NNG_TEST_LIB
	{
	    // Test only option to pass header unmolested.  This allows
	    // us to inject bad header contents.
	    .o_name = "pair1_test_inject_header",
	    .o_set  = pair1_set_test_inject_header,
	},
#endif
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops pair1_sock_ops = {
	.sock_size    = sizeof(pair1_sock),
	.sock_init    = pair1_sock_init,
	.sock_fini    = pair1_sock_fini,
	.sock_open    = pair1_sock_open,
	.sock_close   = pair1_sock_close,
	.sock_recv    = pair1_sock_recv,
	.sock_send    = pair1_sock_send,
	.sock_options = pair1_sock_options,
};

static nni_proto pair1_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PAIR1_SELF, NNG_PAIR1_SELF_NAME },
	.proto_peer     = { NNG_PAIR1_PEER, NNG_PAIR1_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &pair1_sock_ops,
	.proto_pipe_ops = &pair1_pipe_ops,
};

int
nng_pair1_open(nng_socket *sock)
{
	return (nni_proto_open(sock, &pair1_proto));
}

static nni_proto_sock_ops pair1_sock_ops_raw = {
	.sock_size    = sizeof(pair1_sock),
	.sock_init    = pair1_sock_init_raw,
	.sock_fini    = pair1_sock_fini,
	.sock_open    = pair1_sock_open,
	.sock_close   = pair1_sock_close,
	.sock_recv    = pair1_sock_recv,
	.sock_send    = pair1_sock_send,
	.sock_options = pair1_sock_options,
};

static nni_proto pair1_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PAIR1_SELF, NNG_PAIR1_SELF_NAME },
	.proto_peer     = { NNG_PAIR1_PEER, NNG_PAIR1_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &pair1_sock_ops_raw,
	.proto_pipe_ops = &pair1_pipe_ops,
};

int
nng_pair1_open_raw(nng_socket *sock)
{
	return (nni_proto_open(sock, &pair1_proto_raw));
}
