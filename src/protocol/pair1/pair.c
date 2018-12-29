//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

#include "nng/protocol/pair1/pair.h"

// Pair protocol.  The PAIRv1 protocol is a simple 1:1 messaging pattern,
// usually, but it can support a polyamorous mode where a single server can
// communicate with multiple partners.

#ifndef NNI_PROTO_PAIR_V1
#define NNI_PROTO_PAIR_V1 NNI_PROTO(1, 1)
#endif

#define BUMPSTAT(x) nni_stat_inc_atomic(x, 1)

typedef struct pair1_pipe pair1_pipe;
typedef struct pair1_sock pair1_sock;

static void pair1_sock_getq_cb(void *);
static void pair1_pipe_send_cb(void *);
static void pair1_pipe_recv_cb(void *);
static void pair1_pipe_getq_cb(void *);
static void pair1_pipe_putq_cb(void *);
static void pair1_pipe_fini(void *);

// pair1_sock is our per-socket protocol private structure.
struct pair1_sock {
	nni_msgq *    uwq;
	nni_msgq *    urq;
	nni_sock *    nsock;
	bool          raw;
	int           ttl;
	nni_mtx       mtx;
	nni_idhash *  pipes;
	nni_list      plist;
	bool          started;
	bool          poly;
	nni_aio *     aio_getq;
	nni_stat_item stat_poly;
	nni_stat_item stat_raw;
	nni_stat_item stat_rejmismatch;
	nni_stat_item stat_rejinuse;
};

// pair1_pipe is our per-pipe protocol private structure.
struct pair1_pipe {
	nni_pipe *    npipe;
	pair1_sock *  psock;
	nni_msgq *    sendq;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
	nni_aio *     aio_getq;
	nni_aio *     aio_putq;
	nni_list_node node;
};

static void
pair1_sock_fini(void *arg)
{
	pair1_sock *s = arg;

	nni_aio_fini(s->aio_getq);
	nni_idhash_fini(s->pipes);
	nni_mtx_fini(&s->mtx);

	NNI_FREE_STRUCT(s);
}

static int
pair1_sock_init_impl(void **sp, nni_sock *nsock, bool raw)
{
	pair1_sock *s;
	int         rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_idhash_init(&s->pipes)) != 0) {
		NNI_FREE_STRUCT(s);
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&s->plist, pair1_pipe, node);

	// Raw mode uses this.
	nni_mtx_init(&s->mtx);

	if ((rv = nni_aio_init(&s->aio_getq, pair1_sock_getq_cb, s)) != 0) {
		pair1_sock_fini(s);
		return (rv);
	}

	nni_stat_init_bool(
	    &s->stat_poly, "polyamorous", "polyamorous mode?", false);
	nni_stat_set_lock(&s->stat_poly, &s->mtx);
	nni_sock_add_stat(nsock, &s->stat_poly);

	nni_stat_init_bool(&s->stat_raw, "raw", "raw mode?", raw);
	nni_sock_add_stat(nsock, &s->stat_raw);

	nni_stat_init_atomic(&s->stat_rejmismatch, "mismatch",
	    "pipes rejected (protocol mismatch)");
	nni_sock_add_stat(nsock, &s->stat_rejmismatch);

	nni_stat_init_atomic(&s->stat_rejinuse, "already",
	    "pipes rejected (already connected)");
	nni_sock_add_stat(nsock, &s->stat_rejinuse);

	s->nsock = nsock;
	s->raw   = raw;
	s->poly  = false;
	s->uwq   = nni_sock_sendq(nsock);
	s->urq   = nni_sock_recvq(nsock);
	s->ttl   = 8;
	*sp      = s;

	return (0);
}

static int
pair1_sock_init(void **sp, nni_sock *nsock)
{
	return (pair1_sock_init_impl(sp, nsock, false));
}

static int
pair1_sock_init_raw(void **sp, nni_sock *nsock)
{
	return (pair1_sock_init_impl(sp, nsock, true));
}

static void
pair1_pipe_stop(void *arg)
{
	pair1_pipe *p = arg;

	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_putq);
	nni_aio_stop(p->aio_getq);
}

static void
pair1_pipe_fini(void *arg)
{
	pair1_pipe *p = arg;

	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_putq);
	nni_aio_fini(p->aio_getq);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
pair1_pipe_init(void **pp, nni_pipe *npipe, void *psock)
{
	pair1_pipe *p;
	int         rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_msgq_init(&p->sendq, 2)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, pair1_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, pair1_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, pair1_pipe_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, pair1_pipe_putq_cb, p)) != 0)) {
		pair1_pipe_fini(p);
		return (NNG_ENOMEM);
	}

	p->npipe = npipe;
	p->psock = psock;
	*pp      = p;

	return (rv);
}

static int
pair1_pipe_start(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->psock;
	uint32_t    id;
	int         rv;

	nni_mtx_lock(&s->mtx);
	if (nni_pipe_peer(p->npipe) != NNI_PROTO_PAIR_V1) {
		nni_mtx_unlock(&s->mtx);
		BUMPSTAT(&s->stat_rejmismatch);
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	id = nni_pipe_id(p->npipe);
	if ((rv = nni_idhash_insert(s->pipes, id, p)) != 0) {
		nni_mtx_unlock(&s->mtx);
		return (rv);
	}
	if (!s->poly) {
		if (!nni_list_empty(&s->plist)) {
			nni_idhash_remove(s->pipes, id);
			nni_mtx_unlock(&s->mtx);
			BUMPSTAT(&s->stat_rejinuse);
			return (NNG_EBUSY);
		}
	} else {
		if (!s->started) {
			nni_msgq_aio_get(s->uwq, s->aio_getq);
		}
	}
	nni_list_append(&s->plist, p);
	s->started = true;
	nni_mtx_unlock(&s->mtx);

	// Schedule a getq.  In polyamorous mode we get on the per pipe
	// sendq, as the socket distributes to us. In monogamous mode
	// we bypass and get from the upper writeq directly (saving a
	// set of context switches).
	if (s->poly) {
		nni_msgq_aio_get(p->sendq, p->aio_getq);
	} else {
		nni_msgq_aio_get(s->uwq, p->aio_getq);
	}
	// And the pipe read of course.
	nni_pipe_recv(p->npipe, p->aio_recv);

	return (0);
}

static void
pair1_pipe_close(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->psock;

	nni_aio_close(p->aio_send);
	nni_aio_close(p->aio_recv);
	nni_aio_close(p->aio_putq);
	nni_aio_close(p->aio_getq);

	nni_mtx_lock(&s->mtx);
	nni_idhash_remove(s->pipes, nni_pipe_id(p->npipe));
	nni_list_node_remove(&p->node);
	nni_mtx_unlock(&s->mtx);

	nni_msgq_close(p->sendq);
}

static void
pair1_pipe_recv_cb(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->psock;
	nni_msg *   msg;
	uint32_t    hdr;
	nni_pipe *  npipe = p->npipe;
	int         rv;
	size_t      len;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);

	// Store the pipe ID.
	nni_msg_set_pipe(msg, nni_pipe_id(p->npipe));

	// If the message is missing the hop count header, scrap it.
	if (nni_msg_len(msg) < sizeof(uint32_t)) {
		nni_msg_free(msg);
		nni_pipe_close(npipe);
		return;
	}
	hdr = nni_msg_trim_u32(msg);
	if (hdr & 0xffffff00) {
		nni_msg_free(msg);
		nni_pipe_close(npipe);
		return;
	}
	len = nni_msg_len(msg);

	// If we bounced too many times, discard the message, but
	// keep getting more.
	if (hdr > (unsigned) s->ttl) {
		// STAT: bump TTLdrop
		nni_msg_free(msg);
		nni_pipe_recv(npipe, p->aio_recv);
		return;
	}

	// Store the hop count in the header.
	if ((rv = nni_msg_header_append_u32(msg, hdr)) != 0) {
		// STAT: bump allocfail
		nni_msg_free(msg);
		nni_pipe_recv(npipe, p->aio_recv);
		return;
	}

	// Send the message up.
	nni_aio_set_msg(p->aio_putq, msg);
	nni_sock_bump_rx(s->nsock, len);
	nni_msgq_aio_put(s->urq, p->aio_putq);
}

static void
pair1_sock_getq_cb(void *arg)
{
	pair1_pipe *p;
	pair1_sock *s = arg;
	nni_msg *   msg;
	uint32_t    id;

	if (nni_aio_result(s->aio_getq) != 0) {
		// Socket closing...
		return;
	}

	msg = nni_aio_get_msg(s->aio_getq);
	nni_aio_set_msg(s->aio_getq, NULL);

	// By definition we are in polyamorous mode.
	NNI_ASSERT(s->poly);

	p = NULL;
	nni_mtx_lock(&s->mtx);
	// If no pipe was requested, we look for any connected peer.
	if (((id = nni_msg_get_pipe(msg)) == 0) &&
	    (!nni_list_empty(&s->plist))) {
		p = nni_list_first(&s->plist);
	} else {
		nni_idhash_find(s->pipes, id, (void **) &p);
	}
	if (p == NULL) {
		// Pipe not present!
		nni_mtx_unlock(&s->mtx);
		nni_msg_free(msg);
		nni_msgq_aio_get(s->uwq, s->aio_getq);
		return;
	}

	// Try a non-blocking send.  If this fails we just discard the
	// message.  We have to do this to avoid head-of-line blocking
	// for messages sent to other pipes.  Note that there is some
	// buffering in the sendq.
	if (nni_msgq_tryput(p->sendq, msg) != 0) {
		nni_msg_free(msg);
	}

	nni_mtx_unlock(&s->mtx);
	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
pair1_pipe_putq_cb(void *arg)
{
	pair1_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_close(p->npipe);
		return;
	}
	nni_pipe_recv(p->npipe, p->aio_recv);
}

static void
pair1_pipe_getq_cb(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->psock;
	nni_msg *   msg;
	uint32_t    hops;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_close(p->npipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_getq);
	nni_aio_set_msg(p->aio_getq, NULL);

	// Raw mode messages have the header already formed, with
	// a hop count.  Cooked mode messages have no
	// header so we have to add one.
	if (s->raw) {
		if (nni_msg_header_len(msg) != sizeof(uint32_t)) {
			goto badmsg;
		}
		hops = nni_msg_header_trim_u32(msg);
	} else {
		// Strip off any previously existing header, such as when
		// replying to messages.
		nni_msg_header_clear(msg);
		hops = 0;
	}

	hops++;

	// Insert the hops header.
	if (nni_msg_header_append_u32(msg, hops) != 0) {
		goto badmsg;
	}

	nni_aio_set_msg(p->aio_send, msg);
	nni_pipe_send(p->npipe, p->aio_send);
	return;

badmsg:
	nni_msg_free(msg);
	nni_msgq_aio_get(s->poly ? p->sendq : s->uwq, p->aio_getq);
}

static void
pair1_pipe_send_cb(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->psock;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_close(p->npipe);
		return;
	}

	// In polyamorous mode, we want to get from the sendq; in
	// monogamous we get from upper writeq.
	nni_msgq_aio_get(s->poly ? p->sendq : s->uwq, p->aio_getq);
}

static void
pair1_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
pair1_sock_close(void *arg)
{
	pair1_sock *s = arg;
	nni_aio_close(s->aio_getq);
}

static int
pair1_sock_set_maxttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	pair1_sock *s = arg;
	int         rv;
	nni_mtx_lock(&s->mtx); // Have to be locked against recv cb.
	rv = nni_copyin_int(&s->ttl, buf, sz, 1, 255, t);
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static int
pair1_sock_get_maxttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair1_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, t));
}

static int
pair1_sock_set_poly(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	pair1_sock *s = arg;
	int         rv;
	nni_mtx_lock(&s->mtx);
	rv = s->started ? NNG_ESTATE : nni_copyin_bool(&s->poly, buf, sz, t);
	nni_stat_set_value(&s->stat_poly, s->poly);
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static int
pair1_sock_get_poly(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair1_sock *s = arg;
	return (nni_copyout_bool(s->poly, buf, szp, t));
}

static void
pair1_sock_send(void *arg, nni_aio *aio)
{
	pair1_sock *s = arg;

	nni_sock_bump_tx(s->nsock, nni_msg_len(nni_aio_get_msg(aio)));
	nni_msgq_aio_put(s->uwq, aio);
}

static void
pair1_sock_recv(void *arg, nni_aio *aio)
{
	pair1_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static nni_proto_pipe_ops pair1_pipe_ops = {
	.pipe_init  = pair1_pipe_init,
	.pipe_fini  = pair1_pipe_fini,
	.pipe_start = pair1_pipe_start,
	.pipe_close = pair1_pipe_close,
	.pipe_stop  = pair1_pipe_stop,
};

static nni_option pair1_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = pair1_sock_get_maxttl,
	    .o_set  = pair1_sock_set_maxttl,
	},
	{
	    .o_name = NNG_OPT_PAIR1_POLY,
	    .o_get  = pair1_sock_get_poly,
	    .o_set  = pair1_sock_set_poly,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops pair1_sock_ops = {
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
	.proto_self     = { NNI_PROTO_PAIR_V1, "pair1" },
	.proto_peer     = { NNI_PROTO_PAIR_V1, "pair1" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &pair1_sock_ops,
	.proto_pipe_ops = &pair1_pipe_ops,
};

int
nng_pair1_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pair1_proto));
}

static nni_proto_sock_ops pair1_sock_ops_raw = {
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
	.proto_self     = { NNI_PROTO_PAIR_V1, "pair1" },
	.proto_peer     = { NNI_PROTO_PAIR_V1, "pair1" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &pair1_sock_ops_raw,
	.proto_pipe_ops = &pair1_pipe_ops,
};

int
nng_pair1_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pair1_proto_raw));
}
