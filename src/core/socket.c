//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "sockimpl.h"

#include <stdio.h>
#include <string.h>

// Socket implementation.

static nni_list    sock_list;
static nni_idhash *sock_hash;
static nni_mtx     sock_lk;
static nni_idhash *ctx_hash;

struct nni_ctx {
	nni_list_node     c_node;
	nni_sock *        c_sock;
	nni_proto_ctx_ops c_ops;
	void *            c_data;
	size_t            c_size;
	bool              c_closed;
	unsigned          c_refcnt; // protected by global lock
	uint32_t          c_id;
	nng_duration      c_sndtimeo;
	nng_duration      c_rcvtimeo;
};

typedef struct nni_sockopt {
	nni_list_node node;
	char *        name;
	nni_type      typ;
	size_t        sz;
	void *        data;
} nni_sockopt;

typedef struct nni_sock_pipe_cb {
	nng_pipe_cb cb_fn;
	void *      cb_arg;
} nni_sock_pipe_cb;

typedef struct sock_stats {
	nni_stat_item s_root;       // socket scope
	nni_stat_item s_id;         // socket id
	nni_stat_item s_name;       // socket name
	nni_stat_item s_protocol;   // socket protocol
	nni_stat_item s_ndialers;   // number of dialers
	nni_stat_item s_nlisteners; // number of listeners
	nni_stat_item s_npipes;     // number of pipes
	nni_stat_item s_rxbytes;    // number of bytes received
	nni_stat_item s_txbytes;    // number of bytes received
	nni_stat_item s_rxmsgs;     // number of msgs received
	nni_stat_item s_txmsgs;     // number of msgs sent
	nni_stat_item s_reject;     // pipes rejected
} sock_stats;

struct nni_socket {
	nni_list_node s_node;
	nni_mtx       s_mx;
	nni_cv        s_cv;
	nni_cv        s_close_cv;

	uint32_t s_id;
	uint32_t s_flags;
	unsigned s_refcnt; // protected by global lock
	void *   s_data;   // Protocol private
	size_t   s_size;

	nni_msgq *s_uwq; // Upper write queue
	nni_msgq *s_urq; // Upper read queue

	nni_proto_id s_self_id;
	nni_proto_id s_peer_id;

	nni_proto_pipe_ops s_pipe_ops;
	nni_proto_sock_ops s_sock_ops;
	nni_proto_ctx_ops  s_ctx_ops;

	// options
	nni_duration s_sndtimeo;  // send timeout
	nni_duration s_rcvtimeo;  // receive timeout
	nni_duration s_reconn;    // reconnect time
	nni_duration s_reconnmax; // max reconnect time
	size_t       s_rcvmaxsz;  // max receive size
	nni_list     s_options;   // opts not handled by sock/proto
	char         s_name[64];  // socket name (legacy compat)
	char         s_scope[24]; // socket scope ("socket%u", 32 bits max)

	nni_list s_listeners; // active listeners
	nni_list s_dialers;   // active dialers
	nni_list s_pipes;     // active pipes
	nni_list s_ctxs;      // active contexts (protected by global sock_lk)

	bool s_closing; // Socket is closing
	bool s_closed;  // Socket closed, protected by global lock
	bool s_ctxwait; // Waiting for contexts to close.

	nni_mtx          s_pipe_cbs_mtx;
	nni_sock_pipe_cb s_pipe_cbs[NNG_PIPE_EV_NUM];

	sock_stats s_stats;
};

static void nni_ctx_destroy(nni_ctx *);

static void dialer_shutdown_locked(nni_dialer *);
static void listener_shutdown_locked(nni_listener *);

#define SOCK(s) ((nni_sock *) (s))

static int
sock_get_fd(void *s, int flag, int *fdp)
{
	int           rv;
	nni_pollable *p;

	if ((flag & nni_sock_flags(SOCK(s))) == 0) {
		return (NNG_ENOTSUP);
	}

	switch (flag) {
	case NNI_PROTO_FLAG_SND:
		rv = nni_msgq_get_sendable(SOCK(s)->s_uwq, &p);
		break;
	case NNI_PROTO_FLAG_RCV:
		rv = nni_msgq_get_recvable(SOCK(s)->s_urq, &p);
		break;
	default:
		return (NNG_EINVAL);
	}

	if (rv == 0) {
		rv = nni_pollable_getfd(p, fdp);
	}

	return (rv);
}

static int
sock_get_sendfd(void *s, void *buf, size_t *szp, nni_type t)
{
	int fd;
	int rv;

	if ((rv = sock_get_fd(SOCK(s), NNI_PROTO_FLAG_SND, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
sock_get_recvfd(void *s, void *buf, size_t *szp, nni_type t)
{
	int fd;
	int rv;

	if ((rv = sock_get_fd(SOCK(s), NNI_PROTO_FLAG_RCV, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
sock_get_raw(void *s, void *buf, size_t *szp, nni_type t)
{
	bool raw = ((nni_sock_flags(SOCK(s)) & NNI_PROTO_FLAG_RAW) != 0);
	return (nni_copyout_bool(raw, buf, szp, t));
}

static int
sock_set_recvtimeo(void *s, const void *buf, size_t sz, nni_type t)
{
	return (nni_copyin_ms(&SOCK(s)->s_rcvtimeo, buf, sz, t));
}

static int
sock_get_recvtimeo(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_ms(SOCK(s)->s_rcvtimeo, buf, szp, t));
}

static int
sock_set_sendtimeo(void *s, const void *buf, size_t sz, nni_type t)
{
	return (nni_copyin_ms(&SOCK(s)->s_sndtimeo, buf, sz, t));
}

static int
sock_get_sendtimeo(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_ms(SOCK(s)->s_sndtimeo, buf, szp, t));
}

static int
sock_set_recvbuf(void *s, const void *buf, size_t sz, nni_type t)
{
	int len;
	int rv;

	if ((rv = nni_copyin_int(&len, buf, sz, 0, 8192, t)) != 0) {
		return (rv);
	}
	return (nni_msgq_resize(SOCK(s)->s_urq, len));
}

static int
sock_get_recvbuf(void *s, void *buf, size_t *szp, nni_type t)
{
	int len = nni_msgq_cap(SOCK(s)->s_urq);

	return (nni_copyout_int(len, buf, szp, t));
}

static int
sock_set_sendbuf(void *s, const void *buf, size_t sz, nni_type t)
{
	int len;
	int rv;

	if ((rv = nni_copyin_int(&len, buf, sz, 0, 8192, t)) != 0) {
		return (rv);
	}
	return (nni_msgq_resize(SOCK(s)->s_uwq, len));
}

static int
sock_get_sendbuf(void *s, void *buf, size_t *szp, nni_type t)
{
	int len = nni_msgq_cap(SOCK(s)->s_uwq);

	return (nni_copyout_int(len, buf, szp, t));
}

static int
sock_get_sockname(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_str(SOCK(s)->s_name, buf, szp, t));
}

static int
sock_set_sockname(void *s, const void *buf, size_t sz, nni_type t)
{
	return (nni_copyin_str(
	    SOCK(s)->s_name, buf, sizeof(SOCK(s)->s_name), sz, t));
}

static int
sock_get_proto(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_int(nni_sock_proto_id(SOCK(s)), buf, szp, t));
}

static int
sock_get_peer(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_int(nni_sock_peer_id(SOCK(s)), buf, szp, t));
}

static int
sock_get_protoname(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_str(nni_sock_proto_name(SOCK(s)), buf, szp, t));
}

static int
sock_get_peername(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_str(nni_sock_peer_name(SOCK(s)), buf, szp, t));
}

static const nni_option sock_options[] = {
	{
	    .o_name = NNG_OPT_RECVTIMEO,
	    .o_get  = sock_get_recvtimeo,
	    .o_set  = sock_set_recvtimeo,
	},
	{
	    .o_name = NNG_OPT_SENDTIMEO,
	    .o_get  = sock_get_sendtimeo,
	    .o_set  = sock_set_sendtimeo,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = sock_get_recvfd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = sock_get_sendfd,
	},
	{
	    .o_name = NNG_OPT_RECVBUF,
	    .o_get  = sock_get_recvbuf,
	    .o_set  = sock_set_recvbuf,
	},
	{
	    .o_name = NNG_OPT_SENDBUF,
	    .o_get  = sock_get_sendbuf,
	    .o_set  = sock_set_sendbuf,
	},
	{
	    .o_name = NNG_OPT_SOCKNAME,
	    .o_get  = sock_get_sockname,
	    .o_set  = sock_set_sockname,
	},
	{
	    .o_name = NNG_OPT_RAW,
	    .o_get  = sock_get_raw,
	},
	{
	    .o_name = NNG_OPT_PROTO,
	    .o_get  = sock_get_proto,
	},
	{
	    .o_name = NNG_OPT_PEER,
	    .o_get  = sock_get_peer,
	},
	{
	    .o_name = NNG_OPT_PROTONAME,
	    .o_get  = sock_get_protoname,
	},
	{
	    .o_name = NNG_OPT_PEERNAME,
	    .o_get  = sock_get_peername,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static void
nni_free_opt(nni_sockopt *opt)
{
	nni_strfree(opt->name);
	nni_free(opt->data, opt->sz);
	NNI_FREE_STRUCT(opt);
}

uint32_t
nni_sock_id(nni_sock *s)
{
	return (s->s_id);
}

// nni_sock_sendq and nni_sock_recvq are called by the protocol to obtain
// the upper read and write queues.
nni_msgq *
nni_sock_sendq(nni_sock *s)
{
	return (s->s_uwq);
}

nni_msgq *
nni_sock_recvq(nni_sock *s)
{
	return (s->s_urq);
}

int
nni_sock_find(nni_sock **sockp, uint32_t id)
{
	int       rv;
	nni_sock *s;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	nni_mtx_lock(&sock_lk);
	if ((rv = nni_idhash_find(sock_hash, id, (void **) &s)) == 0) {
		if (s->s_closed) {
			rv = NNG_ECLOSED;
		} else {
			s->s_refcnt++;
			*sockp = s;
		}
	}
	nni_mtx_unlock(&sock_lk);

	if (rv == NNG_ENOENT) {
		rv = NNG_ECLOSED;
	}

	return (rv);
}

void
nni_sock_rele(nni_sock *s)
{
	nni_mtx_lock(&sock_lk);
	s->s_refcnt--;
	if (s->s_closed && (s->s_refcnt < 2)) {
		nni_cv_wake(&s->s_close_cv);
	}
	nni_mtx_unlock(&sock_lk);
}

static void
sock_stats_fini(nni_sock *s)
{
#ifdef NNG_ENABLE_STATS
	sock_stats *st = &s->s_stats;
	nni_stat_unregister(&st->s_root);
#else
	NNI_ARG_UNUSED(s);
#endif
}

static void
sock_stats_init(nni_sock *s)
{
#ifdef NNG_ENABLE_STATS
	sock_stats *   st   = &s->s_stats;
	nni_stat_item *root = &s->s_stats.s_root;

	// To make collection cheap and atomic for the socket,
	// we just use a single lock for the entire chain.

	nni_stat_init_scope(root, s->s_scope, "socket statistics");

	nni_stat_init_id(&st->s_id, "id", "socket id", s->s_id);
	nni_stat_add(root, &st->s_id);

	nni_stat_init_string(&st->s_name, "name", "socket name", s->s_name);
	nni_stat_set_lock(&st->s_name, &s->s_mx);
	nni_stat_add(root, &st->s_name);

	nni_stat_init_string(&st->s_protocol, "protocol", "socket protocol",
	    nni_sock_proto_name(s));
	nni_stat_add(root, &st->s_protocol);

	nni_stat_init_atomic(&st->s_ndialers, "ndialers", "open dialers");
	nni_stat_set_type(&st->s_ndialers, NNG_STAT_LEVEL);
	nni_stat_add(root, &st->s_ndialers);

	nni_stat_init_atomic(
	    &st->s_nlisteners, "nlisteners", "open listeners");
	nni_stat_set_type(&st->s_nlisteners, NNG_STAT_LEVEL);
	nni_stat_add(root, &st->s_nlisteners);

	nni_stat_init_atomic(&st->s_npipes, "npipes", "open pipes");
	nni_stat_set_type(&st->s_npipes, NNG_STAT_LEVEL);
	nni_stat_add(root, &st->s_npipes);

	nni_stat_init_atomic(&st->s_rxbytes, "rxbytes", "bytes received");
	nni_stat_set_unit(&st->s_rxbytes, NNG_UNIT_BYTES);
	nni_stat_add(root, &st->s_rxbytes);

	nni_stat_init_atomic(&st->s_txbytes, "txbytes", "bytes sent");
	nni_stat_set_unit(&st->s_txbytes, NNG_UNIT_BYTES);
	nni_stat_add(root, &st->s_txbytes);

	nni_stat_init_atomic(&st->s_rxmsgs, "rxmsgs", "messages received");
	nni_stat_set_unit(&st->s_rxmsgs, NNG_UNIT_MESSAGES);
	nni_stat_add(root, &st->s_rxmsgs);

	nni_stat_init_atomic(&st->s_txmsgs, "txmsgs", "messages sent");
	nni_stat_set_unit(&st->s_txmsgs, NNG_UNIT_MESSAGES);
	nni_stat_add(root, &st->s_txmsgs);

	nni_stat_init_atomic(&st->s_reject, "reject", "pipes rejected");
	nni_stat_add(root, &st->s_reject);
#else
	NNI_ARG_UNUSED(s);
#endif
}

static void
sock_destroy(nni_sock *s)
{
	nni_sockopt *sopt;

	// The protocol needs to clean up its state.
	if (s->s_data != NULL) {
		s->s_sock_ops.sock_fini(s->s_data);
	}

	while ((sopt = nni_list_first(&s->s_options)) != NULL) {
		nni_list_remove(&s->s_options, sopt);
		nni_free_opt(sopt);
	}

	// This exists to silence a false positive in helgrind.
	nni_mtx_lock(&s->s_mx);
	nni_mtx_unlock(&s->s_mx);

	sock_stats_fini(s);
	nni_msgq_fini(s->s_urq);
	nni_msgq_fini(s->s_uwq);
	nni_cv_fini(&s->s_close_cv);
	nni_cv_fini(&s->s_cv);
	nni_mtx_fini(&s->s_mx);
	nni_mtx_fini(&s->s_pipe_cbs_mtx);
	nni_free(s, s->s_size);
}

static int
nni_sock_create(nni_sock **sp, const nni_proto *proto)
{
	int       rv;
	nni_sock *s;
	bool      on;
	size_t    sz;

	sz = NNI_ALIGN_UP(sizeof(*s)) + proto->proto_sock_ops->sock_size;
	if ((s = nni_zalloc(sz)) == NULL) {
		return (NNG_ENOMEM);
	}
	s->s_data      = s + 1;
	s->s_sndtimeo  = -1;
	s->s_rcvtimeo  = -1;
	s->s_reconn    = NNI_SECOND;
	s->s_reconnmax = 0;
	s->s_rcvmaxsz  = 0; // unlimited by default
	s->s_id        = 0;
	s->s_refcnt    = 0;
	s->s_self_id   = proto->proto_self;
	s->s_peer_id   = proto->proto_peer;
	s->s_flags     = proto->proto_flags;
	s->s_sock_ops  = *proto->proto_sock_ops;
	s->s_pipe_ops  = *proto->proto_pipe_ops;
	s->s_closed    = false;
	s->s_closing   = false;

	if (proto->proto_ctx_ops != NULL) {
		s->s_ctx_ops = *proto->proto_ctx_ops;
	}

	NNI_ASSERT(s->s_sock_ops.sock_open != NULL);
	NNI_ASSERT(s->s_sock_ops.sock_close != NULL);

	NNI_LIST_NODE_INIT(&s->s_node);
	NNI_LIST_INIT(&s->s_options, nni_sockopt, node);
	NNI_LIST_INIT(&s->s_ctxs, nni_ctx, c_node);
	NNI_LIST_INIT(&s->s_pipes, nni_pipe, p_sock_node);
	NNI_LIST_INIT(&s->s_listeners, nni_listener, l_node);
	NNI_LIST_INIT(&s->s_dialers, nni_dialer, d_node);
	nni_mtx_init(&s->s_mx);
	nni_mtx_init(&s->s_pipe_cbs_mtx);
	nni_cv_init(&s->s_cv, &s->s_mx);
	nni_cv_init(&s->s_close_cv, &sock_lk);
	sock_stats_init(s);

	if (((rv = nni_msgq_init(&s->s_uwq, 0)) != 0) ||
	    ((rv = nni_msgq_init(&s->s_urq, 1)) != 0) ||
	    ((rv = s->s_sock_ops.sock_init(s->s_data, s)) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_SENDTIMEO, &s->s_sndtimeo,
	          sizeof(nni_duration), NNI_TYPE_DURATION)) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_RECVTIMEO, &s->s_rcvtimeo,
	          sizeof(nni_duration), NNI_TYPE_DURATION)) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_RECONNMINT, &s->s_reconn,
	          sizeof(nni_duration), NNI_TYPE_DURATION)) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_RECONNMAXT, &s->s_reconnmax,
	          sizeof(nni_duration), NNI_TYPE_DURATION)) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_RECVMAXSZ, &s->s_rcvmaxsz,
	          sizeof(size_t), NNI_TYPE_SIZE)) != 0)) {
		sock_destroy(s);
		return (rv);
	}

	// These we *attempt* to call so that we are likely to have initial
	// values loaded.  They should not fail, but if they do we don't
	// worry about it.
	on = true;
	(void) nni_sock_setopt(
	    s, NNG_OPT_TCP_NODELAY, &on, sizeof(on), NNI_TYPE_BOOL);
	on = false;
	(void) nni_sock_setopt(
	    s, NNG_OPT_TCP_KEEPALIVE, &on, sizeof(on), NNI_TYPE_BOOL);

	*sp = s;
	return (rv);
}

int
nni_sock_sys_init(void)
{
	int rv;

	NNI_LIST_INIT(&sock_list, nni_sock, s_node);
	nni_mtx_init(&sock_lk);

	if (((rv = nni_idhash_init(&sock_hash)) != 0) ||
	    ((rv = nni_idhash_init(&ctx_hash)) != 0)) {
		nni_sock_sys_fini();
		return (rv);
	}
	nni_idhash_set_limits(sock_hash, 1, 0x7fffffff, 1);
	nni_idhash_set_limits(ctx_hash, 1, 0x7fffffff, 1);
	return (0);
}

void
nni_sock_sys_fini(void)
{
	if (sock_hash != NULL) {
		nni_idhash_fini(sock_hash);
		sock_hash = NULL;
	}
	if (ctx_hash != NULL) {
		nni_idhash_fini(ctx_hash);
		ctx_hash = NULL;
	}
	nni_mtx_fini(&sock_lk);
}

int
nni_sock_open(nni_sock **sockp, const nni_proto *proto)
{
	nni_sock *s = NULL;
	int       rv;

	if (proto->proto_version != NNI_PROTOCOL_VERSION) {
		// unsupported protocol version
		return (NNG_ENOTSUP);
	}

	if (((rv = nni_init()) != 0) ||
	    ((rv = nni_sock_create(&s, proto)) != 0)) {
		return (rv);
	}

	nni_mtx_lock(&sock_lk);
	if (nni_idhash_alloc32(sock_hash, &s->s_id, s) != 0) {
		sock_destroy(s);
	} else {
		nni_list_append(&sock_list, s);
		s->s_sock_ops.sock_open(s->s_data);
		*sockp = s;
	}
	nni_mtx_unlock(&sock_lk);

	// Set the socket name.
	(void) snprintf(s->s_name, sizeof(s->s_name), "%u", s->s_id);

	// Set up basic stat values.
	(void) snprintf(s->s_scope, sizeof(s->s_scope), "socket%u", s->s_id);
	nni_stat_set_value(&s->s_stats.s_id, s->s_id);

	// Add our stats chain.
	nni_stat_register(&s->s_stats.s_root);

	return (0);
}

// nni_sock_shutdown shuts down the socket; after this point no
// further access to the socket will function, and any threads blocked
// in entry points will be woken (and the functions they are blocked
// in will return NNG_ECLOSED.)
int
nni_sock_shutdown(nni_sock *sock)
{
	nni_pipe *    pipe;
	nni_dialer *  d;
	nni_listener *l;
	nni_ctx *     ctx;
	nni_ctx *     nctx;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	// Mark us closing, so no more EPs or changes can occur.
	sock->s_closing = true;

	// Close the EPs. This prevents new connections from forming
	// but but allows existing ones to drain.
	NNI_LIST_FOREACH (&sock->s_listeners, l) {
		listener_shutdown_locked(l);
	}
	NNI_LIST_FOREACH (&sock->s_dialers, d) {
		dialer_shutdown_locked(d);
	}

	nni_mtx_unlock(&sock->s_mx);

	// We now mark any owned contexts as closing.
	// XXX: Add context draining support here!
	nni_mtx_lock(&sock_lk);
	nctx = nni_list_first(&sock->s_ctxs);
	while ((ctx = nctx) != NULL) {
		nctx          = nni_list_next(&sock->s_ctxs, ctx);
		ctx->c_closed = true;
		if (ctx->c_refcnt == 0) {
			// No open operations.  So close it.
			nni_idhash_remove(ctx_hash, ctx->c_id);
			nni_list_remove(&sock->s_ctxs, ctx);
			nni_ctx_destroy(ctx);
		}
		// If still has a reference count, then wait for last
		// reference to close before nuking it.
	}
	nni_mtx_unlock(&sock_lk);

	// Generally, unless the protocol is blocked trying to perform
	// writes (e.g. a slow reader on the other side), it should be
	// trying to shut things down.  We wait to give it
	// a chance to do so gracefully.

	nni_mtx_lock(&sock_lk);
	while (!nni_list_empty(&sock->s_ctxs)) {
		sock->s_ctxwait = true;
		nni_cv_wait(&sock->s_close_cv);
	}
	nni_mtx_unlock(&sock_lk);

	nni_mtx_lock(&sock->s_mx);

	// At this point, we've done everything we politely can to
	// give the protocol a chance to flush its write side.  Now
	// its time to be a little more insistent.

	// Close the upper queues immediately.  This can happen
	// safely while we hold the lock.
	nni_msgq_close(sock->s_urq);
	nni_msgq_close(sock->s_uwq);

	// Go through the dialers and listeners, attempting to close them.
	// We might already have a close in progress, in which case
	// we skip past it; it will be removed from another thread.
	NNI_LIST_FOREACH (&sock->s_listeners, l) {
		if (nni_listener_hold(l) == 0) {
			nni_listener_close_rele(l);
		}
	}
	NNI_LIST_FOREACH (&sock->s_dialers, d) {
		if (nni_dialer_hold(d) == 0) {
			nni_dialer_close_rele(d);
		}
	}

	// For each pipe, arrange for it to teardown hard.  We would
	// expect there not to be any here.  However, it is possible for
	// a pipe to have been added by an endpoint due to racing conditions
	// in the shutdown.  Therefore it is important that we shutdown pipes
	// *last*.
	NNI_LIST_FOREACH (&sock->s_pipes, pipe) {
		nni_pipe_close(pipe);
	}

	// We have to wait for *both* endpoints and pipes to be
	// removed.
	while ((!nni_list_empty(&sock->s_pipes)) ||
	    (!nni_list_empty(&sock->s_listeners)) ||
	    (!nni_list_empty(&sock->s_dialers))) {
		nni_cv_wait(&sock->s_cv);
	}

	sock->s_sock_ops.sock_close(sock->s_data);

	nni_cv_wake(&sock->s_cv);

	NNI_ASSERT(nni_list_first(&sock->s_pipes) == NULL);

	nni_mtx_unlock(&sock->s_mx);

	// At this point, there are no threads blocked inside of us
	// that are referencing socket state.  User code should call
	// nng_close to release the last resources.
	return (0);
}

// nni_sock_close shuts down the socket, then releases any resources
// associated with it.  It is a programmer error to reference the
// socket after this function is called, as the pointer may reference
// invalid memory or other objects.
void
nni_sock_close(nni_sock *s)
{
	// Shutdown everything if not already done.  This operation
	// is idempotent.
	nni_sock_shutdown(s);

	nni_stat_unregister(&s->s_stats.s_root);

	nni_mtx_lock(&sock_lk);
	if (s->s_closed) {
		// Some other thread called close.  All we need to do
		// is drop our reference count.
		nni_mtx_unlock(&sock_lk);
		nni_sock_rele(s);
		return;
	}
	s->s_closed = true;
	nni_idhash_remove(sock_hash, s->s_id);

	// We might have been removed from the list already, e.g. by
	// nni_sock_closeall.  This is idempotent.
	nni_list_node_remove(&s->s_node);

	// Wait for all other references to drop.  Note that we
	// have a reference already (from our caller).
	s->s_ctxwait = true;
	while ((s->s_refcnt > 1) || (!nni_list_empty(&s->s_ctxs))) {
		nni_cv_wait(&s->s_close_cv);
	}
	nni_mtx_unlock(&sock_lk);

	// Because we already shut everything down before, we should not
	// have any child objects.
	nni_mtx_lock(&s->s_mx);
	NNI_ASSERT(nni_list_empty(&s->s_dialers));
	NNI_ASSERT(nni_list_empty(&s->s_listeners));
	NNI_ASSERT(nni_list_empty(&s->s_pipes));
	nni_mtx_unlock(&s->s_mx);

	sock_destroy(s);
}

void
nni_sock_closeall(void)
{
	nni_sock *s;

	if (sock_hash == NULL) {
		return;
	}
	for (;;) {
		nni_mtx_lock(&sock_lk);
		if ((s = nni_list_first(&sock_list)) == NULL) {
			nni_mtx_unlock(&sock_lk);
			return;
		}
		// Bump the reference count.  The close call below
		// will drop it.
		s->s_refcnt++;
		nni_list_node_remove(&s->s_node);
		nni_mtx_unlock(&sock_lk);
		nni_sock_close(s);
	}
}

void
nni_sock_send(nni_sock *sock, nni_aio *aio)
{
	nni_aio_normalize_timeout(aio, sock->s_sndtimeo);
	sock->s_sock_ops.sock_send(sock->s_data, aio);
}

void
nni_sock_recv(nni_sock *sock, nni_aio *aio)
{
	nni_aio_normalize_timeout(aio, sock->s_rcvtimeo);
	sock->s_sock_ops.sock_recv(sock->s_data, aio);
}

// nni_sock_proto_id returns the socket's 16-bit protocol number.
uint16_t
nni_sock_proto_id(nni_sock *sock)
{
	return (sock->s_self_id.p_id);
}

// nni_sock_peer_id returns the socket peer's 16-bit protocol number.
uint16_t
nni_sock_peer_id(nni_sock *sock)
{
	return (sock->s_peer_id.p_id);
}

const char *
nni_sock_proto_name(nni_sock *sock)
{
	return (sock->s_self_id.p_name);
}

const char *
nni_sock_peer_name(nni_sock *sock)
{
	return (sock->s_peer_id.p_name);
}

struct nni_proto_pipe_ops *
nni_sock_proto_pipe_ops(nni_sock *sock)
{
	return (&sock->s_pipe_ops);
}

void *
nni_sock_proto_data(nni_sock *sock)
{
	return (sock->s_data);
}

int
nni_sock_add_listener(nni_sock *s, nni_listener *l)
{
	nni_sockopt *sopt;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		int rv;
		rv = nni_listener_setopt(
		    l, sopt->name, sopt->data, sopt->sz, sopt->typ);
		if ((rv != 0) && (rv != NNG_ENOTSUP)) {
			nni_mtx_unlock(&s->s_mx);
			return (rv);
		}
	}

	nni_list_append(&s->s_listeners, l);

	nni_stat_inc_atomic(&s->s_stats.s_nlisteners, 1);

	nni_mtx_unlock(&s->s_mx);
	return (0);
}

int
nni_sock_add_dialer(nni_sock *s, nni_dialer *d)
{
	nni_sockopt *sopt;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		int rv;
		rv = nni_dialer_setopt(
		    d, sopt->name, sopt->data, sopt->sz, sopt->typ);
		if ((rv != 0) && (rv != NNG_ENOTSUP)) {
			nni_mtx_unlock(&s->s_mx);
			return (rv);
		}
	}

	nni_list_append(&s->s_dialers, d);

	nni_stat_inc_atomic(&s->s_stats.s_ndialers, 1);

	nni_mtx_unlock(&s->s_mx);
	return (0);
}

int
nni_sock_setopt(
    nni_sock *s, const char *name, const void *v, size_t sz, nni_type t)
{
	int           rv;
	nni_dialer *  d;
	nni_listener *l;
	nni_sockopt * optv;
	nni_sockopt * oldv = NULL;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	// Protocol options.  The protocol can override options that
	// the socket framework would otherwise supply, like buffer
	// sizes.
	rv = nni_setopt(s->s_sock_ops.sock_options, name, s->s_data, v, sz, t);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	// Some options do not go down to transports.  Handle them directly.
	rv = nni_setopt(sock_options, name, s, v, sz, t);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}
	nni_mtx_unlock(&s->s_mx);

	// Validation of generic and transport options.  This is stateless, so
	// transports should not fail to set an option later if they
	// passed it here.
	if ((strcmp(name, NNG_OPT_RECONNMINT) == 0) ||
	    (strcmp(name, NNG_OPT_RECONNMAXT) == 0)) {
		nng_duration ms;
		if ((rv = nni_copyin_ms(&ms, v, sz, t)) != 0) {
			return (rv);
		}
	} else if ((rv = nni_tran_chkopt(name, v, sz, t)) != 0) {
		return (rv);
	}

	// Prepare a copy of the socket option.
	if ((optv = NNI_ALLOC_STRUCT(optv)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((optv->data = nni_alloc(sz)) == NULL) {
		NNI_FREE_STRUCT(optv);
		return (NNG_ENOMEM);
	}
	if ((optv->name = nni_strdup(name)) == NULL) {
		nni_free(optv->data, sz);
		NNI_FREE_STRUCT(optv);
		return (NNG_ENOMEM);
	}
	memcpy(optv->data, v, sz);
	optv->sz  = sz;
	optv->typ = t;
	NNI_LIST_NODE_INIT(&optv->node);

	nni_mtx_lock(&s->s_mx);
	NNI_LIST_FOREACH (&s->s_options, oldv) {
		if (strcmp(oldv->name, name) == 0) {
			if ((oldv->sz != sz) ||
			    (memcmp(oldv->data, v, sz) != 0)) {
				break;
			}

			// The values are the same.  This is a no-op.
			nni_mtx_unlock(&s->s_mx);
			nni_free_opt(optv);
			return (0);
		}
	}

	// Apply the options.  Failure to set any option on any
	// transport (other than ENOTSUP) stops the operation
	// altogether.  Its important that transport wide checks
	// properly pre-validate.
	NNI_LIST_FOREACH (&s->s_listeners, l) {
		int x;
		x = nni_listener_setopt(l, optv->name, optv->data, sz, t);
		if (x != NNG_ENOTSUP) {
			if ((rv = x) != 0) {
				nni_mtx_unlock(&s->s_mx);
				nni_free_opt(optv);
				return (rv);
			}
		}
	}
	NNI_LIST_FOREACH (&s->s_dialers, d) {
		int x;
		x = nni_dialer_setopt(d, optv->name, optv->data, sz, t);
		if (x != NNG_ENOTSUP) {
			if ((rv = x) != 0) {
				nni_mtx_unlock(&s->s_mx);
				nni_free_opt(optv);
				return (rv);
			}
		}
	}

	if (rv == 0) {
		// Remove and toss the old value; we are using a new one.
		if (oldv != NULL) {
			nni_list_remove(&s->s_options, oldv);
			nni_free_opt(oldv);
		}

		// Insert our new value.  This permits it to be
		// compared against later, and for new endpoints to
		// automatically receive these values,
		nni_list_append(&s->s_options, optv);
	} else {
		nni_free_opt(optv);
	}

	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

int
nni_sock_getopt(
    nni_sock *s, const char *name, void *val, size_t *szp, nni_type t)
{
	int          rv;
	nni_sockopt *sopt;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	// Protocol specific options.  The protocol can override
	// options like the send buffer or notification descriptors
	// this way.
	rv = nni_getopt(
	    s->s_sock_ops.sock_options, name, s->s_data, val, szp, t);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	// Socket generic options.
	rv = nni_getopt(sock_options, name, s, val, szp, t);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		if (strcmp(sopt->name, name) == 0) {
			size_t sz = sopt->sz;

			if ((sopt->typ != NNI_TYPE_OPAQUE) &&
			    (t != sopt->typ)) {

				if (t != NNI_TYPE_OPAQUE) {
					nni_mtx_unlock(&s->s_mx);
					return (NNG_EBADTYPE);
				}
				if (*szp != sopt->sz) {
					nni_mtx_unlock(&s->s_mx);
					return (NNG_EINVAL);
				}
			}

			if (sopt->sz > *szp) {
				sz = *szp;
			}
			*szp = sopt->sz;
			memcpy(val, sopt->data, sz);
			rv = 0;
			break;
		}
	}

	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

uint32_t
nni_sock_flags(nni_sock *sock)
{
	return (sock->s_flags);
}

void
nni_sock_set_pipe_cb(nni_sock *s, int ev, nng_pipe_cb cb, void *arg)
{
	if ((ev >= 0) && (ev < NNG_PIPE_EV_NUM)) {
		nni_mtx_lock(&s->s_pipe_cbs_mtx);
		s->s_pipe_cbs[ev].cb_fn  = cb;
		s->s_pipe_cbs[ev].cb_arg = arg;
		nni_mtx_unlock(&s->s_pipe_cbs_mtx);
	}
}

int
nni_ctx_find(nni_ctx **ctxp, uint32_t id, bool closing)
{
	int      rv;
	nni_ctx *ctx;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	nni_mtx_lock(&sock_lk);
	if ((rv = nni_idhash_find(ctx_hash, id, (void **) &ctx)) == 0) {
		// We refuse a reference if either the socket is
		// closed, or the context is closed.  (If the socket
		// is closed, and we are only getting the reference so
		// we can close it, then we still allow.  In the case
		// the only valid operation will be to close the
		// socket.)
		if (ctx->c_closed || ((!closing) && ctx->c_sock->s_closed)) {
			rv = NNG_ECLOSED;
		} else {
			ctx->c_refcnt++;
			*ctxp = ctx;
		}
	}
	nni_mtx_unlock(&sock_lk);

	if (rv == NNG_ENOENT) {
		rv = NNG_ECLOSED;
	}

	return (rv);
}

static void
nni_ctx_destroy(nni_ctx *ctx)
{
	if (ctx->c_data != NULL) {
		ctx->c_ops.ctx_fini(ctx->c_data);
	}

	// Let the socket go, our hold on it is done.
	nni_free(ctx, ctx->c_size);
}

void
nni_ctx_rele(nni_ctx *ctx)
{
	nni_sock *sock = ctx->c_sock;
	nni_mtx_lock(&sock_lk);
	ctx->c_refcnt--;
	if ((ctx->c_refcnt > 0) || (!ctx->c_closed)) {
		// Either still have an active reference, or not
		// actually closing yet.
		nni_mtx_unlock(&sock_lk);
		return;
	}

	// Remove us from the hash, so we can't be found any more.
	// This allows our ID to be reused later, although the system
	// tries to avoid ID reuse.
	nni_idhash_remove(ctx_hash, ctx->c_id);
	nni_list_remove(&sock->s_ctxs, ctx);
	if (sock->s_closed || sock->s_ctxwait) {
		nni_cv_wake(&sock->s_close_cv);
	}
	nni_mtx_unlock(&sock_lk);

	nni_ctx_destroy(ctx);
}

int
nni_ctx_open(nni_ctx **ctxp, nni_sock *sock)
{
	nni_ctx *ctx;
	int      rv;
	size_t   sz;

	if (sock->s_ctx_ops.ctx_init == NULL) {
		return (NNG_ENOTSUP);
	}

	sz = NNI_ALIGN_UP(sizeof(*ctx)) + sock->s_ctx_ops.ctx_size;
	if ((ctx = nni_zalloc(sz)) == NULL) {
		return (NNG_ENOMEM);
	}
	ctx->c_size = sz;
	ctx->c_data = ctx + 1;
	ctx->c_closed   = false;
	ctx->c_refcnt   = 1; // Caller implicitly gets a reference.
	ctx->c_sock     = sock;
	ctx->c_ops      = sock->s_ctx_ops;
	ctx->c_rcvtimeo = sock->s_rcvtimeo;
	ctx->c_sndtimeo = sock->s_sndtimeo;

	nni_mtx_lock(&sock_lk);
	if (sock->s_closed) {
		nni_mtx_unlock(&sock_lk);
		nni_free(ctx, ctx->c_size);
		return (NNG_ECLOSED);
	}
	if ((rv = nni_idhash_alloc32(ctx_hash, &ctx->c_id, ctx)) != 0) {
		nni_mtx_unlock(&sock_lk);
		nni_free(ctx, ctx->c_size);
		return (rv);
	}

	if ((rv = sock->s_ctx_ops.ctx_init(ctx->c_data, sock->s_data)) != 0) {
		nni_idhash_remove(ctx_hash, ctx->c_id);
		nni_mtx_unlock(&sock_lk);
		nni_free(ctx, ctx->c_size);
		return (rv);
	}

	nni_list_append(&sock->s_ctxs, ctx);
	nni_mtx_unlock(&sock_lk);

	// Paranoia, fixing a possible race in close.  Don't let us
	// give back a context if the socket is being shutdown (it
	// might not have reached the "closed" state yet.)
	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		nni_ctx_rele(ctx);
		return (NNG_ECLOSED);
	}
	nni_mtx_unlock(&sock->s_mx);
	*ctxp = ctx;

	return (0);
}

void
nni_ctx_close(nni_ctx *ctx)
{
	nni_mtx_lock(&sock_lk);
	ctx->c_closed = true;
	nni_mtx_unlock(&sock_lk);

	nni_ctx_rele(ctx);
}

uint32_t
nni_ctx_id(nni_ctx *ctx)
{
	return (ctx->c_id);
}

void
nni_ctx_send(nni_ctx *ctx, nni_aio *aio)
{
	nni_aio_normalize_timeout(aio, ctx->c_sndtimeo);
	ctx->c_ops.ctx_send(ctx->c_data, aio);
}

void
nni_ctx_recv(nni_ctx *ctx, nni_aio *aio)
{
	nni_aio_normalize_timeout(aio, ctx->c_rcvtimeo);
	ctx->c_ops.ctx_recv(ctx->c_data, aio);
}

int
nni_ctx_getopt(nni_ctx *ctx, const char *opt, void *v, size_t *szp, nni_type t)
{
	nni_sock *  sock = ctx->c_sock;
	nni_option *o;
	int         rv = NNG_ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (strcmp(opt, NNG_OPT_RECVTIMEO) == 0) {
		rv = nni_copyout_ms(ctx->c_rcvtimeo, v, szp, t);
	} else if (strcmp(opt, NNG_OPT_SENDTIMEO) == 0) {
		rv = nni_copyout_ms(ctx->c_sndtimeo, v, szp, t);
	} else if (ctx->c_ops.ctx_options != NULL) {
		for (o = ctx->c_ops.ctx_options; o->o_name != NULL; o++) {
			if (strcmp(opt, o->o_name) != 0) {
				continue;
			}
			if (o->o_get == NULL) {
				rv = NNG_EWRITEONLY;
				break;
			}
			rv = o->o_get(ctx->c_data, v, szp, t);
			break;
		}
	}
	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}

int
nni_ctx_setopt(
    nni_ctx *ctx, const char *opt, const void *v, size_t sz, nni_type t)
{
	nni_sock *  sock = ctx->c_sock;
	nni_option *o;
	int         rv = NNG_ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (strcmp(opt, NNG_OPT_RECVTIMEO) == 0) {
		rv = nni_copyin_ms(&ctx->c_rcvtimeo, v, sz, t);
	} else if (strcmp(opt, NNG_OPT_SENDTIMEO) == 0) {
		rv = nni_copyin_ms(&ctx->c_sndtimeo, v, sz, t);
	} else if (ctx->c_ops.ctx_options != NULL) {
		for (o = ctx->c_ops.ctx_options; o->o_name != NULL; o++) {
			if (strcmp(opt, o->o_name) != 0) {
				continue;
			}
			if (o->o_set == NULL) {
				rv = NNG_EREADONLY;
				break;
			}
			rv = o->o_set(ctx->c_data, v, sz, t);
			break;
		}
	}

	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}

static void
dialer_timer_start_locked(nni_dialer *d)
{
	nni_duration backoff;
	nni_sock *   sock = d->d_sock;

	if (d->d_closing || sock->s_closed) {
		return;
	}
	backoff = d->d_currtime;
	d->d_currtime *= 2;
	if ((d->d_maxrtime > 0) && (d->d_currtime > d->d_maxrtime)) {
		d->d_currtime = d->d_maxrtime;
	}

	// To minimize damage from storms, etc., we select a backoff
	// value randomly, in the range of [0, backoff-1]; this is
	// pretty similar to 802 style backoff, except that we have a
	// nearly uniform time period instead of discrete slot times.
	// This algorithm may lead to slight biases because we don't
	// have a statistically perfect distribution with the modulo of
	// the random number, but this really doesn't matter.
	nni_sleep_aio(backoff ? nni_random() % backoff : 0, d->d_tmo_aio);
}

void
nni_dialer_timer_start(nni_dialer *d)
{
	nni_sock *s = d->d_sock;
	nni_mtx_lock(&s->s_mx);
	dialer_timer_start_locked(d);
	nni_mtx_unlock(&s->s_mx);
}

void
nni_dialer_add_pipe(nni_dialer *d, void *tpipe)
{
	nni_sock *s = d->d_sock;
	nni_pipe *p;

	nni_mtx_lock(&s->s_mx);

	if (s->s_closed || d->d_closing ||
	    (nni_pipe_create_dialer(&p, d, tpipe) != 0)) {
		nni_mtx_unlock(&s->s_mx);
		return;
	}

	nni_list_append(&d->d_pipes, p);
	nni_list_append(&s->s_pipes, p);
	d->d_pipe     = p;
	d->d_currtime = d->d_inirtime;
	nni_mtx_unlock(&s->s_mx);
	nni_stat_inc_atomic(&s->s_stats.s_npipes, 1);
	nni_stat_inc_atomic(&d->d_stats.s_npipes, 1);

	nni_pipe_run_cb(p, NNG_PIPE_EV_ADD_PRE);

	nni_mtx_lock(&s->s_mx);
	if (p->p_closed) {
		nni_mtx_unlock(&s->s_mx);
		nni_stat_inc_atomic(&d->d_stats.s_reject, 1);
		nni_stat_inc_atomic(&s->s_stats.s_reject, 1);
		nni_pipe_rele(p);
		return;
	}
	if (p->p_proto_ops.pipe_start(p->p_proto_data) != 0) {
		nni_mtx_unlock(&s->s_mx);
		nni_stat_inc_atomic(&d->d_stats.s_reject, 1);
		nni_stat_inc_atomic(&s->s_stats.s_reject, 1);
		nni_pipe_close(p);
		nni_pipe_rele(p);
		return;
	}
	nni_mtx_unlock(&s->s_mx);
	nni_stat_register(&p->p_stats.s_root);
	nni_pipe_run_cb(p, NNG_PIPE_EV_ADD_POST);
	nni_pipe_rele(p);
}

static void
dialer_shutdown_impl(nni_dialer *d)
{
	nni_pipe *p;

	// Abort any remaining in-flight operations.
	nni_aio_close(d->d_con_aio);
	nni_aio_close(d->d_tmo_aio);

	// Stop the underlying transport.
	d->d_ops.d_close(d->d_data);

	NNI_LIST_FOREACH (&d->d_pipes, p) {
		nni_pipe_close(p);
	}
}

static void
dialer_shutdown_locked(nni_dialer *d)
{
	if (!d->d_closing) {
		d->d_closing = true;
		dialer_shutdown_impl(d);
	}
}

void
nni_dialer_shutdown(nni_dialer *d)
{
	nni_sock *s = d->d_sock;
	nni_mtx_lock(&s->s_mx);
	dialer_shutdown_locked(d);
	nni_mtx_unlock(&s->s_mx);
}

void
nni_dialer_reap(nni_dialer *d)
{
	nni_sock *s = d->d_sock;

	nni_aio_stop(d->d_tmo_aio);
	nni_aio_stop(d->d_con_aio);

	nni_stat_unregister(&d->d_stats.s_root);

	nni_mtx_lock(&s->s_mx);
	if (!nni_list_empty(&d->d_pipes)) {
		nni_pipe *p;
		// This should already have been done, but be certain!
		NNI_LIST_FOREACH (&d->d_pipes, p) {
			nni_pipe_close(p);
		}
		nni_mtx_unlock(&s->s_mx);
		// Go back to the end of reap list.
		nni_reap(&d->d_reap, (nni_cb) nni_dialer_reap, d);
		return;
	}

	nni_list_remove(&s->s_dialers, d);
	if ((s->s_closing) && (nni_list_empty(&s->s_dialers))) {
		nni_cv_wake(&s->s_cv);
	}

	nni_mtx_unlock(&s->s_mx);

	nni_dialer_destroy(d);
}

void
nni_listener_add_pipe(nni_listener *l, void *tpipe)
{
	nni_sock *s = l->l_sock;
	nni_pipe *p;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closed || l->l_closing ||
	    (nni_pipe_create_listener(&p, l, tpipe) != 0)) {
		nni_mtx_unlock(&s->s_mx);
		return;
	}

	nni_list_append(&l->l_pipes, p);
	nni_list_append(&s->s_pipes, p);
	nni_mtx_unlock(&s->s_mx);
	nni_stat_inc_atomic(&l->l_stats.s_npipes, 1);
	nni_stat_inc_atomic(&s->s_stats.s_npipes, 1);

	nni_pipe_run_cb(p, NNG_PIPE_EV_ADD_PRE);

	nni_mtx_lock(&s->s_mx);
	if (p->p_closed) {
		nni_mtx_unlock(&s->s_mx);
		nni_stat_inc_atomic(&l->l_stats.s_reject, 1);
		nni_stat_inc_atomic(&s->s_stats.s_reject, 1);
		nni_pipe_rele(p);
		return;
	}
	if (p->p_proto_ops.pipe_start(p->p_proto_data) != 0) {
		nni_mtx_unlock(&s->s_mx);
		nni_stat_inc_atomic(&l->l_stats.s_reject, 1);
		nni_stat_inc_atomic(&s->s_stats.s_reject, 1);
		nni_pipe_close(p);
		nni_pipe_rele(p);
		return;
	}
	nni_mtx_unlock(&s->s_mx);
	nni_stat_register(&p->p_stats.s_root);
	nni_pipe_run_cb(p, NNG_PIPE_EV_ADD_POST);
	nni_pipe_rele(p);
}

static void
listener_shutdown_impl(nni_listener *l)
{
	nni_pipe *p;

	// Abort any remaining in-flight accepts.
	nni_aio_close(l->l_acc_aio);
	nni_aio_close(l->l_tmo_aio);

	// Stop the underlying transport.
	l->l_ops.l_close(l->l_data);

	NNI_LIST_FOREACH (&l->l_pipes, p) {
		nni_pipe_close(p);
	}
}

static void
listener_shutdown_locked(nni_listener *l)
{
	if (!l->l_closing) {
		l->l_closing = true;
		listener_shutdown_impl(l);
	}
}

void
nni_listener_shutdown(nni_listener *l)
{
	nni_sock *s = l->l_sock;

	nni_mtx_lock(&s->s_mx);
	listener_shutdown_locked(l);
	nni_mtx_unlock(&s->s_mx);
}

void
nni_listener_reap(nni_listener *l)
{
	nni_sock *s = l->l_sock;

	nni_aio_stop(l->l_tmo_aio);
	nni_aio_stop(l->l_acc_aio);

	nni_stat_unregister(&l->l_stats.s_root);

	nni_mtx_lock(&s->s_mx);
	if (!nni_list_empty(&l->l_pipes)) {
		nni_pipe *p;
		// This should already have been done, but be certain!
		NNI_LIST_FOREACH (&l->l_pipes, p) {
			nni_pipe_close(p);
		}
		nni_mtx_unlock(&s->s_mx);
		// Go back to the end of reap list.
		nni_reap(&l->l_reap, (nni_cb) nni_listener_reap, l);
		return;
	}

	nni_list_remove(&s->s_listeners, l);
	if ((s->s_closing) && (nni_list_empty(&s->s_listeners))) {
		nni_cv_wake(&s->s_cv);
	}

	nni_mtx_unlock(&s->s_mx);

	nni_listener_destroy(l);
}

void
nni_pipe_run_cb(nni_pipe *p, nng_pipe_ev ev)
{
	nni_sock *  s = p->p_sock;
	nng_pipe_cb cb;
	void *      arg;

	nni_mtx_lock(&s->s_pipe_cbs_mtx);
	if (!p->p_cbs) {
		if (ev == NNG_PIPE_EV_ADD_PRE) {
			// First event, after this we want all other events.
			p->p_cbs = true;
		} else {
			nni_mtx_unlock(&s->s_pipe_cbs_mtx);
			return;
		}
	}
	cb  = s->s_pipe_cbs[ev].cb_fn;
	arg = s->s_pipe_cbs[ev].cb_arg;
	nni_mtx_unlock(&s->s_pipe_cbs_mtx);

	if (cb != NULL) {
		nng_pipe pid;
		pid.id = p->p_id;
		cb(pid, ev, arg);
	}
}

void
nni_pipe_remove(nni_pipe *p)
{
	nni_sock *  s = p->p_sock;
	nni_dialer *d = p->p_dialer;

	nni_mtx_lock(&s->s_mx);
	if (nni_list_node_active(&p->p_sock_node)) {
		nni_stat_dec_atomic(&s->s_stats.s_npipes, 1);
	}
	if (p->p_listener != NULL) {
		nni_stat_dec_atomic(&p->p_listener->l_stats.s_npipes, 1);
	}
	if (p->p_dialer != NULL) {
		nni_stat_dec_atomic(&p->p_dialer->d_stats.s_npipes, 1);
	}
	nni_list_node_remove(&p->p_sock_node);
	nni_list_node_remove(&p->p_ep_node);
	p->p_listener = NULL;
	p->p_dialer   = NULL;
	if ((d != NULL) && (d->d_pipe == p)) {
		d->d_pipe = NULL;
		dialer_timer_start_locked(d); // Kick the timer to redial.
	}
	if (s->s_closing) {
		nni_cv_wake(&s->s_cv);
	}
	nni_mtx_unlock(&s->s_mx);
}

void
nni_sock_add_stat(nni_sock *s, nni_stat_item *stat)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_add(&s->s_stats.s_root, stat);
#else
	NNI_ARG_UNUSED(s);
	NNI_ARG_UNUSED(stat);
#endif
}

void
nni_sock_bump_tx(nni_sock *s, uint64_t sz)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_inc_atomic(&s->s_stats.s_txmsgs, 1);
	nni_stat_inc_atomic(&s->s_stats.s_txbytes, sz);
#else
	NNI_ARG_UNUSED(s);
	NNI_ARG_UNUSED(sz);
#endif
}

void
nni_sock_bump_rx(nni_sock *s, uint64_t sz)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_inc_atomic(&s->s_stats.s_rxmsgs, 1);
	nni_stat_inc_atomic(&s->s_stats.s_rxbytes, sz);
#else
	NNI_ARG_UNUSED(s);
	NNI_ARG_UNUSED(sz);
#endif
}
