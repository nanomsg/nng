//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdio.h>
#include <string.h>

// Socket implementation.

static nni_list    nni_sock_list;
static nni_idhash *nni_sock_hash;
static nni_mtx     nni_sock_lk;
static nni_idhash *nni_ctx_hash;

struct nni_ctx {
	nni_list_node     c_node;
	nni_sock *        c_sock;
	nni_proto_ctx_ops c_ops;
	void *            c_data;
	bool              c_closed;
	unsigned          c_refcnt; // protected by global lock
	uint32_t          c_id;
	nng_duration      c_sndtimeo;
	nng_duration      c_rcvtimeo;
};

typedef struct nni_socket_option {
	const char *so_name;
	int         so_type;
	int (*so_getopt)(nni_sock *, void *, size_t *, int);
	int (*so_setopt)(nni_sock *, const void *, size_t, int);
} nni_socket_option;

typedef struct nni_sockopt {
	nni_list_node node;
	char *        name;
	int           typ;
	size_t        sz;
	void *        data;
} nni_sockopt;

struct nni_socket {
	nni_list_node s_node;
	nni_mtx       s_mx;
	nni_cv        s_cv;
	nni_cv        s_close_cv;

	uint64_t s_id;
	uint32_t s_flags;
	unsigned s_refcnt; // protected by global lock
	void *   s_data;   // Protocol private

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

	nni_list s_eps;   // active endpoints
	nni_list s_pipes; // active pipes
	nni_list s_ctxs;  // active contexts (protected by global nni_sock_lk)

	bool        s_closing;    // Socket is closing
	bool        s_closed;     // Socket closed, protected by global lock
	bool        s_ctxwait;    // Waiting for contexts to close.
	nng_pipe_cb s_pipe_cb;    // User callback for pipe events.
	void *      s_pipe_cbarg; // Argument for pipe events.
};

static void nni_ctx_destroy(nni_ctx *);

static int
nni_sock_get_fd(nni_sock *s, int flag, int *fdp)
{
	int           rv;
	nni_pollable *p;

	if ((flag & nni_sock_flags(s)) == 0) {
		return (NNG_ENOTSUP);
	}

	switch (flag) {
	case NNI_PROTO_FLAG_SND:
		rv = nni_msgq_get_sendable(s->s_uwq, &p);
		break;
	case NNI_PROTO_FLAG_RCV:
		rv = nni_msgq_get_recvable(s->s_urq, &p);
		break;
	default:
		rv = NNG_EINVAL;
		break;
	}

	if (rv == 0) {
		rv = nni_pollable_getfd(p, fdp);
	}

	return (rv);
}

static int
nni_sock_getopt_sendfd(nni_sock *s, void *buf, size_t *szp, int typ)
{
	int fd;
	int rv;

	if ((rv = nni_sock_get_fd(s, NNI_PROTO_FLAG_SND, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, typ));
}

static int
nni_sock_getopt_recvfd(nni_sock *s, void *buf, size_t *szp, int typ)
{
	int fd;
	int rv;

	if ((rv = nni_sock_get_fd(s, NNI_PROTO_FLAG_RCV, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, typ));
}

static int
nni_sock_getopt_raw(nni_sock *s, void *buf, size_t *szp, int typ)
{
	bool raw = ((nni_sock_flags(s) & NNI_PROTO_FLAG_RAW) != 0);
	return (nni_copyout_bool(raw, buf, szp, typ));
}

static int
nni_sock_setopt_recvtimeo(nni_sock *s, const void *buf, size_t sz, int typ)
{
	return (nni_copyin_ms(&s->s_rcvtimeo, buf, sz, typ));
}

static int
nni_sock_getopt_recvtimeo(nni_sock *s, void *buf, size_t *szp, int typ)
{
	return (nni_copyout_ms(s->s_rcvtimeo, buf, szp, typ));
}

static int
nni_sock_setopt_sendtimeo(nni_sock *s, const void *buf, size_t sz, int typ)
{
	return (nni_copyin_ms(&s->s_sndtimeo, buf, sz, typ));
}

static int
nni_sock_getopt_sendtimeo(nni_sock *s, void *buf, size_t *szp, int typ)
{
	return (nni_copyout_ms(s->s_sndtimeo, buf, szp, typ));
}

static int
nni_sock_setopt_reconnmint(nni_sock *s, const void *buf, size_t sz, int typ)
{
	return (nni_copyin_ms(&s->s_reconn, buf, sz, typ));
}

static int
nni_sock_getopt_reconnmint(nni_sock *s, void *buf, size_t *szp, int typ)
{
	return (nni_copyout_ms(s->s_reconn, buf, szp, typ));
}

static int
nni_sock_setopt_reconnmaxt(nni_sock *s, const void *buf, size_t sz, int typ)
{
	return (nni_copyin_ms(&s->s_reconnmax, buf, sz, typ));
}

static int
nni_sock_getopt_reconnmaxt(nni_sock *s, void *buf, size_t *szp, int typ)
{
	return (nni_copyout_ms(s->s_reconnmax, buf, szp, typ));
}

static int
nni_sock_setopt_recvbuf(nni_sock *s, const void *buf, size_t sz, int typ)
{
	int len;
	int rv;

	if ((rv = nni_copyin_int(&len, buf, sz, 0, 8192, typ)) != 0) {
		return (rv);
	}
	return (nni_msgq_resize(s->s_urq, len));
}

static int
nni_sock_getopt_recvbuf(nni_sock *s, void *buf, size_t *szp, int typ)
{
	int len = nni_msgq_cap(s->s_urq);

	return (nni_copyout_int(len, buf, szp, typ));
}

static int
nni_sock_setopt_sendbuf(nni_sock *s, const void *buf, size_t sz, int typ)
{
	int len;
	int rv;

	if ((rv = nni_copyin_int(&len, buf, sz, 0, 8192, typ)) != 0) {
		return (rv);
	}
	return (nni_msgq_resize(s->s_uwq, len));
}

static int
nni_sock_getopt_sendbuf(nni_sock *s, void *buf, size_t *szp, int typ)
{
	int len = nni_msgq_cap(s->s_uwq);

	return (nni_copyout_int(len, buf, szp, typ));
}

static int
nni_sock_getopt_sockname(nni_sock *s, void *buf, size_t *szp, int typ)
{
	return (nni_copyout_str(s->s_name, buf, szp, typ));
}

static int
nni_sock_setopt_sockname(nni_sock *s, const void *buf, size_t sz, int typ)
{
	return (nni_copyin_str(s->s_name, buf, sizeof(s->s_name), sz, typ));
}

static int
nni_sock_getopt_proto(nni_sock *s, void *buf, size_t *szp, int typ)
{
	return (nni_copyout_int(nni_sock_proto(s), buf, szp, typ));
}

static int
nni_sock_getopt_peer(nni_sock *s, void *buf, size_t *szp, int typ)
{
	return (nni_copyout_int(nni_sock_peer(s), buf, szp, typ));
}

static int
nni_sock_getopt_protoname(nni_sock *s, void *buf, size_t *szp, int typ)
{
	return (nni_copyout_str(nni_sock_proto_name(s), buf, szp, typ));
}

static int
nni_sock_getopt_peername(nni_sock *s, void *buf, size_t *szp, int typ)
{
	return (nni_copyout_str(nni_sock_peer_name(s), buf, szp, typ));
}

static const nni_socket_option nni_sock_options[] = {
	{
	    .so_name   = NNG_OPT_RECVTIMEO,
	    .so_type   = NNI_TYPE_DURATION,
	    .so_getopt = nni_sock_getopt_recvtimeo,
	    .so_setopt = nni_sock_setopt_recvtimeo,
	},
	{
	    .so_name   = NNG_OPT_SENDTIMEO,
	    .so_type   = NNI_TYPE_DURATION,
	    .so_getopt = nni_sock_getopt_sendtimeo,
	    .so_setopt = nni_sock_setopt_sendtimeo,
	},
	{
	    .so_name   = NNG_OPT_RECVFD,
	    .so_type   = NNI_TYPE_INT32,
	    .so_getopt = nni_sock_getopt_recvfd,
	    .so_setopt = NULL,
	},
	{
	    .so_name   = NNG_OPT_SENDFD,
	    .so_type   = NNI_TYPE_INT32,
	    .so_getopt = nni_sock_getopt_sendfd,
	    .so_setopt = NULL,
	},
	{
	    .so_name   = NNG_OPT_RECVBUF,
	    .so_type   = NNI_TYPE_INT32,
	    .so_getopt = nni_sock_getopt_recvbuf,
	    .so_setopt = nni_sock_setopt_recvbuf,
	},
	{
	    .so_name   = NNG_OPT_SENDBUF,
	    .so_type   = NNI_TYPE_INT32,
	    .so_getopt = nni_sock_getopt_sendbuf,
	    .so_setopt = nni_sock_setopt_sendbuf,
	},
	{
	    .so_name   = NNG_OPT_RECONNMINT,
	    .so_type   = NNI_TYPE_DURATION,
	    .so_getopt = nni_sock_getopt_reconnmint,
	    .so_setopt = nni_sock_setopt_reconnmint,
	},
	{
	    .so_name   = NNG_OPT_RECONNMAXT,
	    .so_type   = NNI_TYPE_DURATION,
	    .so_getopt = nni_sock_getopt_reconnmaxt,
	    .so_setopt = nni_sock_setopt_reconnmaxt,
	},
	{
	    .so_name   = NNG_OPT_SOCKNAME,
	    .so_type   = NNI_TYPE_STRING,
	    .so_getopt = nni_sock_getopt_sockname,
	    .so_setopt = nni_sock_setopt_sockname,
	},
	{
	    .so_name   = NNG_OPT_RAW,
	    .so_type   = NNI_TYPE_BOOL,
	    .so_getopt = nni_sock_getopt_raw,
	    .so_setopt = NULL,
	},
	{
	    .so_name   = NNG_OPT_PROTO,
	    .so_type   = NNI_TYPE_INT32,
	    .so_getopt = nni_sock_getopt_proto,
	    .so_setopt = NULL,
	},
	{
	    .so_name   = NNG_OPT_PEER,
	    .so_type   = NNI_TYPE_INT32,
	    .so_getopt = nni_sock_getopt_peer,
	    .so_setopt = NULL,
	},
	{
	    .so_name   = NNG_OPT_PROTONAME,
	    .so_type   = NNI_TYPE_STRING,
	    .so_getopt = nni_sock_getopt_protoname,
	    .so_setopt = NULL,
	},
	{
	    .so_name   = NNG_OPT_PEERNAME,
	    .so_type   = NNI_TYPE_STRING,
	    .so_getopt = nni_sock_getopt_peername,
	    .so_setopt = NULL,
	},
	// terminate list
	{
	    .so_name = NULL,
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
	return ((uint32_t) s->s_id);
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
	nni_mtx_lock(&nni_sock_lk);
	if ((rv = nni_idhash_find(nni_sock_hash, id, (void **) &s)) == 0) {
		if (s->s_closed) {
			rv = NNG_ECLOSED;
		} else {
			s->s_refcnt++;
			*sockp = s;
		}
	}
	nni_mtx_unlock(&nni_sock_lk);

	if (rv == NNG_ENOENT) {
		rv = NNG_ECLOSED;
	}

	return (rv);
}

void
nni_sock_rele(nni_sock *s)
{
	nni_mtx_lock(&nni_sock_lk);
	s->s_refcnt--;
	if (s->s_closed && (s->s_refcnt < 2)) {
		nni_cv_wake(&s->s_close_cv);
	}
	nni_mtx_unlock(&nni_sock_lk);
}

int
nni_sock_pipe_start(nni_sock *s, nni_pipe *pipe)
{
	void *      pdata = nni_pipe_get_proto_data(pipe);
	nng_pipe_cb cb;
	int         rv;

	NNI_ASSERT(s != NULL);
	nni_mtx_lock(&s->s_mx);
	if (nni_pipe_peer(pipe) != s->s_peer_id.p_id) {
		// Peer protocol mismatch.
		nni_mtx_unlock(&s->s_mx);
		return (NNG_EPROTO);
	}
	if ((cb = s->s_pipe_cb) != NULL) {
		nng_pipe p;
		void *   arg = s->s_pipe_cbarg;
		nni_mtx_unlock(&s->s_mx);
		p.id = nni_pipe_id(pipe);
		cb(p, NNG_PIPE_ADD, arg);
		if (nni_pipe_closed(pipe)) {
			return (NNG_ECLOSED);
		}
		nni_mtx_lock(&s->s_mx);
	}
	if (s->s_closing) {
		// We're closing, bail out.  This has to be done after
		// we have dropped the lock above in case the sock is closed
		// while the user callback runs.
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	// Protocol can reject for other reasons.
	// This must be the last operation, until this point
	// the protocol has not actually "seen" the pipe.
	rv = s->s_pipe_ops.pipe_start(pdata);

	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

int
nni_sock_pipe_add(nni_sock *s, nni_pipe *p)
{
	int   rv;
	void *pdata;

	if ((rv = s->s_pipe_ops.pipe_init(&pdata, p, s->s_data)) != 0) {
		return (rv);
	}
	nni_pipe_set_proto_data(p, pdata);

	// Initialize protocol pipe data.
	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	nni_list_append(&s->s_pipes, p);

	// Start the initial negotiation I/O...
	nni_pipe_start(p);

	nni_mtx_unlock(&s->s_mx);
	return (0);
}

void
nni_sock_pipe_remove(nni_sock *sock, nni_pipe *pipe)
{
	void *      pdata;
	nng_pipe_cb cb;

	nni_mtx_lock(&sock->s_mx);
	if ((cb = sock->s_pipe_cb) != NULL) {
		void *   arg = sock->s_pipe_cbarg;
		nng_pipe p;
		nni_mtx_unlock(&sock->s_mx);
		p.id = nni_pipe_id(pipe);
		cb(p, NNG_PIPE_REM, arg);
		nni_mtx_lock(&sock->s_mx);
	}
	pdata = nni_pipe_get_proto_data(pipe);
	if (pdata != NULL) {
		sock->s_pipe_ops.pipe_stop(pdata);
		nni_pipe_set_proto_data(pipe, NULL);
		if (nni_list_active(&sock->s_pipes, pipe)) {
			nni_list_remove(&sock->s_pipes, pipe);
		}
		sock->s_pipe_ops.pipe_fini(pdata);
	}
	if (sock->s_closing && nni_list_empty(&sock->s_pipes)) {
		nni_cv_wake(&sock->s_cv);
	}
	nni_mtx_unlock(&sock->s_mx);
}

static void
nni_sock_destroy(nni_sock *s)
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

	nni_msgq_fini(s->s_urq);
	nni_msgq_fini(s->s_uwq);
	nni_cv_fini(&s->s_close_cv);
	nni_cv_fini(&s->s_cv);
	nni_mtx_fini(&s->s_mx);
	NNI_FREE_STRUCT(s);
}

static int
nni_sock_create(nni_sock **sp, const nni_proto *proto)
{
	int       rv;
	nni_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	s->s_sndtimeo  = -1;
	s->s_rcvtimeo  = -1;
	s->s_closing   = 0;
	s->s_reconn    = NNI_SECOND;
	s->s_reconnmax = 0;
	s->s_rcvmaxsz  = 1024 * 1024; // 1 MB by default
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

	NNI_ASSERT(s->s_pipe_ops.pipe_start != NULL);
	NNI_ASSERT(s->s_pipe_ops.pipe_stop != NULL);

	NNI_LIST_NODE_INIT(&s->s_node);
	NNI_LIST_INIT(&s->s_options, nni_sockopt, node);
	NNI_LIST_INIT(&s->s_ctxs, nni_ctx, c_node);

	nni_pipe_sock_list_init(&s->s_pipes);
	nni_ep_list_init(&s->s_eps);
	nni_mtx_init(&s->s_mx);
	nni_cv_init(&s->s_cv, &s->s_mx);
	nni_cv_init(&s->s_close_cv, &nni_sock_lk);

	if (((rv = nni_msgq_init(&s->s_uwq, 0)) != 0) ||
	    ((rv = nni_msgq_init(&s->s_urq, 0)) != 0) ||
	    ((rv = s->s_sock_ops.sock_init(&s->s_data, s)) != 0) ||
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
		nni_sock_destroy(s);
		return (rv);
	}

	if (s->s_sock_ops.sock_filter != NULL) {
		nni_msgq_set_filter(
		    s->s_urq, s->s_sock_ops.sock_filter, s->s_data);
	}

	*sp = s;
	return (rv);
}

int
nni_sock_sys_init(void)
{
	int rv;

	NNI_LIST_INIT(&nni_sock_list, nni_sock, s_node);
	nni_mtx_init(&nni_sock_lk);

	if (((rv = nni_idhash_init(&nni_sock_hash)) != 0) ||
	    ((rv = nni_idhash_init(&nni_ctx_hash)) != 0)) {
		nni_sock_sys_fini();
		return (rv);
	}
	nni_idhash_set_limits(nni_sock_hash, 1, 0x7fffffff, 1);
	nni_idhash_set_limits(nni_ctx_hash, 1, 0x7fffffff, 1);
	return (0);
}

void
nni_sock_sys_fini(void)
{
	if (nni_sock_hash != NULL) {
		nni_idhash_fini(nni_sock_hash);
		nni_sock_hash = NULL;
	}
	if (nni_ctx_hash != NULL) {
		nni_idhash_fini(nni_ctx_hash);
		nni_ctx_hash = NULL;
	}
	nni_mtx_fini(&nni_sock_lk);
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

	nni_mtx_lock(&nni_sock_lk);
	if ((rv = nni_idhash_alloc(nni_sock_hash, &s->s_id, s)) != 0) {
		nni_sock_destroy(s);
	} else {
		nni_list_append(&nni_sock_list, s);
		s->s_sock_ops.sock_open(s->s_data);
		*sockp = s;
	}
	nni_mtx_unlock(&nni_sock_lk);

	// Set the sockname.
	(void) snprintf(
	    s->s_name, sizeof(s->s_name), "%u", (unsigned) s->s_id);

	return (rv);
}

// nni_sock_shutdown shuts down the socket; after this point no further
// access to the socket will function, and any threads blocked in entry
// points will be woken (and the functions they are blocked in will return
// NNG_ECLOSED.)
int
nni_sock_shutdown(nni_sock *sock)
{
	nni_pipe *pipe;
	nni_ep *  ep;
	nni_ep *  nep;
	nni_ctx * ctx;
	nni_ctx * nctx;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	// Mark us closing, so no more EPs or changes can occur.
	sock->s_closing = true;

	// Close the EPs. This prevents new connections from forming but
	// but allows existing ones to drain.
	NNI_LIST_FOREACH (&sock->s_eps, ep) {
		nni_ep_shutdown(ep);
	}
	nni_mtx_unlock(&sock->s_mx);

	// We now mark any owned contexts as closing.
	// XXX: Add context draining support here!
	nni_mtx_lock(&nni_sock_lk);
	nctx = nni_list_first(&sock->s_ctxs);
	while ((ctx = nctx) != NULL) {
		nctx          = nni_list_next(&sock->s_ctxs, ctx);
		ctx->c_closed = true;
		if (ctx->c_refcnt == 0) {
			// No open operations.  So close it.
			nni_idhash_remove(nni_ctx_hash, ctx->c_id);
			nni_list_remove(&sock->s_ctxs, ctx);
			nni_ctx_destroy(ctx);
		}
		// If still has a reference count, then wait for last
		// reference to close before nuking it.
	}
	nni_mtx_unlock(&nni_sock_lk);

	// Generally, unless the protocol is blocked trying to perform
	// writes (e.g. a slow reader on the other side), it should be
	// trying to shut things down.  We wait to give it
	// a chance to do so gracefully.

	nni_mtx_lock(&nni_sock_lk);
	while (!nni_list_empty(&sock->s_ctxs)) {
		sock->s_ctxwait = true;
		nni_cv_wait(&sock->s_close_cv);
	}
	nni_mtx_unlock(&nni_sock_lk);

	nni_mtx_lock(&sock->s_mx);

	// At this point, we've done everything we politely can to give
	// the protocol a chance to flush its write side.  Now its time
	// to be a little more insistent.

	// Close the upper queues immediately.  This can happen
	// safely while we hold the lock.
	nni_msgq_close(sock->s_urq);
	nni_msgq_close(sock->s_uwq);

	// Go through the endpoint list, attempting to close them.
	// We might already have a close in progress, in which case
	// we skip past it; it will be removed from another thread.
	nep = nni_list_first(&sock->s_eps);
	while ((ep = nep) != NULL) {
		nep = nni_list_next(&sock->s_eps, nep);

		if (nni_ep_hold(ep) == 0) {
			nni_mtx_unlock(&sock->s_mx);
			nni_ep_close(ep);
			nni_mtx_lock(&sock->s_mx);
		}
	}

	// For each pipe, arrange for it to teardown hard.
	NNI_LIST_FOREACH (&sock->s_pipes, pipe) {
		nni_pipe_stop(pipe);
	}

	// We have to wait for *both* endpoints and pipes to be removed.
	while ((!nni_list_empty(&sock->s_pipes)) ||
	    (!nni_list_empty(&sock->s_eps))) {
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
// associated with it.  It is a programmer error to reference the socket
// after this function is called, as the pointer may reference invalid
// memory or other objects.
void
nni_sock_close(nni_sock *s)
{
	// Shutdown everything if not already done.  This operation
	// is idempotent.
	nni_sock_shutdown(s);

	nni_mtx_lock(&nni_sock_lk);
	if (s->s_closed) {
		// Some other thread called close.  All we need to do is
		// drop our reference count.
		nni_mtx_unlock(&nni_sock_lk);
		nni_sock_rele(s);
		return;
	}
	s->s_closed = true;
	nni_idhash_remove(nni_sock_hash, s->s_id);

	// We might have been removed from the list already, e.g. by
	// nni_sock_closeall.  This is idempotent.
	nni_list_node_remove(&s->s_node);

	// Wait for all other references to drop.  Note that we
	// have a reference already (from our caller).
	s->s_ctxwait = true;
	while ((s->s_refcnt > 1) || (!nni_list_empty(&s->s_ctxs))) {
		nni_cv_wait(&s->s_close_cv);
	}
	nni_mtx_unlock(&nni_sock_lk);

	// Wait for pipes, eps, and contexts to finish closing.
	nni_mtx_lock(&s->s_mx);
	while (
	    (!nni_list_empty(&s->s_pipes)) || (!nni_list_empty(&s->s_eps))) {
		nni_cv_wait(&s->s_cv);
	}
	nni_mtx_unlock(&s->s_mx);

	nni_sock_destroy(s);
}

void
nni_sock_closeall(void)
{
	nni_sock *s;

	if (nni_sock_hash == NULL) {
		return;
	}
	for (;;) {
		nni_mtx_lock(&nni_sock_lk);
		if ((s = nni_list_first(&nni_sock_list)) == NULL) {
			nni_mtx_unlock(&nni_sock_lk);
			return;
		}
		// Bump the reference count.  The close call below will
		// drop it.
		s->s_refcnt++;
		nni_list_node_remove(&s->s_node);
		nni_mtx_unlock(&nni_sock_lk);
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

// nni_sock_protocol returns the socket's 16-bit protocol number.
uint16_t
nni_sock_proto(nni_sock *sock)
{
	return (sock->s_self_id.p_id);
}

uint16_t
nni_sock_peer(nni_sock *sock)
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

void
nni_sock_reconntimes(nni_sock *sock, nni_duration *rcur, nni_duration *rmax)
{
	// These two values are linked, so get them atomically.
	nni_mtx_lock(&sock->s_mx);
	*rcur = sock->s_reconn;
	*rmax = sock->s_reconnmax ? sock->s_reconnmax : sock->s_reconn;
	nni_mtx_unlock(&sock->s_mx);
}

int
nni_sock_ep_add(nni_sock *s, nni_ep *ep)
{
	nni_sockopt *sopt;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		int rv;
		rv = nni_ep_setopt(
		    ep, sopt->name, sopt->data, sopt->sz, NNI_TYPE_OPAQUE);
		if ((rv != 0) && (rv != NNG_ENOTSUP)) {
			nni_mtx_unlock(&s->s_mx);
			return (rv);
		}
	}

	nni_list_append(&s->s_eps, ep);
	nni_mtx_unlock(&s->s_mx);
	return (0);
}

void
nni_sock_ep_remove(nni_sock *sock, nni_ep *ep)
{
	nni_mtx_lock(&sock->s_mx);
	if (nni_list_active(&sock->s_eps, ep)) {
		nni_list_remove(&sock->s_eps, ep);
		if ((sock->s_closing) && (nni_list_empty(&sock->s_eps))) {
			nni_cv_wake(&sock->s_cv);
		}
	}
	nni_mtx_unlock(&sock->s_mx);
}

int
nni_sock_setopt(nni_sock *s, const char *name, const void *v, size_t sz, int t)
{
	int                          rv = NNG_ENOTSUP;
	nni_ep *                     ep;
	nni_sockopt *                optv;
	nni_sockopt *                oldv = NULL;
	const nni_socket_option *    sso;
	const nni_proto_sock_option *pso;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	// Protocol options.  The protocol can override options that
	// the socket framework would otherwise supply, like buffer sizes.
	for (pso = s->s_sock_ops.sock_options; pso->pso_name != NULL; pso++) {
		if (strcmp(pso->pso_name, name) != 0) {
			continue;
		}
		if (pso->pso_setopt == NULL) {
			nni_mtx_unlock(&s->s_mx);
			return (NNG_EREADONLY);
		}
		rv = pso->pso_setopt(s->s_data, v, sz, t);
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	// Some options do not go down to transports.  Handle them directly.
	for (sso = nni_sock_options; sso->so_name != NULL; sso++) {
		if (strcmp(sso->so_name, name) != 0) {
			continue;
		}
		if (sso->so_setopt == NULL) {
			nni_mtx_unlock(&s->s_mx);
			return (NNG_EREADONLY);
		}
		rv = sso->so_setopt(s, v, sz, t);
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	nni_mtx_unlock(&s->s_mx);

	// If the option was already handled one way or the other,
	if (rv != NNG_ENOTSUP) {
		return (rv);
	}

	// Validation of transport options.  This is stateless, so transports
	// should not fail to set an option later if they passed it here.
	rv = nni_tran_chkopt(name, v, sz, t);

	// Also check a few generic things.  We do this if no transport
	// was found, or even if a transport rejected one of the settings.
	if ((rv == NNG_ENOTSUP) || (rv == 0)) {
		if (strcmp(name, NNG_OPT_RECVMAXSZ) == 0) {
			size_t z;
			// just a sanity test on the size; it also ensures that
			// a size can be set even with no transport configured.
			rv = nni_copyin_size(&z, v, sz, 0, NNI_MAXSZ, t);
		}
	}

	if (rv != 0) {
		return (rv);
	}

	// Prepare a copy of the sockoption.
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

	// Apply the options.  Failure to set any option on any transport
	// (other than ENOTSUP) stops the operation altogether.  Its
	// important that transport wide checks properly pre-validate.
	NNI_LIST_FOREACH (&s->s_eps, ep) {
		int x;
		if (optv->typ == NNI_TYPE_OPAQUE) {
			int t2;
			if (nni_ep_opttype(ep, optv->name, &t2) ==
			    NNG_ENOTSUP) {
				continue;
			}
			// This allows us to determine what the type
			// *should* be.
			optv->typ = t2;
		}
		x = nni_ep_setopt(ep, optv->name, optv->data, sz, t);
		if (x != NNG_ENOTSUP) {
			if ((rv = x) != 0) {
				nni_mtx_unlock(&s->s_mx);
				nni_free_opt(optv);
				return (rv);
			}
		}
	}

	if (rv == 0) {
		// Remove and toss the old value, we are using a new one.
		if (oldv != NULL) {
			nni_list_remove(&s->s_options, oldv);
			nni_free_opt(oldv);
		}

		// Insert our new value.  This permits it to be compared
		// against later, and for new endpoints to automatically
		// receive these values,
		nni_list_append(&s->s_options, optv);
	} else {
		nni_free_opt(optv);
	}

	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

int
nni_sock_getopt(nni_sock *s, const char *name, void *val, size_t *szp, int t)
{
	int                          rv = NNG_ENOTSUP;
	nni_sockopt *                sopt;
	const nni_socket_option *    sso;
	const nni_proto_sock_option *pso;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	// Protocol specific options.  The protocol can override
	// options like the send buffer or notification descriptors this way.
	for (pso = s->s_sock_ops.sock_options; pso->pso_name != NULL; pso++) {
		if (strcmp(name, pso->pso_name) != 0) {
			continue;
		}
		if (pso->pso_getopt == NULL) {
			nni_mtx_unlock(&s->s_mx);
			return (NNG_EWRITEONLY);
		}
		rv = pso->pso_getopt(s->s_data, val, szp, t);
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	// Socket generic options.
	for (sso = nni_sock_options; sso->so_name != NULL; sso++) {
		if (strcmp(name, sso->so_name) != 0) {
			continue;
		}
		if (sso->so_getopt == NULL) {
			nni_mtx_unlock(&s->s_mx);
			return (NNG_EWRITEONLY);
		}
		rv = sso->so_getopt(s, val, szp, t);
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		if (strcmp(sopt->name, name) == 0) {
			size_t sz = sopt->sz;

			if ((sopt->typ != NNI_TYPE_OPAQUE) &&
			    (t != NNI_TYPE_OPAQUE) && (t != sopt->typ)) {
				nni_mtx_unlock(&s->s_mx);
				return (NNG_EBADTYPE);
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
nni_sock_set_pipe_cb(nni_sock *sock, nng_pipe_cb cb, void *arg)
{
	nni_mtx_lock(&sock->s_mx);
	sock->s_pipe_cb    = cb;
	sock->s_pipe_cbarg = arg;
	nni_mtx_unlock(&sock->s_mx);
}

int
nni_ctx_find(nni_ctx **ctxp, uint32_t id, bool closing)
{
	int      rv;
	nni_ctx *ctx;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	nni_mtx_lock(&nni_sock_lk);
	if ((rv = nni_idhash_find(nni_ctx_hash, id, (void **) &ctx)) == 0) {
		// We refuse a reference if either the socket is closed,
		// or the context is closed.  (If the socket is closed,
		// and we are only getting the reference so we can close it,
		// then we still allow.  In the case the only valid operation
		// will be to close the socket.)
		if (ctx->c_closed || ((!closing) && ctx->c_sock->s_closed)) {
			rv = NNG_ECLOSED;
		} else {
			ctx->c_refcnt++;
			*ctxp = ctx;
		}
	}
	nni_mtx_unlock(&nni_sock_lk);

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
	NNI_FREE_STRUCT(ctx);
}

void
nni_ctx_rele(nni_ctx *ctx)
{
	nni_sock *sock = ctx->c_sock;
	nni_mtx_lock(&nni_sock_lk);
	ctx->c_refcnt--;
	if ((ctx->c_refcnt > 0) || (!ctx->c_closed)) {
		// Either still have an active reference, or not actually
		// closing yet.
		nni_mtx_unlock(&nni_sock_lk);
		return;
	}

	// Remove us from the hash, so we can't be found any more.
	// This allows our ID to be reused later, although the system
	// tries to avoid ID reuse.
	nni_idhash_remove(nni_ctx_hash, ctx->c_id);
	nni_list_remove(&sock->s_ctxs, ctx);
	if (sock->s_closed || sock->s_ctxwait) {
		nni_cv_wake(&sock->s_close_cv);
	}
	nni_mtx_unlock(&nni_sock_lk);

	nni_ctx_destroy(ctx);
}

int
nni_ctx_open(nni_ctx **ctxp, nni_sock *sock)
{
	nni_ctx *ctx;
	int      rv;
	uint64_t id;

	if (sock->s_ctx_ops.ctx_init == NULL) {
		return (NNG_ENOTSUP);
	}
	if ((ctx = NNI_ALLOC_STRUCT(ctx)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_lock(&nni_sock_lk);
	if (sock->s_closed) {
		nni_mtx_unlock(&nni_sock_lk);
		NNI_FREE_STRUCT(ctx);
		return (NNG_ECLOSED);
	}
	if ((rv = nni_idhash_alloc(nni_ctx_hash, &id, ctx)) != 0) {
		nni_mtx_unlock(&nni_sock_lk);
		NNI_FREE_STRUCT(ctx);
		return (rv);
	}
	ctx->c_id = (uint32_t) id;

	if ((rv = sock->s_ctx_ops.ctx_init(&ctx->c_data, sock->s_data)) != 0) {
		nni_idhash_remove(nni_ctx_hash, ctx->c_id);
		nni_mtx_unlock(&nni_sock_lk);
		NNI_FREE_STRUCT(ctx);
		return (rv);
	}

	ctx->c_closed   = false;
	ctx->c_refcnt   = 1; // Caller implicitly gets a reference.
	ctx->c_sock     = sock;
	ctx->c_ops      = sock->s_ctx_ops;
	ctx->c_rcvtimeo = sock->s_rcvtimeo;
	ctx->c_sndtimeo = sock->s_sndtimeo;

	nni_list_append(&sock->s_ctxs, ctx);
	nni_mtx_unlock(&nni_sock_lk);

	// Paranoia, fixing a possible race in close.  Don't let us
	// give back a context if the socket is being shutdown (it might
	// not have reached the "closed" state yet.)
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
	nni_mtx_lock(&nni_sock_lk);
	ctx->c_closed = true;
	nni_mtx_unlock(&nni_sock_lk);

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
nni_ctx_getopt(nni_ctx *ctx, const char *opt, void *v, size_t *szp, int typ)
{
	nni_sock *            sock = ctx->c_sock;
	nni_proto_ctx_option *co;
	int                   rv = NNG_ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (strcmp(opt, NNG_OPT_RECVTIMEO) == 0) {
		rv = nni_copyout_ms(ctx->c_rcvtimeo, v, szp, typ);
	} else if (strcmp(opt, NNG_OPT_SENDTIMEO) == 0) {
		rv = nni_copyout_ms(ctx->c_sndtimeo, v, szp, typ);
	} else if (ctx->c_ops.ctx_options != NULL) {
		for (co = ctx->c_ops.ctx_options; co->co_name != NULL; co++) {
			if (strcmp(opt, co->co_name) != 0) {
				continue;
			}
			if (co->co_getopt == NULL) {
				rv = NNG_EWRITEONLY;
				break;
			}
			rv = co->co_getopt(ctx->c_data, v, szp, typ);
			break;
		}
	}
	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}

int
nni_ctx_setopt(
    nni_ctx *ctx, const char *opt, const void *v, size_t sz, int typ)
{
	nni_sock *            sock = ctx->c_sock;
	nni_proto_ctx_option *co;
	int                   rv = NNG_ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (strcmp(opt, NNG_OPT_RECVTIMEO) == 0) {
		rv = nni_copyin_ms(&ctx->c_rcvtimeo, v, sz, typ);
	} else if (strcmp(opt, NNG_OPT_SENDTIMEO) == 0) {
		rv = nni_copyin_ms(&ctx->c_sndtimeo, v, sz, typ);
	} else if (ctx->c_ops.ctx_options != NULL) {
		for (co = ctx->c_ops.ctx_options; co->co_name != NULL; co++) {
			if (strcmp(opt, co->co_name) != 0) {
				continue;
			}
			if (co->co_setopt == NULL) {
				rv = NNG_EREADONLY;
				break;
			}
			rv = co->co_setopt(ctx->c_data, v, sz, typ);
			break;
		}
	}

	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}
