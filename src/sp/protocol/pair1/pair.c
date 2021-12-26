//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
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

#ifdef NNG_ENABLE_STATS
#define BUMP_STAT(x) nni_stat_inc(x, 1)
#else
#define BUMP_STAT(x)
#endif

typedef struct pair1_pipe pair1_pipe;
typedef struct pair1_sock pair1_sock;

static void pair1_pipe_send_cb(void *);
static void pair1_pipe_recv_cb(void *);
static void pair1_pipe_fini(void *);
static void pair1_send_sched(pair1_sock *);
static void pair1_pipe_send(pair1_pipe *, nni_msg *);

// pair1_sock is our per-socket protocol private structure.
struct pair1_sock {
	nni_sock      *sock;
	bool           raw;
	pair1_pipe    *p;
	nni_atomic_int ttl;
	nni_mtx        mtx;
	nni_lmq        wmq;
	nni_list       waq;
	nni_lmq        rmq;
	nni_list       raq;
	nni_pollable   writable;
	nni_pollable   readable;
	bool           rd_ready; // pipe ready for read
	bool           wr_ready; // pipe ready for write

#ifdef NNG_ENABLE_STATS
	nni_stat_item stat_poly;
	nni_stat_item stat_raw;
	nni_stat_item stat_reject_mismatch;
	nni_stat_item stat_reject_already;
	nni_stat_item stat_ttl_drop;
	nni_stat_item stat_rx_malformed;
	nni_stat_item stat_tx_malformed;
	nni_stat_item stat_tx_drop;
#endif
#ifdef NNG_TEST_LIB
	bool inject_header;
#endif
};

// pair1_pipe is our per-pipe protocol private structure.
struct pair1_pipe {
	nni_pipe   *pipe;
	pair1_sock *pair;
	nni_aio     aio_send;
	nni_aio     aio_recv;
};

static void
pair1_sock_fini(void *arg)
{
	pair1_sock *s = arg;

	nni_lmq_fini(&s->rmq);
	nni_lmq_fini(&s->wmq);
	nni_pollable_fini(&s->writable);
	nni_pollable_fini(&s->readable);
	nni_mtx_fini(&s->mtx);
}

#ifdef NNG_ENABLE_STATS
static void
pair1_add_sock_stat(
    pair1_sock *s, nni_stat_item *item, const nni_stat_info *info)
{
	nni_stat_init(item, info);
	nni_sock_add_stat(s->sock, item);
}
#endif

static int
pair1_sock_init_impl(void *arg, nni_sock *sock, bool raw)
{
	pair1_sock *s = arg;

	// Raw mode uses this.
	nni_mtx_init(&s->mtx);
	s->sock = sock;
	s->raw  = raw;

	nni_lmq_init(&s->rmq, 0);
	nni_lmq_init(&s->wmq, 0);
	nni_aio_list_init(&s->raq);
	nni_aio_list_init(&s->waq);
	nni_pollable_init(&s->writable);
	nni_pollable_init(&s->readable);
	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);

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

	if (raw) {
		// This stat only makes sense in raw mode.
		pair1_add_sock_stat(
		    s, &s->stat_tx_malformed, &tx_malformed_info);
	}

	nni_stat_set_bool(&s->stat_raw, raw);
	nni_stat_set_bool(&s->stat_poly, false);
#endif

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
	pair1_sock *s = p->pair;

	nni_mtx_lock(&s->mtx);
	if (s->p == p) {
		s->p = NULL;
		if (s->rd_ready) {
			nni_msg *m = nni_aio_get_msg(&p->aio_recv);
			nni_msg_free(m);
			s->rd_ready = false;
		}
		if (s->wr_ready) {
			s->wr_ready = false;
			nni_pollable_clear(&s->writable);
		}
		if (nni_lmq_empty(&s->rmq)) {
			nni_pollable_clear(&s->readable);
		}
	}
	nni_mtx_unlock(&s->mtx);
	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
}

static void
pair1_pipe_fini(void *arg)
{
	pair1_pipe *p = arg;

	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
}

static int
pair1_pipe_init(void *arg, nni_pipe *pipe, void *pair)
{
	pair1_pipe *p = arg;

	nni_aio_init(&p->aio_send, pair1_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, pair1_pipe_recv_cb, p);

	p->pipe = pipe;
	p->pair = pair;

	return (0);
}

static void
pair1_cancel(nni_aio *aio, void *arg, int rv)
{
	pair1_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->mtx);
}

static int
pair1_pipe_start(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->pair;

	if (nni_pipe_peer(p->pipe) != NNG_PAIR1_PEER) {
		BUMP_STAT(&s->stat_reject_mismatch);
		// Peer protocol mismatch.
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->mtx);
	if (s->p != NULL) {
		nni_mtx_unlock(&s->mtx);
		BUMP_STAT(&s->stat_reject_already);
		return (NNG_EBUSY);
	}
	s->p        = p;
	s->rd_ready = false;
	nni_mtx_unlock(&s->mtx);

	pair1_send_sched(s);

	// And the pipe read of course.
	nni_pipe_recv(p->pipe, &p->aio_recv);

	return (0);
}

static void
pair1_pipe_close(void *arg)
{
	pair1_pipe *p = arg;

	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);
}

static void
pair1_pipe_recv_cb(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->pair;
	nni_msg    *msg;
	uint32_t    hdr;
	nni_pipe   *pipe = p->pipe;
	size_t      len;
	nni_aio    *a;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(&p->aio_recv);

	// Store the pipe ID.
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));
	len = nni_msg_len(msg);

	// If the message is missing the hop count header, scrap it.
	if ((len < sizeof(uint32_t)) ||
	    ((hdr = nni_msg_trim_u32(msg)) > 0xff)) {
		BUMP_STAT(&s->stat_rx_malformed);
		nni_msg_free(msg);
		nni_pipe_close(pipe);
		return;
	}

	// If we bounced too many times, discard the message, but
	// keep getting more.
	if ((int) hdr > nni_atomic_get(&s->ttl)) {
		BUMP_STAT(&s->stat_ttl_drop);
		nni_msg_free(msg);
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_pipe_recv(pipe, &p->aio_recv);
		return;
	}

	nni_sock_bump_rx(s->sock, len);

	// Store the hop count in the header.
	nni_msg_header_append_u32(msg, hdr);

	nni_mtx_lock(&s->mtx);

	// if anyone is blocking, then the lmq will be empty, and
	// we should deliver it there.
	if ((a = nni_list_first(&s->raq)) != NULL) {
		nni_aio_list_remove(a);
		nni_aio_set_msg(a, msg);
		nni_pipe_recv(pipe, &p->aio_recv);
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_sync(a, 0, len);
		return;
	}

	// maybe we have room in the rmq?
	if (!nni_lmq_full(&s->rmq)) {
		nni_lmq_put(&s->rmq, msg);
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_pipe_recv(pipe, &p->aio_recv);
	} else {
		s->rd_ready = true;
	}
	nni_pollable_raise(&s->readable);
	nni_mtx_unlock(&s->mtx);
}

static void
pair1_send_sched(pair1_sock *s)
{
	pair1_pipe *p;
	nni_msg    *m;
	nni_aio    *a = NULL;
	size_t      l = 0;

	nni_mtx_lock(&s->mtx);

	if ((p = s->p) == NULL) {
		nni_mtx_unlock(&s->mtx);
		return;
	}

	s->wr_ready = true;

	// if message waiting in buffered queue, then we prefer that.
	if (nni_lmq_get(&s->wmq, &m) == 0) {
		pair1_pipe_send(p, m);

		if ((a = nni_list_first(&s->waq)) != NULL) {
			nni_aio_list_remove(a);
			m = nni_aio_get_msg(a);
			l = nni_msg_len(m);
			nni_lmq_put(&s->wmq, m);
		}

	} else if ((a = nni_list_first(&s->waq)) != NULL) {
		// Looks like we had the unbuffered case, but
		// someone was waiting.
		nni_aio_list_remove(a);

		m = nni_aio_get_msg(a);
		l = nni_msg_len(m);
		pair1_pipe_send(p, m);
	}

	// if we were blocked before, but not now, update.
	if ((!nni_lmq_full(&s->wmq)) || s->wr_ready) {
		nni_pollable_raise(&s->writable);
	}

	nni_mtx_unlock(&s->mtx);

	if (a != NULL) {
		nni_aio_set_msg(a, NULL);
		nni_aio_finish_sync(a, 0, l);
	}
}

static void
pair1_pipe_send_cb(void *arg)
{
	pair1_pipe *p = arg;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	pair1_send_sched(p->pair);
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
	nni_aio    *a;
	nni_msg    *m;
	nni_mtx_lock(&s->mtx);
	while (((a = nni_list_first(&s->raq)) != NULL) ||
	    ((a = nni_list_first(&s->waq)) != NULL)) {
		nni_aio_list_remove(a);
		nni_aio_finish_error(a, NNG_ECLOSED);
	}
	while ((nni_lmq_get(&s->rmq, &m) == 0) ||
	    (nni_lmq_get(&s->wmq, &m) == 0)) {
		nni_msg_free(m);
	}
	nni_mtx_unlock(&s->mtx);
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
pair1_pipe_send(pair1_pipe *p, nni_msg *m)
{
	pair1_sock *s = p->pair;
	// assumption: we have unique access to the message at this point.
	NNI_ASSERT(!nni_msg_shared(m));

#if NNG_TEST_LIB
	if (s->inject_header) {
		goto inject;
	}
#endif
	NNI_ASSERT(nni_msg_header_len(m) == sizeof(uint32_t));
	nni_msg_header_poke_u32(m, nni_msg_header_peek_u32(m) + 1);

#if NNG_TEST_LIB
inject:
#endif

	nni_aio_set_msg(&p->aio_send, m);
	nni_pipe_send(p->pipe, &p->aio_send);
	s->wr_ready = false;
}

static void
pair1_sock_send(void *arg, nni_aio *aio)
{
	pair1_sock *s = arg;
	nni_msg    *m;
	size_t      len;
	int         rv;

	m   = nni_aio_get_msg(aio);
	len = nni_msg_len(m);
	nni_sock_bump_tx(s->sock, len);

	if (nni_aio_begin(aio) != 0) {
		return;
	}

#if NNG_TEST_LIB
	if (s->inject_header) {
		goto inject;
	}
#endif

	// Raw mode messages have the header already formed, with a hop count.
	// Cooked mode messages have no header so we have to add one.
	if (s->raw) {
		if ((nni_msg_header_len(m) != sizeof(uint32_t)) ||
		    (nni_msg_header_peek_u32(m) >= 0xff)) {
			BUMP_STAT(&s->stat_tx_malformed);
			nni_aio_finish_error(aio, NNG_EPROTO);
			return;
		}

	} else {
		// Strip off any previously existing header, such as when
		// replying to messages.
		nni_msg_header_clear(m);
		nni_msg_header_append_u32(m, 0);
	}

#if NNG_TEST_LIB
inject:
#endif

	nni_mtx_lock(&s->mtx);
	if (s->wr_ready) {
		pair1_pipe *p = s->p;
		if (nni_lmq_full(&s->wmq)) {
			nni_pollable_clear(&s->writable);
		}
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, len);
		pair1_pipe_send(p, m);
		nni_mtx_unlock(&s->mtx);
		return;
	}

	// Can we maybe queue it.
	if (nni_lmq_put(&s->wmq, m) == 0) {
		// Yay, we can.  So we're done.
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, len);
		if (nni_lmq_full(&s->wmq)) {
			nni_pollable_clear(&s->writable);
		}
		nni_mtx_unlock(&s->mtx);
		return;
	}

	if ((rv = nni_aio_schedule(aio, pair1_cancel, s)) != 0) {
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&s->mtx);
		return;
	}
	nni_aio_list_append(&s->waq, aio);
	nni_mtx_unlock(&s->mtx);
}

static void
pair1_sock_recv(void *arg, nni_aio *aio)
{
	pair1_sock *s = arg;
	pair1_pipe *p;
	nni_msg    *m;
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&s->mtx);
	p = s->p;

	// Buffered read.  If there is a message waiting for us, pick
	// it up.  We might need to post another read request as well.
	if (nni_lmq_get(&s->rmq, &m) == 0) {
		nni_aio_set_msg(aio, m);
		nni_aio_finish(aio, 0, nni_msg_len(m));
		if (s->rd_ready) {
			s->rd_ready = false;
			m           = nni_aio_get_msg(&p->aio_recv);
			nni_aio_set_msg(&p->aio_recv, NULL);
			nni_lmq_put(&s->rmq, m);
			nni_pipe_recv(p->pipe, &p->aio_recv);
		}
		if (nni_lmq_empty(&s->rmq)) {
			nni_pollable_clear(&s->readable);
		}
		nni_mtx_unlock(&s->mtx);
		return;
	}

	// Unbuffered -- but waiting.
	if (s->rd_ready) {
		s->rd_ready = false;
		m           = nni_aio_get_msg(&p->aio_recv);
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_aio_set_msg(aio, m);
		nni_aio_finish(aio, 0, nni_msg_len(m));
		nni_pipe_recv(p->pipe, &p->aio_recv);
		nni_pollable_clear(&s->readable);
		nni_mtx_unlock(&s->mtx);
		return;
	}

	if ((rv = nni_aio_schedule(aio, pair1_cancel, s)) != 0) {
		nni_aio_finish_error(aio, rv);
	} else {
		nni_aio_list_append(&s->raq, aio);
	}
	nni_mtx_unlock(&s->mtx);
}

static int
pair1_set_send_buf_len(void *arg, const void *buf, size_t sz, nni_type t)
{
	pair1_sock *s = arg;
	int         val;
	int         rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 0, 8192, t)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&s->mtx);
	rv = nni_lmq_resize(&s->wmq, (size_t) val);
	// Changing the size of the queue can affect our readiness.
	if (!nni_lmq_full(&s->wmq)) {
		nni_pollable_raise(&s->writable);
	} else if (!s->wr_ready) {
		nni_pollable_clear(&s->writable);
	}
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static int
pair1_get_send_buf_len(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair1_sock *s = arg;
	int         val;

	nni_mtx_lock(&s->mtx);
	val = (int) nni_lmq_cap(&s->wmq);
	nni_mtx_unlock(&s->mtx);

	return (nni_copyout_int(val, buf, szp, t));
}

static int
pair1_set_recv_buf_len(void *arg, const void *buf, size_t sz, nni_type t)
{
	pair1_sock *s = arg;
	int         val;
	int         rv;

	if ((rv = nni_copyin_int(&val, buf, sz, 0, 8192, t)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&s->mtx);
	rv = nni_lmq_resize(&s->rmq, (size_t) val);
	// Changing the size of the queue can affect our readiness.
	if (!nni_lmq_empty(&s->rmq)) {
		nni_pollable_raise(&s->readable);
	} else if (!s->rd_ready) {
		nni_pollable_clear(&s->readable);
	}
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static int
pair1_get_recv_buf_len(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair1_sock *s = arg;
	int         val;

	nni_mtx_lock(&s->mtx);
	val = (int) nni_lmq_cap(&s->rmq);
	nni_mtx_unlock(&s->mtx);

	return (nni_copyout_int(val, buf, szp, t));
}

static int
pair1_sock_get_recv_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair1_sock *s = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(&s->readable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
pair1_sock_get_send_fd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	pair1_sock *s = arg;
	int         rv;
	int         fd;

	if ((rv = nni_pollable_getfd(&s->writable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
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
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = pair1_sock_get_recv_fd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = pair1_sock_get_send_fd,
	},
	{
	    .o_name = NNG_OPT_SENDBUF,
	    .o_get  = pair1_get_send_buf_len,
	    .o_set  = pair1_set_send_buf_len,
	},
	{
	    .o_name = NNG_OPT_RECVBUF,
	    .o_get  = pair1_get_recv_buf_len,
	    .o_set  = pair1_set_recv_buf_len,
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
