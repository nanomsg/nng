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
#include "protocol/survey0/survey.h"

// Surveyor protocol.  The SURVEYOR protocol is the "survey" side of the
// survey pattern.  This is useful for building service discovery, voting, etc.

#ifndef NNI_PROTO_SURVEYOR_V0
#define NNI_PROTO_SURVEYOR_V0 NNI_PROTO(6, 2)
#endif

#ifndef NNI_PROTO_RESPONDENT_V0
#define NNI_PROTO_RESPONDENT_V0 NNI_PROTO(6, 3)
#endif

typedef struct surv0_pipe surv0_pipe;
typedef struct surv0_sock surv0_sock;

static void surv0_sock_getq_cb(void *);
static void surv0_getq_cb(void *);
static void surv0_putq_cb(void *);
static void surv0_send_cb(void *);
static void surv0_recv_cb(void *);
static void surv0_timeout(void *);

// surv0_sock is our per-socket protocol private structure.
struct surv0_sock {
	nni_duration   survtime;
	nni_time       expire;
	int            ttl;
	uint32_t       nextid; // next id
	uint32_t       survid; // outstanding request ID (big endian)
	nni_list       pipes;
	nni_aio *      aio_getq;
	nni_timer_node timer;
	nni_msgq *     uwq;
	nni_msgq *     urq;
	nni_mtx        mtx;
};

// surv0_pipe is our per-pipe protocol private structure.
struct surv0_pipe {
	nni_pipe *    npipe;
	surv0_sock *  psock;
	nni_msgq *    sendq;
	nni_list_node node;
	nni_aio *     aio_getq;
	nni_aio *     aio_putq;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
};

static void
surv0_sock_fini(void *arg)
{
	surv0_sock *s = arg;

	nni_aio_stop(s->aio_getq);
	nni_aio_fini(s->aio_getq);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static int
surv0_sock_init(void **sp, nni_sock *nsock)
{
	surv0_sock *s;
	int         rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_aio_init(&s->aio_getq, surv0_sock_getq_cb, s)) != 0) {
		surv0_sock_fini(s);
		return (rv);
	}
	NNI_LIST_INIT(&s->pipes, surv0_pipe, node);
	nni_mtx_init(&s->mtx);
	nni_timer_init(&s->timer, surv0_timeout, s);

	s->nextid   = nni_random();
	s->survtime = NNI_SECOND;
	s->expire   = NNI_TIME_ZERO;
	s->uwq      = nni_sock_sendq(nsock);
	s->urq      = nni_sock_recvq(nsock);
	s->ttl      = 8;

	*sp = s;
	return (0);
}

static void
surv0_sock_open(void *arg)
{
	surv0_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
surv0_sock_close(void *arg)
{
	surv0_sock *s = arg;

	nni_timer_cancel(&s->timer);
	nni_aio_abort(s->aio_getq, NNG_ECLOSED);
}

static void
surv0_pipe_fini(void *arg)
{
	surv0_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_putq);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
surv0_pipe_init(void **pp, nni_pipe *npipe, void *s)
{
	surv0_pipe *p;
	int         rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	// This depth could be tunable.
	if (((rv = nni_msgq_init(&p->sendq, 16)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, surv0_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, surv0_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, surv0_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, surv0_recv_cb, p)) != 0)) {
		surv0_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->psock = s;
	*pp      = p;
	return (0);
}

static int
surv0_pipe_start(void *arg)
{
	surv0_pipe *p = arg;
	surv0_sock *s = p->psock;

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	nni_mtx_unlock(&s->mtx);

	nni_msgq_aio_get(p->sendq, p->aio_getq);
	nni_pipe_recv(p->npipe, p->aio_recv);
	return (0);
}

static void
surv0_pipe_stop(void *arg)
{
	surv0_pipe *p = arg;
	surv0_sock *s = p->psock;

	nni_aio_stop(p->aio_getq);
	nni_aio_stop(p->aio_send);
	nni_aio_stop(p->aio_recv);
	nni_aio_stop(p->aio_putq);

	nni_msgq_close(p->sendq);

	nni_mtx_lock(&s->mtx);
	if (nni_list_active(&s->pipes, p)) {
		nni_list_remove(&s->pipes, p);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
surv0_getq_cb(void *arg)
{
	surv0_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->npipe, p->aio_send);
}

static void
surv0_send_cb(void *arg)
{
	surv0_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, p->aio_getq);
}

static void
surv0_putq_cb(void *arg)
{
	surv0_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_pipe_recv(p->npipe, p->aio_recv);
}

static void
surv0_recv_cb(void *arg)
{
	surv0_pipe *p = arg;
	nni_msg *   msg;

	if (nni_aio_result(p->aio_recv) != 0) {
		goto failed;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->npipe));

	// We yank 4 bytes of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Not enough data, just toss it.
		nni_msg_free(msg);
		goto failed;
	}
	if (nni_msg_header_append(msg, nni_msg_body(msg), 4) != 0) {
		// Should be NNG_ENOMEM
		nni_msg_free(msg);
		goto failed;
	}
	(void) nni_msg_trim(msg, 4);

	nni_aio_set_msg(p->aio_putq, msg);
	nni_msgq_aio_put(p->psock->urq, p->aio_putq);
	return;

failed:
	nni_pipe_stop(p->npipe);
}

static int
surv0_sock_setopt_maxttl(void *arg, const void *buf, size_t sz, int typ)
{
	surv0_sock *s = arg;
	return (nni_copyin_int(&s->ttl, buf, sz, 1, 255, typ));
}

static int
surv0_sock_getopt_maxttl(void *arg, void *buf, size_t *szp, int typ)
{
	surv0_sock *s = arg;
	return (nni_copyout_int(s->ttl, buf, szp, typ));
}

static int
surv0_sock_setopt_surveytime(void *arg, const void *buf, size_t sz, int typ)
{
	surv0_sock *s = arg;
	return (nni_copyin_ms(&s->survtime, buf, sz, typ));
}

static int
surv0_sock_getopt_surveytime(void *arg, void *buf, size_t *szp, int typ)
{
	surv0_sock *s = arg;
	return (nni_copyout_ms(s->survtime, buf, szp, typ));
}

static void
surv0_sock_getq_cb(void *arg)
{
	surv0_sock *s = arg;
	surv0_pipe *p;
	surv0_pipe *last;
	nni_msg *   msg, *dup;

	if (nni_aio_result(s->aio_getq) != 0) {
		// Should be NNG_ECLOSED.
		return;
	}
	msg = nni_aio_get_msg(s->aio_getq);
	nni_aio_set_msg(s->aio_getq, NULL);

	nni_mtx_lock(&s->mtx);
	last = nni_list_last(&s->pipes);
	NNI_LIST_FOREACH (&s->pipes, p) {
		if (p != last) {
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

	nni_msgq_aio_get(s->uwq, s->aio_getq);
	nni_mtx_unlock(&s->mtx);

	if (last == NULL) {
		// If there were no pipes to send on, just toss the message.
		nni_msg_free(msg);
	}
}

static void
surv0_timeout(void *arg)
{
	surv0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	s->survid = 0;
	nni_mtx_unlock(&s->mtx);

	nni_msgq_set_get_error(s->urq, NNG_ETIMEDOUT);
}

static void
surv0_sock_recv(void *arg, nni_aio *aio)
{
	surv0_sock *s = arg;

	nni_mtx_lock(&s->mtx);
	if (s->survid == 0) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	nni_mtx_unlock(&s->mtx);
	nni_msgq_aio_get(s->urq, aio);
}

static void
surv0_sock_send_raw(void *arg, nni_aio *aio)
{
	surv0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static void
surv0_sock_send(void *arg, nni_aio *aio)
{
	surv0_sock *s = arg;
	nni_msg *   msg;
	int         rv;

	nni_mtx_lock(&s->mtx);

	// Generate a new request ID.  We always set the high
	// order bit so that the peer can locate the end of the
	// backtrace.  (Pipe IDs have the high order bit clear.)
	s->survid = (s->nextid++) | 0x80000000u;

	msg = nni_aio_get_msg(aio);
	nni_msg_header_clear(msg);
	if ((rv = nni_msg_header_append_u32(msg, s->survid)) != 0) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	// If another message is there, this cancels it.  We move the
	// survey expiration out.  The timeout thread will wake up in
	// the wake below, and reschedule itself appropriately.
	nni_msgq_set_get_error(s->urq, 0);
	s->expire = nni_clock() + s->survtime;
	nni_timer_schedule(&s->timer, s->expire);

	nni_mtx_unlock(&s->mtx);

	nni_msgq_aio_put(s->uwq, aio);
}

static nni_msg *
surv0_sock_filter(void *arg, nni_msg *msg)
{
	surv0_sock *s = arg;

	nni_mtx_lock(&s->mtx);

	if ((nni_msg_header_len(msg) < sizeof(uint32_t)) ||
	    (nni_msg_header_trim_u32(msg) != s->survid)) {
		// Wrong request id
		nni_mtx_unlock(&s->mtx);
		nni_msg_free(msg);
		return (NULL);
	}
	nni_mtx_unlock(&s->mtx);

	return (msg);
}

static nni_proto_pipe_ops surv0_pipe_ops = {
	.pipe_init  = surv0_pipe_init,
	.pipe_fini  = surv0_pipe_fini,
	.pipe_start = surv0_pipe_start,
	.pipe_stop  = surv0_pipe_stop,
};

static nni_proto_sock_option surv0_sock_options[] = {
	{
	    .pso_name   = NNG_OPT_SURVEYOR_SURVEYTIME,
	    .pso_type   = NNI_TYPE_DURATION,
	    .pso_getopt = surv0_sock_getopt_surveytime,
	    .pso_setopt = surv0_sock_setopt_surveytime,
	},
	{
	    .pso_name   = NNG_OPT_MAXTTL,
	    .pso_type   = NNI_TYPE_INT32,
	    .pso_getopt = surv0_sock_getopt_maxttl,
	    .pso_setopt = surv0_sock_setopt_maxttl,
	},
	// terminate list
	{
	    .pso_name = NULL,
	},
};

static nni_proto_sock_ops surv0_sock_ops = {
	.sock_init    = surv0_sock_init,
	.sock_fini    = surv0_sock_fini,
	.sock_open    = surv0_sock_open,
	.sock_close   = surv0_sock_close,
	.sock_send    = surv0_sock_send,
	.sock_recv    = surv0_sock_recv,
	.sock_filter  = surv0_sock_filter,
	.sock_options = surv0_sock_options,
};

static nni_proto_sock_ops surv0_sock_ops_raw = {
	.sock_init    = surv0_sock_init,
	.sock_fini    = surv0_sock_fini,
	.sock_open    = surv0_sock_open,
	.sock_close   = surv0_sock_close,
	.sock_send    = surv0_sock_send_raw,
	.sock_recv    = surv0_sock_recv,
	.sock_filter  = surv0_sock_filter,
	.sock_options = surv0_sock_options,
};

static nni_proto surv0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_peer     = { NNI_PROTO_RESPONDENT_V0, "respondent" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &surv0_sock_ops,
	.proto_pipe_ops = &surv0_pipe_ops,
};

static nni_proto surv0_proto_raw = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_peer     = { NNI_PROTO_RESPONDENT_V0, "respondent" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &surv0_sock_ops_raw,
	.proto_pipe_ops = &surv0_pipe_ops,
};

int
nng_surveyor0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &surv0_proto));
}

int
nng_surveyor0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &surv0_proto_raw));
}
