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

// Surveyor protocol.  The SURVEYOR protocol is the "survey" side of the
// survey pattern.  This is useful for building service discovery, voting, etc.

typedef struct surv_pipe surv_pipe;
typedef struct surv_sock surv_sock;

static void surv_sock_getq_cb(void *);
static void surv_getq_cb(void *);
static void surv_putq_cb(void *);
static void surv_send_cb(void *);
static void surv_recv_cb(void *);
static void surv_timeout(void *);

// A surv_sock is our per-socket protocol private structure.
struct surv_sock {
	nni_sock *     nsock;
	nni_duration   survtime;
	nni_time       expire;
	int            raw;
	int            closing;
	uint32_t       nextid; // next id
	uint32_t       survid; // outstanding request ID (big endian)
	nni_list       pipes;
	nni_aio *      aio_getq;
	nni_timer_node timer;
	nni_msgq *     uwq;
	nni_msgq *     urq;
	nni_mtx        mtx;
};

// A surv_pipe is our per-pipe protocol private structure.
struct surv_pipe {
	nni_pipe *    npipe;
	surv_sock *   psock;
	nni_msgq *    sendq;
	nni_list_node node;
	nni_aio *     aio_getq;
	nni_aio *     aio_putq;
	nni_aio *     aio_send;
	nni_aio *     aio_recv;
};

static void
surv_sock_fini(void *arg)
{
	surv_sock *s = arg;

	nni_aio_stop(s->aio_getq);
	nni_aio_fini(s->aio_getq);
	nni_mtx_fini(&s->mtx);
	NNI_FREE_STRUCT(s);
}

static int
surv_sock_init(void **sp, nni_sock *nsock)
{
	surv_sock *s;
	int        rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_aio_init(&s->aio_getq, surv_sock_getq_cb, s)) != 0) {
		surv_sock_fini(s);
		return (rv);
	}
	NNI_LIST_INIT(&s->pipes, surv_pipe, node);
	nni_mtx_init(&s->mtx);
	nni_timer_init(&s->timer, surv_timeout, s);

	s->nextid   = nni_random();
	s->nsock    = nsock;
	s->raw      = 0;
	s->survtime = NNI_SECOND * 60;
	s->expire   = NNI_TIME_ZERO;
	s->uwq      = nni_sock_sendq(nsock);
	s->urq      = nni_sock_recvq(nsock);

	*sp = s;
	nni_sock_recverr(nsock, NNG_ESTATE);
	return (0);
}

static void
surv_sock_open(void *arg)
{
	surv_sock *s = arg;

	nni_msgq_aio_get(s->uwq, s->aio_getq);
}

static void
surv_sock_close(void *arg)
{
	surv_sock *s = arg;

	nni_timer_cancel(&s->timer);
	nni_aio_cancel(s->aio_getq, NNG_ECLOSED);
}

static void
surv_pipe_fini(void *arg)
{
	surv_pipe *p = arg;

	nni_aio_fini(p->aio_getq);
	nni_aio_fini(p->aio_send);
	nni_aio_fini(p->aio_recv);
	nni_aio_fini(p->aio_putq);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
surv_pipe_init(void **pp, nni_pipe *npipe, void *s)
{
	surv_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	// This depth could be tunable.
	if (((rv = nni_msgq_init(&p->sendq, 16)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_getq, surv_getq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_putq, surv_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_send, surv_send_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, surv_recv_cb, p)) != 0)) {
		surv_pipe_fini(p);
		return (rv);
	}

	p->npipe = npipe;
	p->psock = s;
	*pp      = p;
	return (0);
}

static int
surv_pipe_start(void *arg)
{
	surv_pipe *p = arg;
	surv_sock *s = p->psock;

	nni_mtx_lock(&s->mtx);
	nni_list_append(&s->pipes, p);
	nni_mtx_unlock(&s->mtx);

	nni_msgq_aio_get(p->sendq, p->aio_getq);
	nni_pipe_recv(p->npipe, p->aio_recv);
	return (0);
}

static void
surv_pipe_stop(void *arg)
{
	surv_pipe *p = arg;
	surv_sock *s = p->psock;

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
surv_getq_cb(void *arg)
{
	surv_pipe *p = arg;

	if (nni_aio_result(p->aio_getq) != 0) {
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_aio_set_msg(p->aio_send, nni_aio_get_msg(p->aio_getq));
	nni_aio_set_msg(p->aio_getq, NULL);

	nni_pipe_send(p->npipe, p->aio_send);
}

static void
surv_send_cb(void *arg)
{
	surv_pipe *p = arg;

	if (nni_aio_result(p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_send));
		nni_aio_set_msg(p->aio_send, NULL);
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_msgq_aio_get(p->psock->uwq, p->aio_getq);
}

static void
surv_putq_cb(void *arg)
{
	surv_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->npipe);
		return;
	}

	nni_pipe_recv(p->npipe, p->aio_recv);
}

static void
surv_recv_cb(void *arg)
{
	surv_pipe *p = arg;
	nni_msg *  msg;

	if (nni_aio_result(p->aio_recv) != 0) {
		goto failed;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);

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
surv_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	surv_sock *s  = arg;
	int        rv = NNG_ENOTSUP;
	int        oldraw;

	if (opt == nng_optid_surveyor_surveytime) {
		rv = nni_setopt_usec(&s->survtime, buf, sz);

	} else if (opt == nng_optid_raw) {
		oldraw = s->raw;
		rv     = nni_setopt_int(&s->raw, buf, sz, 0, 1);
		if (oldraw != s->raw) {
			if (s->raw) {
				nni_sock_recverr(s->nsock, 0);
			} else {
				nni_sock_recverr(s->nsock, NNG_ESTATE);
			}
			s->survid = 0;
			nni_timer_cancel(&s->timer);
		}
	}

	return (rv);
}

static int
surv_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	surv_sock *s  = arg;
	int        rv = NNG_ENOTSUP;

	if (opt == nng_optid_surveyor_surveytime) {
		rv = nni_getopt_usec(s->survtime, buf, szp);
	} else if (opt == nng_optid_raw) {
		rv = nni_getopt_int(s->raw, buf, szp);
	}
	return (rv);
}

static void
surv_sock_getq_cb(void *arg)
{
	surv_sock *s = arg;
	surv_pipe *p;
	surv_pipe *last;
	nni_msg *  msg, *dup;

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
	nni_mtx_unlock(&s->mtx);

	if (last == NULL) {
		// If there were no pipes to send on, just toss the message.
		nni_msg_free(msg);
	}
}

static void
surv_timeout(void *arg)
{
	surv_sock *s = arg;

	nni_sock_lock(s->nsock);
	s->survid = 0;
	nni_sock_recverr(s->nsock, NNG_ESTATE);
	nni_msgq_set_get_error(s->urq, NNG_ETIMEDOUT);
	nni_sock_unlock(s->nsock);
}

static nni_msg *
surv_sock_sfilter(void *arg, nni_msg *msg)
{
	surv_sock *s = arg;

	if (s->raw) {
		// No automatic retry, and the request ID must
		// be in the header coming down.
		return (msg);
	}

	// Generate a new request ID.  We always set the high
	// order bit so that the peer can locate the end of the
	// backtrace.  (Pipe IDs have the high order bit clear.)
	s->survid = (s->nextid++) | 0x80000000u;

	if (nni_msg_header_append_u32(msg, s->survid) != 0) {
		// Should be ENOMEM.
		nni_msg_free(msg);
		return (NULL);
	}

	// If another message is there, this cancels it.  We move the
	// survey expiration out.  The timeout thread will wake up in
	// the wake below, and reschedule itself appropriately.
	s->expire = nni_clock() + s->survtime;
	nni_timer_schedule(&s->timer, s->expire);

	// Clear the error condition.
	nni_sock_recverr(s->nsock, 0);
	// nni_msgq_set_get_error(nni_sock_recvq(psock->nsock), 0);

	return (msg);
}

static nni_msg *
surv_sock_rfilter(void *arg, nni_msg *msg)
{
	surv_sock *s = arg;

	if (s->raw) {
		// Pass it unmolested
		return (msg);
	}

	if ((nni_msg_header_len(msg) < sizeof(uint32_t)) ||
	    (nni_msg_header_trim_u32(msg) != s->survid)) {
		// Wrong request id
		nni_msg_free(msg);
		return (NULL);
	}

	return (msg);
}

static nni_proto_pipe_ops surv_pipe_ops = {
	.pipe_init  = surv_pipe_init,
	.pipe_fini  = surv_pipe_fini,
	.pipe_start = surv_pipe_start,
	.pipe_stop  = surv_pipe_stop,
};

static nni_proto_sock_ops surv_sock_ops = {
	.sock_init    = surv_sock_init,
	.sock_fini    = surv_sock_fini,
	.sock_open    = surv_sock_open,
	.sock_close   = surv_sock_close,
	.sock_setopt  = surv_sock_setopt,
	.sock_getopt  = surv_sock_getopt,
	.sock_rfilter = surv_sock_rfilter,
	.sock_sfilter = surv_sock_sfilter,
};

static nni_proto surv_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_peer     = { NNG_PROTO_RESPONDENT_V0, "respondent" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &surv_sock_ops,
	.proto_pipe_ops = &surv_pipe_ops,
};

int
nng_surveyor0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &surv_proto));
}
