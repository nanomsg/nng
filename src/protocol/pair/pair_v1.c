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

// Pair protocol.  The PAIRv1 protocol is a simple 1:1 messaging pattern.

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
	nni_sock *  nsock;
	nni_msgq *  uwq;
	nni_msgq *  urq;
	int         raw;
	int         ttl;
	nni_mtx     mtx;
	nni_idhash *pipes;
	int         started;
	int         poly;
	nni_aio     aio_getq;
	pair1_pipe *pipe; // cooked mode only
};

// pair1_pipe is our per-pipe protocol private structure.
struct pair1_pipe {
	nni_pipe *  npipe;
	pair1_sock *psock;
	nni_msgq *  sendq;
	nni_aio     aio_send;
	nni_aio     aio_recv;
	nni_aio     aio_getq;
	nni_aio     aio_putq;
};

static void
pair1_sock_fini(void *arg)
{
	pair1_sock *s = arg;

	nni_aio_fini(&s->aio_getq);
	nni_idhash_fini(s->pipes);
	nni_mtx_fini(&s->mtx);

	NNI_FREE_STRUCT(s);
}

static int
pair1_sock_init(void **sp, nni_sock *nsock)
{
	pair1_sock *s;
	int         rv;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	// Raw mode uses this.
	if (((rv = nni_aio_init(&s->aio_getq, pair1_sock_getq_cb, s)) != 0) ||
	    ((rv = nni_mtx_init(&s->mtx)) != 0) ||
	    ((rv = nni_idhash_init(&s->pipes)) != 0)) {
		pair1_sock_fini(s);
	} else {
		s->nsock = nsock;
		s->raw   = 0;
		s->poly  = 0;
		s->uwq   = nni_sock_sendq(nsock);
		s->urq   = nni_sock_recvq(nsock);
		s->ttl   = 8;
		*sp      = s;
	}
	return (0);
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
	} else {
		p->npipe = npipe;
		p->psock = psock;
		*pp      = p;
	}
	return (rv);
}

static void
pair1_pipe_fini(void *arg)
{
	pair1_pipe *p = arg;
	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_putq);
	nni_aio_fini(&p->aio_getq);
	nni_msgq_fini(p->sendq);
	NNI_FREE_STRUCT(p);
}

static int
pair1_pipe_start(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->psock;
	uint32_t    id;
	int         rv;

	id = nni_pipe_id(p->npipe);
	if ((rv = nni_idhash_insert(s->pipes, id, p)) != 0) {
		return (rv);
	}
	nni_mtx_lock(&s->mtx);
	if (!s->poly) {
		if (s->pipe != NULL) {
			nni_mtx_unlock(&s->mtx);
			nni_idhash_remove(s->pipes, id);
			return (NNG_EBUSY);
		}
	} else {
		if (!s->started) {
			nni_msgq_aio_get(s->uwq, &s->aio_getq);
		}
	}

	s->pipe    = p;
	s->started = 1;
	nni_mtx_unlock(&s->mtx);

	// Schedule a getq.  In polyamorous mode we get on the per pipe
	// sendq, as the socket distributes to us. In monogamous mode we
	// bypass and get from the upper writeq directly (saving a set of
	// context switches).
	if (s->poly) {
		nni_msgq_aio_get(p->sendq, &p->aio_getq);
	} else {
		nni_msgq_aio_get(s->uwq, &p->aio_getq);
	}
	// And the pipe read of course.
	nni_pipe_recv(p->npipe, &p->aio_recv);

	return (0);
}

static void
pair1_pipe_stop(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->psock;

	nni_msgq_close(p->sendq);
	nni_aio_cancel(&p->aio_send, NNG_ECANCELED);
	nni_aio_cancel(&p->aio_recv, NNG_ECANCELED);
	nni_aio_cancel(&p->aio_putq, NNG_ECANCELED);
	nni_aio_cancel(&p->aio_getq, NNG_ECANCELED);

	nni_mtx_lock(&s->mtx);
	if (s->pipe == p) {
		s->pipe = NULL;
	}
	nni_mtx_unlock(&s->mtx);
	nni_idhash_remove(s->pipes, nni_pipe_id(p->npipe));
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

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_stop(p->npipe);
		return;
	}

	msg               = p->aio_recv.a_msg;
	p->aio_recv.a_msg = NULL;

	// Store the pipe ID.
	nni_msg_set_pipe(msg, nni_pipe_id(p->npipe));

	// If the message is missing the hop count header, scrap it.
	if (nni_msg_len(msg) < sizeof(uint32_t)) {
		nni_msg_free(msg);
		nni_pipe_stop(npipe);
		return;
	}
	hdr = nni_msg_trim_u32(msg);
	if (hdr & 0xffffff00) {
		nni_msg_free(msg);
		nni_pipe_stop(npipe);
		return;
	}

	// If we bounced too many times, discard the message, but
	// keep getting more.
	if (hdr >= (unsigned) s->ttl) {
		nni_msg_free(msg);
		nni_pipe_recv(npipe, &p->aio_recv);
		return;
	}

	// Store the pipe id followed by the hop count.
	if ((rv = nni_msg_header_append_u32(msg, hdr)) != 0) {
		nni_msg_free(msg);
		nni_pipe_recv(npipe, &p->aio_recv);
		return;
	}

	// Send the message up.
	p->aio_putq.a_msg = msg;
	nni_msgq_aio_put(s->urq, &p->aio_putq);
}

static void
pair1_sock_getq_cb(void *arg)
{
	pair1_pipe *p;
	pair1_sock *s = arg;
	nni_msg *   msg;
	uint32_t    id;

	if (nni_aio_result(&s->aio_getq) != 0) {
		// Socket closing...
		return;
	}

	msg               = s->aio_getq.a_msg;
	s->aio_getq.a_msg = NULL;

	// By definition we are in polyamorous mode.
	NNI_ASSERT(s->poly);

	nni_mtx_lock(&s->mtx);

	// If no pipe was requested, we look for any connected peer.
	if (((id = nni_msg_get_pipe(msg)) == 0) && (s->pipe != NULL)) {
		id = nni_pipe_id(s->pipe->npipe);
	}

	if (nni_idhash_find(s->pipes, id, (void **) &p) != 0) {
		// Pipe not present!
		nni_mtx_unlock(&s->mtx);
		nni_msg_free(msg);
		nni_msgq_aio_get(s->uwq, &s->aio_getq);
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
	nni_msgq_aio_get(s->uwq, &s->aio_getq);
}

static void
pair1_pipe_putq_cb(void *arg)
{
	pair1_pipe *p = arg;

	if (nni_aio_result(&p->aio_putq) != 0) {
		nni_msg_free(p->aio_putq.a_msg);
		p->aio_putq.a_msg = NULL;
		nni_pipe_stop(p->npipe);
		return;
	}
	nni_pipe_recv(p->npipe, &p->aio_recv);
}

static void
pair1_pipe_getq_cb(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->psock;
	nni_msg *   msg;
	uint32_t    hops;

	if (nni_aio_result(&p->aio_getq) != 0) {
		nni_pipe_stop(p->npipe);
		return;
	}

	msg               = p->aio_getq.a_msg;
	p->aio_getq.a_msg = NULL;

	// Raw mode messages have the header already formed, with
	// a hop count.  Cooked mode messages have no
	// header so we have to add one.
	if (s->raw) {
		if (nni_msg_header_len(msg) != sizeof(uint32_t)) {
			goto badmsg;
		}
		hops = nni_msg_header_trim_u32(msg);
	} else {
		hops = 0;
	}

	hops++;

	// Insert the hops header.
	if (nni_msg_header_append_u32(msg, hops) != 0) {
		goto badmsg;
	}

	p->aio_send.a_msg = msg;
	nni_pipe_send(p->npipe, &p->aio_send);
	return;

badmsg:
	nni_msg_free(msg);
	nni_msgq_aio_get(s->poly ? p->sendq : s->uwq, &p->aio_getq);
}

static void
pair1_pipe_send_cb(void *arg)
{
	pair1_pipe *p = arg;
	pair1_sock *s = p->psock;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(p->aio_send.a_msg);
		p->aio_send.a_msg = NULL;
		nni_pipe_stop(p->npipe);
		return;
	}

	// In polyamorous mode, we want to get from the sendq; in
	// monogamous we get from upper writeq.
	if (s->poly) {
		nni_msgq_aio_get(p->sendq, &p->aio_getq);
	} else {
		nni_msgq_aio_get(s->uwq, &p->aio_getq);
	}
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
pair1_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	pair1_sock *s = arg;
	int         rv;

	nni_mtx_lock(&s->mtx);
	switch (opt) {
	case NNG_OPT_RAW:
		if (s->started) {
			rv = NNG_ESTATE;
		} else {
			rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
		}
		break;
	case NNG_OPT_POLYAMOROUS:
		if (s->started) {
			rv = NNG_ESTATE;
		} else {
			rv = nni_setopt_int(&s->poly, buf, sz, 0, 1);
		}
		break;
	case NNG_OPT_MAXTTL:
		rv = nni_setopt_int(&s->ttl, buf, sz, 0, 255);
		break;
	default:
		rv = NNG_ENOTSUP;
	}

	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static int
pair1_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	pair1_sock *s = arg;
	int         rv;

	nni_mtx_lock(&s->mtx);
	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&s->raw, buf, szp);
		break;
	case NNG_OPT_MAXTTL:
		rv = nni_getopt_int(&s->ttl, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static nni_proto_pipe_ops pair1_pipe_ops = {
	.pipe_init  = pair1_pipe_init,
	.pipe_fini  = pair1_pipe_fini,
	.pipe_start = pair1_pipe_start,
	.pipe_stop  = pair1_pipe_stop,
};

static nni_proto_sock_ops pair1_sock_ops = {
	.sock_init   = pair1_sock_init,
	.sock_fini   = pair1_sock_fini,
	.sock_open   = pair1_sock_open,
	.sock_close  = pair1_sock_close,
	.sock_setopt = pair1_sock_setopt,
	.sock_getopt = pair1_sock_getopt,
};

static nni_proto pair1_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_PAIR_V1, "pair1" },
	.proto_peer     = { NNG_PROTO_PAIR_V1, "pair1" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &pair1_sock_ops,
	.proto_pipe_ops = &pair1_pipe_ops,
};

int
nng_pair1_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &pair1_proto));
}
