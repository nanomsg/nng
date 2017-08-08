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

typedef struct nni_pair1_pipe nni_pair1_pipe;
typedef struct nni_pair1_sock nni_pair1_sock;

static void nni_pair1_sock_getq_cb(void *);
static void nni_pair1_pipe_send_cb(void *);
static void nni_pair1_pipe_recv_cb(void *);
static void nni_pair1_pipe_getq_cb(void *);
static void nni_pair1_pipe_putq_cb(void *);
static void nni_pair1_pipe_fini(void *);

// An nni_pair1_sock is our per-socket protocol private structure.
struct nni_pair1_sock {
	nni_sock *      nsock;
	nni_msgq *      uwq;
	nni_msgq *      urq;
	int             raw;
	int             ttl;
	nni_mtx         mtx;
	nni_idhash *    pipes;
	int             started;
	nni_aio         aio_getq;
	nni_pair1_pipe *pipe; // cooked mode only
};

// An nni_pair1_pipe is our per-pipe protocol private structure.
struct nni_pair1_pipe {
	nni_pipe *      npipe;
	nni_pair1_sock *psock;
	nni_msgq *      sendq;
	nni_aio         aio_send;
	nni_aio         aio_recv;
	nni_aio         aio_getq;
	nni_aio         aio_putq;
};

static void
nni_pair1_sock_fini(void *arg)
{
	nni_pair1_sock *psock = arg;

	nni_aio_fini(&psock->aio_getq);
	nni_idhash_fini(psock->pipes);
	nni_mtx_fini(&psock->mtx);

	NNI_FREE_STRUCT(psock);
}

static int
nni_pair1_sock_init(void **sp, nni_sock *nsock)
{
	nni_pair1_sock *psock;
	int             rv;

	if ((psock = NNI_ALLOC_STRUCT(psock)) == NULL) {
		return (NNG_ENOMEM);
	}
	// Raw mode uses this.
	rv = nni_aio_init(&psock->aio_getq, nni_pair1_sock_getq_cb, psock);
	if (rv != 0) {
		goto fail;
	}
	if ((rv = nni_mtx_init(&psock->mtx)) != 0) {
		goto fail;
	}
	if ((rv = nni_idhash_init(&psock->pipes)) != 0) {
		goto fail;
	}
	psock->nsock = nsock;
	psock->raw   = 0;
	psock->uwq   = nni_sock_sendq(nsock);
	psock->urq   = nni_sock_recvq(nsock);
	psock->ttl   = 8;
	*sp          = psock;
	return (0);

fail:
	nni_pair1_sock_fini(psock);
	return (rv);
}

static int
nni_pair1_pipe_init(void **pp, nni_pipe *npipe, void *psock)
{
	nni_pair1_pipe *ppipe;
	int             rv;

	if ((ppipe = NNI_ALLOC_STRUCT(ppipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_msgq_init(&ppipe->sendq, 2)) != 0) {
		goto fail;
	}
	rv = nni_aio_init(&ppipe->aio_send, nni_pair1_pipe_send_cb, ppipe);
	if (rv != 0) {
		goto fail;
	}
	rv = nni_aio_init(&ppipe->aio_recv, nni_pair1_pipe_recv_cb, ppipe);
	if (rv != 0) {
		goto fail;
	}
	rv = nni_aio_init(&ppipe->aio_getq, nni_pair1_pipe_getq_cb, ppipe);
	if (rv != 0) {
		goto fail;
	}
	rv = nni_aio_init(&ppipe->aio_putq, nni_pair1_pipe_putq_cb, ppipe);
	if (rv != 0) {
		goto fail;
	}
	ppipe->npipe = npipe;
	ppipe->psock = psock;
	*pp          = ppipe;
	return (0);

fail:
	nni_pair1_pipe_fini(ppipe);
	return (rv);
}

static void
nni_pair1_pipe_fini(void *arg)
{
	nni_pair1_pipe *ppipe = arg;
	nni_aio_fini(&ppipe->aio_send);
	nni_aio_fini(&ppipe->aio_recv);
	nni_aio_fini(&ppipe->aio_putq);
	nni_aio_fini(&ppipe->aio_getq);
	nni_msgq_fini(ppipe->sendq);
	NNI_FREE_STRUCT(ppipe);
}

static int
nni_pair1_pipe_start(void *arg)
{
	nni_pair1_pipe *ppipe = arg;
	nni_pair1_sock *psock = ppipe->psock;
	uint32_t        id;
	int             rv;

	id = nni_pipe_id(ppipe->npipe);
	rv = nni_idhash_insert(psock->pipes, id, ppipe);
	if (rv != 0) {
		return (rv);
	}
	nni_mtx_lock(&psock->mtx);
	psock->started = 1;
	if (!psock->raw) {
		if (psock->pipe != NULL) {
			nni_mtx_unlock(&psock->mtx);
			nni_idhash_remove(psock->pipes, id);
			return (NNG_EBUSY);
		}
		psock->pipe = ppipe;
	}
	nni_mtx_unlock(&psock->mtx);

	// Schedule a getq.  In raw mode we get on the per pipe
	// sendq, as the socket distributes to us (to allow for
	// polyamorous operation.)  In cooked mode we bypass and
	// get from the upper writeq directly (saving a set of
	// context switches).
	if (psock->raw) {
		nni_msgq_aio_get(ppipe->sendq, &ppipe->aio_getq);
	} else {
		nni_msgq_aio_get(psock->uwq, &ppipe->aio_getq);
	}
	// And the pipe read of course.
	nni_pipe_recv(ppipe->npipe, &ppipe->aio_recv);

	return (0);
}

static void
nni_pair1_pipe_stop(void *arg)
{
	nni_pair1_pipe *ppipe = arg;
	nni_pair1_sock *psock = ppipe->psock;

	nni_msgq_close(ppipe->sendq);
	nni_aio_cancel(&ppipe->aio_send, NNG_ECANCELED);
	nni_aio_cancel(&ppipe->aio_recv, NNG_ECANCELED);
	nni_aio_cancel(&ppipe->aio_putq, NNG_ECANCELED);
	nni_aio_cancel(&ppipe->aio_getq, NNG_ECANCELED);

	nni_mtx_lock(&psock->mtx);
	if (psock->pipe == ppipe) {
		psock->pipe = NULL;
	}
	nni_mtx_unlock(&psock->mtx);

	nni_idhash_remove(psock->pipes, nni_pipe_id(ppipe->npipe));
}

static void
nni_pair1_pipe_recv_cb(void *arg)
{
	nni_pair1_pipe *ppipe = arg;
	nni_pair1_sock *psock = ppipe->psock;
	nni_msg *       msg;
	uint32_t        hdr;
	nni_pipe *      npipe = ppipe->npipe;
	int             rv;

	if (nni_aio_result(&ppipe->aio_recv) != 0) {
		nni_pipe_stop(ppipe->npipe);
		return;
	}

	msg                   = ppipe->aio_recv.a_msg;
	ppipe->aio_recv.a_msg = NULL;

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
	if (hdr >= psock->ttl) {
		nni_msg_free(msg);
		nni_pipe_recv(npipe, &ppipe->aio_recv);
		return;
	}

	// Store the pipe id followed by the hop count.
	if (((rv = nni_msg_header_append_u32(msg, nni_pipe_id(npipe))) != 0) ||
	    ((rv = nni_msg_header_append_u32(msg, hdr)) != 0)) {
		nni_msg_free(msg);
		nni_pipe_recv(npipe, &ppipe->aio_recv);
		return;
	}

	ppipe->aio_putq.a_msg = msg;
	nni_msgq_aio_put(psock->urq, &ppipe->aio_putq);
}

static void
nni_pair1_sock_getq_cb(void *arg)
{
	uint32_t        v;
	nni_pair1_pipe *ppipe;
	nni_pair1_sock *psock = arg;
	nni_msg *       msg;
	uint8_t *       data;

	if (nni_aio_result(&psock->aio_getq) != 0) {
		// Socket closing...
		return;
	}

	msg                   = psock->aio_getq.a_msg;
	psock->aio_getq.a_msg = NULL;

	// We expect two values in the header.  The first is the
	// pipe id, and the second is the hop count.
	if (nni_msg_header_len(msg) != (2 * sizeof(uint32_t))) {
		nni_msg_free(msg);
		nni_msgq_aio_get(psock->uwq, &psock->aio_getq);
		return;
	}

	// Trim off the pipe ID.
	v = nni_msg_header_trim_u32(msg);

	nni_mtx_lock(&psock->mtx);
	if (nni_idhash_find(psock->pipes, v, (void **) &ppipe) != 0) {
		// Pipe not present!
		nni_mtx_unlock(&psock->mtx);
		nni_msg_free(msg);
		nni_msgq_aio_get(psock->uwq, &psock->aio_getq);
		return;
	}

	// Bump the 32-bit value (hop count) in the header.
	data = nni_msg_header(msg);
	NNI_GET32(data, v);
	v++;
	NNI_PUT32(data, v);

	// This should not fail.
	(void) nni_msg_header_prepend_u32(msg, v);

	// Try a non-blocking send.  If this fails we just discard the
	// message.  We have to do this to avoid head-of-line blocking
	// for messages sent to other pipes.  Note that there is some
	// buffering in the sendq.
	if (nni_msgq_tryput(ppipe->sendq, msg) != 0) {
		nni_msg_free(msg);
	}

	nni_mtx_unlock(&psock->mtx);
	nni_msgq_aio_get(psock->uwq, &psock->aio_getq);
}

static void
nni_pair1_pipe_putq_cb(void *arg)
{
	nni_pair1_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_putq) != 0) {
		nni_msg_free(ppipe->aio_putq.a_msg);
		ppipe->aio_putq.a_msg = NULL;
		nni_pipe_stop(ppipe->npipe);
		return;
	}
	nni_pipe_recv(ppipe->npipe, &ppipe->aio_recv);
}

static void
nni_pair1_pipe_getq_cb(void *arg)
{
	nni_pair1_pipe *ppipe = arg;
	nni_pair1_sock *psock = ppipe->psock;
	nni_msg *       msg;
	uint32_t        v;
	uint8_t *       data;

	if (nni_aio_result(&ppipe->aio_getq) != 0) {
		nni_pipe_stop(ppipe->npipe);
		return;
	}

	msg                   = ppipe->aio_getq.a_msg;
	ppipe->aio_getq.a_msg = NULL;

	// Raw mode messages have the header already formed, with
	// a hop count; the pipe id will already have been stripped
	// off by the time we get it.   Cooked mode messages have no
	// header so we have to add one.
	if (psock->raw) {
		// Bump the hop count.
		data = nni_msg_header(msg);

		NNI_GET32(data, v);
		v++;
		NNI_PUT32(data, v);
	} else {
		// Cooked mode.  Stash a hop count.
		nni_msg_trunc_header(msg, nni_msg_header_len(msg));

		if (nni_msg_header_append_u32(msg, 1) != 0) {

			// If we can't, then drop the message and get another.
			nni_msg_free(msg);
			nni_msgq_aio_get(psock->uwq, &ppipe->aio_getq);
			return;
		}
	}

	ppipe->aio_send.a_msg = msg;
	nni_pipe_send(ppipe->npipe, &ppipe->aio_send);
}

static void
nni_pair1_pipe_send_cb(void *arg)
{
	nni_pair1_pipe *ppipe = arg;
	nni_pair1_sock *psock = ppipe->psock;

	if (nni_aio_result(&ppipe->aio_send) != 0) {
		nni_msg_free(ppipe->aio_send.a_msg);
		ppipe->aio_send.a_msg = NULL;
		nni_pipe_stop(ppipe->npipe);
		return;
	}

	// In raw mode, we want to get on the sendq; in
	// cooked we get from upper writeq.
	if (psock->raw) {
		nni_msgq_aio_get(ppipe->sendq, &ppipe->aio_getq);
	} else {
		nni_msgq_aio_get(psock->uwq, &ppipe->aio_getq);
	}
}

static int
nni_pair1_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_pair1_sock *psock = arg;
	int             rv;

	switch (opt) {
	case NNG_OPT_RAW:
		nni_mtx_lock(&psock->mtx);
		if (psock->started) {
			nni_mtx_unlock(&psock->mtx);
			return (NNG_ESTATE);
		}
		rv = nni_setopt_int(&psock->raw, buf, sz, 0, 1);
		nni_mtx_unlock(&psock->mtx);
		break;
	case NNG_OPT_MAXTTL:
		rv = nni_setopt_int(&psock->ttl, buf, sz, 0, 255);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}

static int
nni_pair1_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_pair1_sock *psock = arg;
	int             rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&psock->raw, buf, szp);
		break;
	case NNG_OPT_MAXTTL:
		rv = nni_getopt_int(&psock->ttl, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.

static nni_proto_pipe_ops nni_pair1_pipe_ops = {
	.pipe_init  = nni_pair1_pipe_init,
	.pipe_fini  = nni_pair1_pipe_fini,
	.pipe_start = nni_pair1_pipe_start,
	.pipe_stop  = nni_pair1_pipe_stop,
};

static nni_proto_sock_ops nni_pair1_sock_ops = {
	.sock_init   = nni_pair1_sock_init,
	.sock_fini   = nni_pair1_sock_fini,
	.sock_setopt = nni_pair1_sock_setopt,
	.sock_getopt = nni_pair1_sock_getopt,
};

nni_proto nni_pair1_proto = {
	.proto_self     = NNG_PROTO_PAIR_V1,
	.proto_peer     = NNG_PROTO_PAIR_V1,
	.proto_name     = "pairv1",
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &nni_pair1_sock_ops,
	.proto_pipe_ops = &nni_pair1_pipe_ops,
};
