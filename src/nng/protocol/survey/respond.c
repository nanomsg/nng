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

// Respondent protocol.  The RESPONDENT protocol is the "replier" side of
// the surveyor pattern.  This is useful for building service discovery, or
// voting algorithsm, for example.

typedef struct nni_resp_pipe nni_resp_pipe;
typedef struct nni_resp_sock nni_resp_sock;

static void nni_resp_recv_cb(void *);
static void nni_resp_putq_cb(void *);
static void nni_resp_getq_cb(void *);
static void nni_resp_send_cb(void *);
static void nni_resp_sock_getq_cb(void *);
static void nni_resp_pipe_fini(void *);

// An nni_resp_sock is our per-socket protocol private structure.
struct nni_resp_sock {
	nni_sock *  nsock;
	nni_msgq *  urq;
	nni_msgq *  uwq;
	int         raw;
	int         ttl;
	nni_idhash *pipes;
	char *      btrace;
	size_t      btrace_len;
	nni_aio     aio_getq;
	nni_mtx     mtx;
};

// An nni_resp_pipe is our per-pipe protocol private structure.
struct nni_resp_pipe {
	nni_pipe *     npipe;
	nni_resp_sock *psock;
	uint32_t       id;
	nni_msgq *     sendq;
	nni_aio        aio_getq;
	nni_aio        aio_putq;
	nni_aio        aio_send;
	nni_aio        aio_recv;
};

static void
nni_resp_sock_fini(void *arg)
{
	nni_resp_sock *psock = arg;

	nni_aio_stop(&psock->aio_getq);
	nni_aio_fini(&psock->aio_getq);
	nni_idhash_fini(psock->pipes);
	if (psock->btrace != NULL) {
		nni_free(psock->btrace, psock->btrace_len);
	}
	nni_mtx_fini(&psock->mtx);
	NNI_FREE_STRUCT(psock);
}

static int
nni_resp_sock_init(void **pp, nni_sock *nsock)
{
	nni_resp_sock *psock;
	int            rv;

	if ((psock = NNI_ALLOC_STRUCT(psock)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_idhash_init(&psock->pipes)) != 0) {
		NNI_FREE_STRUCT(psock);
		return (rv);
	}

	psock->ttl        = 8; // Per RFC
	psock->nsock      = nsock;
	psock->raw        = 0;
	psock->btrace     = NULL;
	psock->btrace_len = 0;
	psock->urq        = nni_sock_recvq(nsock);
	psock->uwq        = nni_sock_sendq(nsock);

	nni_mtx_init(&psock->mtx);
	nni_aio_init(&psock->aio_getq, nni_resp_sock_getq_cb, psock);

	*pp = psock;
	nni_sock_senderr(nsock, NNG_ESTATE);
	return (0);
}

static void
nni_resp_sock_open(void *arg)
{
	nni_resp_sock *psock = arg;

	nni_msgq_aio_get(psock->uwq, &psock->aio_getq);
}

static void
nni_resp_sock_close(void *arg)
{
	nni_resp_sock *psock = arg;

	nni_aio_cancel(&psock->aio_getq, NNG_ECLOSED);
}

static int
nni_resp_pipe_init(void **pp, nni_pipe *npipe, void *psock)
{
	nni_resp_pipe *ppipe;
	int            rv;

	if ((ppipe = NNI_ALLOC_STRUCT(ppipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_msgq_init(&ppipe->sendq, 2)) != 0) {
		NNI_FREE_STRUCT(ppipe);
		return (rv);
	}
	nni_aio_init(&ppipe->aio_putq, nni_resp_putq_cb, ppipe);
	nni_aio_init(&ppipe->aio_recv, nni_resp_recv_cb, ppipe);
	nni_aio_init(&ppipe->aio_getq, nni_resp_getq_cb, ppipe);
	nni_aio_init(&ppipe->aio_send, nni_resp_send_cb, ppipe);

	ppipe->npipe = npipe;
	ppipe->psock = psock;
	*pp          = ppipe;
	return (0);
}

static void
nni_resp_pipe_fini(void *arg)
{
	nni_resp_pipe *ppipe = arg;

	nni_aio_fini(&ppipe->aio_putq);
	nni_aio_fini(&ppipe->aio_getq);
	nni_aio_fini(&ppipe->aio_send);
	nni_aio_fini(&ppipe->aio_recv);
	nni_msgq_fini(ppipe->sendq);
	NNI_FREE_STRUCT(ppipe);
}

static int
nni_resp_pipe_start(void *arg)
{
	nni_resp_pipe *ppipe = arg;
	nni_resp_sock *psock = ppipe->psock;
	int            rv;

	ppipe->id = nni_pipe_id(ppipe->npipe);

	nni_mtx_lock(&psock->mtx);
	rv = nni_idhash_insert(psock->pipes, ppipe->id, ppipe);
	nni_mtx_unlock(&psock->mtx);
	if (rv != 0) {
		return (rv);
	}

	nni_pipe_recv(ppipe->npipe, &ppipe->aio_recv);
	nni_msgq_aio_get(ppipe->sendq, &ppipe->aio_getq);

	return (rv);
}

static void
nni_resp_pipe_stop(void *arg)
{
	nni_resp_pipe *ppipe = arg;
	nni_resp_sock *psock = ppipe->psock;

	nni_msgq_close(ppipe->sendq);
	nni_aio_stop(&ppipe->aio_putq);
	nni_aio_stop(&ppipe->aio_getq);
	nni_aio_stop(&ppipe->aio_send);
	nni_aio_stop(&ppipe->aio_recv);

	if (ppipe->id != 0) {
		nni_mtx_lock(&psock->mtx);
		nni_idhash_remove(psock->pipes, ppipe->id);
		nni_mtx_unlock(&psock->mtx);
		ppipe->id = 0;
	}
}

// nni_resp_sock_send watches for messages from the upper write queue,
// extracts the destination pipe, and forwards it to the appropriate
// destination pipe via a separate queue.  This prevents a single bad
// or slow pipe from gumming up the works for the entire socket.s

void
nni_resp_sock_getq_cb(void *arg)
{
	nni_resp_sock *psock = arg;
	nni_msg *      msg;
	uint32_t       id;
	nni_resp_pipe *ppipe;
	int            rv;

	if (nni_aio_result(&psock->aio_getq) != 0) {
		return;
	}
	msg                   = psock->aio_getq.a_msg;
	psock->aio_getq.a_msg = NULL;

	// We yank the outgoing pipe id from the header
	if (nni_msg_header_len(msg) < 4) {
		nni_msg_free(msg);
		// We can't really close down the socket, so just
		// keep going.
		nni_msgq_aio_get(psock->uwq, &psock->aio_getq);
		return;
	}
	id = nni_msg_header_trim_u32(msg);

	nni_mtx_lock(&psock->mtx);
	rv = nni_idhash_find(psock->pipes, id, (void **) &ppipe);

	if (rv != 0) {
		nni_msg_free(msg);
		nni_msgq_aio_get(psock->uwq, &psock->aio_getq);
	} else {
		// Non-blocking put.
		if (nni_msgq_tryput(ppipe->sendq, msg) != 0) {
			nni_msg_free(msg);
		}
	}
	nni_mtx_unlock(&psock->mtx);
}

void
nni_resp_getq_cb(void *arg)
{
	nni_resp_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_getq) != 0) {
		nni_pipe_stop(ppipe->npipe);
		return;
	}

	ppipe->aio_send.a_msg = ppipe->aio_getq.a_msg;
	ppipe->aio_getq.a_msg = NULL;

	nni_pipe_send(ppipe->npipe, &ppipe->aio_send);
}

void
nni_resp_send_cb(void *arg)
{
	nni_resp_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_send) != 0) {
		nni_msg_free(ppipe->aio_send.a_msg);
		ppipe->aio_send.a_msg = NULL;
		nni_pipe_stop(ppipe->npipe);
		return;
	}

	nni_msgq_aio_get(ppipe->sendq, &ppipe->aio_getq);
}

static void
nni_resp_recv_cb(void *arg)
{
	nni_resp_pipe *ppipe = arg;
	nni_resp_sock *psock = ppipe->psock;
	nni_msgq *     urq;
	nni_msg *      msg;
	int            hops;
	int            rv;

	if (nni_aio_result(&ppipe->aio_recv) != 0) {
		goto error;
	}

	urq = nni_sock_recvq(psock->nsock);

	msg                   = ppipe->aio_recv.a_msg;
	ppipe->aio_recv.a_msg = NULL;

	// Store the pipe id in the header, first thing.
	if (nni_msg_header_append_u32(msg, ppipe->id) != 0) {
		nni_msg_free(msg);
		goto error;
	}

	// Move backtrace from body to header
	hops = 0;
	for (;;) {
		int      end = 0;
		uint8_t *body;

		if (hops >= psock->ttl) {
			nni_msg_free(msg);
			goto error;
		}
		if (nni_msg_len(msg) < 4) {
			nni_msg_free(msg);
			goto error;
		}
		body = nni_msg_body(msg);
		end  = (body[0] & 0x80) ? 1 : 0;
		rv   = nni_msg_header_append(msg, body, 4);
		if (rv != 0) {
			nni_msg_free(msg);
			goto error;
		}
		nni_msg_trim(msg, 4);
		if (end) {
			break;
		}
	}

	// Now send it up.
	ppipe->aio_putq.a_msg = msg;
	nni_msgq_aio_put(urq, &ppipe->aio_putq);
	return;

error:
	nni_pipe_stop(ppipe->npipe);
}

static void
nni_resp_putq_cb(void *arg)
{
	nni_resp_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_putq) != 0) {
		nni_msg_free(ppipe->aio_putq.a_msg);
		ppipe->aio_putq.a_msg = NULL;
		nni_pipe_stop(ppipe->npipe);
	}

	nni_pipe_recv(ppipe->npipe, &ppipe->aio_recv);
}

static int
nni_resp_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_resp_sock *psock = arg;
	int            rv    = NNG_ENOTSUP;
	int            oldraw;

	if (opt == nng_optid_maxttl) {
		rv = nni_setopt_int(&psock->ttl, buf, sz, 1, 255);

	} else if (opt == nng_optid_raw) {
		oldraw = psock->raw;
		rv     = nni_setopt_int(&psock->raw, buf, sz, 0, 1);
		if (oldraw != psock->raw) {
			if (!psock->raw) {
				nni_sock_senderr(psock->nsock, 0);
			} else {
				nni_sock_senderr(psock->nsock, NNG_ESTATE);
			}
		}
	}

	return (rv);
}

static int
nni_resp_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_resp_sock *psock = arg;
	int            rv    = NNG_ENOTSUP;

	if (opt == nng_optid_maxttl) {
		rv = nni_getopt_int(&psock->ttl, buf, szp);
	} else if (opt == nng_optid_raw) {
		rv = nni_getopt_int(&psock->raw, buf, szp);
	}
	return (rv);
}

static nni_msg *
nni_resp_sock_sfilter(void *arg, nni_msg *msg)
{
	nni_resp_sock *psock = arg;

	if (psock->raw) {
		return (msg);
	}

	// Cannot send again until a receive is done...
	nni_sock_senderr(psock->nsock, NNG_ESTATE);

	// If we have a stored backtrace, append it to the header...
	// if we don't have a backtrace, discard the message.
	if (psock->btrace == NULL) {
		nni_msg_free(msg);
		return (NULL);
	}

	// drop anything else in the header...
	nni_msg_header_clear(msg);

	if (nni_msg_header_append(msg, psock->btrace, psock->btrace_len) !=
	    0) {
		nni_free(psock->btrace, psock->btrace_len);
		psock->btrace     = NULL;
		psock->btrace_len = 0;
		nni_msg_free(msg);
		return (NULL);
	}

	nni_free(psock->btrace, psock->btrace_len);
	psock->btrace     = NULL;
	psock->btrace_len = 0;
	return (msg);
}

static nni_msg *
nni_resp_sock_rfilter(void *arg, nni_msg *msg)
{
	nni_resp_sock *psock = arg;
	char *         header;
	size_t         len;

	if (psock->raw) {
		return (msg);
	}

	nni_sock_senderr(psock->nsock, 0);
	len    = nni_msg_header_len(msg);
	header = nni_msg_header(msg);
	if (psock->btrace != NULL) {
		nni_free(psock->btrace, psock->btrace_len);
		psock->btrace     = NULL;
		psock->btrace_len = 0;
	}
	if ((psock->btrace = nni_alloc(len)) == NULL) {
		nni_msg_free(msg);
		return (NULL);
	}
	psock->btrace_len = len;
	memcpy(psock->btrace, header, len);
	nni_msg_header_clear(msg);
	return (msg);
}

static nni_proto_pipe_ops nni_resp_pipe_ops = {
	.pipe_init  = nni_resp_pipe_init,
	.pipe_fini  = nni_resp_pipe_fini,
	.pipe_start = nni_resp_pipe_start,
	.pipe_stop  = nni_resp_pipe_stop,
};

static nni_proto_sock_ops nni_resp_sock_ops = {
	.sock_init    = nni_resp_sock_init,
	.sock_fini    = nni_resp_sock_fini,
	.sock_open    = nni_resp_sock_open,
	.sock_close   = nni_resp_sock_close,
	.sock_setopt  = nni_resp_sock_setopt,
	.sock_getopt  = nni_resp_sock_getopt,
	.sock_rfilter = nni_resp_sock_rfilter,
	.sock_sfilter = nni_resp_sock_sfilter,
};

nni_proto nni_respondent_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_RESPONDENT_V0, "respondent" },
	.proto_peer     = { NNG_PROTO_SURVEYOR_V0, "surveyor" },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &nni_resp_sock_ops,
	.proto_pipe_ops = &nni_resp_pipe_ops,
};

int
nng_respondent0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &nni_respondent_proto));
}
