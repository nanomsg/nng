//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

typedef struct nni_resp_pipe	nni_resp_pipe;
typedef struct nni_resp_sock	nni_resp_sock;

// An nni_resp_sock is our per-socket protocol private structure.
struct nni_resp_sock {
	nni_sock *	nsock;
	int		raw;
	int		ttl;
	nni_idhash	pipes;
	char *		btrace;
	size_t		btrace_len;
};

// An nni_resp_pipe is our per-pipe protocol private structure.
struct nni_resp_pipe {
	nni_pipe *	npipe;
	nni_resp_sock * psock;
	nni_msgq *	sendq;
	int		sigclose;
};

static int
nni_resp_sock_init(void **pp, nni_sock *nsock)
{
	nni_resp_sock *psock;
	int rv;

	if ((psock = NNI_ALLOC_STRUCT(psock)) == NULL) {
		return (NNG_ENOMEM);
	}
	psock->ttl = 8;   // Per RFC
	psock->nsock = nsock;
	psock->raw = 0;
	psock->btrace = NULL;
	psock->btrace_len = 0;
	if ((rv = nni_idhash_init(&psock->pipes)) != 0) {
		NNI_FREE_STRUCT(psock);
		return (rv);
	}

	*pp = psock;
	nni_sock_senderr(nsock, NNG_ESTATE);
	return (0);
}


static void
nni_resp_sock_fini(void *arg)
{
	nni_resp_sock *psock = arg;

	if (psock != NULL) {
		nni_idhash_fini(&psock->pipes);
		if (psock->btrace != NULL) {
			nni_free(psock->btrace, psock->btrace_len);
		}
		NNI_FREE_STRUCT(psock);
	}
}


static int
nni_resp_pipe_init(void **pp, nni_pipe *npipe, void *psock)
{
	nni_resp_pipe *ppipe;
	int rv;

	if ((ppipe = NNI_ALLOC_STRUCT(ppipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_msgq_init(&ppipe->sendq, 2)) != 0) {
		NNI_FREE_STRUCT(ppipe);
		return (rv);
	}
	ppipe->npipe = npipe;
	ppipe->psock = psock;
	ppipe->sigclose = 0;
	*pp = ppipe;
	return (0);
}


static void
nni_resp_pipe_fini(void *arg)
{
	nni_resp_pipe *ppipe = arg;

	if (ppipe != NULL) {
		nni_msgq_fini(ppipe->sendq);
		NNI_FREE_STRUCT(ppipe);
	}
}


static int
nni_resp_pipe_add(void *arg)
{
	nni_resp_pipe *ppipe = arg;
	nni_resp_sock *psock = ppipe->psock;
	int rv;

	rv = nni_idhash_insert(&psock->pipes, nni_pipe_id(ppipe->npipe), ppipe);
	return (rv);
}


static void
nni_resp_pipe_rem(void *arg)
{
	nni_resp_pipe *ppipe = arg;
	nni_resp_sock *psock = ppipe->psock;

	nni_idhash_remove(&psock->pipes, nni_pipe_id(ppipe->npipe));
}


// nni_resp_sock_send watches for messages from the upper write queue,
// extracts the destination pipe, and forwards it to the appropriate
// destination pipe via a separate queue.  This prevents a single bad
// or slow pipe from gumming up the works for the entire socket.
static void
nni_resp_sock_send(void *arg)
{
	nni_resp_sock *psock = arg;
	nni_msgq *uwq = nni_sock_sendq(psock->nsock);
	nni_mtx *mx = nni_sock_mtx(psock->nsock);
	nni_msg *msg;

	for (;;) {
		uint8_t *header;
		uint32_t id;
		nni_resp_pipe *ppipe;
		int rv;

		if ((rv = nni_msgq_get(uwq, &msg)) != 0) {
			break;
		}
		// We yank the outgoing pipe id from the header
		if (nni_msg_header_len(msg) < 4) {
			nni_msg_free(msg);
			continue;
		}
		header = nni_msg_header(msg);
		NNI_GET32(header, id);
		nni_msg_trim_header(msg, 4);

		nni_mtx_lock(mx);
		if (nni_idhash_find(&psock->pipes, id, (void **) &ppipe) != 0) {
			nni_mtx_unlock(mx);
			nni_msg_free(msg);
			continue;
		}
		// Try a non-blocking put to the lower writer.
		rv = nni_msgq_put_until(ppipe->sendq, msg, NNI_TIME_ZERO);
		if (rv != 0) {
			// message queue is full, we have no choice but
			// to drop it.  This should not happen under normal
			// circumstances.
			nni_msg_free(msg);
		}
		nni_mtx_unlock(mx);
	}
}


static void
nni_resp_pipe_send(void *arg)
{
	nni_resp_pipe *ppipe = arg;
	nni_resp_sock *psock = ppipe->psock;
	nni_pipe *npipe = ppipe->npipe;
	nni_msgq *sendq = ppipe->sendq;
	nni_msg *msg;
	int rv;

	for (;;) {
		rv = nni_msgq_get_sig(sendq, &msg, &ppipe->sigclose);
		if (rv != 0) {
			break;
		}

		rv = nni_pipe_send(npipe, msg);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgq_signal(nni_sock_recvq(psock->nsock), &ppipe->sigclose);
	nni_pipe_close(npipe);
}


static void
nni_resp_pipe_recv(void *arg)
{
	nni_resp_pipe *ppipe = arg;
	nni_resp_sock *psock = ppipe->psock;
	nni_msgq *urq = nni_sock_recvq(psock->nsock);
	nni_pipe *npipe = ppipe->npipe;
	nni_msg *msg;
	int rv;
	uint8_t idbuf[4];
	uint32_t id = nni_pipe_id(npipe);

	NNI_PUT32(idbuf, id);

	for (;;) {
		uint8_t *body;
		int hops;

again:
		rv = nni_pipe_recv(npipe, &msg);
		if (rv != 0) {
			break;
		}
		// Store the pipe id in the header, first thing.
		rv = nni_msg_append_header(msg, idbuf, 4);
		if (rv != 0) {
			nni_msg_free(msg);
			continue;
		}

		// Move backtrace from body to header
		hops = 0;
		for (;;) {
			int end = 0;
			if (hops >= psock->ttl) {
				nni_msg_free(msg);
				goto again;
			}
			if (nni_msg_len(msg) < 4) {
				nni_msg_free(msg);
				goto again;
			}
			body = nni_msg_body(msg);
			end = (body[0] & 0x80) ? 1 : 0;
			rv = nni_msg_append_header(msg, body, 4);
			if (rv != 0) {
				nni_msg_free(msg);
				goto again;
			}
			nni_msg_trim(msg, 4);
			if (end) {
				break;
			}
		}

		// Now send it up.
		rv = nni_msgq_put_sig(urq, msg, &ppipe->sigclose);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgq_signal(nni_sock_sendq(psock->nsock), &ppipe->sigclose);
	nni_msgq_signal(ppipe->sendq, &ppipe->sigclose);
	nni_pipe_close(npipe);
}


static int
nni_resp_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_resp_sock *psock = arg;
	int rv;
	int oldraw;

	switch (opt) {
	case NNG_OPT_MAXTTL:
		rv = nni_setopt_int(&psock->ttl, buf, sz, 1, 255);
		break;
	case NNG_OPT_RAW:
		oldraw = psock->raw;
		rv = nni_setopt_int(&psock->raw, buf, sz, 0, 1);
		if (oldraw != psock->raw) {
			if (!psock->raw) {
				nni_sock_senderr(psock->nsock, 0);
			} else {
				nni_sock_senderr(psock->nsock, NNG_ESTATE);
			}
		}
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_resp_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_resp_sock *psock = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_MAXTTL:
		rv = nni_getopt_int(&psock->ttl, buf, szp);
		break;
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&psock->raw, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
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
	nni_msg_trunc_header(msg, nni_msg_header_len(msg));

	if (nni_msg_append_header(msg, psock->btrace, psock->btrace_len) != 0) {
		nni_free(psock->btrace, psock->btrace_len);
		psock->btrace = NULL;
		psock->btrace_len = 0;
		nni_msg_free(msg);
		return (NULL);
	}

	nni_free(psock->btrace, psock->btrace_len);
	psock->btrace = NULL;
	psock->btrace_len = 0;
	return (msg);
}


static nni_msg *
nni_resp_sock_rfilter(void *arg, nni_msg *msg)
{
	nni_resp_sock *psock = arg;
	char *header;
	size_t len;

	if (psock->raw) {
		return (msg);
	}

	nni_sock_senderr(psock->nsock, 0);
	len = nni_msg_header_len(msg);
	header = nni_msg_header(msg);
	if (psock->btrace != NULL) {
		nni_free(psock->btrace, psock->btrace_len);
		psock->btrace = NULL;
		psock->btrace_len = 0;
	}
	if ((psock->btrace = nni_alloc(len)) == NULL) {
		nni_msg_free(msg);
		return (NULL);
	}
	psock->btrace_len = len;
	memcpy(psock->btrace, header, len);
	nni_msg_trunc_header(msg, len);
	return (msg);
}


static nni_proto_pipe_ops nni_resp_pipe_ops = {
	.pipe_init	= nni_resp_pipe_init,
	.pipe_fini	= nni_resp_pipe_fini,
	.pipe_add	= nni_resp_pipe_add,
	.pipe_rem	= nni_resp_pipe_rem,
	.pipe_worker	= { nni_resp_pipe_send,
			    nni_resp_pipe_recv },
};

static nni_proto_sock_ops nni_resp_sock_ops = {
	.sock_init	= nni_resp_sock_init,
	.sock_fini	= nni_resp_sock_fini,
	.sock_close	= NULL,
	.sock_setopt	= nni_resp_sock_setopt,
	.sock_getopt	= nni_resp_sock_getopt,
	.sock_rfilter	= nni_resp_sock_rfilter,
	.sock_sfilter	= nni_resp_sock_sfilter,
	.sock_worker	= { nni_resp_sock_send },
};

nni_proto nni_respondent_proto = {
	.proto_self	= NNG_PROTO_RESPONDENT,
	.proto_peer	= NNG_PROTO_SURVEYOR,
	.proto_name	= "respondent",
	.proto_flags	= NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &nni_resp_sock_ops,
	.proto_pipe_ops = &nni_resp_pipe_ops,
};
