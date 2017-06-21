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

// Surveyor protocol.  The SURVEYOR protocol is the "survey" side of the
// survey pattern.  This is useful for building service discovery, voting, etc.

typedef struct nni_surv_pipe	nni_surv_pipe;
typedef struct nni_surv_sock	nni_surv_sock;

static void nni_surv_sock_getq_cb(void *);
static void nni_surv_getq_cb(void *);
static void nni_surv_putq_cb(void *);
static void nni_surv_send_cb(void *);
static void nni_surv_recv_cb(void *);
static void nni_surv_timeout(void *);

// An nni_surv_sock is our per-socket protocol private structure.
struct nni_surv_sock {
	nni_sock *	nsock;
	nni_duration	survtime;
	nni_time	expire;
	int		raw;
	int		closing;
	uint32_t	nextid;         // next id
	uint8_t		survid[4];      // outstanding request ID (big endian)
	nni_list	pipes;
	nni_aio		aio_getq;
	nni_timer_node	timer;
	nni_msgq *	uwq;
	nni_msgq *	urq;
};

// An nni_surv_pipe is our per-pipe protocol private structure.
struct nni_surv_pipe {
	nni_pipe *	npipe;
	nni_surv_sock * psock;
	nni_msgq *	sendq;
	nni_list_node	node;
	nni_aio		aio_getq;
	nni_aio		aio_putq;
	nni_aio		aio_send;
	nni_aio		aio_recv;
	int		running;
};

static int
nni_surv_sock_init(void **sp, nni_sock *nsock)
{
	nni_surv_sock *psock;
	int rv;

	if ((psock = NNI_ALLOC_STRUCT(psock)) == NULL) {
		return (NNG_ENOMEM);
	}
	rv = nni_aio_init(&psock->aio_getq, nni_surv_sock_getq_cb, psock);
	if (rv != 0) {
		NNI_FREE_STRUCT(psock);
		return (rv);
	}
	NNI_LIST_INIT(&psock->pipes, nni_surv_pipe, node);
	nni_timer_init(&psock->timer, nni_surv_timeout, psock);

	psock->nextid = nni_random();
	psock->nsock = nsock;
	psock->raw = 0;
	psock->survtime = NNI_SECOND * 60;
	psock->expire = NNI_TIME_ZERO;
	psock->uwq = nni_sock_sendq(nsock);
	psock->urq = nni_sock_recvq(nsock);

	*sp = psock;
	nni_sock_recverr(nsock, NNG_ESTATE);
	return (0);
}


static void
nni_surv_sock_open(void *arg)
{
	nni_surv_sock *psock = arg;

	nni_msgq_aio_get(psock->uwq, &psock->aio_getq);
}


static void
nni_surv_sock_close(void *arg)
{
	nni_surv_sock *psock = arg;

	nni_timer_cancel(&psock->timer);
	nni_msgq_aio_cancel(psock->uwq, &psock->aio_getq);
}


static void
nni_surv_sock_fini(void *arg)
{
	nni_surv_sock *psock = arg;

	nni_aio_fini(&psock->aio_getq);
	NNI_FREE_STRUCT(psock);
}


static void
nni_surv_pipe_fini(void *arg)
{
	nni_surv_pipe *ppipe = arg;

	nni_aio_fini(&ppipe->aio_getq);
	nni_aio_fini(&ppipe->aio_send);
	nni_aio_fini(&ppipe->aio_recv);
	nni_aio_fini(&ppipe->aio_putq);
	nni_msgq_fini(ppipe->sendq);
	NNI_FREE_STRUCT(ppipe);
}


static int
nni_surv_pipe_init(void **pp, nni_pipe *npipe, void *psock)
{
	nni_surv_pipe *ppipe;
	int rv;

	if ((ppipe = NNI_ALLOC_STRUCT(ppipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	// This depth could be tunable.
	if ((rv = nni_msgq_init(&ppipe->sendq, 16)) != 0) {
		goto failed;
	}
	rv = nni_aio_init(&ppipe->aio_getq, nni_surv_getq_cb, ppipe);
	if (rv != 0) {
		goto failed;
	}
	rv = nni_aio_init(&ppipe->aio_putq, nni_surv_putq_cb, ppipe);
	if (rv != 0) {
		goto failed;
	}
	rv = nni_aio_init(&ppipe->aio_send, nni_surv_send_cb, ppipe);
	if (rv != 0) {
		goto failed;
	}
	rv = nni_aio_init(&ppipe->aio_recv, nni_surv_recv_cb, ppipe);
	if (rv != 0) {
		goto failed;
	}
	ppipe->npipe = npipe;
	ppipe->psock = psock;
	*pp = ppipe;
	return (0);

failed:
	nni_surv_pipe_fini(ppipe);
	return (rv);
}


static int
nni_surv_pipe_start(void *arg)
{
	nni_surv_pipe *ppipe = arg;
	nni_surv_sock *psock = ppipe->psock;

	nni_list_append(&psock->pipes, ppipe);

	nni_pipe_hold(ppipe->npipe);
	nni_msgq_aio_get(ppipe->sendq, &ppipe->aio_getq);

	nni_pipe_hold(ppipe->npipe);
	nni_pipe_aio_recv(ppipe->npipe, &ppipe->aio_recv);
	ppipe->running = 1;
	return (0);
}


static void
nni_surv_pipe_stop(void *arg)
{
	nni_surv_pipe *ppipe = arg;
	nni_surv_sock *psock = ppipe->psock;

	if (ppipe->running) {
		nni_list_remove(&psock->pipes, ppipe);
		nni_msgq_close(ppipe->sendq);
		nni_msgq_aio_cancel(psock->urq, &ppipe->aio_putq);
	}
}


static void
nni_surv_getq_cb(void *arg)
{
	nni_surv_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_getq) != 0) {
		nni_pipe_close(ppipe->npipe);
		nni_pipe_rele(ppipe->npipe);
		return;
	}

	ppipe->aio_send.a_msg = ppipe->aio_getq.a_msg;
	ppipe->aio_getq.a_msg = NULL;

	nni_pipe_aio_send(ppipe->npipe, &ppipe->aio_send);
}


static void
nni_surv_send_cb(void *arg)
{
	nni_surv_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_send) != 0) {
		nni_msg_free(ppipe->aio_send.a_msg);
		ppipe->aio_send.a_msg = NULL;
		nni_pipe_close(ppipe->npipe);
		nni_pipe_rele(ppipe->npipe);
		return;
	}

	nni_msgq_aio_get(ppipe->psock->uwq, &ppipe->aio_getq);
}


static void
nni_surv_putq_cb(void *arg)
{
	nni_surv_pipe *ppipe = arg;

	if (nni_aio_result(&ppipe->aio_putq) != 0) {
		nni_msg_free(ppipe->aio_putq.a_msg);
		ppipe->aio_putq.a_msg = NULL;
		nni_pipe_close(ppipe->npipe);
		nni_pipe_rele(ppipe->npipe);
		return;
	}

	nni_pipe_aio_recv(ppipe->npipe, &ppipe->aio_recv);
}


static void
nni_surv_recv_cb(void *arg)
{
	nni_surv_pipe *ppipe = arg;
	nni_msg *msg;
	int rv;

	if (nni_aio_result(&ppipe->aio_recv) != 0) {
		goto failed;
	}

	msg = ppipe->aio_recv.a_msg;
	ppipe->aio_recv.a_msg = NULL;

	// We yank 4 bytes of body, and move them to the header.
	if (nni_msg_len(msg) < 4) {
		// Not enough data, just toss it.
		nni_msg_free(msg);
		goto failed;
	}
	if (nni_msg_append_header(msg, nni_msg_body(msg), 4) != 0) {
		// Should be NNG_ENOMEM
		nni_msg_free(msg);
		goto failed;
	}
	if (nni_msg_trim(msg, 4) != 0) {
		// This should never happen - could be an assert.
		nni_msg_free(msg);
		goto failed;
	}
	ppipe->aio_putq.a_msg = msg;
	nni_msgq_aio_put(ppipe->psock->urq, &ppipe->aio_putq);
	return;

failed:
	nni_pipe_close(ppipe->npipe);
	nni_pipe_rele(ppipe->npipe);
}


static int
nni_surv_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_surv_sock *psock = arg;
	int rv;
	int oldraw;

	switch (opt) {
	case NNG_OPT_SURVEYTIME:
		rv = nni_setopt_duration(&psock->survtime, buf, sz);
		break;
	case NNG_OPT_RAW:
		oldraw = psock->raw;
		rv = nni_setopt_int(&psock->raw, buf, sz, 0, 1);
		if (oldraw != psock->raw) {
			if (psock->raw) {
				nni_sock_recverr(psock->nsock, 0);
			} else {
				nni_sock_recverr(psock->nsock, NNG_ESTATE);
			}
			memset(psock->survid, 0, sizeof (psock->survid));
			nni_timer_cancel(&psock->timer);
		}
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_surv_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_surv_sock *psock = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_SURVEYTIME:
		rv = nni_getopt_duration(&psock->survtime, buf, szp);
		break;
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&psock->raw, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static void
nni_surv_sock_getq_cb(void *arg)
{
	nni_surv_sock *psock = arg;
	nni_surv_pipe *ppipe;
	nni_surv_pipe *last;
	nni_msg *msg, *dup;

	if (nni_aio_result(&psock->aio_getq) != 0) {
		// Should be NNG_ECLOSED.
		return;
	}
	msg = psock->aio_getq.a_msg;
	psock->aio_getq.a_msg = NULL;

	nni_sock_lock(psock->nsock);
	last = nni_list_last(&psock->pipes);
	NNI_LIST_FOREACH (&psock->pipes, ppipe) {
		if (ppipe != last) {
			if (nni_msg_dup(&dup, msg) != 0) {
				continue;
			}
		} else {
			dup = msg;
		}
		if (nni_msgq_tryput(ppipe->sendq, dup) != 0) {
			nni_msg_free(dup);
		}
	}
	nni_sock_unlock(psock->nsock);

	if (last == NULL) {
		// If there were no pipes to send on, just toss the message.
		nni_msg_free(msg);
	}
}


static void
nni_surv_timeout(void *arg)
{
	nni_surv_sock *psock = arg;

	nni_sock_lock(psock->nsock);
	memset(psock->survid, 0, sizeof (psock->survid));
	nni_sock_recverr(psock->nsock, NNG_ESTATE);
	nni_msgq_set_get_error(psock->urq, NNG_ETIMEDOUT);
	nni_sock_unlock(psock->nsock);
}


static nni_msg *
nni_surv_sock_sfilter(void *arg, nni_msg *msg)
{
	nni_surv_sock *psock = arg;
	uint32_t id;

	if (psock->raw) {
		// No automatic retry, and the request ID must
		// be in the header coming down.
		return (msg);
	}

	// Generate a new request ID.  We always set the high
	// order bit so that the peer can locate the end of the
	// backtrace.  (Pipe IDs have the high order bit clear.)
	id = (psock->nextid++) | 0x80000000u;

	// Survey ID is in big endian format.
	NNI_PUT32(psock->survid, id);

	if (nni_msg_append_header(msg, psock->survid, 4) != 0) {
		// Should be ENOMEM.
		nni_msg_free(msg);
		return (NULL);
	}

	// If another message is there, this cancels it.  We move the
	// survey expiration out.  The timeout thread will wake up in
	// the wake below, and reschedule itself appropriately.
	psock->expire = nni_clock() + psock->survtime;
	nni_timer_schedule(&psock->timer, psock->expire);

	// Clear the error condition.
	nni_sock_recverr(psock->nsock, 0);
	//nni_msgq_set_get_error(nni_sock_recvq(psock->nsock), 0);

	return (msg);
}


static nni_msg *
nni_surv_sock_rfilter(void *arg, nni_msg *msg)
{
	nni_surv_sock *ssock = arg;

	if (ssock->raw) {
		// Pass it unmolested
		return (msg);
	}

	if (nni_msg_header_len(msg) < 4) {
		nni_msg_free(msg);
		return (NULL);
	}

	if (memcmp(nni_msg_header(msg), ssock->survid, 4) != 0) {
		// Wrong request id
		nni_msg_free(msg);
		return (NULL);
	}
	// Prune the survey ID.
	nni_msg_trim_header(msg, 4);

	return (msg);
}


static nni_proto_pipe_ops nni_surv_pipe_ops = {
	.pipe_init	= nni_surv_pipe_init,
	.pipe_fini	= nni_surv_pipe_fini,
	.pipe_start	= nni_surv_pipe_start,
	.pipe_stop	= nni_surv_pipe_stop,
};

static nni_proto_sock_ops nni_surv_sock_ops = {
	.sock_init	= nni_surv_sock_init,
	.sock_fini	= nni_surv_sock_fini,
	.sock_open	= nni_surv_sock_open,
	.sock_close	= nni_surv_sock_close,
	.sock_setopt	= nni_surv_sock_setopt,
	.sock_getopt	= nni_surv_sock_getopt,
	.sock_rfilter	= nni_surv_sock_rfilter,
	.sock_sfilter	= nni_surv_sock_sfilter,
};

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
nni_proto nni_surveyor_proto = {
	.proto_self	= NNG_PROTO_SURVEYOR,
	.proto_peer	= NNG_PROTO_RESPONDENT,
	.proto_name	= "surveyor",
	.proto_flags	= NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &nni_surv_sock_ops,
	.proto_pipe_ops = &nni_surv_pipe_ops,
};
