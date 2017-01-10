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

// An nni_surv_sock is our per-socket protocol private structure.
struct nni_surv_sock {
	nni_sock *	nsock;
	nni_cv		cv;
	nni_duration	survtime;
	nni_time	expire;
	int		raw;
	int		closing;
	uint32_t	nextid;         // next id
	uint8_t		survid[4];      // outstanding request ID (big endian)
	nni_list	pipes;
};

// An nni_surv_pipe is our per-pipe protocol private structure.
struct nni_surv_pipe {
	nni_pipe *	npipe;
	nni_surv_sock * psock;
	nni_msgq *	sendq;
	nni_list_node	node;
	int		sigclose;
};

static int
nni_surv_sock_init(void **sp, nni_sock *nsock)
{
	nni_surv_sock *psock;
	int rv;

	if ((psock = NNI_ALLOC_STRUCT(psock)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_cv_init(&psock->cv, nni_sock_mtx(nsock))) != 0) {
		NNI_FREE_STRUCT(psock);
		return (rv);
	}
	NNI_LIST_INIT(&psock->pipes, nni_surv_pipe, node);
	psock->nextid = nni_random();
	psock->nsock = nsock;
	psock->raw = 0;
	psock->survtime = NNI_SECOND * 60;
	psock->expire = NNI_TIME_ZERO;

	*sp = psock;
	nni_sock_recverr(nsock, NNG_ESTATE);
	return (0);
}


static void
nni_surv_sock_close(void *arg)
{
	nni_surv_sock *psock = arg;

	// Shut down the resender.
	psock->closing = 1;
	nni_cv_wake(&psock->cv);
}


static void
nni_surv_sock_fini(void *arg)
{
	nni_surv_sock *psock = arg;

	nni_cv_fini(&psock->cv);
	NNI_FREE_STRUCT(psock);
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
nni_surv_pipe_fini(void *arg)
{
	nni_surv_pipe *sp = arg;

	NNI_FREE_STRUCT(sp);
}


static int
nni_surv_pipe_add(void *arg)
{
	nni_surv_pipe *ppipe = arg;
	nni_surv_sock *psock = ppipe->psock;

	nni_list_append(&psock->pipes, ppipe);
	return (0);
}


static void
nni_surv_pipe_rem(void *arg)
{
	nni_surv_pipe *ppipe = arg;
	nni_surv_sock *psock = ppipe->psock;

	nni_list_remove(&psock->pipes, ppipe);
}


static void
nni_surv_pipe_sender(void *arg)
{
	nni_surv_pipe *ppipe = arg;
	nni_surv_sock *psock = ppipe->psock;
	nni_pipe *npipe = ppipe->npipe;
	nni_msgq *uwq = ppipe->sendq;
	nni_msgq *urq = nni_sock_recvq(psock->nsock);
	nni_mtx *mx = nni_sock_mtx(psock->nsock);
	nni_msg *msg;
	int rv;

	for (;;) {
		rv = nni_msgq_get_sig(uwq, &msg, &ppipe->sigclose);
		if (rv != 0) {
			break;
		}
		rv = nni_pipe_send(npipe, msg);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgq_signal(urq, &ppipe->sigclose);
	nni_pipe_close(npipe);
}


static void
nni_surv_pipe_receiver(void *arg)
{
	nni_surv_pipe *ppipe = arg;
	nni_surv_sock *psock = ppipe->psock;
	nni_msgq *urq = nni_sock_recvq(psock->nsock);
	nni_msgq *uwq = nni_sock_sendq(psock->nsock);
	nni_pipe *npipe = ppipe->npipe;
	nni_msg *msg;
	int rv;

	for (;;) {
		rv = nni_pipe_recv(npipe, &msg);
		if (rv != 0) {
			break;
		}
		// We yank 4 bytes of body, and move them to the header.
		if (nni_msg_len(msg) < 4) {
			// Not enough data, just toss it.
			nni_msg_free(msg);
			continue;
		}
		if (nni_msg_append_header(msg, nni_msg_body(msg), 4) != 0) {
			// Should be NNG_ENOMEM
			nni_msg_free(msg);
			continue;
		}
		if (nni_msg_trim(msg, 4) != 0) {
			// This should never happen - could be an assert.
			nni_panic("Failed to trim SURV header from body");
		}
		rv = nni_msgq_put_sig(urq, msg, &ppipe->sigclose);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgq_signal(uwq, &ppipe->sigclose);
	nni_msgq_signal(ppipe->sendq, &ppipe->sigclose);
	nni_pipe_close(npipe);
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
			psock->expire = NNI_TIME_NEVER;
			nni_cv_wake(&psock->cv);
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
nni_surv_sock_sender(void *arg)
{
	nni_surv_sock *psock = arg;
	nni_msgq *uwq = nni_sock_sendq(psock->nsock);
	nni_mtx *mx = nni_sock_mtx(psock->nsock);
	nni_msg *msg, *dup;

	for (;;) {
		nni_surv_pipe *ppipe;
		nni_surv_pipe *last;
		int rv;

		if ((rv = nni_msgq_get(uwq, &msg)) != 0) {
			break;
		}

		nni_mtx_lock(mx);
		last = nni_list_last(&psock->pipes);
		NNI_LIST_FOREACH (&psock->pipes, ppipe) {
			if (ppipe != last) {
				rv = nni_msg_dup(&dup, msg);
				if (rv != 0) {
					continue;
				}
			} else {
				dup = msg;
			}
			if ((rv = nni_msgq_tryput(ppipe->sendq, dup)) != 0) {
				nni_msg_free(dup);
			}
		}
		nni_mtx_unlock(mx);

		if (last == NULL) {
			nni_msg_free(msg);
		}
	}
}


static void
nni_surv_sock_timeout(void *arg)
{
	nni_surv_sock *psock = arg;
	nni_mtx *mx = nni_sock_mtx(psock->nsock);
	nni_msgq *urq = nni_sock_recvq(psock->nsock);

	nni_mtx_lock(mx);
	for (;;) {
		if (psock->closing) {
			nni_mtx_unlock(mx);
			return;
		}
		if (nni_clock() > psock->expire) {
			// Set the expiration ~forever
			psock->expire = NNI_TIME_NEVER;
			// Survey IDs *always* have the high order bit set,
			// so zeroing means that nothing can match.
			memset(psock->survid, 0, sizeof (psock->survid));
			nni_sock_recverr(psock->nsock, NNG_ESTATE);
			nni_msgq_set_get_error(urq, NNG_ETIMEDOUT);
		}
		nni_cv_until(&psock->cv, psock->expire);
	}
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
	nni_cv_wake(&psock->cv);

	// Clear the error condition.
	nni_sock_recverr(psock->nsock, 0);
	nni_msgq_set_get_error(nni_sock_recvq(psock->nsock), 0);

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
	.pipe_add	= nni_surv_pipe_add,
	.pipe_rem	= nni_surv_pipe_rem,
	.pipe_worker	= { nni_surv_pipe_sender,
			    nni_surv_pipe_receiver }
};

static nni_proto_sock_ops nni_surv_sock_ops = {
	.sock_init	= nni_surv_sock_init,
	.sock_fini	= nni_surv_sock_fini,
	.sock_close	= nni_surv_sock_close,
	.sock_setopt	= nni_surv_sock_setopt,
	.sock_getopt	= nni_surv_sock_getopt,
	.sock_rfilter	= nni_surv_sock_rfilter,
	.sock_sfilter	= nni_surv_sock_sfilter,
	.sock_worker	= { nni_surv_sock_sender,
			    nni_surv_sock_timeout }
};

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
nni_proto nni_surveyor_proto = {
	.proto_self	= NNG_PROTO_SURVEYOR,
	.proto_peer	= NNG_PROTO_RESPONDENT,
	.proto_name	= "surveyor",
	.proto_sock_ops = &nni_surv_sock_ops,
	.proto_pipe_ops = &nni_surv_pipe_ops,
};
