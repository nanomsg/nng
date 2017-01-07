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

// Push protocol.  The PUSH protocol is the "write" side of a pipeline.
// Push distributes fairly, or tries to, by giving messages in round-robin
// order.

typedef struct nni_push_pipe	nni_push_pipe;
typedef struct nni_push_sock	nni_push_sock;

// An nni_push_sock is our per-socket protocol private structure.
struct nni_push_sock {
	nni_mtx		mx;
	nni_cv		cv;
	nni_msgq *	uwq;
	nni_thr		sender;
	int		raw;
	int		closing;
	int		wantw;
	nni_list	pipes;
	nni_push_pipe * nextpipe;
	int		npipes;
};

// An nni_push_pipe is our per-pipe protocol private structure.
struct nni_push_pipe {
	nni_pipe *	pipe;
	nni_push_sock * push;
	nni_msgq *	mq;
	int		sigclose;
	nni_list_node	node;
};

static void nni_push_rrdist(void *);

static int
nni_push_init(void **pushp, nni_sock *sock)
{
	nni_push_sock *push;
	int rv;

	if ((push = NNI_ALLOC_STRUCT(push)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&push->mx)) != 0) {
		NNI_FREE_STRUCT(push);
		return (rv);
	}
	if ((rv = nni_cv_init(&push->cv, &push->mx)) != 0) {
		nni_mtx_fini(&push->mx);
		NNI_FREE_STRUCT(push);
		return (rv);
	}
	NNI_LIST_INIT(&push->pipes, nni_push_pipe, node);
	push->raw = 0;
	push->npipes = 0;
	push->wantw = 0;
	push->uwq = nni_sock_sendq(sock);
	*pushp = push;
	nni_sock_recverr(sock, NNG_ENOTSUP);
	rv = nni_thr_init(&push->sender, nni_push_rrdist, push);
	if (rv != 0) {
		nni_cv_fini(&push->cv);
		nni_mtx_fini(&push->mx);
		NNI_FREE_STRUCT(push);
		return (rv);
	}
	nni_thr_run(&push->sender);
	return (0);
}


static void
nni_push_fini(void *arg)
{
	nni_push_sock *push = arg;

	// Shut down the resender.  We request it to exit by clearing
	// its old value, then kick it.
	nni_mtx_lock(&push->mx);
	push->closing = 1;
	nni_cv_wake(&push->cv);
	nni_mtx_unlock(&push->mx);

	nni_thr_fini(&push->sender);
	nni_cv_fini(&push->cv);
	nni_mtx_fini(&push->mx);
	NNI_FREE_STRUCT(push);
}


static int
nni_push_pipe_init(void **ppp, nni_pipe *pipe, void *psock)
{
	nni_push_pipe *pp;
	int rv;

	if ((pp = NNI_ALLOC_STRUCT(pp)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_msgq_init(&pp->mq, 0)) != 0) {
		NNI_FREE_STRUCT(pp);
		return (rv);
	}
	NNI_LIST_NODE_INIT(&pp->node);
	pp->pipe = pipe;
	pp->sigclose = 0;
	pp->push = psock;
	*ppp = pp;
	return (0);
}


static void
nni_push_pipe_fini(void *arg)
{
	nni_push_pipe *pp = arg;

	nni_msgq_fini(pp->mq);
	NNI_FREE_STRUCT(pp);
}


static int
nni_push_pipe_add(void *arg)
{
	nni_push_pipe *pp = arg;
	nni_push_sock *push = pp->push;

	if (nni_pipe_peer(pp->pipe) != NNG_PROTO_PULL) {
		return (NNG_EPROTO);
	}
	// Wake the sender since we have a new pipe.
	nni_mtx_lock(&push->mx);
	if (push->nextpipe) {
		// Inject us right before the next pipe, so that we're next.
		nni_list_insert_before(&push->pipes, pp, push);
	} else {
		nni_list_append(&push->pipes, pp);
	}
	// Wake the top sender, as we can accept a job.
	push->npipes++;
	nni_cv_wake(&push->cv);
	nni_mtx_unlock(&push->mx);
	return (0);
}


static void
nni_push_pipe_rem(void *arg)
{
	nni_push_pipe *pp = arg;
	nni_push_sock *push = pp->push;

	nni_mtx_lock(&push->mx);
	if (pp == push->nextpipe) {
		push->nextpipe = nni_list_next(&push->pipes, pp);
	}
	push->npipes--;
	nni_list_remove(&push->pipes, pp);
	nni_mtx_unlock(&push->mx);
}


static void
nni_push_pipe_send(void *arg)
{
	nni_push_pipe *pp = arg;
	nni_push_sock *push = pp->push;
	nni_msg *msg;

	for (;;) {
		if (nni_msgq_get_sig(pp->mq, &msg, &pp->sigclose) != 0) {
			break;
		}
		nni_mtx_lock(&push->mx);
		if (push->wantw) {
			nni_cv_wake(&push->cv);
		}
		nni_mtx_unlock(&push->mx);
		if (nni_pipe_send(pp->pipe, msg) != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_pipe_close(pp->pipe);
}


static void
nni_push_pipe_recv(void *arg)
{
	nni_push_pipe *pp = arg;
	nni_msg *msg;

	for (;;) {
		if (nni_pipe_recv(pp->pipe, &msg) != 0) {
			break;
		}
		nni_msg_free(msg);
	}
	nni_msgq_signal(pp->mq, &pp->sigclose);
	nni_pipe_close(pp->pipe);
}


static int
nni_push_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_push_sock *push = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		nni_mtx_lock(&push->mx);
		rv = nni_setopt_int(&push->raw, buf, sz, 0, 1);
		nni_mtx_unlock(&push->mx);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_push_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_push_sock *push = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		nni_mtx_lock(&push->mx);
		rv = nni_getopt_int(&push->raw, buf, szp);
		nni_mtx_unlock(&push->mx);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static void
nni_push_rrdist(void *arg)
{
	nni_push_sock *push = arg;
	nni_push_pipe *pp;
	nni_msgq *uwq = push->uwq;
	nni_msg *msg = NULL;
	int rv;
	int i;

	for (;;) {
		if ((msg == NULL) && (nni_msgq_get(uwq, &msg) != 0)) {
			// Should only be NNG_ECLOSED
			return;
		}

		nni_mtx_lock(&push->mx);
		if (push->closing) {
			if (msg != NULL) {
				nni_mtx_unlock(&push->mx);
				nni_msg_free(msg);
				return;
			}
		}
		for (i = 0; i < push->npipes; i++) {
			pp = push->nextpipe;
			if (pp == NULL) {
				pp = nni_list_first(&push->pipes);
			}
			push->nextpipe = nni_list_next(&push->pipes, pp);
			if (nni_msgq_tryput(pp->mq, msg) == 0) {
				msg = NULL;
				break;
			}
		}
		if (msg != NULL) {
			// We weren't able to deliver it, so keep it and
			// wait for a sender to let us know its ready.
			push->wantw = 1;
			nni_cv_wait(&push->cv);
		} else {
			push->wantw = 0;
		}
		nni_mtx_unlock(&push->mx);
	}
}


// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe nni_push_proto_pipe = {
	.pipe_init	= nni_push_pipe_init,
	.pipe_fini	= nni_push_pipe_fini,
	.pipe_add	= nni_push_pipe_add,
	.pipe_rem	= nni_push_pipe_rem,
	.pipe_send	= nni_push_pipe_send,
	.pipe_recv	= nni_push_pipe_recv,
};

nni_proto nni_push_proto = {
	.proto_self		= NNG_PROTO_PUSH,
	.proto_peer		= NNG_PROTO_PULL,
	.proto_name		= "push",
	.proto_pipe		= &nni_push_proto_pipe,
	.proto_init		= nni_push_init,
	.proto_fini		= nni_push_fini,
	.proto_setopt		= nni_push_setopt,
	.proto_getopt		= nni_push_getopt,
	.proto_recv_filter	= NULL,
	.proto_send_filter	= NULL,
};
