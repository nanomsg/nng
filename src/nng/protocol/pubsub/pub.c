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

// Publish protocol.  The PUB protocol simply sends messages out, as
// a broadcast.  It has nothing more sophisticated because it does not
// perform sender-side filtering.  Its best effort delivery, so anything
// that can't receive the message won't get one.

typedef struct nni_pub_pipe nni_pub_pipe;
typedef struct nni_pub_sock nni_pub_sock;

static void nni_pub_pipe_recv_cb(void *);
static void nni_pub_pipe_send_cb(void *);
static void nni_pub_pipe_getq_cb(void *);
static void nni_pub_sock_getq_cb(void *);
static void nni_pub_sock_fini(void *);
static void nni_pub_pipe_fini(void *);

// An nni_pub_sock is our per-socket protocol private structure.
struct nni_pub_sock {
	nni_sock *sock;
	nni_msgq *uwq;
	int       raw;
	nni_aio   aio_getq;
	nni_list  pipes;
	nni_mtx   mtx;
};

// An nni_pub_pipe is our per-pipe protocol private structure.
struct nni_pub_pipe {
	nni_pipe *    pipe;
	nni_pub_sock *pub;
	nni_msgq *    sendq;
	nni_aio       aio_getq;
	nni_aio       aio_send;
	nni_aio       aio_recv;
	nni_list_node node;
};

static int
nni_pub_sock_init(void **pubp, nni_sock *sock)
{
	nni_pub_sock *pub;

	if ((pub = NNI_ALLOC_STRUCT(pub)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&pub->mtx);
	nni_aio_init(&pub->aio_getq, nni_pub_sock_getq_cb, pub);

	pub->sock = sock;
	pub->raw  = 0;
	NNI_LIST_INIT(&pub->pipes, nni_pub_pipe, node);

	pub->uwq = nni_sock_sendq(sock);

	*pubp = pub;
	nni_sock_recverr(sock, NNG_ENOTSUP);
	return (0);
}

static void
nni_pub_sock_fini(void *arg)
{
	nni_pub_sock *pub = arg;

	nni_aio_stop(&pub->aio_getq);
	nni_aio_fini(&pub->aio_getq);
	nni_mtx_fini(&pub->mtx);
	NNI_FREE_STRUCT(pub);
}

static void
nni_pub_sock_open(void *arg)
{
	nni_pub_sock *pub = arg;

	nni_msgq_aio_get(pub->uwq, &pub->aio_getq);
}

static void
nni_pub_sock_close(void *arg)
{
	nni_pub_sock *pub = arg;

	nni_aio_cancel(&pub->aio_getq, NNG_ECLOSED);
}

static void
nni_pub_pipe_fini(void *arg)
{
	nni_pub_pipe *pp = arg;
	nni_aio_fini(&pp->aio_getq);
	nni_aio_fini(&pp->aio_send);
	nni_aio_fini(&pp->aio_recv);
	nni_msgq_fini(pp->sendq);
	NNI_FREE_STRUCT(pp);
}

static int
nni_pub_pipe_init(void **ppp, nni_pipe *pipe, void *psock)
{
	nni_pub_pipe *pp;
	int           rv;

	if ((pp = NNI_ALLOC_STRUCT(pp)) == NULL) {
		return (NNG_ENOMEM);
	}
	// XXX: consider making this depth tunable
	if ((rv = nni_msgq_init(&pp->sendq, 16)) != 0) {
		NNI_FREE_STRUCT(pp);
		return (rv);
	}

	nni_aio_init(&pp->aio_getq, nni_pub_pipe_getq_cb, pp);
	nni_aio_init(&pp->aio_send, nni_pub_pipe_send_cb, pp);
	nni_aio_init(&pp->aio_recv, nni_pub_pipe_recv_cb, pp);

	pp->pipe = pipe;
	pp->pub  = psock;
	*ppp     = pp;
	return (0);
}

static int
nni_pub_pipe_start(void *arg)
{
	nni_pub_pipe *pp  = arg;
	nni_pub_sock *pub = pp->pub;

	if (nni_pipe_peer(pp->pipe) != NNG_PROTO_SUB) {
		return (NNG_EPROTO);
	}
	nni_mtx_lock(&pub->mtx);
	nni_list_append(&pub->pipes, pp);
	nni_mtx_unlock(&pub->mtx);

	// Start the receiver and the queue reader.
	nni_pipe_recv(pp->pipe, &pp->aio_recv);
	nni_msgq_aio_get(pp->sendq, &pp->aio_getq);

	return (0);
}

static void
nni_pub_pipe_stop(void *arg)
{
	nni_pub_pipe *pp  = arg;
	nni_pub_sock *pub = pp->pub;

	nni_aio_stop(&pp->aio_getq);
	nni_aio_stop(&pp->aio_send);
	nni_aio_stop(&pp->aio_recv);

	nni_msgq_close(pp->sendq);

	nni_mtx_lock(&pub->mtx);
	if (nni_list_active(&pub->pipes, pp)) {
		nni_list_remove(&pub->pipes, pp);
	}
	nni_mtx_unlock(&pub->mtx);
}

static void
nni_pub_sock_getq_cb(void *arg)
{
	nni_pub_sock *pub = arg;
	nni_msgq *    uwq = pub->uwq;
	nni_msg *     msg, *dup;

	nni_pub_pipe *pp;
	nni_pub_pipe *last;
	int           rv;

	if (nni_aio_result(&pub->aio_getq) != 0) {
		return;
	}

	msg                 = pub->aio_getq.a_msg;
	pub->aio_getq.a_msg = NULL;

	nni_mtx_lock(&pub->mtx);
	last = nni_list_last(&pub->pipes);
	NNI_LIST_FOREACH (&pub->pipes, pp) {
		if (pp != last) {
			rv = nni_msg_dup(&dup, msg);
			if (rv != 0) {
				continue;
			}
		} else {
			dup = msg;
		}
		if ((rv = nni_msgq_tryput(pp->sendq, dup)) != 0) {
			nni_msg_free(dup);
		}
	}
	nni_mtx_unlock(&pub->mtx);

	if (last == NULL) {
		nni_msg_free(msg);
	}

	nni_msgq_aio_get(uwq, &pub->aio_getq);
}

static void
nni_pub_pipe_recv_cb(void *arg)
{
	nni_pub_pipe *pp = arg;

	if (nni_aio_result(&pp->aio_recv) != 0) {
		nni_pipe_stop(pp->pipe);
		return;
	}

	nni_msg_free(pp->aio_recv.a_msg);
	pp->aio_recv.a_msg = NULL;
	nni_pipe_recv(pp->pipe, &pp->aio_recv);
}

static void
nni_pub_pipe_getq_cb(void *arg)
{
	nni_pub_pipe *pp = arg;

	if (nni_aio_result(&pp->aio_getq) != 0) {
		nni_pipe_stop(pp->pipe);
		return;
	}

	pp->aio_send.a_msg = pp->aio_getq.a_msg;
	pp->aio_getq.a_msg = NULL;

	nni_pipe_send(pp->pipe, &pp->aio_send);
}

static void
nni_pub_pipe_send_cb(void *arg)
{
	nni_pub_pipe *pp = arg;

	if (nni_aio_result(&pp->aio_send) != 0) {
		nni_msg_free(pp->aio_send.a_msg);
		pp->aio_send.a_msg = NULL;
		nni_pipe_stop(pp->pipe);
		return;
	}

	pp->aio_send.a_msg = NULL;
	nni_msgq_aio_get(pp->sendq, &pp->aio_getq);
}

static int
nni_pub_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_pub_sock *pub = arg;
	int           rv  = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_setopt_int(&pub->raw, buf, sz, 0, 1);
	}
	return (rv);
}

static int
nni_pub_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_pub_sock *pub = arg;
	int           rv  = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_getopt_int(&pub->raw, buf, szp);
	}
	return (rv);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops nni_pub_pipe_ops = {
	.pipe_init  = nni_pub_pipe_init,
	.pipe_fini  = nni_pub_pipe_fini,
	.pipe_start = nni_pub_pipe_start,
	.pipe_stop  = nni_pub_pipe_stop,
};

nni_proto_sock_ops nni_pub_sock_ops = {
	.sock_init   = nni_pub_sock_init,
	.sock_fini   = nni_pub_sock_fini,
	.sock_open   = nni_pub_sock_open,
	.sock_close  = nni_pub_sock_close,
	.sock_setopt = nni_pub_sock_setopt,
	.sock_getopt = nni_pub_sock_getopt,
};

nni_proto nni_pub_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_PUB_V0, "pub" },
	.proto_peer     = { NNG_PROTO_SUB_V0, "sub" },
	.proto_flags    = NNI_PROTO_FLAG_SND,
	.proto_sock_ops = &nni_pub_sock_ops,
	.proto_pipe_ops = &nni_pub_pipe_ops,
};

int
nng_pub0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &nni_pub_proto));
}
