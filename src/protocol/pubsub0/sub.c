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
#include "protocol/pubsub0/sub.h"

// Subscriber protocol.  The SUB protocol receives messages sent to
// it from publishers, and filters out those it is not interested in,
// only passing up ones that match known subscriptions.

#ifndef NNI_PROTO_SUB_V0
#define NNI_PROTO_SUB_V0 NNI_PROTO(2, 1)
#endif

#ifndef NNI_PROTO_PUB_V0
#define NNI_PROTO_PUB_V0 NNI_PROTO(2, 0)
#endif

typedef struct sub0_pipe  sub0_pipe;
typedef struct sub0_sock  sub0_sock;
typedef struct sub0_topic sub0_topic;

static void sub0_recv_cb(void *);
static void sub0_putq_cb(void *);
static void sub0_pipe_fini(void *);

struct sub0_topic {
	nni_list_node node;
	size_t        len;
	void *        buf;
};

// sub0_sock is our per-socket protocol private structure.
struct sub0_sock {
	nni_list  topics;
	nni_msgq *urq;
	bool      raw;
	nni_mtx   lk;
};

// sub0_pipe is our per-pipe protocol private structure.
struct sub0_pipe {
	nni_pipe * pipe;
	sub0_sock *sub;
	nni_aio *  aio_recv;
	nni_aio *  aio_putq;
};

static int
sub0_sock_init(void **sp, nni_sock *sock)
{
	sub0_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->lk);
	NNI_LIST_INIT(&s->topics, sub0_topic, node);
	s->raw = false;

	s->urq = nni_sock_recvq(sock);
	*sp    = s;
	return (0);
}

static void
sub0_sock_fini(void *arg)
{
	sub0_sock * s = arg;
	sub0_topic *topic;

	while ((topic = nni_list_first(&s->topics)) != NULL) {
		nni_list_remove(&s->topics, topic);
		nni_free(topic->buf, topic->len);
		NNI_FREE_STRUCT(topic);
	}
	nni_mtx_fini(&s->lk);
	NNI_FREE_STRUCT(s);
}

static void
sub0_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
sub0_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
sub0_pipe_fini(void *arg)
{
	sub0_pipe *p = arg;

	nni_aio_fini(p->aio_putq);
	nni_aio_fini(p->aio_recv);
	NNI_FREE_STRUCT(p);
}

static int
sub0_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	sub0_pipe *p;
	int        rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&p->aio_putq, sub0_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, sub0_recv_cb, p)) != 0)) {
		sub0_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->sub  = s;
	*pp     = p;
	return (0);
}

static int
sub0_pipe_start(void *arg)
{
	sub0_pipe *p = arg;

	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
sub0_pipe_stop(void *arg)
{
	sub0_pipe *p = arg;

	nni_aio_stop(p->aio_putq);
	nni_aio_stop(p->aio_recv);
}

static void
sub0_recv_cb(void *arg)
{
	sub0_pipe *p   = arg;
	sub0_sock *s   = p->sub;
	nni_msgq * urq = s->urq;
	nni_msg *  msg;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	msg = nni_aio_get_msg(p->aio_recv);
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));
	nni_aio_set_msg(p->aio_putq, msg);
	nni_msgq_aio_put(urq, p->aio_putq);
}

static void
sub0_putq_cb(void *arg)
{
	sub0_pipe *p = arg;

	if (nni_aio_result(p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(p->aio_putq));
		nni_aio_set_msg(p->aio_putq, NULL);
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_pipe_recv(p->pipe, p->aio_recv);
}

// For now we maintain subscriptions on a sorted linked list.  As we do not
// expect to have huge numbers of subscriptions, and as the operation is
// really O(n), we think this is acceptable.  In the future we might decide
// to replace this with a patricia trie, like old nanomsg had.

static int
sub0_subscribe(void *arg, const void *buf, size_t sz)
{
	sub0_sock * s = arg;
	sub0_topic *topic;
	sub0_topic *newtopic;

	nni_mtx_lock(&s->lk);
	NNI_LIST_FOREACH (&s->topics, topic) {
		int rv;

		if (topic->len >= sz) {
			rv = memcmp(topic->buf, buf, sz);
		} else {
			rv = memcmp(topic->buf, buf, topic->len);
		}
		if (rv == 0) {
			if (topic->len == sz) {
				// Already inserted.
				nni_mtx_unlock(&s->lk);
				return (0);
			}
			if (topic->len > sz) {
				break;
			}
		} else if (rv > 0) {
			break;
		}
	}

	if ((newtopic = NNI_ALLOC_STRUCT(newtopic)) == NULL) {
		nni_mtx_unlock(&s->lk);
		return (NNG_ENOMEM);
	}
	if ((newtopic->buf = nni_alloc(sz)) == NULL) {
		nni_mtx_unlock(&s->lk);
		return (NNG_ENOMEM);
	}
	NNI_LIST_NODE_INIT(&newtopic->node);
	newtopic->len = sz;
	memcpy(newtopic->buf, buf, sz);
	if (topic != NULL) {
		nni_list_insert_before(&s->topics, newtopic, topic);
	} else {
		nni_list_append(&s->topics, newtopic);
	}
	nni_mtx_unlock(&s->lk);
	return (0);
}

static int
sub0_unsubscribe(void *arg, const void *buf, size_t sz)
{
	sub0_sock * s = arg;
	sub0_topic *topic;
	int         rv;

	nni_mtx_lock(&s->lk);
	NNI_LIST_FOREACH (&s->topics, topic) {
		if (topic->len >= sz) {
			rv = memcmp(topic->buf, buf, sz);
		} else {
			rv = memcmp(topic->buf, buf, topic->len);
		}
		if (rv == 0) {
			if (topic->len == sz) {
				nni_list_remove(&s->topics, topic);
				nni_mtx_unlock(&s->lk);
				nni_free(topic->buf, topic->len);
				NNI_FREE_STRUCT(topic);
				return (0);
			}
			if (topic->len > sz) {
				nni_mtx_unlock(&s->lk);
				return (NNG_ENOENT);
			}
		}
		if (rv > 0) {
			nni_mtx_unlock(&s->lk);
			return (NNG_ENOENT);
		}
	}
	nni_mtx_unlock(&s->lk);
	return (NNG_ENOENT);
}

static int
sub0_sock_setopt_raw(void *arg, const void *buf, size_t sz)
{
	sub0_sock *s = arg;
	return (nni_setopt_bool(&s->raw, buf, sz));
}

static int
sub0_sock_getopt_raw(void *arg, void *buf, size_t *szp)
{
	sub0_sock *s = arg;
	return (nni_getopt_bool(s->raw, buf, szp));
}

static void
sub0_sock_send(void *arg, nni_aio *aio)
{
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static void
sub0_sock_recv(void *arg, nni_aio *aio)
{
	sub0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static nni_msg *
sub0_sock_filter(void *arg, nni_msg *msg)
{
	sub0_sock * s = arg;
	sub0_topic *topic;
	char *      body;
	size_t      len;
	int         match;

	nni_mtx_lock(&s->lk);
	if (s->raw) {
		nni_mtx_unlock(&s->lk);
		return (msg);
	}

	body = nni_msg_body(msg);
	len  = nni_msg_len(msg);

	match = 0;
	// Check to see if the message matches one of our subscriptions.
	NNI_LIST_FOREACH (&s->topics, topic) {
		if (len >= topic->len) {
			int rv = memcmp(topic->buf, body, topic->len);
			if (rv == 0) {
				// Matched!
				match = 1;
				break;
			}
			if (rv > 0) {
				match = 0;
				break;
			}
		} else if (memcmp(topic->buf, body, len) >= 0) {
			match = 0;
			break;
		}
	}
	nni_mtx_unlock(&s->lk);
	if (!match) {
		nni_msg_free(msg);
		return (NULL);
	}
	return (msg);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops sub0_pipe_ops = {
	.pipe_init  = sub0_pipe_init,
	.pipe_fini  = sub0_pipe_fini,
	.pipe_start = sub0_pipe_start,
	.pipe_stop  = sub0_pipe_stop,
};

static nni_proto_sock_option sub0_sock_options[] = {
	{
	    .pso_name   = NNG_OPT_RAW,
	    .pso_getopt = sub0_sock_getopt_raw,
	    .pso_setopt = sub0_sock_setopt_raw,
	},
	{
	    .pso_name   = NNG_OPT_SUB_SUBSCRIBE,
	    .pso_getopt = NULL,
	    .pso_setopt = sub0_subscribe,
	},
	{
	    .pso_name   = NNG_OPT_SUB_UNSUBSCRIBE,
	    .pso_getopt = NULL,
	    .pso_setopt = sub0_unsubscribe,
	},
	// terminate list
	{ NULL, NULL, NULL },
};

static nni_proto_sock_ops sub0_sock_ops = {
	.sock_init    = sub0_sock_init,
	.sock_fini    = sub0_sock_fini,
	.sock_open    = sub0_sock_open,
	.sock_close   = sub0_sock_close,
	.sock_send    = sub0_sock_send,
	.sock_recv    = sub0_sock_recv,
	.sock_filter  = sub0_sock_filter,
	.sock_options = sub0_sock_options,
};

static nni_proto sub0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNI_PROTO_SUB_V0, "sub" },
	.proto_peer     = { NNI_PROTO_PUB_V0, "pub" },
	.proto_flags    = NNI_PROTO_FLAG_RCV,
	.proto_sock_ops = &sub0_sock_ops,
	.proto_pipe_ops = &sub0_pipe_ops,
};

int
nng_sub0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &sub0_proto));
}
