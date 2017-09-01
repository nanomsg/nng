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

// Subscriber protocol.  The SUB protocol receives messages sent to
// it from publishers, and filters out those it is not interested in,
// only passing up ones that match known subscriptions.

typedef struct sub_pipe  sub_pipe;
typedef struct sub_sock  sub_sock;
typedef struct sub_topic sub_topic;

static void sub_recv_cb(void *);
static void sub_putq_cb(void *);
static void sub_pipe_fini(void *);

struct sub_topic {
	nni_list_node node;
	size_t        len;
	void *        buf;
};

// An nni_rep_sock is our per-socket protocol private structure.
struct sub_sock {
	nni_sock *sock;
	nni_list  topics;
	nni_msgq *urq;
	int       raw;
};

// An nni_rep_pipe is our per-pipe protocol private structure.
struct sub_pipe {
	nni_pipe *pipe;
	sub_sock *sub;
	nni_aio * aio_recv;
	nni_aio * aio_putq;
};

static int
sub_sock_init(void **sp, nni_sock *sock)
{
	sub_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&s->topics, sub_topic, node);
	s->sock = sock;
	s->raw  = 0;

	s->urq = nni_sock_recvq(sock);
	nni_sock_senderr(sock, NNG_ENOTSUP);
	*sp = s;
	return (0);
}

static void
sub_sock_fini(void *arg)
{
	sub_sock * s = arg;
	sub_topic *topic;

	while ((topic = nni_list_first(&s->topics)) != NULL) {
		nni_list_remove(&s->topics, topic);
		nni_free(topic->buf, topic->len);
		NNI_FREE_STRUCT(topic);
	}
	NNI_FREE_STRUCT(s);
}

static void
sub_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
sub_sock_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
sub_pipe_fini(void *arg)
{
	sub_pipe *p = arg;

	nni_aio_fini(p->aio_putq);
	nni_aio_fini(p->aio_recv);
	NNI_FREE_STRUCT(p);
}

static int
sub_pipe_init(void **pp, nni_pipe *pipe, void *s)
{
	sub_pipe *p;
	int       rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((rv = nni_aio_init(&p->aio_putq, sub_putq_cb, p)) != 0) ||
	    ((rv = nni_aio_init(&p->aio_recv, sub_recv_cb, p)) != 0)) {
		sub_pipe_fini(p);
		return (rv);
	}

	p->pipe = pipe;
	p->sub  = s;
	*pp     = p;
	return (0);
}

static int
sub_pipe_start(void *arg)
{
	sub_pipe *p = arg;

	nni_pipe_recv(p->pipe, p->aio_recv);
	return (0);
}

static void
sub_pipe_stop(void *arg)
{
	sub_pipe *p = arg;

	nni_aio_stop(p->aio_putq);
	nni_aio_stop(p->aio_recv);
}

static void
sub_recv_cb(void *arg)
{
	sub_pipe *p   = arg;
	sub_sock *s   = p->sub;
	nni_msgq *urq = s->urq;

	if (nni_aio_result(p->aio_recv) != 0) {
		nni_pipe_stop(p->pipe);
		return;
	}

	nni_aio_set_msg(p->aio_putq, nni_aio_get_msg(p->aio_recv));
	nni_aio_set_msg(p->aio_recv, NULL);
	nni_msgq_aio_put(urq, p->aio_putq);
}

static void
sub_putq_cb(void *arg)
{
	sub_pipe *p = arg;

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
sub_subscribe(sub_sock *s, const void *buf, size_t sz)
{
	sub_topic *topic;
	sub_topic *newtopic;

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
		return (NNG_ENOMEM);
	}
	if ((newtopic->buf = nni_alloc(sz)) == NULL) {
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
	return (0);
}

static int
sub_unsubscribe(sub_sock *s, const void *buf, size_t sz)
{
	sub_topic *topic;
	int        rv;

	NNI_LIST_FOREACH (&s->topics, topic) {
		if (topic->len >= sz) {
			rv = memcmp(topic->buf, buf, sz);
		} else {
			rv = memcmp(topic->buf, buf, topic->len);
		}
		if (rv == 0) {
			if (topic->len == sz) {
				nni_list_remove(&s->topics, topic);
				nni_free(topic->buf, topic->len);
				NNI_FREE_STRUCT(topic);
				return (0);
			}
			if (topic->len > sz) {
				return (NNG_ENOENT);
			}
		}
		if (rv > 0) {
			return (NNG_ENOENT);
		}
	}
	return (NNG_ENOENT);
}

static int
sub_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	sub_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_setopt_int(&s->raw, buf, sz, 0, 1);
	} else if (opt == nng_optid_sub_subscribe) {
		rv = sub_subscribe(s, buf, sz);
	} else if (opt == nng_optid_sub_unsubscribe) {
		rv = sub_unsubscribe(s, buf, sz);
	}
	return (rv);
}

static int
sub_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	sub_sock *s  = arg;
	int       rv = NNG_ENOTSUP;

	if (opt == nng_optid_raw) {
		rv = nni_getopt_int(&s->raw, buf, szp);
	}
	return (rv);
}

static nni_msg *
sub_sock_rfilter(void *arg, nni_msg *msg)
{
	sub_sock * s = arg;
	sub_topic *topic;
	char *     body;
	size_t     len;
	int        match;

	if (s->raw) {
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
	if (!match) {
		nni_msg_free(msg);
		return (NULL);
	}
	return (msg);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops sub_pipe_ops = {
	.pipe_init  = sub_pipe_init,
	.pipe_fini  = sub_pipe_fini,
	.pipe_start = sub_pipe_start,
	.pipe_stop  = sub_pipe_stop,
};

static nni_proto_sock_ops sub_sock_ops = {
	.sock_init    = sub_sock_init,
	.sock_fini    = sub_sock_fini,
	.sock_open    = sub_sock_open,
	.sock_close   = sub_sock_close,
	.sock_setopt  = sub_sock_setopt,
	.sock_getopt  = sub_sock_getopt,
	.sock_rfilter = sub_sock_rfilter,
};

static nni_proto sub_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_PROTO_SUB_V0, "sub" },
	.proto_peer     = { NNG_PROTO_PUB_V0, "pub" },
	.proto_flags    = NNI_PROTO_FLAG_RCV,
	.proto_sock_ops = &sub_sock_ops,
	.proto_pipe_ops = &sub_pipe_ops,
};

int
nng_sub0_open(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &sub_proto));
}
