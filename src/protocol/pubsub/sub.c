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

// Subscriber protocol.  The SUB protocol receives messages sent to
// it from publishers, and filters out those it is not interested in,
// only passing up ones that match known subscriptions.

typedef struct nni_sub_pipe	nni_sub_pipe;
typedef struct nni_sub_sock	nni_sub_sock;
typedef struct nni_sub_topic	nni_sub_topic;

struct nni_sub_topic {
	nni_list_node	node;
	size_t		len;
	void *		buf;
};

// An nni_rep_sock is our per-socket protocol private structure.
struct nni_sub_sock {
	nni_sock *	sock;
	nni_list	topics;
	nni_msgq *	urq;
	int		raw;
};

// An nni_rep_pipe is our per-pipe protocol private structure.
struct nni_sub_pipe {
	nni_pipe *	pipe;
	nni_sub_sock *	sub;
};

static int
nni_sub_sock_init(void **subp, nni_sock *sock)
{
	nni_sub_sock *sub;

	if ((sub = NNI_ALLOC_STRUCT(sub)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&sub->topics, nni_sub_topic, node);
	sub->sock = sock;
	sub->raw = 0;

	sub->urq = nni_sock_recvq(sock);
	nni_sock_senderr(sock, NNG_ENOTSUP);
	*subp = sub;
	return (0);
}


static void
nni_sub_sock_fini(void *arg)
{
	nni_sub_sock *sub = arg;
	nni_sub_topic *topic;

	while ((topic = nni_list_first(&sub->topics)) != NULL) {
		nni_list_remove(&sub->topics, topic);
		nni_free(topic->buf, topic->len);
		NNI_FREE_STRUCT(topic);
	}
	NNI_FREE_STRUCT(sub);
}


static int
nni_sub_pipe_init(void **spp, nni_pipe *pipe, void *ssock)
{
	nni_sub_pipe *sp;

	if ((sp = NNI_ALLOC_STRUCT(sp)) == NULL) {
		return (NNG_ENOMEM);
	}
	sp->pipe = pipe;
	sp->sub = ssock;
	*spp = sp;
	return (0);
}


static void
nni_sub_pipe_fini(void *arg)
{
	nni_sub_pipe *sp = arg;

	NNI_FREE_STRUCT(sp);
}


static void
nni_sub_pipe_recv(void *arg)
{
	nni_sub_pipe *sp = arg;
	nni_sub_sock *sub = sp->sub;
	nni_msgq *urq = sub->urq;
	nni_pipe *pipe = sp->pipe;
	nni_msg *msg;
	int rv;

	for (;;) {
		rv = nni_pipe_recv(pipe, &msg);
		if (rv != 0) {
			break;
		}

		// Now send it up.
		rv = nni_msgq_put(urq, msg);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	// Nobody else to signal...
	nni_pipe_close(pipe);
}


// For now we maintain subscriptions on a sorted linked list.  As we do not
// expect to have huge numbers of subscriptions, and as the operation is
// really O(n), we think this is acceptable.  In the future we might decide
// to replace this with a patricia trie, like old nanomsg had.

static int
nni_sub_subscribe(nni_sub_sock *sub, const void *buf, size_t sz)
{
	nni_sub_topic *topic;
	nni_sub_topic *newtopic;

	NNI_LIST_FOREACH (&sub->topics, topic) {
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
		nni_list_insert_before(&sub->topics, newtopic, topic);
	} else {
		nni_list_append(&sub->topics, newtopic);
	}
	return (0);
}


static int
nni_sub_unsubscribe(nni_sub_sock *sub, const void *buf, size_t sz)
{
	nni_sub_topic *topic;
	int rv;

	NNI_LIST_FOREACH (&sub->topics, topic) {
		if (topic->len >= sz) {
			rv = memcmp(topic->buf, buf, sz);
		} else {
			rv = memcmp(topic->buf, buf, topic->len);
		}
		if (rv == 0) {
			if (topic->len == sz) {
				nni_list_remove(&sub->topics, topic);
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
nni_sub_sock_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	nni_sub_sock *sub = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_setopt_int(&sub->raw, buf, sz, 0, 1);
		break;
	case NNG_OPT_SUBSCRIBE:
		rv = nni_sub_subscribe(sub, buf, sz);
		break;
	case NNG_OPT_UNSUBSCRIBE:
		rv = nni_sub_unsubscribe(sub, buf, sz);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static int
nni_sub_sock_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	nni_sub_sock *sub = arg;
	int rv;

	switch (opt) {
	case NNG_OPT_RAW:
		rv = nni_getopt_int(&sub->raw, buf, szp);
		break;
	default:
		rv = NNG_ENOTSUP;
	}
	return (rv);
}


static nni_msg *
nni_sub_sock_rfilter(void *arg, nni_msg *msg)
{
	nni_sub_sock *sub = arg;
	nni_sub_topic *topic;
	char *body;
	size_t len;
	int match;

	if (sub->raw) {
		return (msg);
	}

	body = nni_msg_body(msg);
	len = nni_msg_len(msg);

	match = 0;
	// Check to see if the message matches one of our subscriptions.
	NNI_LIST_FOREACH (&sub->topics, topic) {
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
static nni_proto_pipe_ops nni_sub_pipe_ops = {
	.pipe_init	= nni_sub_pipe_init,
	.pipe_fini	= nni_sub_pipe_fini,
	.pipe_worker	= { nni_sub_pipe_recv },
};

static nni_proto_sock_ops nni_sub_sock_ops = {
	.sock_init	= nni_sub_sock_init,
	.sock_fini	= nni_sub_sock_fini,
	.sock_setopt	= nni_sub_sock_setopt,
	.sock_getopt	= nni_sub_sock_getopt,
	.sock_rfilter	= nni_sub_sock_rfilter,
};

nni_proto nni_sub_proto = {
	.proto_self	= NNG_PROTO_SUB,
	.proto_peer	= NNG_PROTO_PUB,
	.proto_name	= "sub",
	.proto_sock_ops = &nni_sub_sock_ops,
	.proto_pipe_ops = &nni_sub_pipe_ops,
};
