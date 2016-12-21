/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

/*
 * Pair protocol.  The PAIR protocol is a simple 1:1 messaging pattern.
 */

typedef struct pair *		pair_t;
typedef struct pairpipe *	pairpipe_t;

/*
 * Note that pair can only have a single pipe, so we don't need
 * to create separate data structures for diferent pipe instances.
 */
struct pair {
	nni_socket_t	sock;
	nni_mutex_t	mx;
	nni_pipe_t	pipe;
	nni_msgqueue_t	uwq;
	nni_msgqueue_t	urq;
};

struct pairpipe {
	nni_pipe_t	pipe;
	pair_t		pair;
	int		good;
	nni_thread_t	sthr;
	nni_thread_t	rthr;
	int		sigclose;
};

static void pair_receiver(void *);
static void pair_sender(void *);

static int
pair_create(void **pairp, nni_socket_t sock)
{
	pair_t pair;
	int rv;

	if ((pair = nni_alloc(sizeof (*pair))) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mutex_create(&pair->mx)) != 0) {
		nni_free(pair, sizeof (*pair));
		return (rv);
	}
	pair->sock = sock;
	pair->uwq = nni_socket_sendq(sock);
	pair->urq = nni_socket_recvq(sock);
	*pairp = pair;
	return (0);
}


static void
pair_destroy(void *arg)
{
	pair_t pair = arg;

	nni_mutex_destroy(pair->mx);
	nni_free(pair, sizeof (*pair));
}


static void
pair_shutdown(void *arg, uint64_t usec)
{
	pair_t pair = arg;
	nni_pipe_t pipe;

	NNI_ARG_UNUSED(usec);

	/*
	 * XXX: correct implementation here is to set a draining flag,
	 * and wait a bit for the sender to finish draining (linger),
	 * then reap the pipe.  For now we just act a little more harshly.
	 */
	nni_mutex_enter(pair->mx);
	pipe = pair->pipe;
	pair->pipe = NULL;
	nni_mutex_exit(pair->mx);

	nni_pipe_close(pipe);
}


static int
pair_add_pipe(void *arg, nni_pipe_t pipe)
{
	pair_t pair = arg;
	pairpipe_t pp;
	int rv;

	pp = nni_alloc(sizeof (*pp));
	pp->pipe = pipe;
	pp->good = 0;
	pp->sigclose = 0;
	pp->sthr = NULL;
	pp->rthr = NULL;

	nni_mutex_enter(pair->mx);
	if (pair->pipe != NULL) {
		/* Already have a peer, denied. */
		nni_mutex_exit(pair->mx);
		nni_free(pp, sizeof (*pp));
		return (NNG_EBUSY);
	}
	if ((rv = nni_thread_create(&pp->rthr, pair_receiver, pp)) != 0) {
		nni_mutex_exit(pair->mx);
		return (rv);
	}
	if ((rv = nni_thread_create(&pp->sthr, pair_sender, pp)) != 0) {
		nni_mutex_exit(pair->mx);
		return (rv);
	}
	pp->good = 1;
	pair->pipe = pipe;
	nni_mutex_exit(pair->mx);
	return (NNG_EINVAL);
}


static int
pair_remove_pipe(void *arg, nni_pipe_t pipe)
{
	pairpipe_t pp = arg;
	pair_t pair = pp->pair;

	if (pp->sthr) {
		(void) nni_thread_reap(pp->sthr);
	}
	if (pp->rthr) {
		(void) nni_thread_reap(pp->rthr);
	}
	nni_mutex_enter(pair->mx);
	if (pair->pipe != pipe) {
		nni_mutex_exit(pair->mx);
		return (NNG_EINVAL);
	}
	nni_mutex_exit(pair->mx);
	return (NNG_EINVAL);
}


static void
pair_sender(void *arg)
{
	pairpipe_t pp = arg;
	pair_t pair = pp->pair;
	nni_msgqueue_t uwq = pair->uwq;
	nni_msgqueue_t urq = pair->urq;
	nni_pipe_t pipe = pp->pipe;
	nni_msg_t msg;
	int rv;

	nni_mutex_enter(pair->mx);
	if (!pp->good) {
		nni_mutex_exit(pair->mx);
		return;
	}
	nni_mutex_exit(pair->mx);


	for (;;) {
		rv = nni_msgqueue_get_sig(uwq, &msg, -1, &pp->sigclose);
		if (rv != 0) {
			break;
		}
		rv = nni_pipe_send(pipe, msg);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgqueue_signal(urq, &pp->sigclose);
	nni_pipe_close(pipe);
	nni_socket_remove_pipe(pair->sock, pipe);
}


static void
pair_receiver(void *arg)
{
	pairpipe_t pp = arg;
	pair_t pair = pp->pair;
	nni_msgqueue_t urq = pair->urq;
	nni_msgqueue_t uwq = pair->uwq;
	nni_pipe_t pipe = pp->pipe;
	nni_msg_t msg;
	int rv;

	nni_mutex_enter(pair->mx);
	if (!pp->good) {
		nni_mutex_exit(pair->mx);
		return;
	}
	nni_mutex_exit(pair->mx);

	for (;;) {
		rv = nni_pipe_recv(pipe, &msg);
		if (rv != 0) {
			break;
		}
		rv = nni_msgqueue_put_sig(urq, msg, -1, &pp->sigclose);
		if (rv != 0) {
			nni_msg_free(msg);
			break;
		}
	}
	nni_msgqueue_signal(uwq, &pp->sigclose);
	nni_pipe_close(pipe);
	nni_socket_remove_pipe(pair->sock, pipe);
}


static int
pair_setopt(void *arg, int opt, const void *buf, size_t sz)
{
	return (NNG_ENOTSUP);
}


static int
pair_getopt(void *arg, int opt, void *buf, size_t *szp)
{
	return (NNG_ENOTSUP);
}


/*
 * Global inproc state - this contains the list of active endpoints
 * which we use for coordinating rendezvous.
 */

struct nni_protocol nni_pair_protocol = {
	NNG_PROTO_PAIR,         /* proto_self */
	NNG_PROTO_PAIR,         /* proto_peer */
	"pair",
	pair_create,
	pair_destroy,
	pair_shutdown,
	pair_add_pipe,
	pair_remove_pipe,
	pair_setopt,
	pair_getopt,
	NULL,                   /* proto_recvfilter */
	NULL,                   /* proto_sendfilter */
};
