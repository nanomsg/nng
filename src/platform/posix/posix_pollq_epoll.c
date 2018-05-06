//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Liam Staskawicz <liam@stask.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifdef NNG_HAVE_EPOLL

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h> /* for strerror() */
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

#define NNI_MAX_EPOLL_EVENTS 64

// flags we always want enabled as long as at least one event is active
#define NNI_EPOLL_FLAGS (EPOLLONESHOT | EPOLLERR | EPOLLHUP)

// nni_posix_pollq is a work structure that manages state for the epoll-based
// pollq implementation
struct nni_posix_pollq {
	nni_mtx               mtx;
	nni_cv                cv;
	int                   epfd;  // epoll handle
	int                   evfd;  // event fd
	bool                  close; // request for worker to exit
	bool                  started;
	nni_idhash *          nodes;
	nni_thr               thr;    // worker thread
	nni_posix_pollq_node *wait;   // cancel waiting on this
	nni_posix_pollq_node *active; // active node (in callback)
};

int
nni_posix_pollq_add(nni_posix_pollq_node *node)
{
	int                rv;
	nni_posix_pollq *  pq;
	struct epoll_event ev;
	uint64_t           id;

	pq = nni_posix_pollq_get(node->fd);
	if (pq == NULL) {
		return (NNG_EINVAL);
	}

	// ensure node was not previously associated with a pollq
	if (node->pq != NULL) {
		return (NNG_ESTATE);
	}

	nni_mtx_lock(&pq->mtx);
	if (pq->close) {
		// This shouldn't happen!
		nni_mtx_unlock(&pq->mtx);
		return (NNG_ECLOSED);
	}

	if ((rv = nni_idhash_alloc(pq->nodes, &id, node)) != 0) {
		nni_mtx_unlock(&pq->mtx);
		return (rv);
	}
	node->index  = (int) id;
	node->pq     = pq;
	node->events = 0;

	// notifications disabled to begin with
	ev.events   = 0;
	ev.data.u64 = id;

	rv = epoll_ctl(pq->epfd, EPOLL_CTL_ADD, node->fd, &ev);
	if (rv != 0) {
		rv = nni_plat_errno(errno);
		nni_idhash_remove(pq->nodes, id);
		node->index = 0;
		node->pq    = NULL;
	}

	nni_mtx_unlock(&pq->mtx);
	return (rv);
}

// common functionality for nni_posix_pollq_remove() and nni_posix_pollq_fini()
// called while pq's lock is held
static void
nni_posix_pollq_remove_helper(nni_posix_pollq *pq, nni_posix_pollq_node *node)
{
	int                rv;
	struct epoll_event ev;

	node->events = 0;
	node->pq     = NULL;

	ev.events   = 0;
	ev.data.u64 = (uint64_t) node->index;

	if (node->index != 0) {
		// This deregisters the node.  If the poller was blocked
		// then this keeps it from coming back in to find us.
		nni_idhash_remove(pq->nodes, (uint64_t) node->index);
	}

	// NB: EPOLL_CTL_DEL actually *ignores* the event, but older Linux
	// versions need it to be non-NULL.
	rv = epoll_ctl(pq->epfd, EPOLL_CTL_DEL, node->fd, &ev);
	if (rv != 0) {
		NNI_ASSERT(errno == EBADF || errno == ENOENT);
	}
}

// nni_posix_pollq_remove removes the node from the pollq, but
// does not ensure that the pollq node is safe to destroy.  In particular,
// this function can be called from a callback (the callback may be active).
void
nni_posix_pollq_remove(nni_posix_pollq_node *node)
{
	nni_posix_pollq *pq = node->pq;

	if (pq == NULL) {
		return;
	}

	nni_mtx_lock(&pq->mtx);
	nni_posix_pollq_remove_helper(pq, node);

	if (pq->close) {
		nni_cv_wake(&pq->cv);
	}
	nni_mtx_unlock(&pq->mtx);
}

// nni_posix_pollq_init merely ensures that the node is ready for use.
// It does not register the node with any pollq in particular.
int
nni_posix_pollq_init(nni_posix_pollq_node *node)
{
	node->index = 0;
	return (0);
}

// nni_posix_pollq_fini does everything that nni_posix_pollq_remove does,
// but it also ensures that the callback is not active, so that the node
// may be deallocated.  This function must not be called in a callback.
void
nni_posix_pollq_fini(nni_posix_pollq_node *node)
{
	nni_posix_pollq *pq = node->pq;
	if (pq == NULL) {
		return;
	}

	nni_mtx_lock(&pq->mtx);
	while (pq->active == node) {
		pq->wait = node;
		nni_cv_wait(&pq->cv);
	}

	nni_posix_pollq_remove_helper(pq, node);

	if (pq->close) {
		nni_cv_wake(&pq->cv);
	}
	nni_mtx_unlock(&pq->mtx);
}

void
nni_posix_pollq_arm(nni_posix_pollq_node *node, int events)
{
	int                rv;
	struct epoll_event ev;
	nni_posix_pollq *  pq = node->pq;

	NNI_ASSERT(pq != NULL);
	if (events == 0) {
		return;
	}

	nni_mtx_lock(&pq->mtx);

	node->events |= events;
	ev.events   = node->events | NNI_EPOLL_FLAGS;
	ev.data.u64 = (uint64_t) node->index;

	rv = epoll_ctl(pq->epfd, EPOLL_CTL_MOD, node->fd, &ev);
	NNI_ASSERT(rv == 0);

	nni_mtx_unlock(&pq->mtx);
}

static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *  pq = arg;
	struct epoll_event events[NNI_MAX_EPOLL_EVENTS];

	nni_mtx_lock(&pq->mtx);

	while (!pq->close) {
		int i;
		int nevents;

		// block indefinitely, timers are handled separately
		nni_mtx_unlock(&pq->mtx);

		nevents =
		    epoll_wait(pq->epfd, events, NNI_MAX_EPOLL_EVENTS, -1);

		nni_mtx_lock(&pq->mtx);

		if (nevents <= 0) {
			continue;
		}

		// dispatch events
		for (i = 0; i < nevents; ++i) {
			const struct epoll_event *ev;
			nni_posix_pollq_node *    node;

			ev = &events[i];
			// If the waker pipe was signaled, read from it.
			if ((ev->data.u64 == 0) && (ev->events & POLLIN)) {
				int      rv;
				uint64_t clear;
				rv = read(pq->evfd, &clear, sizeof(clear));
				NNI_ASSERT(rv == sizeof(clear));
				continue;
			}

			if (nni_idhash_find(pq->nodes, ev->data.u64,
			        (void **) &node) != 0) {
				// node was removed while we were blocking
				continue;
			}

			node->revents = ev->events &
			    (EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP);

			// mark events as cleared
			node->events &= ~node->revents;

			// Save the active node; we can notice this way
			// when it is busy, and avoid freeing it until
			// we are sure that it is not in use.
			pq->active = node;

			// Execute the callback with lock released
			nni_mtx_unlock(&pq->mtx);
			node->cb(node->data);
			nni_mtx_lock(&pq->mtx);

			// We finished with this node.  If something
			// was blocked waiting for that, wake it up.
			pq->active = NULL;
			if (pq->wait == node) {
				pq->wait = NULL;
				nni_cv_wake(&pq->cv);
			}
		}
	}

	nni_mtx_unlock(&pq->mtx);
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	if (pq->started) {
		int      rv;
		uint64_t wakeval = 1;

		nni_mtx_lock(&pq->mtx);
		pq->close   = true;
		pq->started = false;
		rv          = write(pq->evfd, &wakeval, sizeof(wakeval));
		NNI_ASSERT(rv == sizeof(wakeval));
		nni_mtx_unlock(&pq->mtx);
	}
	nni_thr_fini(&pq->thr);

	if (pq->evfd >= 0) {
		close(pq->evfd);
		pq->evfd = -1;
	}

	close(pq->epfd);
	pq->epfd = -1;

	if (pq->nodes != NULL) {
		nni_idhash_fini(pq->nodes);
	}

	nni_mtx_fini(&pq->mtx);
}

static int
nni_posix_pollq_add_eventfd(nni_posix_pollq *pq)
{
	// add event fd so we can wake ourself on exit
	struct epoll_event ev;
	int                rv;

	memset(&ev, 0, sizeof(ev));

	pq->evfd = eventfd(0, EFD_NONBLOCK);
	if (pq->evfd == -1) {
		return (nni_plat_errno(errno));
	}

	ev.events   = EPOLLIN;
	ev.data.u64 = 0;

	rv = epoll_ctl(pq->epfd, EPOLL_CTL_ADD, pq->evfd, &ev);
	if (rv != 0) {
		return (nni_plat_errno(errno));
	}
	return (0);
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

	if ((pq->epfd = epoll_create1(0)) < 0) {
		return (nni_plat_errno(errno));
	}

	pq->evfd  = -1;
	pq->close = false;

	nni_mtx_init(&pq->mtx);
	nni_cv_init(&pq->cv, &pq->mtx);

	if (((rv = nni_idhash_init(&pq->nodes)) != 0) ||
	    ((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0) ||
	    ((rv = nni_posix_pollq_add_eventfd(pq)) != 0)) {
		nni_posix_pollq_destroy(pq);
		return (rv);
	}

	// Positive values only for node indices. (0 is reserved for eventfd).
	nni_idhash_set_limits(pq->nodes, 1, 0x7FFFFFFFu, 1);
	pq->started = true;
	nni_thr_run(&pq->thr);
	return (0);
}

// single global instance for now
static nni_posix_pollq nni_posix_global_pollq;

nni_posix_pollq *
nni_posix_pollq_get(int fd)
{
	NNI_ARG_UNUSED(fd);
	return (&nni_posix_global_pollq);
}

int
nni_posix_pollq_sysinit(void)
{
	return (nni_posix_pollq_create(&nni_posix_global_pollq));
}

void
nni_posix_pollq_sysfini(void)
{
	nni_posix_pollq_destroy(&nni_posix_global_pollq);
}

#endif // NNG_HAVE_EPOLL
