//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

#ifdef NNG_USE_POSIX_POLLQ_POLL

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// POSIX AIO using poll().  We use a single poll thread to perform
// I/O operations for the entire system.  This isn't entirely scalable,
// and it might be a good idea to create a few threads and group the
// I/O operations into separate pollers to limit the amount of work each
// thread does, and to scale across multiple cores.  For now we don't
// worry about it.

// nni_posix_pollq is a work structure used by the poller thread, that keeps
// track of all the underlying pipe handles and so forth being used by poll().
struct nni_posix_pollq {
	nni_mtx               mtx;
	nni_cv                cv;
	struct pollfd *       fds;
	int                   nfds;
	int                   wakewfd; // write side of waker pipe
	int                   wakerfd; // read side of waker pipe
	int                   close;   // request for worker to exit
	int                   started;
	nni_thr               thr;    // worker thread
	nni_list              polled; // polled nodes
	nni_list              armed;  // armed nodes
	nni_list              idle;   // idle nodes
	int                   nnodes; // num of nodes in nodes list
	int                   inpoll; // poller asleep in poll
	nni_posix_pollq_node *wait;   // cancel waiting on this
	nni_posix_pollq_node *active; // active node (in callback)
};

static int
nni_posix_pollq_poll_grow(nni_posix_pollq *pq)
{
	int            grow = pq->nnodes + 2; // one for us, one for waker
	struct pollfd *newfds;

	if (grow < pq->nfds) {
		return (0);
	}

	grow = grow + 128;

	if ((newfds = NNI_ALLOC_STRUCTS(newfds, grow)) == NULL) {
		return (NNG_ENOMEM);
	}

	if (pq->nfds != 0) {
		NNI_FREE_STRUCTS(pq->fds, pq->nfds);
	}
	pq->fds  = newfds;
	pq->nfds = grow;

	return (0);
}

static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *     pollq = arg;
	nni_posix_pollq_node *node;

	nni_mtx_lock(&pollq->mtx);
	for (;;) {
		int            rv;
		int            nfds;
		struct pollfd *fds;

		if (pollq->close) {
			break;
		}

		fds  = pollq->fds;
		nfds = 0;

		// The waker pipe is set up so that we will be woken
		// when it is written (this allows us to be signaled).
		fds[nfds].fd      = pollq->wakerfd;
		fds[nfds].events  = POLLIN;
		fds[nfds].revents = 0;
		nfds++;

		// Set up the poll list.
		while ((node = nni_list_first(&pollq->armed)) != NULL) {
			nni_list_remove(&pollq->armed, node);
			nni_list_append(&pollq->polled, node);
			fds[nfds].fd      = node->fd;
			fds[nfds].events  = node->events;
			fds[nfds].revents = 0;
			node->index       = nfds;
			nfds++;
		}

		// Now poll it.  We block indefinitely, since we use separate
		// timeouts to wake and remove the elements from the list.
		pollq->inpoll = 1;
		nni_mtx_unlock(&pollq->mtx);
		rv = poll(fds, nfds, -1);
		nni_mtx_lock(&pollq->mtx);
		pollq->inpoll = 0;

		if (rv < 0) {
			// This shouldn't happen really.  If it does, we
			// just try again.  (EINTR is probably the only
			// reasonable failure here, unless internal memory
			// allocations fail in the kernel, leading to EAGAIN.)
			continue;
		}

		// If the waker pipe was signaled, read from it.
		if (fds[0].revents & POLLIN) {
			NNI_ASSERT(fds[0].fd == pollq->wakerfd);
			nni_plat_pipe_clear(pollq->wakerfd);
		}

		while ((node = nni_list_first(&pollq->polled)) != NULL) {
			int index = node->index;

			// We remove ourselves from the polled list, and
			// then put it on either the idle or armed list
			// depending on whether it remains armed.
			node->index = 0;
			nni_list_remove(&pollq->polled, node);
			NNI_ASSERT(index > 0);
			if (fds[index].revents == 0) {
				// If still watching for events, return it
				// to the armed list.
				if (node->events) {
					nni_list_append(&pollq->armed, node);
				} else {
					nni_list_append(&pollq->idle, node);
				}
				continue;
			}

			// We are calling the callback, so disarm
			// all events; the node can rearm them in its
			// callback.
			node->revents = fds[index].revents;
			node->events &= ~node->revents;
			if (node->events == 0) {
				nni_list_append(&pollq->idle, node);
			} else {
				nni_list_append(&pollq->armed, node);
			}

			// Save the active node; we can notice this way
			// when it is busy, and avoid freeing it until
			// we are sure that it is not in use.
			pollq->active = node;

			// Execute the callback -- without locks held.
			nni_mtx_unlock(&pollq->mtx);
			node->cb(node->data);
			nni_mtx_lock(&pollq->mtx);

			// We finished with this node.  If something
			// was blocked waiting for that, wake it up.
			pollq->active = NULL;
			if (pollq->wait == node) {
				pollq->wait = NULL;
				nni_cv_wake(&pollq->cv);
			}
		}
	}
	nni_mtx_unlock(&pollq->mtx);
}

int
nni_posix_pollq_add(nni_posix_pollq_node *node)
{
	int              rv;
	nni_posix_pollq *pq;

	NNI_ASSERT(!nni_list_node_active(&node->node));

	pq = nni_posix_pollq_get(node->fd);
	if (node->pq != NULL) {
		return (NNG_ESTATE);
	}

	nni_mtx_lock(&pq->mtx);
	if (pq->close) {
		// This shouldn't happen!
		nni_mtx_unlock(&pq->mtx);
		return (NNG_ECLOSED);
	}
	node->pq = pq;
	if ((rv = nni_posix_pollq_poll_grow(pq)) != 0) {
		nni_mtx_unlock(&pq->mtx);
		return (rv);
	}
	pq->nnodes++;
	nni_list_append(&pq->idle, node);
	nni_mtx_unlock(&pq->mtx);
	return (0);
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
	node->pq = NULL;
	nni_mtx_lock(&pq->mtx);
	if (nni_list_node_active(&node->node)) {
		nni_list_node_remove(&node->node);
		pq->nnodes--;
	}
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
	NNI_LIST_NODE_INIT(&node->node);
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
	node->pq = NULL;
	nni_mtx_lock(&pq->mtx);
	while (pq->active == node) {
		pq->wait = node;
		nni_cv_wait(&pq->cv);
	}
	if (nni_list_node_active(&node->node)) {
		nni_list_node_remove(&node->node);
		pq->nnodes--;
	}
	if (pq->close) {
		nni_cv_wake(&pq->cv);
	}
	nni_mtx_unlock(&pq->mtx);
}

void
nni_posix_pollq_arm(nni_posix_pollq_node *node, int events)
{
	nni_posix_pollq *pq = node->pq;
	int              oevents;

	NNI_ASSERT(pq != NULL);

	nni_mtx_lock(&pq->mtx);
	oevents = node->events;
	node->events |= events;

	// We move this to the armed list if its not armed, or already
	// on the polled list.  The polled list would be the case where
	// the index is set to a positive value.
	if ((oevents == 0) && (events != 0) && (node->index < 1)) {
		nni_list_node_remove(&node->node);
		nni_list_append(&pq->armed, node);
	}
	if ((events != 0) && (oevents != events)) {
		// Possibly wake up poller since we're looking for new events.
		if (pq->inpoll) {
			nni_plat_pipe_raise(pq->wakewfd);
		}
	}
	nni_mtx_unlock(&pq->mtx);
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	if (pq->started) {
		nni_mtx_lock(&pq->mtx);
		pq->close   = 1;
		pq->started = 0;
		nni_plat_pipe_raise(pq->wakewfd);
		nni_mtx_unlock(&pq->mtx);
	}
	nni_thr_fini(&pq->thr);

	// All pipes should have been closed before this is called.
	NNI_ASSERT(nni_list_empty(&pq->polled));
	NNI_ASSERT(nni_list_empty(&pq->armed));
	NNI_ASSERT(nni_list_empty(&pq->idle));
	NNI_ASSERT(pq->nnodes == 0);

	if (pq->wakewfd >= 0) {
		nni_plat_pipe_close(pq->wakewfd, pq->wakerfd);
		pq->wakewfd = pq->wakerfd = -1;
	}
	if (pq->nfds != 0) {
		NNI_FREE_STRUCTS(pq->fds, pq->nfds);
		pq->fds  = NULL;
		pq->nfds = 0;
	}
	nni_mtx_fini(&pq->mtx);
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

	NNI_LIST_INIT(&pq->polled, nni_posix_pollq_node, node);
	NNI_LIST_INIT(&pq->armed, nni_posix_pollq_node, node);
	NNI_LIST_INIT(&pq->idle, nni_posix_pollq_node, node);
	pq->wakewfd = -1;
	pq->wakerfd = -1;
	pq->close   = 0;

	nni_mtx_init(&pq->mtx);
	nni_cv_init(&pq->cv, &pq->mtx);

	if (((rv = nni_posix_pollq_poll_grow(pq)) != 0) ||
	    ((rv = nni_plat_pipe_open(&pq->wakewfd, &pq->wakerfd)) != 0) ||
	    ((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0)) {
		nni_posix_pollq_destroy(pq);
		return (rv);
	}
	pq->started = 1;
	nni_thr_run(&pq->thr);
	return (0);
}

// We use a single pollq for the entire system, which means only a single
// thread is polling.  This may be somewhat less than optimally efficient,
// and it may be worth investigating having multiple threads to improve
// efficiency and scalability.  (This would shorten the linked lists,
// improving C10K scalability, and also allow us to engage multiple cores.)
// It's not entirely clear how many threads are "optimal".
static nni_posix_pollq nni_posix_global_pollq;

nni_posix_pollq *
nni_posix_pollq_get(int fd)
{
	NNI_ARG_UNUSED(fd);
	// This is the point where we could choose a pollq based on FD.
	return (&nni_posix_global_pollq);
}

int
nni_posix_pollq_sysinit(void)
{
	int rv;

	rv = nni_posix_pollq_create(&nni_posix_global_pollq);
	return (rv);
}

void
nni_posix_pollq_sysfini(void)
{
	nni_posix_pollq_destroy(&nni_posix_global_pollq);
}

#endif // NNG_USE_POSIX_POLLQ_POLL
