//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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
	nni_mtx        mtx;
	nni_cv         cv;
	struct pollfd *fds;
	struct pollfd *newfds;
	int            nfds;
	int            nnewfds;
	int            wakewfd; // write side of waker pipe
	int            wakerfd; // read side of waker pipe
	int            close;   // request for worker to exit
	int            started;
	nni_thr        thr;    // worker thread
	nni_list       nodes;  // poll list
	nni_list       notify; // notify list
	int            nnodes; // num of nodes in nodes list
	int            cancel; // waiters for cancellation
	int            inpoll; // poller asleep in poll

	nni_posix_pollq_node *active; // active node (in callback)
};

static int
nni_posix_pollq_poll_grow(nni_posix_pollq *pq)
{
	int            grow = pq->nnodes + 2; // one for us, one for waker
	int            noldfds;
	struct pollfd *oldfds;
	struct pollfd *newfds;

	if ((grow < pq->nfds) || (grow < pq->nnewfds)) {
		return (0);
	}

	grow = grow + 128;

	// Maybe we are adding a *lot* of pipes at once, and have to grow
	// multiple times before the poller gets scheduled.  In that case
	// toss the old array before we finish.
	oldfds  = pq->newfds;
	noldfds = pq->nnewfds;

	if ((newfds = nni_alloc(grow * sizeof(struct pollfd))) == NULL) {
		return (NNG_ENOMEM);
	}

	pq->newfds  = newfds;
	pq->nnewfds = grow;

	if (noldfds != 0) {
		nni_free(oldfds, noldfds * sizeof(struct pollfd));
	}
	return (0);
}

static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *     pollq = arg;
	nni_posix_pollq_node *node, *nextnode;

	nni_mtx_lock(&pollq->mtx);
	for (;;) {
		int            rv;
		int            nfds;
		struct pollfd *fds;

		if (pollq->close) {
			break;
		}

		if (pollq->newfds != NULL) {
			// We have "grown" by the caller.  Free up the old
			// space, and start using the new.
			nni_free(
			    pollq->fds, pollq->nfds * sizeof(struct pollfd));
			pollq->fds    = pollq->newfds;
			pollq->nfds   = pollq->nnewfds;
			pollq->newfds = NULL;
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
		NNI_LIST_FOREACH (&pollq->nodes, node) {
			fds[nfds].fd      = node->fd;
			fds[nfds].events  = node->armed;
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

		// Now we iterate through all the nodes.  Note that one
		// may have been added or removed.  New pipedescs will have
		// their index set to -1.  Removed ones will just be absent.
		// Note that we may remove the pipedesc from the list, so we
		// have to use a custom iterator.
		nextnode = nni_list_first(&pollq->nodes);
		while ((node = nextnode) != NULL) {
			int index;

			// Save the nextpd for our next iteration.  This
			// way we can remove the PD from the list without
			// breaking the iteration.

			nextnode = nni_list_next(&pollq->nodes, node);

			// If index is less than 1, then we have just added
			// this and there is no FD for it in the pollfds.
			if ((index = node->index) < 1) {
				continue;
			}

			if (fds[index].revents == 0) {
				continue;
			}

			// Clear the index for the next time around.
			node->index   = 0;
			node->revents = fds[index].revents;

			// Now we move this node to the callback list.
			node->armed = 0;
			nni_list_remove(&pollq->nodes, node);
			nni_list_append(&pollq->notify, node);
			pollq->nnodes--;
		}

		// Finally we can call the callbacks.  We record the
		// active callback so any attempt to cancel blocks until
		// the callback is finished.
		while ((node = nni_list_first(&pollq->notify)) != NULL) {
			nni_list_remove(&pollq->notify, node);
			if (node->cb != NULL) {
				pollq->active = node;
				nni_mtx_unlock(&pollq->mtx);
				node->cb(node->data);
				nni_mtx_lock(&pollq->mtx);
				pollq->active = NULL;
			}
		}

		// Wake any cancelers.
		if (pollq->cancel != 0) {
			pollq->cancel = 0;
			nni_cv_wake(&pollq->cv);
		}
	}
	nni_mtx_unlock(&pollq->mtx);
}

void
nni_posix_pollq_cancel(nni_posix_pollq *pq, nni_posix_pollq_node *node)
{
	nni_mtx_lock(&pq->mtx);
	while (pq->active == node) {
		pq->cancel++;
		nni_cv_wait(&pq->cv);
	}
	if (nni_list_active(&pq->nodes, node)) {
		node->armed = 0;
		nni_list_remove(&pq->nodes, node);
	}
	// Since we're not removing the fd from the outstanding poll, we
	// may get an event.  In that case, we'll wake and rebuild the
	// pollset without it, with no further action.  Otherwise having the
	// poll present does no harm beyond the "spurious" wake of the poller
	// thread.  (If we had port_disassociate or somesuch, this would be
	// a great time for that.)
	nni_mtx_unlock(&pq->mtx);
}

int
nni_posix_pollq_submit(nni_posix_pollq *pq, nni_posix_pollq_node *node)
{
	int wake;
	int rv;
	int evs;

	nni_mtx_lock(&pq->mtx);

	if (node->events == 0) {
		// Nothing to schedule?
		nni_mtx_unlock(&pq->mtx);
		return (0);
	}

	if (node->armed == 0) {
		NNI_ASSERT(!nni_list_active(&pq->nodes, node));

		rv = nni_posix_pollq_poll_grow(pq);
		if (rv != 0) {
			nni_mtx_unlock(&pq->mtx);
			return (rv);
		}

		nni_list_append(&pq->nodes, node);
		pq->nnodes++;
	}

	node->armed |= node->events;

	// Wake up the poller since we're adding a new poll, but only bother
	// if it's already asleep.  (Frequently it will *not* be.)
	if (pq->inpoll) {
		nni_plat_pipe_raise(pq->wakewfd);
	}
	nni_mtx_unlock(&pq->mtx);
	return (0);
}

static void
nni_posix_pollq_fini(nni_posix_pollq *pq)
{
	if (pq->started) {
		nni_mtx_lock(&pq->mtx);
		pq->close   = 1;
		pq->started = 0;
		nni_plat_pipe_raise(pq->wakewfd);

		// All pipes should have been closed before this is called.
		NNI_ASSERT(nni_list_empty(&pq->nodes));
		nni_mtx_unlock(&pq->mtx);
	}

	nni_thr_fini(&pq->thr);
	if (pq->wakewfd >= 0) {
		nni_plat_pipe_close(pq->wakewfd, pq->wakerfd);
		pq->wakewfd = pq->wakerfd = -1;
	}
	nni_free(pq->newfds, pq->nnewfds * sizeof(struct pollfd));
	nni_free(pq->fds, pq->nfds * sizeof(struct pollfd));
	nni_mtx_fini(&pq->mtx);
}

static int
nni_posix_pollq_init(nni_posix_pollq *pq)
{
	int rv;

	NNI_LIST_INIT(&pq->nodes, nni_posix_pollq_node, node);
	NNI_LIST_INIT(&pq->notify, nni_posix_pollq_node, node);
	pq->wakewfd = -1;
	pq->wakerfd = -1;
	pq->close   = 0;

	if (((rv = nni_mtx_init(&pq->mtx)) != 0) ||
	    ((rv = nni_cv_init(&pq->cv, &pq->mtx)) != 0) ||
	    ((rv = nni_posix_pollq_poll_grow(pq)) != 0) ||
	    ((rv = nni_plat_pipe_open(&pq->wakewfd, &pq->wakerfd)) != 0) ||
	    ((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0)) {
		nni_posix_pollq_fini(pq);
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
	// This is the point where we could choose a pollq based on FD.
	return (&nni_posix_global_pollq);
}

int
nni_posix_pollq_sysinit(void)
{
	int rv;

	rv = nni_posix_pollq_init(&nni_posix_global_pollq);
	return (rv);
}

void
nni_posix_pollq_sysfini(void)
{
	nni_posix_pollq_fini(&nni_posix_global_pollq);
}

#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_pollq_poll_used = 0;

#endif // NNG_USE_POSIX_POLLQ_POLL
