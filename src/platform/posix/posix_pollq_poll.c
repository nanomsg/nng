//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/defs.h"
#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
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

typedef struct nni_posix_pollq {
	nni_mtx         mtx;
	nni_cv          cv;
	int             wakewfd; // write side of waker pipe
	int             wakerfd; // read side of waker pipe
	nni_thr         thr;     // worker thread
	nni_list        pollq;   // armed nodes - only updated by thread
	nni_list        reapq;   // list of nodes to reap, protected by mtx
	nni_list        addq;    // list of nodes to add, protected by mtx
	struct pollfd  *fds;
	nni_posix_pfd **pfds;
	unsigned        nalloc;
	bool            closed;
} nni_posix_pollq;

static nni_posix_pollq nni_posix_global_pollq;

void
nni_posix_pfd_init(nni_posix_pfd *pfd, int fd, nni_posix_pfd_cb cb, void *arg)
{
	nni_posix_pollq *pq = &nni_posix_global_pollq;

	// Set this is as soon as possible (narrow the close-exec race as
	// much as we can; better options are system calls that suppress
	// this behavior from descriptor creation.)
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);
#ifdef SO_NOSIGPIPE
	// Darwin lacks MSG_NOSIGNAL, but has a socket option.
	// If this code is getting used, you really should be using the
	// kqueue poller, or you need to upgrade your older system.
	int one = 1;
	(void) setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

	NNI_LIST_NODE_INIT(&pfd->node);
	NNI_LIST_NODE_INIT(&pfd->reap);
	pfd->fd     = fd;
	pfd->cb     = cb;
	pfd->arg    = arg;
	pfd->pq     = pq;
	pfd->reaped = false;
	nni_atomic_init(&pfd->events);
	nni_mtx_lock(&pq->mtx);
	nni_list_append(&pq->addq, pfd);
	nni_mtx_unlock(&pq->mtx);
	nni_plat_pipe_raise(pq->wakewfd);
}

int
nni_posix_pfd_fd(nni_posix_pfd *pfd)
{
	return (pfd->fd);
}

void
nni_posix_pfd_close(nni_posix_pfd *pfd)
{
	(void) shutdown(pfd->fd, SHUT_RDWR);
}

void
nni_posix_pfd_stop(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq = pfd->pq;

	if (pq == NULL) {
		return;
	}

	nni_posix_pfd_close(pfd);

	nni_mtx_lock(&pq->mtx);
	if (!pfd->reaped) {
		if ((!nni_thr_is_self(&pq->thr)) && (!pq->closed)) {
			// it might have been on the addq
			nni_list_node_remove(&pfd->reap);
			nni_list_append(&pq->reapq, pfd);
			nni_plat_pipe_raise(pq->wakewfd);
			while (!pfd->reaped) {
				nni_cv_wait(&pq->cv);
			}
		} else {
			nni_list_node_remove(&pfd->node);
			nni_list_node_remove(&pfd->reap);
			pfd->reaped = true;
		}
	}
	nni_mtx_unlock(&pq->mtx);
}

void
nni_posix_pfd_fini(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq = pfd->pq;

	if (pq == NULL) {
		return;
	}
	nni_posix_pfd_stop(pfd);

	// We're exclusive now.
	(void) close(pfd->fd);
}

int
nni_posix_pfd_arm(nni_posix_pfd *pfd, unsigned events)
{
	nni_posix_pollq *pq = pfd->pq;

	(void) nni_atomic_or(&pfd->events, (int) events);

	// If we're running on the callback, then don't bother to kick
	// the pollq again.  This is necessary because we cannot modify
	// the poller while it is polling.
	if (!nni_thr_is_self(&pq->thr)) {
		nni_plat_pipe_raise(pq->wakewfd);
	}
	return (0);
}

static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *pq   = arg;
	struct pollfd   *fds  = pq->fds;
	nni_posix_pfd  **pfds = pq->pfds;
	nni_posix_pfd   *pfd;
	int              nfds;
	int              events;

	for (;;) {

		// The waker pipe is set up so that we will be woken
		// when it is written (this allows us to be signaled).
		fds[0].fd         = pq->wakerfd;
		fds[0].events     = POLLIN;
		fds[0].revents    = 0;
		pfds[pq->wakerfd] = NULL;
		nfds              = 1;

		// Set up the poll list.
		NNI_LIST_FOREACH (&pq->pollq, pfd) {

			events = nni_atomic_get(&pfd->events);

			if (events != 0) {
				fds[nfds].fd      = pfd->fd;
				fds[nfds].events  = (unsigned) events;
				fds[nfds].revents = 0;
				nfds++;
			}
		}

		// We could get the result from poll, and avoid iterating
		// over the entire set of pollfds, but since on average we
		// will be walking half the list, doubling the work we do
		// (the condition with a potential pipeline stall) seems like
		// adding complexity with no real benefit.  It also makes the
		// worst case even worse.
		(void) poll(fds, nfds, -1);

		// If the waker pipe was signaled, read from it.

		bool update = false;
		bool stop   = false;
		for (int i = 0; i < nfds; i++) {
			int fd = fds[i].fd;
			events = (int) fds[i].revents;
			pfd    = pfds[fd];
			if (events == 0) {
				continue;
			}
			if (pfd == NULL || fd == pq->wakerfd) {
				update = true;
				if (fd == pq->wakerfd &&
				    ((events & POLLHUP) != 0)) {
					stop = true;
				}
			} else {
				if ((events & (POLLIN | POLLOUT)) != 0) {
					// don't emit pollhup yet, we want
					// to finish reading.
					events &= ~POLLHUP;
				}
				(void) nni_atomic_and(&pfd->events, ~events);

				pfd->cb(pfd->arg, events);
			}
		}

		if (stop) {
			break;
		}
		if (update) {
			// process adds first
			nni_mtx_lock(&pq->mtx);
			nni_plat_pipe_clear(pq->wakerfd);
			while ((pfd = nni_list_first(&pq->addq)) != NULL) {
				nni_list_remove(&pq->addq, pfd);
				nni_list_append(&pq->pollq, pfd);
				pfds[pfd->fd] = pfd;
			}
			// then reaps
			while ((pfd = nni_list_first(&pq->reapq)) != NULL) {
				nni_list_node_remove(&pfd->node);
				nni_list_node_remove(&pfd->reap);
				pfd->reaped   = true;
				pfds[pfd->fd] = NULL;
			}
			nni_cv_wake(&pq->cv);
			nni_mtx_unlock(&pq->mtx);
		}
	}
	nni_mtx_lock(&pq->mtx);
	nni_plat_pipe_clear(pq->wakerfd);
	while (((pfd = nni_list_first(&pq->reapq)) != NULL) ||
	    ((pfd = nni_list_first(&pq->addq)) != NULL) ||
	    ((pfd = nni_list_first(&pq->pollq)) != NULL)) {
		nni_list_node_remove(&pfd->node);
		nni_list_node_remove(&pfd->reap);
		pfd->reaped   = true;
		pfds[pfd->fd] = NULL;
	}
	nni_cv_wake(&pq->cv);
	nni_mtx_unlock(&pq->mtx);
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	nni_plat_pipe_raise(pq->wakewfd);

	(void) close(pq->wakewfd);
	nni_thr_fini(&pq->thr);
	(void) close(pq->wakerfd);
	nni_cv_fini(&pq->cv);
	nni_mtx_fini(&pq->mtx);
	if (pq->fds != NULL) {
		NNI_FREE_STRUCTS(pq->fds, pq->nalloc);
		pq->fds = NULL;
	}
	if (pq->pfds != NULL) {
		NNI_FREE_STRUCTS(pq->pfds, pq->nalloc);
		pq->pfds = NULL;
	}
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

	NNI_LIST_INIT(&pq->pollq, nni_posix_pfd, node);
	NNI_LIST_INIT(&pq->reapq, nni_posix_pfd, reap);
	NNI_LIST_INIT(&pq->addq, nni_posix_pfd, reap);
	nni_mtx_init(&pq->mtx);
	nni_cv_init(&pq->cv, &pq->mtx);

	pq->closed = false;
#if NNG_MAX_OPEN
	pq->nalloc = NNG_MAX_OPEN;
#else
	struct rlimit limits;
	pq->nalloc = 0;
	if (getrlimit(RLIMIT_NOFILE, &limits) == 0) {
		if (limits.rlim_cur != RLIM_INFINITY &&
		    limits.rlim_cur < 1U << 20) {
			pq->nalloc = (unsigned) limits.rlim_cur;
		} else if (limits.rlim_max != RLIM_INFINITY &&
		    limits.rlim_max < 1U << 20) {
			pq->nalloc = (unsigned) limits.rlim_max;
		}
	}
#endif
	if (pq->nalloc == 0) {
		// 5K files default.  If you need more, either set
		// rlimit properly, or
		pq->nalloc = 5000;
	}
	if (pq->nalloc < 128) { // 20 is minimum allowed per POSIX, but we need
		                // more for testing
		pq->nalloc = 20;
	}
	if (((pq->pfds = NNI_ALLOC_STRUCTS(pq->pfds, pq->nalloc)) == NULL) ||
	    ((pq->fds = NNI_ALLOC_STRUCTS(pq->fds, pq->nalloc)) == NULL)) {
		return (NNG_ENOMEM);
	}

	if ((rv = nni_plat_pipe_open(&pq->wakewfd, &pq->wakerfd)) != 0) {
		return (rv);
	}
	if ((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0) {
		nni_plat_pipe_close(pq->wakewfd, pq->wakerfd);
		return (rv);
	}
	nni_thr_set_name(&pq->thr, "nng:poll:poll");
	nni_thr_run(&pq->thr);
	return (0);
}

int
nni_posix_pollq_sysinit(nng_init_params *params)
{
	NNI_ARG_UNUSED(params);
	return (nni_posix_pollq_create(&nni_posix_global_pollq));
}

void
nni_posix_pollq_sysfini(void)
{
	nni_posix_pollq_destroy(&nni_posix_global_pollq);
}
