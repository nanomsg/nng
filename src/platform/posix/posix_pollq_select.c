//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// POSIX AIO using select().  We use a single poll thread to perform
// I/O operations for the entire system.  This is the worst form of
// I/O multiplexing, but short of using threads or spin-polling from
// a single thread, this is our only reasonable solution.
//
// Note that select() is not scalable, and we will be limited to a small
// number of open files/sockets.  As such it is is not suitable for use
// on large servers. However, this may be enough for use in constrained
// systems that are not likely to have many open files anyway.
//

typedef struct nni_posix_pollq {
	nni_mtx               mtx;
	int                   wakewfd; // write side of waker pipe
	int                   wakerfd; // read side of waker pipe
	bool                  closing; // request for worker to exit
	bool                  closed;
	nni_thr               thr; // worker thread
	int                   maxfd;
	struct nni_posix_pfd *pfds[FD_SETSIZE];
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

	if (fd >= FD_SETSIZE) {
		return;
	}
	nni_mtx_init(&pfd->mtx);
	nni_cv_init(&pfd->cv, &pq->mtx);
	pfd->fd      = fd;
	pfd->events  = 0;
	pfd->cb      = cb;
	pfd->arg     = arg;
	pfd->pq      = pq;
	pfd->stopped = false;
	pfd->reap    = false;
	nni_mtx_lock(&pq->mtx);
	pq->pfds[fd] = pfd;
	if (fd > pq->maxfd) {
		pq->maxfd = fd;
	}
	nni_mtx_unlock(&pq->mtx);
}

int
nni_posix_pfd_fd(nni_posix_pfd *pfd)
{
	return (pfd->fd);
}

void
nni_posix_pfd_close(nni_posix_pfd *pfd)
{
	if (pfd->pq != NULL) {
		(void) shutdown(pfd->fd, SHUT_RDWR);
	}
}

void
nni_posix_pfd_stop(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq = pfd->pq;
	if (pq == NULL) {
		return;
	}
	nni_posix_pfd_close(pfd);
	NNI_ASSERT(!nni_thr_is_self(&pq->thr));

	nni_mtx_lock(&pq->mtx);
	if (!pfd->stopped) {
		pfd->stopped = true;
		pfd->reap    = true;
		nni_plat_pipe_raise(pq->wakewfd);
		while (pfd->reap) {
			nni_cv_wait(&pfd->cv);
		}
	}
	nni_mtx_unlock(&pq->mtx);
}

void
nni_posix_pfd_fini(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq = pfd->pq;
	int              fd = pfd->fd;

	if (pq == NULL) {
		return;
	}

	nni_posix_pfd_stop(pfd);
	NNI_ASSERT(!nni_thr_is_self(&pq->thr));

	// We're exclusive now.
	(void) close(fd);
	nni_cv_fini(&pfd->cv);
	nni_mtx_fini(&pfd->mtx);
}

int
nni_posix_pfd_arm(nni_posix_pfd *pfd, unsigned events)
{
	nni_posix_pollq *pq = pfd->pq;

	nni_mtx_lock(&pq->mtx);
	pfd->events |= events;
	nni_mtx_unlock(&pq->mtx);

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
	nni_posix_pollq *pq = arg;
	fd_set           rfds;
	fd_set           wfds;
	fd_set           efds;
	int              maxfd;

	for (;;) {
		unsigned       events;
		nni_posix_pfd *pfd;

		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);

		// The waker pipe is set up so that we will be woken
		// when it is written (this allows us to be signaled).
		FD_SET(pq->wakerfd, &rfds);
		FD_SET(pq->wakerfd, &efds);

		nni_plat_pipe_clear(pq->wakerfd);
		nni_mtx_lock(&pq->mtx);

		// If we're closing down, bail now.  This is done *after* we
		// have ensured that the reapq is empty.  Anything still in
		// the pollq is not going to receive further callbacks.
		if (pq->closing) {
			for (int fd = 0; fd <= pq->maxfd; fd++) {
				if ((pfd = pq->pfds[fd]) != NULL) {
					pq->pfds[fd] = NULL;
					pfd->reap    = false;
					nni_cv_wake(&pfd->cv);
				}
			}
			pq->closed = true;
			nni_mtx_unlock(&pq->mtx);
			break;
		}

		// Set up the poll list.
		maxfd = pq->wakerfd;
		for (int fd = 0; fd <= pq->maxfd; fd++) {
			if ((pfd = pq->pfds[fd]) == NULL) {
				continue;
			}
			NNI_ASSERT(pfd->fd == fd);
			if (pfd->reap) {
				pq->pfds[fd] = NULL;
				pfd->reap    = false;
				nni_cv_wake(&pfd->cv);
				continue;
			}
			events = pfd->events;

			if (events != 0) {
				if (events & NNI_POLL_IN) {
					FD_SET(fd, &rfds);
				}
				if (events & NNI_POLL_OUT) {
					FD_SET(fd, &wfds);
				}
				FD_SET(fd, &efds);
				if (maxfd < fd) {
					maxfd = fd;
				}
			}
		}
		while (pq->maxfd > 0 && (pq->pfds[pq->maxfd] == NULL)) {
			pq->maxfd--;
		}
		nni_mtx_unlock(&pq->mtx);

		// We could get the result from poll, and avoid iterating
		// over the entire set of pollfds, but since on average we
		// will be walking half the list, doubling the work we do
		// (the condition with a potential pipeline stall) seems like
		// adding complexity with no real benefit.  It also makes the
		// worst case even worse.
		(void) select(maxfd + 1, &rfds, &wfds, &efds, NULL);

		nni_mtx_lock(&pq->mtx);
		for (int fd = 0; fd <= maxfd; fd++) {
			events = 0;
			if (FD_ISSET(fd, &rfds)) {
				events |= NNI_POLL_IN;
			}
			if (FD_ISSET(fd, &wfds)) {
				events |= NNI_POLL_OUT;
			}
			if (FD_ISSET(fd, &efds)) {
				events |= NNI_POLL_HUP;
			}
			if (events != 0) {
				if ((pfd = pq->pfds[fd]) != NULL) {
					pfd->events &= ~events;

					nni_mtx_unlock(&pq->mtx);
					pfd->cb(pfd->arg, events);
					nni_mtx_lock(&pq->mtx);
				}
			}
		}
		nni_mtx_unlock(&pq->mtx);
	}
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	nni_mtx_lock(&pq->mtx);
	pq->closing = true;
	nni_mtx_unlock(&pq->mtx);

	nni_plat_pipe_raise(pq->wakewfd);

	close(pq->wakewfd);
	nni_thr_fini(&pq->thr);
	close(pq->wakerfd);
	// nni_plat_pipe_close(pq->wakewfd, pq->wakerfd);
	nni_mtx_fini(&pq->mtx);
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

	pq->closing = false;
	pq->closed  = false;

	if ((rv = nni_plat_pipe_open(&pq->wakewfd, &pq->wakerfd)) != 0) {
		return (rv);
	}
	if ((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0) {
		nni_plat_pipe_close(pq->wakewfd, pq->wakerfd);
		return (rv);
	}
	nni_thr_set_name(&pq->thr, "nng:poll:select");
	nni_mtx_init(&pq->mtx);
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
