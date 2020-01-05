//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h> /* for strerror() */
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

typedef struct nni_posix_pollq nni_posix_pollq;

#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC 0
#endif
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK 0
#endif

#define NNI_MAX_EPOLL_EVENTS 64

// flags we always want enabled as long as at least one event is active
#define NNI_EPOLL_FLAGS ((unsigned) EPOLLONESHOT | (unsigned) EPOLLERR)

// Locking strategy:
//
// The pollq mutex protects its own reapq, close state, and the close
// state of the individual pfds.  It also protects the pfd cv, which is
// only signaled when the pfd is closed.  This mutex is only acquired
// when shutting down the pollq, or closing a pfd.  For normal hot-path
// operations we don't need it.
//
// The pfd mutex protects the pfd's own "closing" flag (test and set),
// the callback and arg, and its event mask.  This mutex is used a lot,
// but it should be uncontended excepting possibly when closing.

// nni_posix_pollq is a work structure that manages state for the epoll-based
// pollq implementation
struct nni_posix_pollq {
	nni_mtx  mtx;
	int      epfd;  // epoll handle
	int      evfd;  // event fd (to wake us for other stuff)
	bool     close; // request for worker to exit
	nni_thr  thr;   // worker thread
	nni_list reapq;
};

struct nni_posix_pfd {
	nni_posix_pollq *pq;
	nni_list_node    node;
	int              fd;
	nni_posix_pfd_cb cb;
	void *           arg;
	bool             closed;
	bool             closing;
	bool             reap;
	unsigned         events;
	nni_mtx          mtx;
	nni_cv           cv;
};

// single global instance for now.
static nni_posix_pollq nni_posix_global_pollq;

int
nni_posix_pfd_init(nni_posix_pfd **pfdp, int fd)
{
	nni_posix_pfd *    pfd;
	nni_posix_pollq *  pq;
	struct epoll_event ev;
	int                rv;

	pq = &nni_posix_global_pollq;

	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);

	if ((pfd = NNI_ALLOC_STRUCT(pfd)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&pfd->mtx);
	nni_cv_init(&pfd->cv, &pq->mtx);

	nni_mtx_lock(&pfd->mtx);
	pfd->pq      = pq;
	pfd->fd      = fd;
	pfd->cb      = NULL;
	pfd->arg     = NULL;
	pfd->events  = 0;
	pfd->closing = false;
	pfd->closed  = false;

	NNI_LIST_NODE_INIT(&pfd->node);
	nni_mtx_unlock(&pfd->mtx);

	// notifications disabled to begin with
	ev.events   = 0;
	ev.data.ptr = pfd;

	if (epoll_ctl(pq->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
		rv = nni_plat_errno(errno);
		nni_cv_fini(&pfd->cv);
		NNI_FREE_STRUCT(pfd);
		return (rv);
	}

	*pfdp = pfd;
	return (0);
}

int
nni_posix_pfd_arm(nni_posix_pfd *pfd, unsigned events)
{
	nni_posix_pollq *pq = pfd->pq;

	// NB: We depend on epoll event flags being the same as their POLLIN
	// equivalents.  I.e. POLLIN == EPOLLIN, POLLOUT == EPOLLOUT, and so
	// forth.  This turns out to be true both for Linux and the illumos
	// epoll implementation.

	nni_mtx_lock(&pfd->mtx);
	if (!pfd->closing) {
		struct epoll_event ev;
		pfd->events |= events;
		events = pfd->events;

		ev.events   = events | NNI_EPOLL_FLAGS;
		ev.data.ptr = pfd;

		if (epoll_ctl(pq->epfd, EPOLL_CTL_MOD, pfd->fd, &ev) != 0) {
			int rv = nni_plat_errno(errno);
			nni_mtx_unlock(&pfd->mtx);
			return (rv);
		}
	}
	nni_mtx_unlock(&pfd->mtx);
	return (0);
}

int
nni_posix_pfd_fd(nni_posix_pfd *pfd)
{
	return (pfd->fd);
}

void
nni_posix_pfd_set_cb(nni_posix_pfd *pfd, nni_posix_pfd_cb cb, void *arg)
{
	nni_mtx_lock(&pfd->mtx);
	pfd->cb  = cb;
	pfd->arg = arg;
	nni_mtx_unlock(&pfd->mtx);
}

void
nni_posix_pfd_close(nni_posix_pfd *pfd)
{
	nni_mtx_lock(&pfd->mtx);
	if (!pfd->closing) {
		nni_posix_pollq *  pq = pfd->pq;
		struct epoll_event ev; // Not actually used.
		pfd->closing = true;

		(void) shutdown(pfd->fd, SHUT_RDWR);
		(void) epoll_ctl(pq->epfd, EPOLL_CTL_DEL, pfd->fd, &ev);
	}
	nni_mtx_unlock(&pfd->mtx);
}

void
nni_posix_pfd_fini(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq = pfd->pq;

	nni_posix_pfd_close(pfd);

	// We have to synchronize with the pollq thread (unless we are
	// on that thread!)
	NNI_ASSERT(!nni_thr_is_self(&pq->thr));

	uint64_t one = 1;

	nni_mtx_lock(&pq->mtx);
	nni_list_append(&pq->reapq, pfd);

	// Wake the remote side.  For now we assume this always
	// succeeds.  The only failure modes here occur when we
	// have already excessively signaled this (2^64 times
	// with no read!!), or when the evfd is closed, or some
	// kernel bug occurs.  Those errors would manifest as
	// a hang waiting for the poller to reap the pfd in fini,
	// if it were possible for them to occur.  (Barring other
	// bugs, it isn't.)
	(void) write(pq->evfd, &one, sizeof(one));

	while (!pfd->closed) {
		nni_cv_wait(&pfd->cv);
	}
	nni_mtx_unlock(&pq->mtx);

	// We're exclusive now.

	(void) close(pfd->fd);
	nni_cv_fini(&pfd->cv);
	nni_mtx_fini(&pfd->mtx);
	NNI_FREE_STRUCT(pfd);
}

static void
nni_posix_pollq_reap(nni_posix_pollq *pq)
{
	nni_posix_pfd *pfd;
	nni_mtx_lock(&pq->mtx);
	while ((pfd = nni_list_first(&pq->reapq)) != NULL) {
		nni_list_remove(&pq->reapq, pfd);

		// Let fini know we're done with it, and it's safe to
		// remove.
		pfd->closed = true;
		nni_cv_wake(&pfd->cv);
	}
	nni_mtx_unlock(&pq->mtx);
}

static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *  pq = arg;
	struct epoll_event events[NNI_MAX_EPOLL_EVENTS];

	for (;;) {
		int  n;
		bool reap = false;

		n = epoll_wait(pq->epfd, events, NNI_MAX_EPOLL_EVENTS, -1);
		if ((n < 0) && (errno == EBADF)) {
			// Epoll fd closed, bail.
			return;
		}

		// dispatch events
		for (int i = 0; i < n; ++i) {
			const struct epoll_event *ev;

			ev = &events[i];
			// If the waker pipe was signaled, read from it.
			if ((ev->data.ptr == NULL) &&
			    (ev->events & (unsigned) POLLIN)) {
				uint64_t clear;
				(void) read(pq->evfd, &clear, sizeof(clear));
				reap = true;
			} else {
				nni_posix_pfd *  pfd = ev->data.ptr;
				nni_posix_pfd_cb cb;
				void *           cbarg;
				unsigned         mask;

				mask = ev->events &
				    ((unsigned) EPOLLIN | (unsigned) EPOLLOUT |
				        (unsigned) EPOLLERR);

				nni_mtx_lock(&pfd->mtx);
				pfd->events &= ~mask;
				cb    = pfd->cb;
				cbarg = pfd->arg;
				nni_mtx_unlock(&pfd->mtx);

				// Execute the callback with lock released
				if (cb != NULL) {
					cb(pfd, mask, cbarg);
				}
			}
		}

		if (reap) {
			nni_posix_pollq_reap(pq);
			nni_mtx_lock(&pq->mtx);
			if (pq->close) {
				nni_mtx_unlock(&pq->mtx);
				return;
			}
			nni_mtx_unlock(&pq->mtx);
		}
	}
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	uint64_t one = 1;

	nni_mtx_lock(&pq->mtx);
	pq->close = true;
	(void) write(pq->evfd, &one, sizeof(one));
	nni_mtx_unlock(&pq->mtx);

	nni_thr_fini(&pq->thr);

	close(pq->evfd);
	close(pq->epfd);

	nni_mtx_fini(&pq->mtx);
}

static int
nni_posix_pollq_add_eventfd(nni_posix_pollq *pq)
{
	// add event fd so we can wake ourself on exit
	struct epoll_event ev;
	int                fd;

	memset(&ev, 0, sizeof(ev));

	if ((fd = eventfd(0, EFD_NONBLOCK)) < 0) {
		return (nni_plat_errno(errno));
	}
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);

	// This is *NOT* one shot.  We want to wake EVERY single time.
	ev.events   = EPOLLIN;
	ev.data.ptr = 0;

	if (epoll_ctl(pq->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
		(void) close(fd);
		return (nni_plat_errno(errno));
	}
	pq->evfd = fd;
	return (0);
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

#if NNG_HAVE_EPOLL_CREATE1
	if ((pq->epfd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
		return (nni_plat_errno(errno));
	}
#else
	// Old Linux.  Size is a "hint" about number of descriptors.
	// Hopefully not a hard limit, and not used in modern Linux.
	if ((pq->epfd = epoll_create(16)) < 0) {
		return (nni_plat_errno(errno));
	}
	(void) fcntl(pq->epfd, F_SETFD, FD_CLOEXEC);
#endif

	pq->close = false;

	NNI_LIST_INIT(&pq->reapq, nni_posix_pfd, node);
	nni_mtx_init(&pq->mtx);

	if ((rv = nni_posix_pollq_add_eventfd(pq)) != 0) {
		(void) close(pq->epfd);
		nni_mtx_fini(&pq->mtx);
		return (rv);
	}
	if ((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0) {
		(void) close(pq->epfd);
		(void) close(pq->evfd);
		nni_mtx_fini(&pq->mtx);
		return (rv);
	}
	nni_thr_run(&pq->thr);
	return (0);
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
