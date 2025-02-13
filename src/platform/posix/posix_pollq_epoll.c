//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
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

#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC 0
#endif
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK 0
#endif

#define NNI_MAX_EPOLL_EVENTS 64

// nni_posix_pollq is a work structure that manages state for the epoll-based
// pollq implementation
typedef struct nni_posix_pollq {
	nni_mtx  mtx;
	nni_cv   cv;
	int      epfd;  // epoll handle
	int      evfd;  // event fd (to wake us for other stuff)
	bool     close; // request for worker to exit
	bool     init;
	nni_thr  thr; // worker thread
	nni_list reapq;
} nni_posix_pollq;

// single global instance for now.
static nni_posix_pollq *nni_epoll_pqs;
static int              nni_epoll_npq;

void
nni_posix_pfd_init(nni_posix_pfd *pfd, int fd, nni_posix_pfd_cb cb, void *arg)
{
	nni_posix_pollq *pq;

	pq = &nni_epoll_pqs[fd % nni_epoll_npq];

	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);

	nni_atomic_init(&pfd->events);
	nni_atomic_flag_reset(&pfd->stopped);
	nni_atomic_flag_reset(&pfd->closing);

	pfd->pq    = pq;
	pfd->fd    = fd;
	pfd->cb    = cb;
	pfd->arg   = arg;
	pfd->added = false;

	NNI_LIST_NODE_INIT(&pfd->node);
}

int
nni_posix_pfd_arm(nni_posix_pfd *pfd, unsigned events)
{
	nni_posix_pollq *pq = pfd->pq;
	int              rv;

	// NB: We depend on epoll event flags being the same as their POLLIN
	// equivalents.  I.e. POLLIN == EPOLLIN, POLLOUT == EPOLLOUT, and so
	// forth.  This turns out to be true both for Linux and the illumos
	// epoll implementation.

	struct epoll_event ev;
	events |= nni_atomic_or(&pfd->events, (int) events);

	memset(&ev, 0, sizeof(ev));
	ev.events   = events | EPOLLONESHOT;
	ev.data.ptr = pfd;

	// if this fails the system is probably out of memory - it will fail in
	// arm with ENOENT most likely.
	if (!pfd->added) {
		rv = epoll_ctl(pq->epfd, EPOLL_CTL_ADD, pfd->fd, &ev);
		if (rv == 0) {
			pfd->added = true;
		}
	} else {
		rv = epoll_ctl(pq->epfd, EPOLL_CTL_MOD, pfd->fd, &ev);
	}
	if (rv != 0) {
		rv = nni_plat_errno(errno);
	}
	return (rv);
}

int
nni_posix_pfd_fd(nni_posix_pfd *pfd)
{
	return (pfd->fd);
}

void
nni_posix_pfd_close(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq = pfd->pq;
	if (pq == NULL) {
		return;
	}
	if (nni_atomic_flag_test_and_set(&pfd->closing)) {
		return;
	}

	struct epoll_event ev; // Not actually used.

	(void) shutdown(pfd->fd, SHUT_RDWR);
	(void) epoll_ctl(pq->epfd, EPOLL_CTL_DEL, pfd->fd, &ev);
}

void
nni_posix_pfd_stop(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq  = pfd->pq;
	uint64_t         one = 1;

	if (pq == NULL) {
		return;
	}
	if (nni_atomic_flag_test_and_set(&pfd->stopped)) {
		return;
	}

	nni_posix_pfd_close(pfd);

	// We have to synchronize with the pollq thread (unless we are
	// on that thread!)
	NNI_ASSERT(!nni_thr_is_self(&pq->thr));

	nni_mtx_lock(&pq->mtx);
	if (!pq->close) {
		nni_list_append(&pq->reapq, pfd);

		// Wake the remote side.  For now we assume this always
		// succeeds.  The only failure modes here occur when we
		// have already excessively signaled this (2^64 times
		// with no read!!), or when the evfd is closed, or some
		// kernel bug occurs.  Those errors would manifest as
		// a hang waiting for the poller to reap the pfd in fini,
		// if it were possible for them to occur.  (Barring other
		// bugs, it isn't.)
		if (write(pq->evfd, &one, sizeof(one)) != sizeof(one)) {
			nni_panic("BUG! write to epoll fd incorrect!");
		}

		while (nni_list_node_active(&pfd->node)) {
			nni_cv_wait(&pq->cv);
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

	(void) close(pfd->fd);
}

static void
nni_posix_pollq_reap(nni_posix_pollq *pq)
{
	nni_posix_pfd *pfd;
	while ((pfd = nni_list_first(&pq->reapq)) != NULL) {
		nni_list_remove(&pq->reapq, pfd);
	}
	nni_cv_wake(&pq->cv);
}

static void
nni_epoll_thr(void *arg)
{
	nni_posix_pollq   *pq = arg;
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
				nni_posix_pfd *pfd = ev->data.ptr;
				unsigned       mask;

				mask = ev->events &
				    ((unsigned) (EPOLLIN | EPOLLOUT |
				        EPOLLERR | EPOLLHUP));

				nni_atomic_and(&pfd->events, (int) ~mask);

				// Execute the callback with lock released
				pfd->cb(pfd->arg, mask);
			}
		}

		if (reap) {
			nni_mtx_lock(&pq->mtx);
			nni_posix_pollq_reap(pq);
			if (pq->close) {
				nni_mtx_unlock(&pq->mtx);
				return;
			}
			nni_mtx_unlock(&pq->mtx);
		}
	}
}

static void
nni_epoll_pq_destroy(nni_posix_pollq *pq)
{
	uint64_t one = 1;

	if (pq->init) {
		nni_mtx_lock(&pq->mtx);
		pq->close = true;

		if (write(pq->evfd, &one, sizeof(one)) != sizeof(one)) {
			// This should never occur, and if it does it could
			// lead to a hang.
			nni_panic("BUG! unable to write to evfd!");
		}
		nni_mtx_unlock(&pq->mtx);

		nni_thr_fini(&pq->thr);

		close(pq->evfd);
		close(pq->epfd);

		nni_mtx_fini(&pq->mtx);
	}
}

static int
nni_epoll_pq_add_eventfd(nni_posix_pollq *pq)
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
nni_epoll_pq_create(nni_posix_pollq *pq)
{
	int rv;

	NNI_LIST_INIT(&pq->reapq, nni_posix_pfd, node);
	nni_mtx_init(&pq->mtx);
	nni_cv_init(&pq->cv, &pq->mtx);
	pq->epfd = -1;
	pq->init = true;

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

	if ((rv = nni_epoll_pq_add_eventfd(pq)) != 0) {
		(void) close(pq->epfd);
		nni_mtx_fini(&pq->mtx);
		return (rv);
	}
	if ((rv = nni_thr_init(&pq->thr, nni_epoll_thr, pq)) != 0) {
		(void) close(pq->epfd);
		(void) close(pq->evfd);
		nni_mtx_fini(&pq->mtx);
		return (rv);
	}
	nni_thr_set_name(&pq->thr, "nng:poll:epoll");
	nni_thr_run(&pq->thr);
	return (0);
}

int
nni_posix_pollq_sysinit(nng_init_params *params)
{
	int16_t num_thr;
	int16_t max_thr;

	max_thr = params->max_poller_threads;
	num_thr = params->num_poller_threads;

	if ((max_thr > 0) && (num_thr > max_thr)) {
		num_thr = max_thr;
	}
	if (num_thr < 1) {
		num_thr = 1;
	}
	params->num_poller_threads = num_thr;
	if ((nni_epoll_pqs = NNI_ALLOC_STRUCTS(nni_epoll_pqs, num_thr)) ==
	    NULL) {
		return (NNG_ENOMEM);
	}

	nni_epoll_npq = num_thr;
	for (int i = 0; i < num_thr; i++) {
		int rv;
		if ((rv = nni_epoll_pq_create(&nni_epoll_pqs[i])) != 0) {
			nni_posix_pollq_sysfini();
			return (rv);
		}
	}
	return (0);
}

void
nni_posix_pollq_sysfini(void)
{
	if (nni_epoll_npq > 0) {
		for (int i = 0; i < nni_epoll_npq; i++) {
			nni_epoll_pq_destroy(&nni_epoll_pqs[i]);
		}
		NNI_FREE_STRUCTS(nni_epoll_pqs, nni_epoll_npq);
		nni_epoll_pqs = NULL;
		nni_epoll_npq = 0;
	}
}

#endif // NNG_HAVE_EPOLL
