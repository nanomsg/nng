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

#ifdef NNG_HAVE_KQUEUE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h> /* for strerror() */
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

typedef struct nni_posix_pollq nni_posix_pollq;

// nni_posix_pollq is a work structure that manages state for the kqueue-based
// pollq implementation
struct nni_posix_pollq {
	nni_mtx  mtx;
	int      kq;    // kqueue handle
	nni_thr  thr;   // worker thread
	nni_list reapq; // items to reap
};

struct nni_posix_pfd {
	nni_list_node    node; // linkage into the reap list
	nni_posix_pollq *pq;   // associated pollq
	int              fd;   // file descriptor to poll
	void *           data; // user data
	nni_posix_pfd_cb cb;   // user callback on event
	nni_cv           cv;   // signaled when poller has unregistered
	nni_mtx          mtx;
	unsigned         events;
	bool             closing;
	bool             closed;
};

#define NNI_MAX_KQUEUE_EVENTS 64

// single global instance for now
static nni_posix_pollq nni_posix_global_pollq;

int
nni_posix_pfd_init(nni_posix_pfd **pfdp, int fd)
{
	nni_posix_pfd *  pf;
	nni_posix_pollq *pq;
	struct kevent    ev[2];
	unsigned         flags = EV_ADD | EV_DISABLE | EV_CLEAR;

	// Set this is as soon as possible (narrow the close-exec race as
	// much as we can; better options are system calls that suppress
	// this behavior from descriptor creation.)
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);
#ifdef SO_NOSIGPIPE
	// Darwin lacks MSG_NOSIGNAL, but has a socket option.
	int one = 1;
	(void) setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

	pq = &nni_posix_global_pollq;

	if ((pf = NNI_ALLOC_STRUCT(pf)) == NULL) {
		return (NNG_ENOMEM);
	}

	// Create entries in the kevent queue, without enabling them.
	EV_SET(&ev[0], (uintptr_t) fd, EVFILT_READ, flags, 0, 0, pf);
	EV_SET(&ev[1], (uintptr_t) fd, EVFILT_WRITE, flags, 0, 0, pf);

	// We update the kqueue list, without polling for events.
	if (kevent(pq->kq, ev, 2, NULL, 0, NULL) != 0) {
		NNI_FREE_STRUCT(pf);
		return (nni_plat_errno(errno));
	}
	pf->fd = fd;
	pf->cb = NULL;
	pf->pq = pq;
	nni_mtx_init(&pf->mtx);
	nni_cv_init(&pf->cv, &pq->mtx);
	NNI_LIST_NODE_INIT(&pf->node);
	*pfdp = pf;

	return (0);
}

void
nni_posix_pfd_close(nni_posix_pfd *pf)
{
	nni_posix_pollq *pq = pf->pq;

	nni_mtx_lock(&pq->mtx);
	if (!pf->closing) {
		struct kevent ev[2];
		pf->closing = true;
		EV_SET(&ev[0], pf->fd, EVFILT_READ, EV_DELETE, 0, 0, pf);
		EV_SET(&ev[1], pf->fd, EVFILT_WRITE, EV_DELETE, 0, 0, pf);
		(void) shutdown(pf->fd, SHUT_RDWR);
		// This should never fail -- no allocations, just deletion.
		(void) kevent(pq->kq, ev, 2, NULL, 0, NULL);
	}
	nni_mtx_unlock(&pq->mtx);
}

void
nni_posix_pfd_fini(nni_posix_pfd *pf)
{
	nni_posix_pollq *pq;

	pq = pf->pq;

	nni_posix_pfd_close(pf);

	// All consumers take care to move finalization to the reap thread,
	// unless they are synchronous on user threads.
	NNI_ASSERT(!nni_thr_is_self(&pq->thr));

	struct kevent ev;
	nni_mtx_lock(&pq->mtx);
	nni_list_append(&pq->reapq, pf);
	EV_SET(
	    &ev, 0, EVFILT_USER, EV_ENABLE | EV_CLEAR, NOTE_TRIGGER, 0, NULL);

	// If this fails, the cleanup will stall.  That should
	// only occur in a memory pressure situation, and it
	// will self-heal when the next event comes in.
	(void) kevent(pq->kq, &ev, 1, NULL, 0, NULL);
	while (!pf->closed) {
		nni_cv_wait(&pf->cv);
	}
	nni_mtx_unlock(&pq->mtx);

	(void) close(pf->fd);
	nni_cv_fini(&pf->cv);
	nni_mtx_fini(&pf->mtx);
	NNI_FREE_STRUCT(pf);
}

int
nni_posix_pfd_fd(nni_posix_pfd *pf)
{
	return (pf->fd);
}

void
nni_posix_pfd_set_cb(nni_posix_pfd *pf, nni_posix_pfd_cb cb, void *arg)
{
	NNI_ASSERT(cb != NULL); // must not be null when established.
	nni_mtx_lock(&pf->mtx);
	pf->cb   = cb;
	pf->data = arg;
	nni_mtx_unlock(&pf->mtx);
}

int
nni_posix_pfd_arm(nni_posix_pfd *pf, unsigned events)
{
	struct kevent    ev[2];
	int              nev   = 0;
	unsigned         flags = EV_ENABLE | EV_DISPATCH | EV_CLEAR;
	nni_posix_pollq *pq    = pf->pq;

	nni_mtx_lock(&pf->mtx);
	if (pf->closing) {
		events = 0;
	} else {
		pf->events |= events;
		events = pf->events;
	}
	nni_mtx_unlock(&pf->mtx);

	if (events == 0) {
		// No events, and kqueue is oneshot, so nothing to do.
		return (0);
	}

	if (events & POLLIN) {
		EV_SET(&ev[nev++], pf->fd, EVFILT_READ, flags, 0, 0, pf);
	}
	if (events & POLLOUT) {
		EV_SET(&ev[nev++], pf->fd, EVFILT_WRITE, flags, 0, 0, pf);
	}
	while (kevent(pq->kq, ev, nev, NULL, 0, NULL) != 0) {
		if (errno == EINTR) {
			continue;
		}
		return (nni_plat_errno(errno));
	}
	return (0);
}

static void
nni_posix_pollq_reap(nni_posix_pollq *pq)
{
	nni_posix_pfd *pf;
	nni_mtx_lock(&pq->mtx);
	while ((pf = nni_list_first(&pq->reapq)) != NULL) {
		nni_list_remove(&pq->reapq, pf);
		pf->closed = true;
		nni_cv_wake(&pf->cv);
	}
	nni_mtx_unlock(&pq->mtx);
}

static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *pq = arg;

	for (;;) {
		int              n;
		struct kevent    evs[NNI_MAX_KQUEUE_EVENTS];
		nni_posix_pfd *  pf;
		nni_posix_pfd_cb cb;
		void *           cbarg;
		unsigned         revents;
		bool             reap = false;

		n = kevent(pq->kq, NULL, 0, evs, NNI_MAX_KQUEUE_EVENTS, NULL);
		if (n < 0) {
			if (errno == EBADF) {
				nni_posix_pollq_reap(pq);
				return;
			}
			reap = true;
		}

		for (int i = 0; i < n; i++) {
			struct kevent *ev = &evs[i];

			switch (ev->filter) {
			case EVFILT_READ:
				revents = POLLIN;
				break;
			case EVFILT_WRITE:
				revents = POLLOUT;
				break;
			case EVFILT_USER:
			default:
				reap = true;
				continue;
			}
			pf = (void *) ev->udata;
			if (ev->flags & EV_ERROR) {
				revents |= POLLHUP;
			}

			nni_mtx_lock(&pf->mtx);
			cb    = pf->cb;
			cbarg = pf->data;
			pf->events &= ~(revents);
			nni_mtx_unlock(&pf->mtx);

			if (cb != NULL) {
				cb(pf, revents, cbarg);
			}
		}
		if (reap) {
			nni_posix_pollq_reap(pq);
		}
	}
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	if (pq->kq >= 0) {
		close(pq->kq);
	}
	nni_thr_fini(&pq->thr);
	pq->kq = -1;

	nni_posix_pollq_reap(pq);

	nni_mtx_fini(&pq->mtx);
}

static int
nni_posix_pollq_add_wake_evt(nni_posix_pollq *pq)
{
	int           rv;
	struct kevent ev;

	EV_SET(&ev, 0, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
	while ((rv = kevent(pq->kq, &ev, 1, NULL, 0, NULL)) != 0) {
		if (errno == EINTR) {
			continue;
		}
		return (nni_plat_errno(errno));
	}
	return (0);
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

	if ((pq->kq = kqueue()) < 0) {
		return (nni_plat_errno(errno));
	}

	nni_mtx_init(&pq->mtx);
	NNI_LIST_INIT(&pq->reapq, nni_posix_pfd, node);

	if (((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0) ||
	    (rv = nni_posix_pollq_add_wake_evt(pq)) != 0) {
		nni_posix_pollq_destroy(pq);
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

#endif // NNG_HAVE_KQUEUE
