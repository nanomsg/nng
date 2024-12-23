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

// nni_posix_pollq is a work structure that manages state for the kqueue-based
// pollq implementation
typedef struct nni_posix_pollq {
	nni_mtx  mtx;
	int      wake_wfd; // write side of wake pipe
	int      wake_rfd; // read side of wake pipe
	bool     closed;   // request for worker to exit
	int      kq;       // kqueue handle
	nni_thr  thr;      // worker thread
	nni_list reapq;    // items to reap
} nni_posix_pollq;

#define NNI_MAX_KQUEUE_EVENTS 64

// single global instance for now
static nni_posix_pollq nni_posix_global_pollq;

void
nni_posix_pfd_init(nni_posix_pfd *pf, int fd, nni_posix_pfd_cb cb, void *arg)
{
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

	nni_atomic_init(&pf->events);
	nni_cv_init(&pf->cv, &pq->mtx);

	pf->pq  = pq;
	pf->fd  = fd;
	pf->cb  = cb;
	pf->arg = arg;

	nni_atomic_flag_reset(&pf->closed);
	nni_atomic_flag_reset(&pf->stopped);

	NNI_LIST_NODE_INIT(&pf->node);
	// Create entries in the kevent queue, without enabling them.
	EV_SET(&ev[0], (uintptr_t) fd, EVFILT_READ, flags, 0, 0, pf);
	EV_SET(&ev[1], (uintptr_t) fd, EVFILT_WRITE, flags, 0, 0, pf);

	// This may fail, but if it does, we get another try with
	// ARM.  It's an attempt to preallocate anyway.
	(void) kevent(pq->kq, ev, 2, NULL, 0, NULL);
}

void
nni_posix_pfd_close(nni_posix_pfd *pf)
{
	nni_posix_pollq *pq = pf->pq;
	struct kevent    ev[2];
	if (pq == NULL) {
		return;
	}

	if (nni_atomic_flag_test_and_set(&pf->closed)) {
		return;
	}

	nni_mtx_lock(&pq->mtx);
	EV_SET(&ev[0], pf->fd, EVFILT_READ, EV_DELETE, 0, 0, pf);
	EV_SET(&ev[1], pf->fd, EVFILT_WRITE, EV_DELETE, 0, 0, pf);
	(void) shutdown(pf->fd, SHUT_RDWR);
	// This should never fail -- no allocations, just deletion.
	(void) kevent(pq->kq, ev, 2, NULL, 0, NULL);
	nni_mtx_unlock(&pq->mtx);
}

void
nni_posix_pfd_stop(nni_posix_pfd *pf)
{
	nni_posix_pollq *pq = pf->pq;

	if (pq == NULL) {
		return;
	}

	// All consumers take care to move finalization to the reap thread,
	// unless they are synchronous on user threads.
	NNI_ASSERT(!nni_thr_is_self(&pq->thr));

	if (nni_atomic_flag_test_and_set(&pf->stopped)) {
		return;
	}

	nni_posix_pfd_close(pf);
	nni_mtx_lock(&pq->mtx);
	if (!pq->closed) {
		nni_list_append(&pq->reapq, pf);
		nni_plat_pipe_raise(pq->wake_wfd);
		while (nni_list_node_active(&pf->node)) {
			nni_cv_wait(&pf->cv);
		}
	}
	nni_mtx_unlock(&pq->mtx);
}

void
nni_posix_pfd_fini(nni_posix_pfd *pf)
{
	nni_posix_pollq *pq = pf->pq;

	if (pq == NULL) {
		return;
	}

	// All consumers take care to move finalization to the reap thread,
	// unless they are synchronous on user threads.
	NNI_ASSERT(!nni_thr_is_self(&pq->thr));

	nni_posix_pfd_stop(pf);

	(void) close(pf->fd);
	nni_cv_fini(&pf->cv);
}

int
nni_posix_pfd_fd(nni_posix_pfd *pf)
{
	return (pf->fd);
}

int
nni_posix_pfd_arm(nni_posix_pfd *pf, unsigned events)
{
	struct kevent    ev[2];
	int              nev   = 0;
	unsigned         flags = EV_ENABLE | EV_DISPATCH | EV_CLEAR;
	nni_posix_pollq *pq    = pf->pq;

	if (events == 0) {
		// No events, and kqueue is oneshot, so nothing to do.
		return (0);
	}

	nni_atomic_or(&pf->events, (int) events);

	if (events & NNI_POLL_IN) {
		EV_SET(&ev[nev++], pf->fd, EVFILT_READ, flags, 0, 0, pf);
	}
	if (events & NNI_POLL_OUT) {
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
		nni_cv_wake(&pf->cv);
	}
	nni_mtx_unlock(&pq->mtx);
}

static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *pq = arg;

	nni_thr_set_name(NULL, "nng:poll:kqueue");

	for (;;) {
		int            n;
		struct kevent  evs[NNI_MAX_KQUEUE_EVENTS];
		nni_posix_pfd *pf;
		unsigned       revents;

		n = kevent(pq->kq, NULL, 0, evs, NNI_MAX_KQUEUE_EVENTS, NULL);

		for (int i = 0; i < n; i++) {
			struct kevent *ev = &evs[i];

			switch (ev->filter) {
			case EVFILT_READ:
				revents = NNI_POLL_IN;
				break;
			case EVFILT_WRITE:
				revents = NNI_POLL_OUT;
				break;
			}
			if (ev->udata == NULL) {
				if (ev->flags & EV_EOF) {
					nni_posix_pollq_reap(pq);
					return;
				}
				nni_plat_pipe_clear(pq->wake_rfd);
				nni_posix_pollq_reap(pq);
				continue;
			}
			pf = (void *) ev->udata;
			if (ev->flags & EV_ERROR) {
				revents |= NNI_POLL_HUP;
			}

			nni_atomic_and(&pf->events, (int) (~revents));

			pf->cb(pf->arg, revents);
		}
	}
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	nni_mtx_lock(&pq->mtx);
	pq->closed = true;
	nni_mtx_unlock(&pq->mtx);
	nni_plat_pipe_raise(pq->wake_wfd);

	(void) close(pq->wake_wfd);
	nni_thr_fini(&pq->thr);
	(void) close(pq->wake_rfd);

	if (pq->kq >= 0) {
		close(pq->kq);
		pq->kq = -1;
	}
	nni_mtx_fini(&pq->mtx);
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int           rv;
	struct kevent ev;

	if ((pq->kq = kqueue()) < 0) {
		return (nni_plat_errno(errno));
	}

	nni_mtx_init(&pq->mtx);
	NNI_LIST_INIT(&pq->reapq, nni_posix_pfd, node);

	if (((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0) ||
	    ((rv = nni_plat_pipe_open(&pq->wake_wfd, &pq->wake_rfd)) != 0)) {
		nni_posix_pollq_destroy(pq);
		return (rv);
	}

	// Register the wake pipe.  We use this to synchronize closing
	// file descriptors.
	EV_SET(&ev, (uintptr_t) pq->wake_rfd, EVFILT_READ, EV_ADD | EV_CLEAR,
	    0, 0, NULL);

	if ((rv = kevent(pq->kq, &ev, 1, NULL, 0, NULL)) != 0) {
		rv = nni_plat_errno(rv);
		nni_posix_pollq_destroy(pq);
		return (rv);
	}

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

#endif // NNG_HAVE_KQUEUE
