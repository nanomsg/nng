//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifdef NNG_HAVE_PORT_CREATE

#include <errno.h>
#include <fcntl.h>
#include <port.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h> /* for strerror() */
#include <unistd.h>

#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

#define NNI_MAX_PORTEV 64
typedef struct nni_posix_pollq nni_posix_pollq;

// nni_posix_pollq is a work structure that manages state for the port-event
// based pollq implementation.  We only really need to keep track of the
// single thread, and the associated port itself.
struct nni_posix_pollq {
	int     port; // port id (from port_create)
	nni_thr thr;  // worker thread
};

struct nni_posix_pfd {
	nni_posix_pollq *pq;
	int              fd;
	nni_mtx          mtx;
	nni_cv           cv;
	unsigned         events;
	bool             closed;
	bool             closing;
	nni_posix_pfd_cb cb;
	void *           data;
};

// single global instance for now
static nni_posix_pollq nni_posix_global_pollq;

int
nni_posix_pfd_init(nni_posix_pfd **pfdp, int fd)
{
	nni_posix_pollq *pq;
	nni_posix_pfd *  pfd;

	pq = &nni_posix_global_pollq;

	if ((pfd = NNI_ALLOC_STRUCT(pfd)) == NULL) {
		return (NNG_ENOMEM);
	}
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);

	nni_mtx_init(&pfd->mtx);
	nni_cv_init(&pfd->cv, &pfd->mtx);
	pfd->closed  = false;
	pfd->closing = false;
	pfd->fd      = fd;
	pfd->pq      = pq;
	pfd->cb      = NULL;
	pfd->data    = NULL;
	*pfdp        = pfd;
	return (0);
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

	nni_mtx_lock(&pfd->mtx);
	if (!pfd->closing) {
		pfd->closing = true;
		(void) shutdown(pfd->fd, SHUT_RDWR);
		port_dissociate(pq->port, PORT_SOURCE_FD, pfd->fd);
	}
	nni_mtx_unlock(&pfd->mtx);

	// Send the wake event to the poller to synchronize with it.
	// Note that port_send should only really fail if out of memory
	// or we run into a resource limit.
}

void
nni_posix_pfd_fini(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq = pfd->pq;

	nni_posix_pfd_close(pfd);

	NNI_ASSERT(!nni_thr_is_self(&pq->thr));

	while (port_send(pq->port, 1, pfd) != 0) {
		if ((errno == EBADF) || (errno == EBADFD)) {
			pfd->closed = true;
			break;
		}
		sched_yield(); // try again later...
	}

	nni_mtx_lock(&pfd->mtx);
	while (!pfd->closed) {
		nni_cv_wait(&pfd->cv);
	}
	nni_mtx_unlock(&pfd->mtx);

	// We're exclusive now.
	(void) close(pfd->fd);
	nni_cv_fini(&pfd->cv);
	nni_mtx_fini(&pfd->mtx);
	NNI_FREE_STRUCT(pfd);
}

int
nni_posix_pfd_arm(nni_posix_pfd *pfd, unsigned events)
{
	nni_posix_pollq *pq = pfd->pq;

	nni_mtx_lock(&pfd->mtx);
	if (!pfd->closing) {
		pfd->events |= events;
		if (port_associate(pq->port, PORT_SOURCE_FD, pfd->fd,
		        (int) pfd->events, pfd) != 0) {
			int rv = nni_plat_errno(errno);
			nni_mtx_unlock(&pfd->mtx);
			return (rv);
		}
	}
	nni_mtx_unlock(&pfd->mtx);
	return (0);
}

static void
nni_posix_poll_thr(void *arg)
{
	for (;;) {
		nni_posix_pollq *pq = arg;
		port_event_t     ev[NNI_MAX_PORTEV];
		nni_posix_pfd *  pfd;
		unsigned         events;
		nni_posix_pfd_cb cb;
		void *           arg;
		unsigned         n;

		n = 1; // wake us even on just one event
		if (port_getn(pq->port, ev, NNI_MAX_PORTEV, &n, NULL) != 0) {
			if (errno == EINTR) {
				continue;
			}
			return;
		}

		// We run through the returned ports twice.  First we
		// get the callbacks.  Then we do the reaps.  This way
		// we ensure that we only reap *after* callbacks have run.
		for (unsigned i = 0; i < n; i++) {
			if (ev[i].portev_source != PORT_SOURCE_FD) {
				continue;
			}
			pfd    = ev[i].portev_user;
			events = ev[i].portev_events;

			nni_mtx_lock(&pfd->mtx);
			cb  = pfd->cb;
			arg = pfd->data;
			pfd->events &= ~events;
			nni_mtx_unlock(&pfd->mtx);

			if (cb != NULL) {
				cb(pfd, events, arg);
			}
		}
		for (unsigned i = 0; i < n; i++) {
			if (ev[i].portev_source != PORT_SOURCE_USER) {
				continue;
			}

			// User event telling us to stop doing things.
			// We signal back to use this as a coordination
			// event between the pollq and the thread
			// handler. NOTE: It is absolutely critical
			// that there is only a single thread per
			// pollq.  Otherwise we cannot be sure that we
			// are blocked completely,
			pfd = ev[i].portev_user;
			nni_mtx_lock(&pfd->mtx);
			pfd->closed = true;
			nni_cv_wake(&pfd->cv);
			nni_mtx_unlock(&pfd->mtx);
		}
	}
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	(void) close(pq->port);
	nni_thr_fini(&pq->thr);
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

	if ((pq->port = port_create()) < 0) {
		return (nni_plat_errno(errno));
	}

	if ((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0) {
		nni_posix_pollq_destroy(pq);
		return (rv);
	}

	nni_thr_run(&pq->thr);
	return (0);
}

void
nni_posix_pfd_set_cb(nni_posix_pfd *pfd, nni_posix_pfd_cb cb, void *arg)
{
	NNI_ASSERT(cb != NULL); // must not be null when established.

	nni_mtx_lock(&pfd->mtx);
	pfd->cb   = cb;
	pfd->data = arg;
	nni_mtx_unlock(&pfd->mtx);
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

#endif // NNG_HAVE_PORT_CREATE
