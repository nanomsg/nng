//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
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

// nni_posix_pollq is a work structure that manages state for the port-event
// based pollq implementation.  We only really need to keep track of the
// single thread, and the associated port itself.
typedef struct nni_posix_pollq {
	int     port; // port id (from port_create)
	nni_thr thr;  // worker thread
	nni_mtx mtx;
	nni_cv  cv;
	bool    init;
} nni_posix_pollq;

static nni_posix_pollq *nni_port_pqs;
static int              nni_port_npq;

void
nni_posix_pfd_init(nni_posix_pfd *pfd, int fd, nni_posix_pfd_cb cb, void *arg)
{
	nni_posix_pollq *pq;

	pq = &nni_port_pqs[fd % nni_port_npq];

	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);

	nni_atomic_init(&pfd->events);
	pfd->closed = false;
	pfd->fd     = fd;
	pfd->pq     = pq;
	pfd->cb     = cb;
	pfd->data   = arg;
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

	(void) shutdown(pfd->fd, SHUT_RDWR);
	port_dissociate(pq->port, PORT_SOURCE_FD, pfd->fd);

	// Send the wake event to the poller to synchronize with it.
	// Note that port_send should only really fail if out of memory
	// or we run into a resource limit.
}

void
nni_posix_pfd_stop(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq = pfd->pq;

	if (pq == NULL) {
		return;
	}

	NNI_ASSERT(!nni_thr_is_self(&pq->thr));

	while (port_send(pq->port, 1, pfd) != 0) {
		if ((errno == EBADF) || (errno == EBADFD)) {
			pfd->closed = true;
			break;
		}
		sched_yield(); // try again later...
	}
	nni_mtx_lock(&pq->mtx);
	while (!pfd->closed) {
		nni_cv_wait(&pq->cv);
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
	int              rv;
	int              ev = (int) events;

	ev |= nni_atomic_or(&pfd->events, ev);
	rv = port_associate(pq->port, PORT_SOURCE_FD, pfd->fd, ev, pfd);
	if (rv != 0) {
		nni_plat_errno(errno);
	}
	return (rv);
}

static void
nni_port_thr(void *arg)
{
	for (;;) {
		nni_posix_pollq *pq = arg;
		port_event_t     ev[NNI_MAX_PORTEV];
		nni_posix_pfd   *pfd;
		int              events;
		nni_posix_pfd_cb cb;
		void            *arg;
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
		bool user_wake = false;
		for (unsigned i = 0; i < n; i++) {
			switch (ev[i].portev_source) {
			case PORT_SOURCE_USER:
				user_wake = true;
				continue;
			case PORT_SOURCE_FD:
				if (ev[i].portev_source != PORT_SOURCE_FD) {
					continue;
				}
				pfd    = ev[i].portev_user;
				events = ev[i].portev_events;

				cb  = pfd->cb;
				arg = pfd->data;
				nni_atomic_and(&pfd->events, ~events);

				cb(arg, (unsigned) events);
			}
		}
		if (user_wake) {
			nni_mtx_lock(&pq->mtx);
			for (unsigned i = 0; i < n; i++) {
				if (ev[i].portev_source == PORT_SOURCE_USER) {
					pfd->closed = true;
				}
			}
			nni_cv_wake(&pq->cv);
			nni_mtx_unlock(&pq->mtx);
		}
	}
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	if (pq->init) {
		(void) close(pq->port);
		nni_cv_fini(&pq->cv);
		nni_mtx_fini(&pq->mtx);
		nni_thr_fini(&pq->thr);
	}
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

	nni_mtx_init(&pq->mtx);
	nni_cv_init(&pq->cv, &pq->mtx);
	pq->init = true;
	pq->port = -1;

	if ((pq->port = port_create()) < 0) {
		return (nni_plat_errno(errno));
	}

	if ((rv = nni_thr_init(&pq->thr, nni_port_thr, pq)) != 0) {
		nni_posix_pollq_destroy(pq);
		return (rv);
	}
	nni_thr_set_name(&pq->thr, "nng:poll:port");

	nni_thr_run(&pq->thr);
	return (0);
}

void
nni_posix_pollq_sysfini(void)
{
	if (nni_port_npq > 0) {
		for (int i = 0; i < nni_port_npq; i++) {
			nni_posix_pollq_destroy(&nni_port_pqs[i]);
		}
		NNI_FREE_STRUCTS(nni_port_pqs, nni_port_npq);
		nni_port_pqs = NULL;
		nni_port_npq = 0;
	}
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
	if ((nni_port_pqs = NNI_ALLOC_STRUCTS(nni_port_pqs, num_thr)) ==
	    NULL) {
		return (NNG_ENOMEM);
	}

	nni_port_npq = num_thr;
	for (int i = 0; i < num_thr; i++) {
		int rv;
		if ((rv = nni_posix_pollq_create(&nni_port_pqs[i])) != 0) {
			nni_posix_pollq_sysfini();
			return (rv);
		}
	}
	return (0);
}

#endif // NNG_HAVE_PORT_CREATE
