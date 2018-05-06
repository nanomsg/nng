//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
#include <stdbool.h>
#include <stdio.h>
#include <string.h> /* for strerror() */
#include <sys/event.h>
#include <unistd.h>

#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

// TODO: can this be feature detected in cmake,
//       rather than relying on platform?
#if defined NNG_PLATFORM_NETBSD
#define kevent_udata_t intptr_t
#else
#define kevent_udata_t void *
#endif

#define NNI_MAX_KQUEUE_EVENTS 64

// user event id used to shutdown the polling thread
#define NNI_KQ_EV_EXIT_ID 0xF

// nni_posix_pollq is a work structure that manages state for the kqueue-based
// pollq implementation
struct nni_posix_pollq {
	nni_mtx               mtx;
	nni_cv                cv;
	int                   kq;    // kqueue handle
	bool                  close; // request for worker to exit
	bool                  started;
	nni_thr               thr;    // worker thread
	nni_posix_pollq_node *wait;   // cancel waiting on this
	nni_posix_pollq_node *active; // active node (in callback)
};

int
nni_posix_pollq_add(nni_posix_pollq_node *node)
{
	nni_posix_pollq *pq;
	struct kevent    kevents[2];

	pq = nni_posix_pollq_get(node->fd);
	if (pq == NULL) {
		return (NNG_EINVAL);
	}

	// ensure node was not previously associated with a pollq
	if (node->pq != NULL) {
		return (NNG_ESTATE);
	}

	nni_mtx_lock(&pq->mtx);
	if (pq->close) {
		// This shouldn't happen!
		nni_mtx_unlock(&pq->mtx);
		return (NNG_ECLOSED);
	}

	node->pq     = pq;
	node->events = 0;

	EV_SET(&kevents[0], (uintptr_t) node->fd, EVFILT_READ,
	    EV_ADD | EV_DISABLE, 0, 0, (kevent_udata_t) node);

	EV_SET(&kevents[1], (uintptr_t) node->fd, EVFILT_WRITE,
	    EV_ADD | EV_DISABLE, 0, 0, (kevent_udata_t) node);

	if (kevent(pq->kq, kevents, 2, NULL, 0, NULL) != 0) {
		nni_mtx_unlock(&pq->mtx);
		return (nni_plat_errno(errno));
	}

	nni_mtx_unlock(&pq->mtx);
	return (0);
}

// common functionality for nni_posix_pollq_remove() and nni_posix_pollq_fini()
// called while pq's lock is held
static void
nni_posix_pollq_remove_helper(nni_posix_pollq *pq, nni_posix_pollq_node *node)
{
	struct kevent kevents[2];

	node->events = 0;
	node->pq     = NULL;

	EV_SET(&kevents[0], (uintptr_t) node->fd, EVFILT_READ, EV_DELETE, 0, 0,
	    (kevent_udata_t) node);

	EV_SET(&kevents[1], (uintptr_t) node->fd, EVFILT_WRITE, EV_DELETE, 0,
	    0, (kevent_udata_t) node);

	// So it turns out that we can get EBADF, ENOENT, and apparently
	// also EINPROGRESS (new on macOS Sierra).  Frankly, we're deleting
	// an event, and its harmless if the event removal fails (worst
	// case would be a spurious wakeup), so lets ignore it.
	(void) kevent(pq->kq, kevents, 2, NULL, 0, NULL);
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

	nni_mtx_lock(&pq->mtx);
	nni_posix_pollq_remove_helper(pq, node);

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
	NNI_ARG_UNUSED(node);
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

	nni_mtx_lock(&pq->mtx);
	while (pq->active == node) {
		pq->wait = node;
		nni_cv_wait(&pq->cv);
	}

	nni_posix_pollq_remove_helper(pq, node);

	if (pq->close) {
		nni_cv_wake(&pq->cv);
	}
	nni_mtx_unlock(&pq->mtx);
}

void
nni_posix_pollq_arm(nni_posix_pollq_node *node, int events)
{
	nni_posix_pollq *pq = node->pq;
	struct kevent    kevents[2];
	int              nevents = 0;

	NNI_ASSERT(pq != NULL);
	if (events == 0) {
		return;
	}

	nni_mtx_lock(&pq->mtx);

	if (!(node->events & POLLIN) && (events & POLLIN)) {
		EV_SET(&kevents[nevents++], (uintptr_t) node->fd, EVFILT_READ,
		    EV_ENABLE | EV_DISPATCH, 0, 0, (kevent_udata_t) node);
	}

	if (!(node->events & POLLOUT) && (events & POLLOUT)) {
		EV_SET(&kevents[nevents++], (uintptr_t) node->fd, EVFILT_WRITE,
		    EV_ENABLE | EV_DISPATCH, 0, 0, (kevent_udata_t) node);
	}

	if (nevents > 0) {
		// This call should never fail, really.  The only possible
		// legitimate failure would be ENOMEM, but in that case
		// lots of other things are going to be failing, or ENOENT
		// or ESRCH, indicating we already lost interest; the
		// only consequence of ignoring these errors is that a given
		// descriptor might appear "stuck".  This beats the alternative
		// of just blithely crashing the application with an assertion.
		(void) kevent(pq->kq, kevents, nevents, NULL, 0, NULL);
		node->events |= events;
	}

	nni_mtx_unlock(&pq->mtx);
}

static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *pq = arg;
	struct kevent    kevents[NNI_MAX_KQUEUE_EVENTS];

	nni_mtx_lock(&pq->mtx);

	while (!pq->close) {
		int i;
		int nevents;

		// block indefinitely, timers are handled separately
		nni_mtx_unlock(&pq->mtx);
		nevents = kevent(
		    pq->kq, NULL, 0, kevents, NNI_MAX_KQUEUE_EVENTS, NULL);
		nni_mtx_lock(&pq->mtx);

		if (nevents < 0) {
			continue;
		}

		// dispatch events
		for (i = 0; i < nevents; ++i) {
			struct kevent         ev_disable;
			const struct kevent * ev;
			nni_posix_pollq_node *node;

			ev = &kevents[i];
			if (ev->filter == EVFILT_USER &&
			    ev->ident == NNI_KQ_EV_EXIT_ID) {
				// we've woken up to exit the polling thread
				break;
			}

			node = (nni_posix_pollq_node *) ev->udata;
			if (node->pq == NULL) {
				// node was removed while we were blocking
				continue;
			}
			node->revents = 0;

			if (ev->flags & (EV_ERROR | EV_EOF)) {
				node->revents |= POLLHUP;
			}
			if (ev->filter == EVFILT_WRITE) {
				node->revents |= POLLOUT;
			} else if (ev->filter == EVFILT_READ) {
				node->revents |= POLLIN;
			} else {
				NNI_ASSERT(false); // unhandled filter
				break;
			}

			// explicitly disable this event. we'd ideally rely on
			// the behavior of EV_DISPATCH to do this,
			// but that only happens once we've acknowledged the
			// event by reading/or writing the fd. because there
			// can currently be some latency between the time we
			// receive this event and the time we read/write in
			// response, disable the event in the meantime to avoid
			// needless wakeups.
			// revisit if we're able to reduce/remove this latency.
			EV_SET(&ev_disable, (uintptr_t) node->fd, ev->filter,
			    EV_DISABLE, 0, 0, NULL);
			// this will only fail if the fd is already
			// closed/invalid which we don't mind anyway,
			// so ignore return value.
			(void) kevent(pq->kq, &ev_disable, 1, NULL, 0, NULL);

			// mark events as cleared
			node->events &= ~node->revents;

			// Save the active node; we can notice this way
			// when it is busy, and avoid freeing it until
			// we are sure that it is not in use.
			pq->active = node;

			// Execute the callback with lock released
			nni_mtx_unlock(&pq->mtx);
			node->cb(node->data);
			nni_mtx_lock(&pq->mtx);

			// We finished with this node.  If something
			// was blocked waiting for that, wake it up.
			pq->active = NULL;
			if (pq->wait == node) {
				pq->wait = NULL;
				nni_cv_wake(&pq->cv);
			}
		}
	}

	nni_mtx_unlock(&pq->mtx);
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	if (pq->started) {
		struct kevent ev;
		EV_SET(&ev, NNI_KQ_EV_EXIT_ID, EVFILT_USER, EV_ENABLE,
		    NOTE_TRIGGER, 0, NULL);
		nni_mtx_lock(&pq->mtx);
		pq->close   = true;
		pq->started = false;
		(void) kevent(pq->kq, &ev, 1, NULL, 0, NULL);
		nni_mtx_unlock(&pq->mtx);
	}
	nni_thr_fini(&pq->thr);

	if (pq->kq >= 0) {
		close(pq->kq);
		pq->kq = -1;
	}

	nni_mtx_fini(&pq->mtx);
}

static int
nni_posix_pollq_add_wake_evt(nni_posix_pollq *pq)
{
	// add user event so we can wake ourself on exit
	struct kevent ev;
	EV_SET(&ev, NNI_KQ_EV_EXIT_ID, EVFILT_USER, EV_ADD, 0, 0, NULL);
	return (nni_plat_errno(kevent(pq->kq, &ev, 1, NULL, 0, NULL)));
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

	if ((pq->kq = kqueue()) < 0) {
		return (nni_plat_errno(errno));
	}

	pq->close = false;

	nni_mtx_init(&pq->mtx);
	nni_cv_init(&pq->cv, &pq->mtx);

	if (((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0) ||
	    (rv = nni_posix_pollq_add_wake_evt(pq)) != 0) {
		nni_posix_pollq_destroy(pq);
		return (rv);
	}

	pq->started = true;
	nni_thr_run(&pq->thr);
	return (0);
}

// single global instance for now
static nni_posix_pollq nni_posix_global_pollq;

nni_posix_pollq *
nni_posix_pollq_get(int fd)
{
	NNI_ARG_UNUSED(fd);
	return (&nni_posix_global_pollq);
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
