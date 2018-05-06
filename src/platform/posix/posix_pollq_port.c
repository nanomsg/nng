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

#ifdef NNG_HAVE_PORT_CREATE

#include <errno.h>
#include <port.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h> /* for strerror() */
#include <unistd.h>

#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

// nni_posix_pollq is a work structure that manages state for the port-event
// based pollq implementation.  We only really need to keep track of the
// single thread, and the associated port itself.
struct nni_posix_pollq {
	int     port; // port id (from port_create)
	nni_thr thr;  // worker thread
};

int
nni_posix_pollq_add(nni_posix_pollq_node *node)
{
	nni_posix_pollq *pq;

	pq = nni_posix_pollq_get(node->fd);
	if (pq == NULL) {
		return (NNG_EINVAL);
	}

	nni_mtx_lock(&node->mx);
	// ensure node was not previously associated with a pollq
	if (node->pq != NULL) {
		nni_mtx_unlock(&node->mx);
		return (NNG_ESTATE);
	}

	node->pq     = pq;
	node->events = 0;
	node->armed  = false;
	nni_mtx_unlock(&node->mx);

	return (0);
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

	nni_mtx_lock(&node->mx);
	node->events = 0;
	if (node->armed) {
		// Failure modes that can occur are uninteresting.
		(void) port_dissociate(pq->port, PORT_SOURCE_FD, node->fd);
		node->armed = false;
	}
	nni_mtx_unlock(&node->mx);
}

// nni_posix_pollq_init merely ensures that the node is ready for use.
// It does not register the node with any pollq in particular.
int
nni_posix_pollq_init(nni_posix_pollq_node *node)
{
	nni_mtx_init(&node->mx);
	nni_cv_init(&node->cv, &node->mx);
	node->pq    = NULL;
	node->armed = false;
	NNI_LIST_NODE_INIT(&node->node);
	return (0);
}

// nni_posix_pollq_fini does everything that nni_posix_pollq_remove does,
// but it also ensures that the node is removed properly.
void
nni_posix_pollq_fini(nni_posix_pollq_node *node)
{
	nni_posix_pollq *pq = node->pq;

	nni_mtx_lock(&node->mx);
	if ((pq = node->pq) != NULL) {
		// Dissociate the port; if it isn't already associated we
		// don't care.  (An extra syscall, but it should not matter.)
		(void) port_dissociate(pq->port, PORT_SOURCE_FD, node->fd);
		node->armed = false;

		for (;;) {
			if (port_send(pq->port, 0, node) == 0) {
				break;
			}
			switch (errno) {
			case EAGAIN:
			case ENOMEM:
				// Resource exhaustion.
				// Best bet in these cases is to sleep it off.
				// This may appear like a total application
				// hang, but by sleeping here maybe we give
				// a chance for things to clear up.
				nni_mtx_unlock(&node->mx);
				nni_msleep(5000);
				nni_mtx_unlock(&node->mx);
				continue;
			case EBADFD:
			case EBADF:
				// Most likely these indicate that the pollq
				// itself has been closed.  That's ok.
				break;
			}
		}
		// Wait for the pollq thread to tell us with certainty that
		// they are done.  This is needed to ensure that the pollq
		// thread isn't executing (or about to execute) the callback
		// before we destroy it.
		while (node->pq != NULL) {
			nni_cv_wait(&node->cv);
		}
	}
	nni_mtx_unlock(&node->mx);
	nni_cv_fini(&node->cv);
	nni_mtx_fini(&node->mx);
}

void
nni_posix_pollq_arm(nni_posix_pollq_node *node, int events)
{
	nni_posix_pollq *pq = node->pq;

	NNI_ASSERT(pq != NULL);
	if (events == 0) {
		return;
	}

	nni_mtx_lock(&node->mx);
	node->events |= events;
	node->armed = true;
	(void) port_associate(
	    pq->port, PORT_SOURCE_FD, node->fd, node->events, node);

	// Possible errors here are:
	//
	// EBADF -- programming error on our part
	// EBADFD -- programming error on our part
	// ENOMEM -- not much we can do here
	// EAGAIN -- too many port events registered (65K!!)
	//
	// For now we ignore them all. (We need to be able to return
	// errors to our caller.)  Effect on the application will appear
	// to be a stalled file descriptor (no notifications).
	nni_mtx_unlock(&node->mx);
}

static void
nni_posix_poll_thr(void *arg)
{

	for (;;) {
		nni_posix_pollq *     pq = arg;
		port_event_t          ev;
		nni_posix_pollq_node *node;

		if (port_get(pq->port, &ev, NULL) != 0) {
			if (errno == EINTR) {
				continue;
			}
			return;
		}

		switch (ev.portev_source) {
		case PORT_SOURCE_ALERT:
			return;

		case PORT_SOURCE_FD:
			node = ev.portev_user;

			nni_mtx_lock(&node->mx);
			node->revents = ev.portev_events;
			// mark events as cleared
			node->events &= ~node->revents;
			node->armed = false;
			nni_mtx_unlock(&node->mx);

			node->cb(node->data);
			break;

		case PORT_SOURCE_USER:
			// User event telling us to stop doing things.
			// We signal back to use this as a coordination event
			// between the pollq and the thread handler.
			// NOTE: It is absolutely critical that there is only
			// a single thread per pollq.  Otherwise we cannot
			// be sure that we are blocked completely,
			node = ev.portev_user;
			nni_mtx_lock(&node->mx);
			node->pq = NULL;
			nni_cv_wake(&node->cv);
			nni_mtx_unlock(&node->mx);
		}
	}
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	port_alert(pq->port, PORT_ALERT_SET, 1, NULL);
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

#endif // NNG_HAVE_PORT_CREATE
