//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Functionality related to end points.

static void nni_ep_acc_start(nni_ep *);
static void nni_ep_acc_cb(void *);
static void nni_ep_con_start(nni_ep *);
static void nni_ep_con_cb(void *);
static void nni_ep_tmo_start(nni_ep *);
static void nni_ep_tmo_cb(void *);
static void nni_ep_reaper(void *);

static nni_idhash *nni_eps;

static nni_mtx  nni_ep_lk;
static nni_list nni_ep_reap_list;
static nni_mtx  nni_ep_reap_lk;
static nni_cv   nni_ep_reap_cv;
static nni_thr  nni_ep_reap_thr;
static int      nni_ep_reap_run;

int
nni_ep_sys_init(void)
{
	int rv;

	NNI_LIST_INIT(&nni_ep_reap_list, nni_ep, ep_reap_node);

	if (((rv = nni_mtx_init(&nni_ep_lk)) != 0) ||
	    ((rv = nni_mtx_init(&nni_ep_reap_lk)) != 0) ||
	    ((rv = nni_cv_init(&nni_ep_reap_cv, &nni_ep_reap_lk)) != 0) ||
	    ((rv = nni_thr_init(&nni_ep_reap_thr, nni_ep_reaper, 0)) != 0) ||
	    ((rv = nni_idhash_init(&nni_eps)) != 0)) {
		return (rv);
	}
	nni_idhash_set_limits(
	    nni_eps, 1, 0x7fffffff, nni_random() & 0x7fffffff);

	nni_ep_reap_run = 1;
	nni_thr_run(&nni_ep_reap_thr);

	return (0);
}

void
nni_ep_sys_fini(void)
{
	if (nni_ep_reap_run) {
		nni_mtx_lock(&nni_ep_reap_lk);
		nni_ep_reap_run = 0;
		nni_cv_wake(&nni_ep_reap_cv);
		nni_mtx_unlock(&nni_ep_reap_lk);
	}
	nni_thr_fini(&nni_ep_reap_thr);
	nni_cv_fini(&nni_ep_reap_cv);
	nni_mtx_fini(&nni_ep_reap_lk);
	nni_mtx_fini(&nni_ep_lk);
	nni_idhash_fini(nni_eps);
	nni_eps = NULL;
}

uint32_t
nni_ep_id(nni_ep *ep)
{
	return (ep->ep_id);
}

static void
nni_ep_destroy(nni_ep *ep)
{
	if (ep == NULL) {
		return;
	}

	// Remove us form the table so we cannot be found.
	if (ep->ep_id != 0) {
		nni_idhash_remove(nni_eps, ep->ep_id);
	}
	nni_aio_stop(&ep->ep_acc_aio);
	nni_aio_stop(&ep->ep_con_aio);
	nni_aio_stop(&ep->ep_con_syn);
	nni_aio_stop(&ep->ep_tmo_aio);

	nni_aio_fini(&ep->ep_acc_aio);
	nni_aio_fini(&ep->ep_con_aio);
	nni_aio_fini(&ep->ep_con_syn);
	nni_aio_fini(&ep->ep_tmo_aio);

	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_data != NULL) {
		ep->ep_ops.ep_fini(ep->ep_data);
	}
	nni_mtx_unlock(&ep->ep_mtx);
	nni_cv_fini(&ep->ep_cv);
	nni_mtx_fini(&ep->ep_mtx);
	NNI_FREE_STRUCT(ep);
}

int
nni_ep_create(nni_ep **epp, nni_sock *s, const char *addr, int mode)
{
	nni_tran *tran;
	nni_ep *  ep;
	int       rv;

	if ((tran = nni_tran_find(addr)) == NULL) {
		return (NNG_ENOTSUP);
	}
	if (strlen(addr) >= NNG_MAXADDRLEN) {
		return (NNG_EINVAL);
	}

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ep->ep_closed = 0;
	ep->ep_bound  = 0;
	ep->ep_data   = NULL;
	ep->ep_refcnt = 0;
	ep->ep_sock   = s;
	ep->ep_tran   = tran;
	ep->ep_mode   = mode;

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	ep->ep_ops = *tran->tran_ep;

	// Could safely use strcpy here, but this avoids discussion.
	(void) snprintf(ep->ep_addr, sizeof(ep->ep_addr), "%s", addr);

	NNI_LIST_NODE_INIT(&ep->ep_node);
	NNI_LIST_NODE_INIT(&ep->ep_reap_node);

	nni_pipe_ep_list_init(&ep->ep_pipes);

	if (((rv = nni_mtx_init(&ep->ep_mtx)) != 0) ||
	    ((rv = nni_cv_init(&ep->ep_cv, &ep->ep_mtx)) != 0) ||
	    ((rv = nni_idhash_alloc(nni_eps, &ep->ep_id, ep)) != 0) ||
	    ((rv = nni_aio_init(&ep->ep_acc_aio, nni_ep_acc_cb, ep)) != 0) ||
	    ((rv = nni_aio_init(&ep->ep_con_aio, nni_ep_con_cb, ep)) != 0) ||
	    ((rv = nni_aio_init(&ep->ep_tmo_aio, nni_ep_tmo_cb, ep)) != 0) ||
	    ((rv = nni_aio_init(&ep->ep_con_syn, NULL, NULL)) != 0) ||
	    ((rv = ep->ep_ops.ep_init(&ep->ep_data, addr, s, mode)) != 0)) {
		nni_ep_destroy(ep);
		return (rv);
	}

	*epp = ep;
	return (0);
}

int
nni_ep_find(nni_ep **epp, uint32_t id)
{
	int     rv;
	nni_ep *ep;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	nni_mtx_lock(&nni_ep_lk);
	if ((rv = nni_idhash_find(nni_eps, id, (void **) &ep)) == 0) {
		if (ep->ep_closed) {
			rv = NNG_ECLOSED;
		} else {
			ep->ep_refcnt++;
			*epp = ep;
		}
	}
	nni_mtx_unlock(&nni_ep_lk);
	return (rv);
}

void
nni_ep_rele(nni_ep *ep)
{
	nni_mtx_lock(&nni_ep_lk);
	ep->ep_refcnt--;
	if (ep->ep_closing) {
		nni_cv_wake(&ep->ep_cv);
	}
	nni_mtx_unlock(&nni_ep_lk);
}

void
nni_ep_close(nni_ep *ep)
{
	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		return;
	}
	ep->ep_closed = 1;
	nni_mtx_unlock(&ep->ep_mtx);

	// Abort any remaining in-flight operations.
	nni_aio_cancel(&ep->ep_acc_aio, NNG_ECLOSED);
	nni_aio_cancel(&ep->ep_con_aio, NNG_ECLOSED);
	nni_aio_cancel(&ep->ep_con_syn, NNG_ECLOSED);
	nni_aio_cancel(&ep->ep_tmo_aio, NNG_ECLOSED);

	// Stop the underlying transport.
	ep->ep_ops.ep_close(ep->ep_data);
}

static void
nni_ep_reap(nni_ep *ep)
{
	nni_ep_close(ep); // Extra sanity.

	nni_aio_stop(&ep->ep_acc_aio);
	nni_aio_stop(&ep->ep_con_aio);
	nni_aio_stop(&ep->ep_con_syn);
	nni_aio_stop(&ep->ep_tmo_aio);

	// Take us off the sock list.
	nni_sock_ep_remove(ep->ep_sock, ep);

	// Make sure any other unlocked users (references) are gone
	// before we actually remove the memory.  We should not have
	// to wait long as we have closed the underlying pipe and
	// done everything we can to wake any waiter (synchronous
	// connect) gracefully.
	nni_mtx_lock(&ep->ep_mtx);
	ep->ep_closed = 1;
	for (;;) {
		if ((!nni_list_empty(&ep->ep_pipes)) || (ep->ep_refcnt != 0)) {
			nni_cv_wait(&ep->ep_cv);
			continue;
		}
		break;
	}
	nni_mtx_unlock(&ep->ep_mtx);

	nni_ep_destroy(ep);
}

void
nni_ep_stop(nni_ep *ep)
{
	nni_pipe *pipe;

	nni_mtx_lock(&ep->ep_mtx);

	// Protection against recursion.
	if (ep->ep_stop) {
		nni_mtx_unlock(&ep->ep_mtx);
		return;
	}
	ep->ep_stop = 1;
	NNI_LIST_FOREACH (&ep->ep_pipes, pipe) {
		nni_pipe_stop(pipe);
	}
	nni_mtx_unlock(&ep->ep_mtx);

	nni_mtx_lock(&nni_ep_reap_lk);
	NNI_ASSERT(!nni_list_node_active(&ep->ep_reap_node));
	nni_list_append(&nni_ep_reap_list, ep);
	nni_cv_wake(&nni_ep_reap_cv);
	nni_mtx_unlock(&nni_ep_reap_lk);
}

static void
nni_ep_tmo_cancel(nni_aio *aio, int rv)
{
	// The only way this ever gets "finished", is via cancellation.
	nni_aio_finish_error(aio, rv);
}

static void
nni_ep_tmo_start(nni_ep *ep)
{
	nni_duration backoff;

	if (ep->ep_closed) {
		return;
	}
	backoff = ep->ep_currtime;
	ep->ep_currtime *= 2;
	if (ep->ep_currtime > ep->ep_maxrtime) {
		ep->ep_currtime = ep->ep_maxrtime;
	}

	// To minimize damage from storms, etc., we select a backoff
	// value randomly, in the range of [0, backoff-1]; this is
	// pretty similar to 802 style backoff, except that we have a
	// nearly uniform time period instead of discrete slot times.
	// This algorithm may lead to slight biases because we don't
	// have a statistically perfect distribution with the modulo of
	// the random number, but this really doesn't matter.

	ep->ep_tmo_aio.a_expire = nni_clock() + (nni_random() % backoff);
	nni_aio_start(&ep->ep_tmo_aio, nni_ep_tmo_cancel, ep);
}

static void
nni_ep_tmo_cb(void *arg)
{
	nni_ep * ep  = arg;
	nni_aio *aio = &ep->ep_tmo_aio;

	nni_mtx_lock(&ep->ep_mtx);
	if (nni_aio_result(aio) == NNG_ETIMEDOUT) {
		if (ep->ep_mode == NNI_EP_MODE_DIAL) {
			nni_ep_con_start(ep);
		} else {
			nni_ep_acc_start(ep);
		}
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_con_cb(void *arg)
{
	nni_ep * ep  = arg;
	nni_aio *aio = &ep->ep_con_aio;
	int      rv;

	if ((rv = nni_aio_result(aio)) == 0) {
		rv = nni_pipe_create(ep, aio->a_pipe);
	}
	nni_mtx_lock(&ep->ep_mtx);
	switch (rv) {
	case 0:
		// Good connect, so reset the backoff timer.
		// Note that a host that accepts the connect, but drops
		// us immediately, is going to get hit pretty hard
		// (depending on the initial backoff) with no
		// exponential backoff. This can happen if we wind up
		// trying to connect to some port that does not speak
		// SP for example.
		ep->ep_currtime = ep->ep_inirtime;

		// No further outgoing connects -- we will restart a
		// connection from the pipe when the pipe is removed.
		break;
	case NNG_ECLOSED:
	case NNG_ECANCELED:
		// Canceled/closed -- stop everything.
		break;
	default:
		// Other errors involve the use of the backoff timer.
		nni_ep_tmo_start(ep);
		break;
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_con_start(nni_ep *ep)
{
	nni_aio *aio = &ep->ep_con_aio;

	// Call with the Endpoint lock held.
	if (ep->ep_closed) {
		return;
	}

	aio->a_endpt = ep->ep_data;
	ep->ep_ops.ep_connect(ep->ep_data, aio);
}

int
nni_ep_dial(nni_ep *ep, int flags)
{
	int      rv = 0;
	nni_aio *aio;

	nni_sock_reconntimes(ep->ep_sock, &ep->ep_inirtime, &ep->ep_maxrtime);
	ep->ep_currtime = ep->ep_inirtime;

	nni_mtx_lock(&ep->ep_mtx);

	if (ep->ep_mode != NNI_EP_MODE_DIAL) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ENOTSUP);
	}
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}

	if ((flags & NNG_FLAG_SYNCH) == 0) {
		nni_ep_con_start(ep);
		nni_mtx_unlock(&ep->ep_mtx);
		return (0);
	}

	// Synchronous mode: so we have to wait for it to complete.
	aio          = &ep->ep_con_syn;
	aio->a_endpt = ep->ep_data;
	ep->ep_ops.ep_connect(ep->ep_data, aio);
	nni_mtx_unlock(&ep->ep_mtx);

	nni_aio_wait(aio);

	// As we're synchronous, we also have to handle the completion.
	if ((rv = nni_aio_result(aio)) == 0) {
		NNI_ASSERT(aio->a_pipe != NULL);
		rv = nni_pipe_create(ep, aio->a_pipe);
	}

	return (rv);
}

static void
nni_ep_acc_cb(void *arg)
{
	nni_ep * ep  = arg;
	nni_aio *aio = &ep->ep_acc_aio;
	int      rv;

	if ((rv = nni_aio_result(aio)) == 0) {
		NNI_ASSERT(aio->a_pipe != NULL);
		rv = nni_pipe_create(ep, aio->a_pipe);
	}

	nni_mtx_lock(&ep->ep_mtx);
	switch (rv) {
	case 0:
		nni_ep_acc_start(ep);
		break;
	case NNG_ECLOSED:
	case NNG_ECANCELED:
		// Canceled or closed, no furhter action.
		break;
	case NNG_ECONNABORTED:
	case NNG_ECONNRESET:
		// These are remote conditions, no cool down.
		nni_ep_acc_start(ep);
		break;
	default:
		// We don't really know why we failed, but we backoff
		// here. This is because errors here are probably due
		// to system failures (resource exhaustion) and we hope
		// by not thrashing we give the system a chance to
		// recover.
		nni_ep_tmo_start(ep);
		break;
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_acc_start(nni_ep *ep)
{
	nni_aio *aio = &ep->ep_acc_aio;

	// Call with the Endpoint lock held.
	if (ep->ep_closed) {
		return;
	}
	aio->a_pipe  = NULL;
	aio->a_endpt = ep->ep_data;
	ep->ep_ops.ep_accept(ep->ep_data, aio);
}

int
nni_ep_listen(nni_ep *ep, int flags)
{
	int rv = 0;

	nni_sock_reconntimes(ep->ep_sock, &ep->ep_inirtime, &ep->ep_maxrtime);
	ep->ep_currtime = ep->ep_inirtime;

	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_mode != NNI_EP_MODE_LISTEN) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ENOTSUP);
	}
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}

	rv = ep->ep_ops.ep_bind(ep->ep_data);
	if (rv != 0) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (rv);
	}
	ep->ep_bound = 1;

	nni_ep_acc_start(ep);
	nni_mtx_unlock(&ep->ep_mtx);

	return (0);
}

int
nni_ep_pipe_add(nni_ep *ep, nni_pipe *p)
{
	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}
	nni_list_append(&ep->ep_pipes, p);
	p->p_ep = ep;
	nni_mtx_unlock(&ep->ep_mtx);
	return (0);
}

void
nni_ep_pipe_remove(nni_ep *ep, nni_pipe *pipe)
{
	// Break up the relationship between the EP and the pipe.
	nni_mtx_lock(&ep->ep_mtx);
	// During early init, the pipe might not have this set.
	if (nni_list_active(&ep->ep_pipes, pipe)) {
		nni_list_remove(&ep->ep_pipes, pipe);
	}
	pipe->p_ep = NULL;
	// Wake up the close thread if it is waiting.
	if (ep->ep_closed && nni_list_empty(&ep->ep_pipes)) {
		nni_cv_wake(&ep->ep_cv);
	}

	// If this pipe closed, then lets restart the dial operation.
	// Since the remote side seems to have closed, lets start with
	// a backoff.  This keeps us from pounding the crap out of the
	// thing if a remote server accepts but then disconnects
	// immediately.
	if ((!ep->ep_closed) && (ep->ep_mode == NNI_EP_MODE_DIAL)) {
		nni_ep_tmo_start(ep);
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

void
nni_ep_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_ep, ep_node);
}

nni_tran *
nni_ep_tran(nni_ep *ep)
{
	return (ep->ep_tran);
}

nni_sock *
nni_ep_sock(nni_ep *ep)
{
	return (ep->ep_sock);
}

static void
nni_ep_reaper(void *notused)
{
	NNI_ARG_UNUSED(notused);

	nni_mtx_lock(&nni_ep_reap_lk);
	for (;;) {
		nni_ep *ep;

		if ((ep = nni_list_first(&nni_ep_reap_list)) != NULL) {
			nni_list_remove(&nni_ep_reap_list, ep);
			nni_mtx_unlock(&nni_ep_reap_lk);
			nni_ep_reap(ep);
			nni_mtx_lock(&nni_ep_reap_lk);
			continue;
		}

		if (!nni_ep_reap_run) {
			break;
		}

		nni_cv_wait(&nni_ep_reap_cv);
	}
	nni_mtx_unlock(&nni_ep_reap_lk);
}