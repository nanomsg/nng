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

static void nni_ep_accept_start(nni_ep *);
static void nni_ep_accept_done(void *);
static void nni_ep_connect_start(nni_ep *);
static void nni_ep_connect_done(void *);
static void nni_ep_backoff_done(void *);

static nni_idhash *nni_eps;

int
nni_ep_sys_init(void)
{
	int rv;

	if ((rv = nni_idhash_init(&nni_eps)) != 0) {
		return (rv);
	}

	nni_idhash_set_limits(
	    nni_eps, 1, 0x7fffffff, nni_random() & 0x7fffffff);

	return (0);
}

void
nni_ep_sys_fini(void)
{
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
	nni_aio_fini(&ep->ep_acc_aio);
	nni_aio_fini(&ep->ep_con_aio);
	nni_aio_fini(&ep->ep_con_syn);
	nni_aio_fini(&ep->ep_backoff);
	if (ep->ep_data != NULL) {
		ep->ep_ops.ep_fini(ep->ep_data);
	}
	if (ep->ep_id != 0) {
		nni_idhash_remove(nni_eps, ep->ep_id);
	}
	nni_cv_fini(&ep->ep_cv);
	nni_mtx_fini(&ep->ep_mtx);
	NNI_FREE_STRUCT(ep);
}

int
nni_ep_create(nni_ep **epp, nni_sock *sock, const char *addr, int mode)
{
	nni_tran *tran;
	nni_ep *  ep;
	int       rv;
	uint32_t  id;

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
	ep->ep_pipe   = NULL;
	ep->ep_id     = id;
	ep->ep_data   = NULL;
	ep->ep_refcnt = 0;

	NNI_LIST_NODE_INIT(&ep->ep_node);

	nni_pipe_ep_list_init(&ep->ep_pipes);

	if (((rv = nni_mtx_init(&ep->ep_mtx)) != 0) ||
	    ((rv = nni_cv_init(&ep->ep_cv, &ep->ep_mtx)) != 0) ||
	    ((rv = nni_idhash_alloc(nni_eps, &ep->ep_id, ep)) != 0)) {
		nni_ep_destroy(ep);
		return (rv);
	}
	rv = nni_aio_init(&ep->ep_acc_aio, nni_ep_accept_done, ep);
	if (rv != 0) {
		nni_ep_destroy(ep);
		return (rv);
	}
	rv = nni_aio_init(&ep->ep_con_aio, nni_ep_connect_done, ep);
	if (rv != 0) {
		nni_ep_destroy(ep);
		return (rv);
	}
	rv = nni_aio_init(&ep->ep_con_syn, NULL, NULL);
	if (rv != 0) {
		nni_ep_destroy(ep);
		return (rv);
	}
	rv = nni_aio_init(&ep->ep_backoff, nni_ep_backoff_done, ep);
	if (rv != 0) {
		nni_ep_destroy(ep);
		return (rv);
	}

	ep->ep_sock = sock;
	ep->ep_tran = tran;
	ep->ep_mode = mode;

	// Could safely use strcpy here, but this avoids discussion.
	(void) snprintf(ep->ep_addr, sizeof(ep->ep_addr), "%s", addr);

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	ep->ep_ops = *tran->tran_ep;

	if ((rv = ep->ep_ops.ep_init(&ep->ep_data, addr, sock, mode)) != 0) {
		nni_ep_destroy(ep);
		return (rv);
	}

	*epp = ep;
	return (0);
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

	// Stop the underlying transport.
	ep->ep_ops.ep_close(ep->ep_data);
}

static void
nni_ep_reap(nni_ep *ep)
{
	nni_pipe *pipe;

	nni_ep_close(ep); // Extra sanity.

	// Take us off the sock list.
	nni_sock_ep_remove(ep->ep_sock, ep);

	// Make sure any other unlocked users (references) are gone
	// before we actually remove the memory.  We should not have
	// to wait long as we have closed the underlying pipe and
	// done everything we can to wake any waiter (synchronous connect)
	// gracefully.
	nni_mtx_lock(&ep->ep_mtx);
	while (ep->ep_refcnt != 0) {
		nni_cv_wait(&ep->ep_cv);
	}
	nni_mtx_unlock(&ep->ep_mtx);

	nni_ep_destroy(ep);
}

void
nni_ep_stop(nni_ep *ep)
{
	nni_mtx_lock(&ep->ep_mtx);

	// Protection against recursion.
	if (ep->ep_stop) {
		nni_mtx_unlock(&ep->ep_mtx);
		return;
	}
	ep->ep_stop = 1;
	nni_taskq_ent_init(&ep->ep_reap_tqe, (nni_cb) nni_ep_reap, ep);
	nni_taskq_dispatch(NULL, &ep->ep_reap_tqe);
	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_backoff_done(void *arg)
{
	nni_ep * ep  = arg;
	nni_aio *aio = &ep->ep_backoff;

	nni_mtx_lock(&ep->ep_mtx);
	if (nni_aio_result(aio) == NNG_ETIMEDOUT) {
		if (ep->ep_mode == NNI_EP_MODE_DIAL) {
			nni_ep_connect_start(ep);
		} else {
			nni_ep_accept_start(ep);
		}
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_connect_done(void *arg)
{
	nni_ep *             ep  = arg;
	nni_aio *            aio = &ep->ep_con_aio;
	void *               tpipe;
	nni_pipe *           pipe;
	const nni_tran_pipe *ops;
	int                  rv;
	nni_time             cooldown;

	ops = ep->ep_tran->tran_pipe;

	nni_mtx_lock(&ep->ep_mtx);
	if ((rv = nni_aio_result(aio)) == 0) {

		tpipe = aio->a_pipe;
		NNI_ASSERT(tpipe != NULL);

		rv = nni_pipe_create(&pipe, ep->ep_sock, ep->ep_tran);
		if (rv != 0) {
			ops->p_fini(tpipe);
		}
	}

done:
	switch (rv) {
	case 0:
		pipe->p_tran_ops  = *ops;
		pipe->p_tran_data = tpipe;

		// Good connect, so reset the backoff timer.
		// XXX: This is kind of bad if a remote host just drops
		// the connection without completing our negotiation.
		// We should reset on close instead, when the pipe is
		// removed *after* a good connect is made, and only
		// if we manage to keep the pipe open for at least
		// some meaningful amount of time.  Alternatively we
		// can dial into the pipe start logic...
		ep->ep_currtime = ep->ep_inirtime;
		nni_pipe_start(pipe);

		// No further outgoing connects -- we will restart a
		// connection from the pipe when the pipe is removed.
		break;
	case NNG_ECLOSED:
	case NNG_ECANCELED:
		// Canceled/closed -- stop everything.
		break;
	default:
		// Other errors involve the use of the backoff timer.
		// XXX: randomize this slightly to prevent reconnect
		// storms.
		ep->ep_backoff.a_expire = nni_clock() + ep->ep_currtime;
		ep->ep_currtime *= 2;
		if (ep->ep_currtime > ep->ep_maxrtime) {
			ep->ep_currtime = ep->ep_maxrtime;
		}
		nni_aio_start(&ep->ep_backoff, NULL, ep);
		break;
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_connect_start(nni_ep *ep)
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
	int                  rv = 0;
	nni_aio *            aio;
	void *               tpipe;
	nni_pipe *           pipe;
	const nni_tran_pipe *ops;

	nni_sock_reconntimes(ep->ep_sock, &ep->ep_inirtime, &ep->ep_maxrtime);
	ep->ep_currtime = ep->ep_inirtime;

	nni_mtx_lock(&ep->ep_mtx);
	ops = ep->ep_tran->tran_pipe;

	if (ep->ep_mode != NNI_EP_MODE_DIAL) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ENOTSUP);
	}
	if (ep->ep_started) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_EBUSY);
	}
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}

	ep->ep_started = 1;

	if ((flags & NNG_FLAG_SYNCH) == 0) {
		nni_ep_connect_start(ep);
		nni_mtx_unlock(&ep->ep_mtx);
		return (0);
	}

	// This one is kind of special, since we need
	// to block for the connection to complete.  Ick.
	aio          = &ep->ep_con_syn;
	aio->a_endpt = ep->ep_data;
	ep->ep_ops.ep_connect(ep->ep_data, aio);

	// We're about to drop the lock, but we cannot allow the
	// endpoint to be removed.  Put a hold on it.
	ep->ep_refcnt++;
	nni_mtx_unlock(&ep->ep_mtx);

	nni_aio_wait(aio);

	nni_mtx_lock(&ep->ep_mtx);
	ep->ep_refcnt--;

	if (ep->ep_closed) {
		rv = NNG_ECLOSED;
	} else {
		rv = nni_aio_result(aio);
	}

	if (rv != 0) {
		ep->ep_started = 0;
		nni_cv_wake(&ep->ep_cv);
		nni_mtx_unlock(&ep->ep_mtx);
		return (rv);
	}

	tpipe = aio->a_pipe;
	NNI_ASSERT(tpipe != NULL);
	rv = nni_pipe_create(&pipe, ep->ep_sock, ep->ep_tran);
	if (rv != 0) {
		ops->p_fini(tpipe);
	} else {
		pipe->p_tran_ops  = *ops;
		pipe->p_tran_data = tpipe;
		nni_pipe_start(pipe);
	}

	nni_cv_wake(&ep->ep_cv);
	nni_mtx_unlock(&ep->ep_mtx);
	return (rv);
}

static void
nni_ep_accept_done(void *arg)
{
	nni_ep *             ep  = arg;
	nni_aio *            aio = &ep->ep_acc_aio;
	void *               tpipe;
	nni_pipe *           pipe;
	int                  rv;
	const nni_tran_pipe *ops;

	ops = ep->ep_tran->tran_pipe;

	nni_mtx_lock(&ep->ep_mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		goto done;
	}
	tpipe = aio->a_pipe;
	NNI_ASSERT(tpipe != NULL);

	rv = nni_pipe_create(&pipe, ep->ep_sock, ep->ep_tran);
	if (rv != 0) {
		ops->p_fini(tpipe);
		goto done;
	}

done:
	switch (rv) {
	case 0:
		pipe->p_tran_ops  = *ops;
		pipe->p_tran_data = tpipe;
		nni_pipe_start(pipe);
		nni_ep_accept_start(ep);
		break;
	case NNG_ECLOSED:
	case NNG_ECANCELED:
		// Canceled or closed, no furhter action.
		break;
	case NNG_ECONNABORTED:
	case NNG_ECONNRESET:
		// These are remote conditions, no cool down.
		// cooldown = 0;
		nni_ep_accept_start(ep);
		break;
	default:
		// We don't really know why we failed, but we backoff here.
		// This is because errors here are probably due to system
		// failures (resource exhaustion) and we hope by not
		// thrashing we give the system a chance to recover.
		ep->ep_backoff.a_expire = nni_clock() + ep->ep_currtime;
		ep->ep_currtime *= 2;
		if (ep->ep_currtime > ep->ep_maxrtime) {
			ep->ep_currtime = ep->ep_maxrtime;
		}
		nni_aio_start(&ep->ep_backoff, NULL, ep);
		break;
	}

	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_accept_start(nni_ep *ep)
{
	nni_aio *aio = &ep->ep_acc_aio;

	// Call with the Endpoint lock held.
	if (ep->ep_closed) {
		return;
	}

	aio->a_endpt = ep->ep_data;
	ep->ep_ops.ep_accept(ep->ep_data, aio);
}

int
nni_ep_listen(nni_ep *ep, int flags)
{
	int rv = 0;

	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_mode != NNI_EP_MODE_LISTEN) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ENOTSUP);
	}
	if (ep->ep_started) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_EBUSY);
	}
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}

	ep->ep_started = 1;

	rv = ep->ep_ops.ep_bind(ep->ep_data);
	if (rv != 0) {
		ep->ep_started = 0;
		nni_mtx_unlock(&ep->ep_mtx);
		return (rv);
	}
	ep->ep_bound = 1;

	nni_ep_accept_start(ep);
	nni_mtx_unlock(&ep->ep_mtx);

	return (0);
}

void
nni_ep_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_ep, ep_node);
}
