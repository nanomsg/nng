//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Functionality related to end points.

static nni_objhash *nni_eps = NULL;
static void *nni_ep_ctor(uint32_t);
static void nni_ep_dtor(void *);

int
nni_ep_sys_init(void)
{
	int rv;

	rv = nni_objhash_init(&nni_eps, nni_ep_ctor, nni_ep_dtor);

	return (rv);
}


void
nni_ep_sys_fini(void)
{
	nni_objhash_fini(nni_eps);
	nni_eps = NULL;
}


int
nni_ep_find(nni_ep **epp, uint32_t id)
{
	int rv;
	nni_ep *ep;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	rv = nni_objhash_find(nni_eps, id, (void **) &ep);
	if (rv != 0) {
		return (NNG_ECLOSED);
	}
	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		nni_objhash_unref(nni_eps, id);
		return (NNG_ECLOSED);
	}
	nni_mtx_unlock(&ep->ep_mtx);
	if (epp != NULL) {
		*epp = ep;
	}
	return (0);
}


void
nni_ep_hold(nni_ep *ep)
{
	int rv;

	rv = nni_objhash_find(nni_eps, ep->ep_id, NULL);
	NNI_ASSERT(rv == 0);
}


void
nni_ep_rele(nni_ep *ep)
{
	nni_objhash_unref(nni_eps, ep->ep_id);
}


uint32_t
nni_ep_id(nni_ep *ep)
{
	return (ep->ep_id);
}


static void *
nni_ep_ctor(uint32_t id)
{
	nni_ep *ep;
	int rv;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NULL);
	}
	ep->ep_closed = 0;
	ep->ep_bound = 0;
	ep->ep_pipe = NULL;
	ep->ep_id = id;
	ep->ep_data = NULL;

	NNI_LIST_NODE_INIT(&ep->ep_node);

	nni_pipe_ep_list_init(&ep->ep_pipes);

	if ((rv = nni_mtx_init(&ep->ep_mtx)) != 0) {
		NNI_FREE_STRUCT(ep);
		return (NULL);
	}

	if ((rv = nni_cv_init(&ep->ep_cv, &ep->ep_mtx)) != 0) {
		nni_mtx_fini(&ep->ep_mtx);
		NNI_FREE_STRUCT(ep);
		return (NULL);
	}

	return (ep);
}


static void
nni_ep_dtor(void *ptr)
{
	nni_ep *ep = ptr;

	// If a thread is running, make sure it is stopped.
	nni_thr_fini(&ep->ep_thr);

	if (ep->ep_sock != NULL) {
		// This is idempotent; harmless if not already on the list.
		nni_sock_rem_ep(ep->ep_sock, ep);
	}
	if (ep->ep_data != NULL) {
		ep->ep_ops.ep_fini(ep->ep_data);
	}
	nni_cv_fini(&ep->ep_cv);
	nni_mtx_fini(&ep->ep_mtx);
	NNI_FREE_STRUCT(ep);
}


int
nni_ep_create(nni_ep **epp, nni_sock *sock, const char *addr)
{
	nni_tran *tran;
	nni_ep *ep;
	int rv;
	uint32_t id;

	if ((tran = nni_tran_find(addr)) == NULL) {
		return (NNG_ENOTSUP);
	}
	if (strlen(addr) >= NNG_MAXADDRLEN) {
		return (NNG_EINVAL);
	}

	rv = nni_objhash_alloc(nni_eps, &id, (void **) &ep);
	if (rv != 0) {
		return (rv);
	}
	ep->ep_sock = sock;
	ep->ep_tran = tran;

	// Could safely use strcpy here, but this avoids discussion.
	(void) snprintf(ep->ep_addr, sizeof (ep->ep_addr), "%s", addr);

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	ep->ep_ops = *tran->tran_ep;


	if ((rv = ep->ep_ops.ep_init(&ep->ep_data, addr, sock)) != 0) {
		nni_objhash_unref(nni_eps, id);
		return (rv);
	}

	if ((rv = nni_sock_add_ep(sock, ep)) != 0) {
		nni_objhash_unref(nni_eps, id);
		return (rv);
	}

	*epp = ep;
	return (0);
}


void
nni_ep_close(nni_ep *ep)
{
	nni_pipe *pipe;
	nni_sock *sock = ep->ep_sock;

	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_closed == 0) {
		ep->ep_closed = 1;
		ep->ep_ops.ep_close(ep->ep_data);
		if ((pipe = ep->ep_pipe) != NULL) {
			pipe->p_ep = NULL;
			ep->ep_pipe = NULL;
		}
		nni_cv_wake(&ep->ep_cv);
	}
	nni_mtx_unlock(&ep->ep_mtx);
}


static int
nni_ep_connect(nni_ep *ep)
{
	nni_pipe *pipe;
	int rv;

	if ((rv = nni_pipe_create(&pipe, ep, ep->ep_sock, ep->ep_tran)) != 0) {
		return (rv);
	}
	rv = ep->ep_ops.ep_connect(ep->ep_data, pipe->p_tran_data);
	if (rv != 0) {
		nni_pipe_destroy(pipe);
		return (rv);
	}
	if ((rv = nni_pipe_start(pipe)) != 0) {
		nni_pipe_close(pipe);
		return (rv);
	}
	ep->ep_pipe = pipe;
	pipe->p_ep = ep;
	return (0);
}


int
nni_ep_add_pipe(nni_ep *ep, nni_pipe *pipe)
{
	nni_ep_hold(ep);
	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		nni_ep_rele(ep);
		return (NNG_ECLOSED);
	}
	nni_list_append(&ep->ep_pipes, pipe);
	nni_mtx_unlock(&ep->ep_mtx);

	return (0);
}


void
nni_ep_rem_pipe(nni_ep *ep, nni_pipe *pipe)
{
	nni_mtx_lock(&ep->ep_mtx);
	if (!nni_list_active(&ep->ep_pipes, pipe)) {
		nni_mtx_unlock(&ep->ep_mtx);
		return;
	}
	nni_list_remove(&ep->ep_pipes, pipe);
	nni_mtx_unlock(&ep->ep_mtx);
	nni_ep_rele(ep);
}


// nni_dialer is the thread worker that dials in the background.
static void
nni_dialer(void *arg)
{
	nni_ep *ep = arg;
	int rv;
	nni_time cooldown;
	nni_duration maxrtime, nmaxrtime;
	nni_duration defrtime, ndefrtime;
	nni_duration rtime;

	nni_sock_reconntimes(ep->ep_sock, &defrtime, &maxrtime);

	for (;;) {
		nni_sock_reconntimes(ep->ep_sock, &ndefrtime, &nmaxrtime);
		if ((defrtime != ndefrtime) || (maxrtime != nmaxrtime)) {
			// Times changed, so reset them.
			defrtime = ndefrtime;
			maxrtime = nmaxrtime;
			rtime = defrtime;
		}

		nni_mtx_lock(&ep->ep_mtx);
		while ((!ep->ep_closed) && (ep->ep_pipe != NULL)) {
			rtime = defrtime;
			nni_cv_wait(&ep->ep_cv);
		}
		if (ep->ep_closed) {
			nni_mtx_unlock(&ep->ep_mtx);
			break;
		}
		nni_mtx_unlock(&ep->ep_mtx);

		rv = nni_ep_connect(ep);
		switch (rv) {
		case 0:
			// good connection
			continue;
		case NNG_ECLOSED:
			return;

		default:
			cooldown = nni_clock() + rtime;
			rtime *= 2;
			if ((maxrtime >= defrtime) && (rtime > maxrtime)) {
				rtime = maxrtime;
			}
			break;
		}
		// we inject a delay so we don't just spin hard on
		// errors like connection refused.
		nni_mtx_lock(&ep->ep_mtx);
		while (!ep->ep_closed) {
			rv = nni_cv_until(&ep->ep_cv, cooldown);
			if (rv == NNG_ETIMEDOUT) {
				break;
			}
		}
		nni_mtx_unlock(&ep->ep_mtx);
	}
}


int
nni_ep_dial(nni_ep *ep, int flags)
{
	int rv = 0;

	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_mode != NNI_EP_MODE_IDLE) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_EBUSY);
	}
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}

	if ((rv = nni_thr_init(&ep->ep_thr, nni_dialer, ep)) != 0) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (rv);
	}
	ep->ep_mode = NNI_EP_MODE_DIAL;

	if (flags & NNG_FLAG_SYNCH) {
		nni_mtx_unlock(&ep->ep_mtx);
		rv = nni_ep_connect(ep);
		if (rv != 0) {
			nni_thr_fini(&ep->ep_thr);
			ep->ep_mode = NNI_EP_MODE_IDLE;
			return (rv);
		}
		nni_mtx_lock(&ep->ep_mtx);
	}

	nni_thr_run(&ep->ep_thr);
	nni_mtx_unlock(&ep->ep_mtx);

	return (rv);
}


int
nni_ep_accept(nni_ep *ep)
{
	nni_pipe *pipe;
	int rv;

	if (ep->ep_closed) {
		return (NNG_ECLOSED);
	}
	if ((rv = nni_pipe_create(&pipe, ep, ep->ep_sock, ep->ep_tran)) != 0) {
		return (rv);
	}
	rv = ep->ep_ops.ep_accept(ep->ep_data, pipe->p_tran_data);
	if (rv != 0) {
		nni_pipe_destroy(pipe);
		return (rv);
	}
	if ((rv = nni_pipe_start(pipe)) != 0) {
		nni_pipe_close(pipe);
		return (rv);
	}
	return (0);
}


static void
nni_listener(void *arg)
{
	nni_ep *ep = arg;
	int rv;

	for (;;) {
		nni_time cooldown;
		nni_mtx_lock(&ep->ep_mtx);

		// If we didn't bind synchronously, do it now.
		while (!ep->ep_bound && !ep->ep_closed) {
			int rv;

			nni_mtx_unlock(&ep->ep_mtx);
			rv = ep->ep_ops.ep_bind(ep->ep_data);
			nni_mtx_lock(&ep->ep_mtx);

			if (rv == 0) {
				ep->ep_bound = 1;
				break;
			}
			// Invalid address? Out of memory?  Who knows.
			// Try again in a bit (10ms).
			// XXX: PROPER BACKOFF NEEDED
			cooldown = 10000;
			cooldown += nni_clock();
			while (!ep->ep_closed) {
				rv = nni_cv_until(&ep->ep_cv, cooldown);
				if (rv == NNG_ETIMEDOUT) {
					break;
				}
			}
		}
		if (ep->ep_closed) {
			nni_mtx_unlock(&ep->ep_mtx);
			break;
		}
		nni_mtx_unlock(&ep->ep_mtx);

		if ((rv = nni_ep_accept(ep)) == 0) {
			// Success! Loop around for the next one.
			continue;
		}

		switch (rv) {
		case NNG_ECLOSED:
			// This indicates the listening socket got closed.
			// We just bail.
			return;

		case NNG_ECONNABORTED:
		case NNG_ECONNRESET:
			// These are remote conditions, no cool down.
			cooldown = 0;
			break;
		case NNG_ENOMEM:
			// We're running low on memory, so its best to wait
			// a whole second to give the system a chance to
			// recover memory.
			cooldown = 1000000;
			break;
		default:
			// Other cases we sleep just a tiny bit to avoid
			// burning the cpu (e.g. out of files).
			cooldown = 1000;        // 1 msec
			break;
		}
		cooldown += nni_clock();
		nni_mtx_lock(&ep->ep_mtx);
		while (!ep->ep_closed) {
			rv = nni_cv_until(&ep->ep_cv, cooldown);
			if (rv == NNG_ETIMEDOUT) {
				break;
			}
		}
		nni_mtx_unlock(&ep->ep_mtx);
	}
}


int
nni_ep_listen(nni_ep *ep, int flags)
{
	int rv = 0;

	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_mode != NNI_EP_MODE_IDLE) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_EBUSY);
	}

	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}

	if ((rv = nni_thr_init(&ep->ep_thr, nni_listener, ep)) != 0) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (rv);
	}

	ep->ep_mode = NNI_EP_MODE_LISTEN;

	if (flags & NNG_FLAG_SYNCH) {
		nni_mtx_unlock(&ep->ep_mtx);
		rv = ep->ep_ops.ep_bind(ep->ep_data);
		if (rv != 0) {
			nni_thr_fini(&ep->ep_thr);
			ep->ep_mode = NNI_EP_MODE_IDLE;
			return (rv);
		}
		nni_mtx_lock(&ep->ep_mtx);
		ep->ep_bound = 1;
	}

	nni_thr_run(&ep->ep_thr);
	nni_mtx_unlock(&ep->ep_mtx);

	return (0);
}


void
nni_ep_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_ep, ep_node);
}
