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

// Functionality realited to end points.

int
nni_ep_hold(nni_ep **epp, uint32_t id)
{
	int rv;
	nni_ep *ep;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	nni_mtx_lock(nni_idlock);
	if ((rv = nni_idhash_find(nni_endpoints, id, (void **) &ep)) != 0) {
		nni_mtx_unlock(nni_idlock);
		return (NNG_ECLOSED);
	}
	ep->ep_holds++;
	nni_mtx_unlock(nni_idlock);
	*epp = ep;
	return (0);
}


void
nni_ep_rele(nni_ep *ep)
{
	nni_mtx_lock(nni_idlock);
	ep->ep_holds--;
	if (ep->ep_holds == 0) {
		nni_cv_wake(&ep->ep_holdcv);
	}
	nni_mtx_unlock(nni_idlock);
}


int
nni_ep_hold_close(nni_ep **epp, uint32_t id)
{
	int rv;
	nni_ep *ep;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	nni_mtx_lock(nni_idlock);
	if ((rv = nni_idhash_find(nni_endpoints, id, (void **) &ep)) != 0) {
		nni_mtx_unlock(nni_idlock);
		return (NNG_ECLOSED);
	}
	ep->ep_id = 0;
	nni_idhash_remove(nni_endpoints, id);
	while (ep->ep_holds) {
		nni_cv_wait(&ep->ep_holdcv);
	}
	nni_mtx_unlock(nni_idlock);
	return (0);
}


uint32_t
nni_ep_id(nni_ep *ep)
{
	return (ep->ep_id);
}


int
nni_ep_create(nni_ep **epp, nni_sock *sock, const char *addr)
{
	nni_tran *tran;
	nni_ep *ep;
	int rv;

	if ((tran = nni_tran_find(addr)) == NULL) {
		return (NNG_ENOTSUP);
	}
	if (strlen(addr) >= NNG_MAXADDRLEN) {
		return (NNG_EINVAL);
	}

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ep->ep_sock = sock;
	ep->ep_close = 0;
	ep->ep_bound = 0;
	ep->ep_pipe = NULL;
	ep->ep_tran = tran;
	ep->ep_holds = 0;
	ep->ep_id = 0;
	memset(&ep->ep_cv, 0, sizeof (ep->ep_cv));
	memset(&ep->ep_holdcv, 0, sizeof (ep->ep_holdcv));
	NNI_LIST_NODE_INIT(&ep->ep_node);
	// Could safely use strcpy here, but this avoids discussion.
	(void) snprintf(ep->ep_addr, sizeof (ep->ep_addr), "%s", addr);

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	ep->ep_ops = *tran->tran_ep;

	if (((rv = nni_cv_init(&ep->ep_cv, &sock->s_mx)) != 0) ||
	    ((rv = nni_cv_init(&ep->ep_holdcv, nni_idlock)) != 0)) {
		nni_cv_fini(&ep->ep_cv);
		nni_cv_fini(&ep->ep_holdcv);
		NNI_FREE_STRUCT(ep);
		return (rv);
	}

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		nni_cv_fini(&ep->ep_cv);
		nni_cv_fini(&ep->ep_holdcv);
		NNI_FREE_STRUCT(ep);
		return (NNG_ECLOSED);
	}

	rv = ep->ep_ops.ep_init(&ep->ep_data, addr, sock);
	if (rv != 0) {
		nni_mtx_unlock(&sock->s_mx);
		nni_cv_fini(&ep->ep_cv);
		nni_cv_fini(&ep->ep_holdcv);
		NNI_FREE_STRUCT(ep);
		return (rv);
	}
	nni_list_append(&sock->s_eps, ep);
	nni_mtx_unlock(&sock->s_mx);

	nni_mtx_lock(nni_idlock);
	rv = nni_idhash_alloc(nni_endpoints, &ep->ep_id, ep);
	nni_mtx_unlock(nni_idlock);
	if (rv != 0) {
		nni_mtx_lock(&sock->s_mx);
		nni_list_remove(&sock->s_eps, ep);
		ep->ep_ops.ep_fini(ep->ep_data);
		nni_cv_fini(&ep->ep_cv);
		nni_cv_fini(&ep->ep_holdcv);
		NNI_FREE_STRUCT(ep);
	}

	*epp = ep;
	return (0);
}


void
nni_ep_close(nni_ep *ep)
{
	nni_pipe *pipe;
	nni_mtx *mx = &ep->ep_sock->s_mx;

	nni_mtx_lock(nni_idlock);
	if (ep->ep_id != 0) {
		// We might have removed this already as a result of
		// application initiated endpoint close request instead
		// of socket close.
		nni_idhash_remove(nni_endpoints, ep->ep_id);
		ep->ep_id = 0;
	}
	while (ep->ep_holds) {
		nni_cv_wait(&ep->ep_holdcv);
	}
	nni_mtx_unlock(nni_idlock);

	nni_mtx_lock(mx);
	NNI_ASSERT(ep->ep_close == 0);
	ep->ep_close = 1;
	ep->ep_ops.ep_close(ep->ep_data);
	if ((pipe = ep->ep_pipe) != NULL) {
		pipe->p_ep = NULL;
		ep->ep_pipe = NULL;
	}
	nni_cv_wake(&ep->ep_cv);
	nni_list_remove(&ep->ep_sock->s_eps, ep);
	nni_mtx_unlock(mx);

	nni_thr_fini(&ep->ep_thr);
	ep->ep_ops.ep_fini(ep->ep_data);

	nni_cv_fini(&ep->ep_cv);
	NNI_FREE_STRUCT(ep);
}


static int
nni_ep_connect(nni_ep *ep, nni_pipe **pp)
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
	ep->ep_pipe = pipe;
	pipe->p_ep = ep;
	*pp = pipe;
	return (0);
}


// nni_dial_once just does a single dial call, so it can be used
// for synchronous dialing.
static int
nni_dial_once(nni_ep *ep)
{
	nni_pipe *pipe;
	int rv;

	if (((rv = nni_ep_connect(ep, &pipe)) == 0) &&
	    ((rv = nni_pipe_start(pipe)) == 0)) {
		return (0);
	}

	return (rv);
}


// nni_dialer is the thread worker that dials in the background.
static void
nni_dialer(void *arg)
{
	nni_ep *ep = arg;
	int rv;
	nni_time cooldown;
	nni_duration maxrtime;
	nni_duration defrtime;
	nni_duration rtime;
	nni_mtx *mx = &ep->ep_sock->s_mx;

	nni_mtx_lock(mx);
	defrtime = ep->ep_sock->s_reconn;
	if ((maxrtime = ep->ep_sock->s_reconnmax) == 0) {
		maxrtime = defrtime;
	}
	nni_mtx_unlock(mx);

	for (;;) {
		nni_mtx_lock(mx);
		if ((defrtime != ep->ep_sock->s_reconn) ||
		    (maxrtime != ep->ep_sock->s_reconnmax)) {
			// Times changed, so reset them.
			defrtime = ep->ep_sock->s_reconn;
			if ((maxrtime = ep->ep_sock->s_reconnmax) == 0) {
				maxrtime = defrtime;
			}
			rtime = defrtime;
		}
		while ((!ep->ep_close) && (ep->ep_pipe != NULL)) {
			rtime = defrtime;
			nni_cv_wait(&ep->ep_cv);
		}
		if (ep->ep_close) {
			nni_mtx_unlock(mx);
			break;
		}
		nni_mtx_unlock(mx);

		rv = nni_dial_once(ep);
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
		nni_mtx_lock(mx);
		while (!ep->ep_close) {
			// We need a different condvar...
			rv = nni_cv_until(&ep->ep_cv, cooldown);
			if (rv == NNG_ETIMEDOUT) {
				break;
			}
		}
		nni_mtx_unlock(mx);
	}
}


int
nni_ep_dial(nni_ep *ep, int flags)
{
	int rv = 0;
	nni_mtx *mx = &ep->ep_sock->s_mx;

	nni_mtx_lock(mx);
	if (ep->ep_mode != NNI_EP_MODE_IDLE) {
		nni_mtx_unlock(mx);
		return (NNG_EBUSY);
	}
	if (ep->ep_close) {
		nni_mtx_unlock(mx);
		return (NNG_ECLOSED);
	}

	if ((rv = nni_thr_init(&ep->ep_thr, nni_dialer, ep)) != 0) {
		nni_mtx_unlock(mx);
		return (rv);
	}
	ep->ep_mode = NNI_EP_MODE_DIAL;

	if (flags & NNG_FLAG_SYNCH) {
		nni_mtx_unlock(mx);
		rv = nni_dial_once(ep);
		if (rv != 0) {
			nni_thr_fini(&ep->ep_thr);
			ep->ep_mode = NNI_EP_MODE_IDLE;
			return (rv);
		}
		nni_mtx_lock(mx);
	}

	nni_thr_run(&ep->ep_thr);
	nni_mtx_unlock(mx);

	return (rv);
}


int
nni_ep_accept(nni_ep *ep, nni_pipe **pp)
{
	nni_pipe *pipe;
	int rv;

	if (ep->ep_close) {
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
	*pp = pipe;
	return (0);
}


static void
nni_listener(void *arg)
{
	nni_ep *ep = arg;
	nni_pipe *pipe;
	int rv;
	nni_mtx *mx = &ep->ep_sock->s_mx;

	for (;;) {
		nni_time cooldown;
		nni_mtx_lock(mx);

		// If we didn't bind synchronously, do it now.
		while (!ep->ep_bound && !ep->ep_close) {
			int rv;

			nni_mtx_unlock(mx);
			rv = ep->ep_ops.ep_bind(ep->ep_data);
			nni_mtx_lock(mx);

			if (rv == 0) {
				ep->ep_bound = 1;
				break;
			}
			// Invalid address? Out of memory?  Who knows.
			// Try again in a bit (10ms).
			// XXX: PROPER BACKOFF NEEDED
			cooldown = 10000;
			cooldown += nni_clock();
			while (!ep->ep_close) {
				rv = nni_cv_until(&ep->ep_cv, cooldown);
				if (rv == NNG_ETIMEDOUT) {
					break;
				}
			}
		}
		if (ep->ep_close) {
			nni_mtx_unlock(mx);
			break;
		}
		nni_mtx_unlock(mx);

		pipe = NULL;

		if (((rv = nni_ep_accept(ep, &pipe)) == 0) &&
		    ((rv = nni_pipe_start(pipe)) == 0)) {
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
		nni_mtx_lock(mx);
		while (!ep->ep_close) {
			rv = nni_cv_until(&ep->ep_cv, cooldown);
			if (rv == NNG_ETIMEDOUT) {
				break;
			}
		}
		nni_mtx_unlock(mx);
	}
}


int
nni_ep_listen(nni_ep *ep, int flags)
{
	int rv = 0;
	nni_mtx *mx = &ep->ep_sock->s_mx;

	nni_mtx_lock(mx);
	if (ep->ep_mode != NNI_EP_MODE_IDLE) {
		nni_mtx_unlock(mx);
		return (NNG_EBUSY);
	}

	if (ep->ep_close) {
		nni_mtx_unlock(mx);
		return (NNG_ECLOSED);
	}

	if ((rv = nni_thr_init(&ep->ep_thr, nni_listener, ep)) != 0) {
		nni_mtx_unlock(mx);
		return (rv);
	}

	ep->ep_mode = NNI_EP_MODE_LISTEN;

	if (flags & NNG_FLAG_SYNCH) {
		nni_mtx_unlock(mx);
		rv = ep->ep_ops.ep_bind(ep->ep_data);
		if (rv != 0) {
			nni_thr_fini(&ep->ep_thr);
			ep->ep_mode = NNI_EP_MODE_IDLE;
			return (rv);
		}
		nni_mtx_lock(mx);
		ep->ep_bound = 1;
	}

	nni_thr_run(&ep->ep_thr);
	nni_mtx_unlock(mx);

	return (0);
}


void
nni_ep_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_ep, ep_node);
}
