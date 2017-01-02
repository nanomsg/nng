//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
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
nni_endpt_create(nni_endpt **epp, nni_sock *sock, const char *addr)
{
	nni_tran *tran;
	nni_endpt *ep;
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
	NNI_LIST_NODE_INIT(&ep->ep_node);

	if ((rv = nni_cv_init(&ep->ep_cv, &ep->ep_sock->s_mx)) != 0) {
		NNI_FREE_STRUCT(ep);
		return (NNG_ENOMEM);
	}

	// Could safely use strcpy here, but this avoids discussion.
	(void) snprintf(ep->ep_addr, sizeof (ep->ep_addr), "%s", addr);
	ep->ep_ops = *tran->tran_ep_ops;

	rv = ep->ep_ops.ep_create(&ep->ep_data, addr, nni_sock_proto(sock));
	if (rv != 0) {
		nni_cv_fini(&ep->ep_cv);
		NNI_FREE_STRUCT(ep);
		return (rv);
	}

	nni_mtx_lock(&sock->s_mx);
	nni_list_append(&sock->s_eps, ep);
	nni_mtx_unlock(&sock->s_mx);

	*epp = ep;
	return (0);
}


void
nni_endpt_close(nni_endpt *ep)
{
	nni_pipe *pipe;
	nni_mtx *mx = &ep->ep_sock->s_mx;

	nni_mtx_lock(mx);
	if (ep->ep_close) {
		nni_mtx_unlock(mx);
		return;
	}
	ep->ep_close = 1;
	ep->ep_ops.ep_close(ep->ep_data);
	if ((pipe = ep->ep_pipe) != NULL) {
		pipe->p_ep = NULL;
		ep->ep_pipe = NULL;
	}
	nni_cv_wake(&ep->ep_cv);
	nni_list_remove(&ep->ep_sock->s_eps, ep);
	nni_mtx_unlock(mx);

	if (ep->ep_mode != NNI_EP_MODE_IDLE) {
		nni_thr_fini(&ep->ep_thr);
	}

	ep->ep_ops.ep_destroy(ep->ep_data);

	nni_cv_fini(&ep->ep_cv);
	NNI_FREE_STRUCT(ep);
}


static int
nni_endpt_connect(nni_endpt *ep, nni_pipe **pp)
{
	nni_pipe *pipe;
	int rv;

	if ((rv = nni_pipe_create(&pipe, ep)) != 0) {
		return (rv);
	}
	rv = ep->ep_ops.ep_connect(ep->ep_data, &pipe->p_tran_data);
	if (rv != 0) {
		nni_pipe_close(pipe);
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
nni_dial_once(nni_endpt *ep)
{
	nni_pipe *pipe;
	int rv;

	if (((rv = nni_endpt_connect(ep, &pipe)) == 0) &&
	    ((rv = nni_pipe_start(pipe)) == 0)) {
		return (0);
	}

	return (rv);
}


// nni_dialer is the thread worker that dials in the background.
static void
nni_dialer(void *arg)
{
	nni_endpt *ep = arg;
	nni_pipe *pipe;
	int rv;
	nni_time cooldown;
	nni_mtx *mx = &ep->ep_sock->s_mx;

	for (;;) {
		nni_mtx_lock(mx);
		while ((!ep->ep_close) && (ep->ep_pipe != NULL)) {
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
		case NNG_ENOMEM:
			cooldown = 1000000;
			break;
		case NNG_ECLOSED:
			return;

		default:
			// XXX: THIS NEEDS TO BE A PROPER BACKOFF.
			cooldown = 1000000;
			break;
		}
		// we inject a delay so we don't just spin hard on
		// errors like connection refused.  For NNG_ENOMEM, we
		// wait even longer, since the system needs time to
		// release resources.
		cooldown += nni_clock();
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
nni_endpt_dial(nni_endpt *ep, int flags)
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
nni_endpt_accept(nni_endpt *ep, nni_pipe **pp)
{
	nni_pipe *pipe;
	int rv;

	if (ep->ep_close) {
		return (NNG_ECLOSED);
	}
	if ((rv = nni_pipe_create(&pipe, ep)) != 0) {
		return (rv);
	}
	rv = ep->ep_ops.ep_accept(ep->ep_data, &pipe->p_tran_data);
	if (rv != 0) {
		nni_pipe_close(pipe);
		return (rv);
	}
	*pp = pipe;
	return (0);
}


static void
nni_listener(void *arg)
{
	nni_endpt *ep = arg;
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

		if (((rv = nni_endpt_accept(ep, &pipe)) == 0) &&
		    ((rv = nni_pipe_start(pipe)) == 0)) {
			continue;
		}
		if (rv == NNG_ECLOSED) {
			break;
		}
		cooldown = 1000;        // 1 ms cooldown
		if (rv == NNG_ENOMEM) {
			// For out of memory, we need to give more
			// time for the system to reclaim resources.
			cooldown = 100000;      // 100ms
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
nni_endpt_listen(nni_endpt *ep, int flags)
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
