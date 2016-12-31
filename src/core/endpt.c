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
nni_endpt_create(nni_endpt **epp, nni_socket *sock, const char *addr)
{
	nni_transport *tran;
	nni_endpt *ep;
	int rv;

	if ((tran = nni_transport_find(addr)) == NULL) {
		return (NNG_ENOTSUP);
	}
	if (strlen(addr) >= NNG_MAXADDRLEN) {
		return (NNG_EINVAL);
	}

	if ((ep = nni_alloc(sizeof (*ep))) == NULL) {
		return (NNG_ENOMEM);
	}
	ep->ep_dialer = NULL;
	ep->ep_listener = NULL;
	ep->ep_close = 0;
	ep->ep_start = 0;
	ep->ep_bound = 0;
	ep->ep_pipe = NULL;
	NNI_LIST_NODE_INIT(&ep->ep_node);
	if ((rv = nni_mutex_init(&ep->ep_mx)) != 0) {
		nni_free(ep, sizeof (*ep));
		return (NNG_ENOMEM);
	}
	if ((rv = nni_cond_init(&ep->ep_cv, &ep->ep_mx)) != 0) {
		nni_mutex_fini(&ep->ep_mx);
		nni_free(ep, sizeof (*ep));
		return (NNG_ENOMEM);
	}

	// Could safely use strcpy here, but this avoids discussion.
	(void) snprintf(ep->ep_addr, sizeof (ep->ep_addr), "%s", addr);
	ep->ep_sock = sock;
	ep->ep_ops = *tran->tran_ep_ops;

	rv = ep->ep_ops.ep_create(&ep->ep_data, addr, nni_socket_proto(sock));
	if (rv != 0) {
		nni_cond_fini(&ep->ep_cv);
		nni_mutex_fini(&ep->ep_mx);
		nni_free(ep, sizeof (*ep));
		return (rv);
	}
	*epp = ep;
	return (0);
}


void
nni_endpt_destroy(nni_endpt *ep)
{
	// We should already have been closed at this point, so this
	// should proceed very quickly.
	if (ep->ep_dialer != NULL) {
		nni_thread_reap(ep->ep_dialer);
	}
	if (ep->ep_listener != NULL) {
		nni_thread_reap(ep->ep_listener);
	}

	ep->ep_ops.ep_destroy(ep->ep_data);

	nni_cond_fini(&ep->ep_cv);
	nni_mutex_fini(&ep->ep_mx);
	nni_free(ep, sizeof (*ep));
}


void
nni_endpt_close(nni_endpt *ep)
{
	nni_pipe *pipe;

	nni_mutex_enter(&ep->ep_mx);
	if (ep->ep_close) {
		nni_mutex_exit(&ep->ep_mx);
		return;
	}
	ep->ep_close = 1;
	ep->ep_ops.ep_close(ep->ep_data);
	if ((pipe = ep->ep_pipe) != NULL) {
		pipe->p_ep = NULL;
		ep->ep_pipe = NULL;
	}
	nni_cond_broadcast(&ep->ep_cv);
	nni_mutex_exit(&ep->ep_mx);
}


static int
nni_endpt_connect(nni_endpt *ep, nni_pipe **pp)
{
	nni_pipe *pipe;
	int rv;

	if ((rv = nni_pipe_create(&pipe, ep)) != 0) {
		return (rv);
	}
	rv = ep->ep_ops.ep_connect(ep->ep_data, &pipe->p_trandata);
	if (rv != 0) {
		nni_pipe_destroy(pipe);
		return (rv);
	}
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


// nni_socket_dialer is the thread worker that dials in the background.
static void
nni_dialer(void *arg)
{
	nni_endpt *ep = arg;
	nni_pipe *pipe;
	int rv;
	nni_time cooldown;

	nni_mutex_enter(&ep->ep_mx);
	while ((!ep->ep_start) && (!ep->ep_close) && (!ep->ep_stop)) {
		nni_cond_wait(&ep->ep_cv);
	}
	if (ep->ep_stop || ep->ep_close) {
		nni_mutex_exit(&ep->ep_mx);
		return;
	}
	nni_mutex_exit(&ep->ep_mx);

	for (;;) {
		nni_mutex_enter(&ep->ep_mx);
		while ((!ep->ep_close) && (ep->ep_pipe != NULL)) {
			nni_cond_wait(&ep->ep_cv);
		}
		if (ep->ep_close) {
			nni_mutex_exit(&ep->ep_mx);
			break;
		}
		nni_mutex_exit(&ep->ep_mx);

		rv = nni_dial_once(ep);
		switch (rv) {
		case 0:
			// good connection
			continue;
		case NNG_ENOMEM:
			cooldown = 1000000;
			break;
		case NNG_ECLOSED:
			break;
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
		nni_mutex_enter(&ep->ep_mx);
		while (!ep->ep_close) {
			// We need a different condvar...
			rv = nni_cond_waituntil(&ep->ep_cv, cooldown);
			if (rv == NNG_ETIMEDOUT) {
				break;
			}
		}
		nni_mutex_exit(&ep->ep_mx);
	}
}


int
nni_endpt_dial(nni_endpt *ep, int flags)
{
	int rv = 0;
	nni_thread *reap = NULL;

	nni_mutex_enter(&ep->ep_mx);
	if ((ep->ep_dialer != NULL) || (ep->ep_listener != NULL)) {
		rv = NNG_EBUSY;
		goto out;
	}
	if (ep->ep_close) {
		rv = NNG_ECLOSED;
		goto out;
	}

	ep->ep_stop = 0;
	ep->ep_start = (flags & NNG_FLAG_SYNCH) ? 0 : 1;
	if (nni_thread_create(&ep->ep_dialer, nni_dialer, ep) != 0) {
		rv = NNG_ENOMEM;
		goto out;
	}
	if ((rv == 0) && (flags & NNG_FLAG_SYNCH)) {
		nni_mutex_exit(&ep->ep_mx);
		rv = nni_dial_once(ep);
		nni_mutex_enter(&ep->ep_mx);

		if (rv == 0) {
			ep->ep_start = 1;
		} else {
			// This will cause the thread to exit instead of
			// starting.
			ep->ep_stop = 1;
			reap = ep->ep_dialer;
			ep->ep_dialer = NULL;
		}
		nni_cond_signal(&ep->ep_cv);
	}
out:
	nni_mutex_exit(&ep->ep_mx);

	if (reap != NULL) {
		nni_thread_reap(reap);
	}

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
	if ((rv = ep->ep_ops.ep_accept(ep->ep_data, &pipe->p_trandata)) != 0) {
		nni_pipe_destroy(pipe);
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

	nni_mutex_enter(&ep->ep_mx);
	while ((!ep->ep_start) && (!ep->ep_close) && (!ep->ep_stop)) {
		nni_cond_wait(&ep->ep_cv);
	}
	if (ep->ep_stop || ep->ep_close) {
		nni_mutex_exit(&ep->ep_mx);
		return;
	}
	nni_mutex_exit(&ep->ep_mx);
	for (;;) {
		nni_time cooldown;
		nni_mutex_enter(&ep->ep_mx);

		// If we didn't bind synchronously, do it now.
		while (!ep->ep_bound && !ep->ep_close) {
			int rv;

			nni_mutex_exit(&ep->ep_mx);
			rv = ep->ep_ops.ep_bind(ep->ep_data);
			nni_mutex_enter(&ep->ep_mx);

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
				rv = nni_cond_waituntil(&ep->ep_cv, cooldown);
				if (rv == NNG_ETIMEDOUT) {
					break;
				}
			}
		}
		if (ep->ep_close) {
			nni_mutex_exit(&ep->ep_mx);
			break;
		}
		nni_mutex_exit(&ep->ep_mx);

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
		nni_mutex_enter(&ep->ep_mx);
		while (!ep->ep_close) {
			rv = nni_cond_waituntil(&ep->ep_cv, cooldown);
			if (rv == NNG_ETIMEDOUT) {
				break;
			}
		}
		nni_mutex_exit(&ep->ep_mx);
	}
}


int
nni_endpt_listen(nni_endpt *ep, int flags)
{
	int rv = 0;
	nni_thread *reap = NULL;

	nni_mutex_enter(&ep->ep_mx);
	if ((ep->ep_dialer != NULL) || (ep->ep_listener != NULL)) {
		rv = NNG_EBUSY;
		goto out;
	}
	if (ep->ep_close) {
		rv = NNG_ECLOSED;
		goto out;
	}

	ep->ep_stop = 0;
	ep->ep_start = (flags & NNG_FLAG_SYNCH) ? 0 : 1;
	if (nni_thread_create(&ep->ep_listener, nni_listener, ep) != 0) {
		rv = NNG_ENOMEM;
		goto out;
	}
	if ((rv == 0) && (flags & NNG_FLAG_SYNCH)) {
		nni_mutex_exit(&ep->ep_mx);
		rv = ep->ep_ops.ep_bind(ep->ep_data);
		nni_mutex_enter(&ep->ep_mx);
		if (rv == 0) {
			ep->ep_bound = 1;
			ep->ep_start = 1;
		} else {
			// This will cause the thread to exit instead of
			// starting.
			ep->ep_stop = 1;
			reap = ep->ep_listener;
			ep->ep_listener = NULL;
		}
		nni_cond_signal(&ep->ep_cv);
	}
out:
	nni_mutex_exit(&ep->ep_mx);

	if (reap != NULL) {
		nni_thread_reap(reap);
	}

	return (rv);
}
