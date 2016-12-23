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
#if 0
struct nng_endpt {
	struct nni_endpt_ops	ep_ops;
	void *			ep_data;
	nni_list_node_t		ep_sock_node;
	nni_socket *		ep_sock;
	char			ep_addr[NNG_MAXADDRLEN];
	nni_thread *		ep_dialer;
	nni_thread *		ep_listener;
	int			ep_close;
	nni_mutex		ep_mx;
	nni_cond		ep_cv;
};
#endif

int
nni_endpt_create(nni_endpt **epp, nni_socket *sock, const char *addr)
{
	nni_transport *tran;
	nni_endpt *ep;
	int rv;

	if ((tran = nni_transport_find(addr)) == NULL) {
		return (NNG_EINVAL);
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
	ep->ep_pipe = NULL;
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


int
nni_endpt_listen(nni_endpt *ep)
{
	if (ep->ep_close) {
		return (NNG_ECLOSED);
	}
	return (ep->ep_ops.ep_listen(ep->ep_data));
}


int
nni_endpt_dial(nni_endpt *ep, nni_pipe **pp)
{
	nni_pipe *pipe;
	int rv;

	if (ep->ep_close) {
		return (NNG_ECLOSED);
	}
	if ((rv = nni_pipe_create(&pipe, ep->ep_ops.ep_pipe_ops)) != 0) {
		return (rv);
	}
	if ((rv = ep->ep_ops.ep_dial(ep->ep_data, &pipe->p_data)) != 0) {
		nni_pipe_destroy(pipe);
		return (rv);
	}
	pipe->p_ep = ep;
	*pp = pipe;
	return (0);
}


int
nni_endpt_accept(nni_endpt *ep, nni_pipe **pp)
{
	nni_pipe *pipe;
	int rv;

	if (ep->ep_close) {
		return (NNG_ECLOSED);
	}
	if ((rv = nni_pipe_create(&pipe, ep->ep_ops.ep_pipe_ops)) != 0) {
		return (rv);
	}
	if ((rv = ep->ep_ops.ep_accept(ep->ep_data, &pipe->p_data)) != 0) {
		nni_pipe_destroy(pipe);
		return (rv);
	}
	pipe->p_ep = ep;
	*pp = pipe;
	return (0);
}
