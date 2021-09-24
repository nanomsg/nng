//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <stdlib.h>

#include "core/nng_impl.h"

#include <nng/transport/ipc/ipc.h>

// IPC transport.   Platform specific IPC operations must be
// supplied as well.  Normally the IPC is UNIX domain sockets or
// Windows named pipes.  Other platforms could use other mechanisms,
// but all implementations on the platform must use the same mechanism.

static int
ipc_ep_init_dialer(void **dp, nni_url *url, nni_dialer *dialer)
{
	nni_sp_tran_ep *ep;
	int             rv;
	nni_sock *      sock = nni_dialer_sock(dialer);

	if ((rv = nni_sp_ep_dialer_init(&ep, url, url, sock)) != 0) {
		return (rv);
	}

#ifdef NNG_ENABLE_STATS
	nni_dialer_add_stat(dialer, &ep->st_rcv_max);
#endif
	*dp = ep;
	return (0);
}

static int
ipc_ep_init_listener(void **dp, nni_url *url, nni_listener *listener)
{
	nni_sp_tran_ep *  ep;
	int               rv;
	nni_sock         *sock = nni_listener_sock(listener);

	if ((rv = nni_sp_ep_listener_init(&ep, url, sock)) != 0) {
		return (rv);
	}

#ifdef NNG_ENABLE_STATS
	nni_listener_add_stat(listener, &ep->st_rcv_max);
#endif
	*dp = ep;
	return (0);
}

static nni_sp_pipe_ops ipc_tran_pipe_ops = {
	.p_init   = nni_sp_pipe_init,
	.p_fini   = nni_sp_pipe_fini,
	.p_stop   = nni_sp_pipe_stop,
	.p_send   = nni_sp_pipe_send,
	.p_recv   = nni_sp_pipe_recv,
	.p_close  = nni_sp_pipe_close,
	.p_peer   = nni_sp_pipe_peer,
	.p_getopt = nni_sp_pipe_getopt,
};

static const nni_option ipc_ep_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = nni_sp_ep_get_recvmaxsz,
	    .o_set  = nni_sp_ep_set_recvmaxsz,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
ipc_dialer_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	return nni_sp_ep_dialer_get(arg, ipc_ep_options, name, buf, szp, t);
}

static int
ipc_dialer_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	return nni_sp_ep_dialer_set(arg, ipc_ep_options, name, buf, sz, t);
}

static int
ipc_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	return nni_sp_ep_listener_get(arg, ipc_ep_options, name, buf, szp, t);
}

static int
ipc_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	return nni_sp_ep_listener_set(arg, ipc_ep_options, name, buf, sz, t);
}

static nni_sp_dialer_ops ipc_dialer_ops = {
	.d_init    = ipc_ep_init_dialer,
	.d_fini    = nni_sp_ep_fini,
	.d_connect = nni_sp_ep_connect,
	.d_close   = nni_sp_ep_close,
	.d_getopt  = ipc_dialer_get,
	.d_setopt  = ipc_dialer_set,
};

static nni_sp_listener_ops ipc_listener_ops = {
	.l_init   = ipc_ep_init_listener,
	.l_fini   = nni_sp_ep_fini,
	.l_bind   = nni_sp_ep_bind,
	.l_accept = nni_sp_ep_accept,
	.l_close  = nni_sp_ep_close,
	.l_getopt = ipc_listener_get,
	.l_setopt = ipc_listener_set,
};

static nni_sp_tran ipc_tran = {
	.tran_scheme   = "ipc",
	.tran_dialer   = &ipc_dialer_ops,
	.tran_listener = &ipc_listener_ops,
	.tran_pipe     = &ipc_tran_pipe_ops,
	.tran_init     = nni_sp_tran_init,
	.tran_fini     = nni_sp_tran_fini,
};

#ifdef NNG_PLATFORM_POSIX
static nni_sp_tran ipc_tran_unix = {
	.tran_scheme   = "unix",
	.tran_dialer   = &ipc_dialer_ops,
	.tran_listener = &ipc_listener_ops,
	.tran_pipe     = &ipc_tran_pipe_ops,
	.tran_init     = nni_sp_tran_init,
	.tran_fini     = nni_sp_tran_fini,
};
#endif

#ifdef NNG_HAVE_ABSTRACT_SOCKETS
static nni_sp_tran ipc_tran_abstract = {
	.tran_scheme   = "abstract",
	.tran_dialer   = &ipc_dialer_ops,
	.tran_listener = &ipc_listener_ops,
	.tran_pipe     = &ipc_tran_pipe_ops,
	.tran_init     = nni_sp_tran_init,
	.tran_fini     = nni_sp_tran_fini,
};
#endif


#ifndef NNG_ELIDE_DEPRECATED
int
nng_ipc_register(void)
{
	return (nni_init());
}
#endif

void
nni_sp_ipc_register(void)
{
	nni_sp_tran_register(&ipc_tran);
#ifdef NNG_PLATFORM_POSIX
	nni_sp_tran_register(&ipc_tran_unix);
#endif
#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	nni_sp_tran_register(&ipc_tran_abstract);
#endif
}
