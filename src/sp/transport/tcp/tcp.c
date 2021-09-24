//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
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
#include <string.h>

#include "core/nng_impl.h"

// TCP transport.   Platform specific TCP operations must be
// supplied as well.

static int
tcptran_url_get_af(const nni_url *url, int *afp)
{
	if (strcmp(url->u_scheme, "tcp") == 0) {
		*afp = NNG_AF_UNSPEC;
	} else if (strcmp(url->u_scheme, "tcp4") == 0) {
		*afp = NNG_AF_INET;
	} else if (strcmp(url->u_scheme, "tcp6") == 0) {
		*afp = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}
	return 0;
}

static int
tcptran_dialer_init(void **dp, nng_url *url, nni_dialer *ndialer)
{
	nni_sp_tran_ep * ep;
	int              rv;
	nng_sockaddr     srcsa;
	nni_sock *       sock = nni_dialer_sock(ndialer);
	nng_url          myurl;

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL) || (strlen(url->u_hostname) == 0) ||
	    (strlen(url->u_port) == 0)) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_sp_url_parse_source(&myurl, &srcsa, url, tcptran_url_get_af)) != 0) {
		return (rv);
	}

	if ((rv = nni_sp_ep_dialer_init(&ep, url, &myurl, sock)) != 0) {
		return (rv);
	}

	if ((srcsa.s_family != NNG_AF_UNSPEC) &&
	    ((rv = nni_stream_dialer_set(ep->dialer, NNG_OPT_LOCADDR, &srcsa,
	          sizeof(srcsa), NNI_TYPE_SOCKADDR)) != 0)) {
		nni_sp_ep_fini(ep);
		return (rv);
	}

#ifdef NNG_ENABLE_STATS
	nni_dialer_add_stat(ndialer, &ep->st_rcv_max);
#endif
	*dp = ep;
	return (0);
}

static int
tcptran_listener_init(void **lp, nng_url *url, nni_listener *nlistener)
{
	nni_sp_tran_ep *ep;
	int             rv;
	nni_sock *      sock = nni_listener_sock(nlistener);

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL)) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_sp_ep_listener_init(&ep, url, sock)) != 0) {
		return (rv);
	}

#ifdef NNG_ENABLE_STATS
	nni_listener_add_stat(nlistener, &ep->st_rcv_max);
#endif

	*lp = ep;
	return (0);
}

static nni_sp_pipe_ops tcptran_pipe_ops = {
	.p_init   = nni_sp_pipe_init,
	.p_fini   = nni_sp_pipe_fini,
	.p_stop   = nni_sp_pipe_stop,
	.p_send   = nni_sp_pipe_send,
	.p_recv   = nni_sp_pipe_recv,
	.p_close  = nni_sp_pipe_close,
	.p_peer   = nni_sp_pipe_peer,
	.p_getopt = nni_sp_pipe_getopt,
};

static const nni_option tcptran_ep_opts[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = nni_sp_ep_get_recvmaxsz,
	    .o_set  = nni_sp_ep_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_get  = nni_sp_ep_get_url,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
tcptran_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	return nni_sp_ep_dialer_get(arg, tcptran_ep_opts, name, buf, szp, t);
}

static int
tcptran_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	return nni_sp_ep_dialer_set(arg, tcptran_ep_opts, name, buf, sz, t);
}

static int
tcptran_listener_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	return nni_sp_ep_listener_get(arg, tcptran_ep_opts, name, buf, szp, t);
}

static int
tcptran_listener_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	return nni_sp_ep_listener_set(arg, tcptran_ep_opts, name, buf, sz, t);
}

static nni_sp_dialer_ops tcptran_dialer_ops = {
	.d_init    = tcptran_dialer_init,
	.d_fini    = nni_sp_ep_fini,
	.d_connect = nni_sp_ep_connect,
	.d_close   = nni_sp_ep_close,
	.d_getopt  = tcptran_dialer_getopt,
	.d_setopt  = tcptran_dialer_setopt,
};

static nni_sp_listener_ops tcptran_listener_ops = {
	.l_init   = tcptran_listener_init,
	.l_fini   = nni_sp_ep_fini,
	.l_bind   = nni_sp_ep_bind,
	.l_accept = nni_sp_ep_accept,
	.l_close  = nni_sp_ep_close,
	.l_getopt = tcptran_listener_getopt,
	.l_setopt = tcptran_listener_setopt,
};

static nni_sp_tran tcp_tran = {
	.tran_scheme   = "tcp",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = nni_sp_tran_init,
	.tran_fini     = nni_sp_tran_fini,
};

static nni_sp_tran tcp4_tran = {
	.tran_scheme   = "tcp4",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = nni_sp_tran_init,
	.tran_fini     = nni_sp_tran_fini,
};

static nni_sp_tran tcp6_tran = {
	.tran_scheme   = "tcp6",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = nni_sp_tran_init,
	.tran_fini     = nni_sp_tran_fini,
};

#ifndef NNG_ELIDE_DEPRECATED
int
nng_tcp_register(void)
{
	return (nni_init());
}
#endif

void
nni_sp_tcp_register(void)
{
	nni_sp_tran_register(&tcp_tran);
	nni_sp_tran_register(&tcp4_tran);
	nni_sp_tran_register(&tcp6_tran);
}
