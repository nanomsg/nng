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

#include <stdbool.h>
#include <string.h>

#include "core/nng_impl.h"

#include "nng/supplemental/tls/tls.h"
#include "nng/transport/tls/tls.h"

// TLS over TCP transport.   Platform specific TCP operations must be
// supplied as well, and uses the supplemental TLS v1.2 code.  It is not
// an accident that this very closely resembles the TCP transport itself.

static int
tlstran_url_get_af(const nni_url *url, int *afp)
{
	if (strcmp(url->u_scheme, "tls+tcp") == 0) {
		*afp = NNG_AF_UNSPEC;
	} else if (strcmp(url->u_scheme, "tls+tcp4") == 0) {
		*afp = NNG_AF_INET;
	} else if (strcmp(url->u_scheme, "tls+tcp6") == 0) {
		*afp = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}
	return 0;
}

static int
tlstran_ep_init_dialer(void **dp, nni_url *url, nni_dialer *ndialer)
{
	nni_sp_tran_ep * ep;
	int              rv;
	nng_sockaddr     srcsa;
	nni_sock *       sock = nni_dialer_sock(ndialer);
	nni_url          myurl;

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL) || (strlen(url->u_hostname) == 0) ||
	    (strlen(url->u_port) == 0)) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = nni_sp_url_parse_source(&myurl, &srcsa, url, tlstran_url_get_af)) != 0) {
		return (rv);
	}

	if ((rv = nni_sp_ep_dialer_init(&ep, url, &myurl, sock)) != 0) {
		return (rv);
	}
	ep->authmode = NNG_TLS_AUTH_MODE_REQUIRED;

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
tlstran_ep_init_listener(void **lp, nni_url *url, nni_listener *nlistener)
{
	nni_sp_tran_ep *ep;
	int             rv;
	int             af;
	char *          host = url->u_hostname;
	nni_aio *       aio;
	nni_sock *      sock = nni_listener_sock(nlistener);

	if ((rv = tlstran_url_get_af(url, &af)) != 0) {
		return rv;
	}

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

	ep->authmode = NNG_TLS_AUTH_MODE_NONE;

	if (strlen(host) == 0) {
		host = NULL;
	}

	// XXX: We are doing lookup at listener initialization.  There is
	// a valid argument that this should be done at bind time, but that
	// would require making bind asynchronous.  In some ways this would
	// be worse than the cost of just waiting here.  We always recommend
	// using local IP addresses rather than names when possible.

	if ((rv = nni_aio_alloc(&aio, NULL, NULL)) != 0) {
		nni_sp_ep_fini(ep);
		return (rv);
	}
	nni_resolv_ip(host, url->u_port, af, true, &ep->sa, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_free(aio);

	if ((rv != 0) ||
	    ((rv = nni_stream_listener_set(ep->listener, NNG_OPT_TLS_AUTH_MODE,
	          &ep->authmode, sizeof(ep->authmode), NNI_TYPE_INT32)) !=
	        0)) {
		nni_sp_ep_fini(ep);
		return (rv);
	}
#ifdef NNG_ENABLE_STATS
	nni_listener_add_stat(nlistener, &ep->st_rcv_max);
#endif
	*lp = ep;
	return (0);
}

static nni_sp_pipe_ops tlstran_pipe_ops = {
	.p_init   = nni_sp_pipe_init,
	.p_fini   = nni_sp_pipe_fini,
	.p_stop   = nni_sp_pipe_stop,
	.p_send   = nni_sp_pipe_send,
	.p_recv   = nni_sp_pipe_recv,
	.p_close  = nni_sp_pipe_close,
	.p_peer   = nni_sp_pipe_peer,
	.p_getopt = nni_sp_pipe_getopt,
};

static nni_option tlstran_ep_options[] = {
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
tlstran_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	return nni_sp_ep_dialer_get(arg, tlstran_ep_options, name, buf, szp, t);
}

static int
tlstran_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	return nni_sp_ep_dialer_set(arg, tlstran_ep_options, name, buf, sz, t);
}

static int
tlstran_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	return nni_sp_ep_listener_get(arg, tlstran_ep_options, name, buf, szp, t);
}

static int
tlstran_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	return nni_sp_ep_listener_set(arg, tlstran_ep_options, name, buf, sz, t);
}

static nni_sp_dialer_ops tlstran_dialer_ops = {
	.d_init    = tlstran_ep_init_dialer,
	.d_fini    = nni_sp_ep_fini,
	.d_connect = nni_sp_ep_connect,
	.d_close   = nni_sp_ep_close,
	.d_getopt  = tlstran_dialer_getopt,
	.d_setopt  = tlstran_dialer_setopt,
};

static nni_sp_listener_ops tlstran_listener_ops = {
	.l_init   = tlstran_ep_init_listener,
	.l_fini   = nni_sp_ep_fini,
	.l_bind   = nni_sp_ep_bind,
	.l_accept = nni_sp_ep_accept,
	.l_close  = nni_sp_ep_close,
	.l_getopt = tlstran_listener_get,
	.l_setopt = tlstran_listener_set,
};

static nni_sp_tran tls_tran = {
	.tran_scheme   = "tls+tcp",
	.tran_dialer   = &tlstran_dialer_ops,
	.tran_listener = &tlstran_listener_ops,
	.tran_pipe     = &tlstran_pipe_ops,
	.tran_init     = nni_sp_tran_init,
	.tran_fini     = nni_sp_tran_fini,
};

static nni_sp_tran tls4_tran = {
	.tran_scheme   = "tls+tcp4",
	.tran_dialer   = &tlstran_dialer_ops,
	.tran_listener = &tlstran_listener_ops,
	.tran_pipe     = &tlstran_pipe_ops,
	.tran_init     = nni_sp_tran_init,
	.tran_fini     = nni_sp_tran_fini,
};

static nni_sp_tran tls6_tran = {
	.tran_scheme   = "tls+tcp6",
	.tran_dialer   = &tlstran_dialer_ops,
	.tran_listener = &tlstran_listener_ops,
	.tran_pipe     = &tlstran_pipe_ops,
	.tran_init     = nni_sp_tran_init,
	.tran_fini     = nni_sp_tran_fini,
};

int
nng_tls_register(void)
{
	return (nni_init());
}

void
nni_sp_tls_register(void)
{
	nni_sp_tran_register(&tls_tran);
	nni_sp_tran_register(&tls4_tran);
	nni_sp_tran_register(&tls6_tran);
}
