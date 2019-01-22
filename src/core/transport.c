//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_TRANSPORT_INPROC
#include "nng/transport/inproc/inproc.h"
#endif
#ifdef NNG_TRANSPORT_IPC
#include "nng/transport/ipc/ipc.h"
#endif
#ifdef NNG_TRANSPORT_TCP
#include "nng/transport/tcp/tcp.h"
#endif
#ifdef NNG_TRANSPORT_TLS
#include "nng/transport/tls/tls.h"
#endif
#ifdef NNG_TRANSPORT_WS
#include "nng/transport/ws/websocket.h"
#endif
#ifdef NNG_TRANSPORT_ZEROTIER
#include "nng/transport/zerotier/zerotier.h"
#endif

#include <stdio.h>
#include <string.h>

// For now the list of transports is hard-wired.  Adding new transports
// to the system dynamically is something that might be considered later.
extern nni_tran nni_tcp_tran;
extern nni_tran nni_ipc_tran;

typedef struct nni_transport {
	nni_tran      t_tran;
	nni_list_node t_node;
} nni_transport;

static nni_list nni_tran_list;
static nni_mtx  nni_tran_lk;
static int      nni_tran_inited;

int
nni_tran_register(const nni_tran *tran)
{
	nni_transport *t;
	int            rv;

	// Its entirely possible that we are called before any sockets
	// are opened.  Make sure we are initialized.  This has to be
	// protected by a guard to prevent infinite recursion, since
	// nni_init also winds up calling us.
	if (!nni_tran_inited) {
		nni_init();
	}

	if (tran->tran_version != NNI_TRANSPORT_VERSION) {
		return (NNG_ENOTSUP);
	}

	nni_mtx_lock(&nni_tran_lk);
	// Check to see if the transport is already registered...
	NNI_LIST_FOREACH (&nni_tran_list, t) {
		if (strcmp(tran->tran_scheme, t->t_tran.tran_scheme) == 0) {
			if (tran->tran_init == t->t_tran.tran_init) {
				// duplicate.
				nni_mtx_unlock(&nni_tran_lk);
				return (0);
			}
			nni_mtx_unlock(&nni_tran_lk);
			return (NNG_ESTATE);
		}
	}
	if ((t = NNI_ALLOC_STRUCT(t)) == NULL) {
		nni_mtx_unlock(&nni_tran_lk);
		return (NNG_ENOMEM);
	}

	t->t_tran = *tran;
	if ((rv = t->t_tran.tran_init()) != 0) {
		nni_mtx_unlock(&nni_tran_lk);
		NNI_FREE_STRUCT(t);
		return (rv);
	}
	nni_list_append(&nni_tran_list, t);
	nni_mtx_unlock(&nni_tran_lk);
	return (0);
}

nni_tran *
nni_tran_find(nni_url *url)
{
	// address is of the form "<scheme>://blah..."
	nni_transport *t;

	nni_mtx_lock(&nni_tran_lk);
	NNI_LIST_FOREACH (&nni_tran_list, t) {
		if (strcmp(url->u_scheme, t->t_tran.tran_scheme) == 0) {
			nni_mtx_unlock(&nni_tran_lk);
			return (&t->t_tran);
		}
	}
	nni_mtx_unlock(&nni_tran_lk);
	return (NULL);
}

int
nni_tran_chkopt(const char *name, const void *v, size_t sz, int typ)
{
	nni_transport *t;
	int            rv = NNG_ENOTSUP;

	nni_mtx_lock(&nni_tran_lk);
	NNI_LIST_FOREACH (&nni_tran_list, t) {
		const nni_tran_dialer_ops *  dops;
		const nni_tran_listener_ops *lops;
		const nni_option *           o;

		// Check option entry point is cleaner than endpoint hacks.
		if (t->t_tran.tran_checkopt != NULL) {
			rv = t->t_tran.tran_checkopt(name, v, sz, typ);
			if (rv != NNG_ENOTSUP) {
				nni_mtx_unlock(&nni_tran_lk);
				return (rv);
			}
			continue;
		}

		// Generally we look for endpoint options. We check both
		// dialers and listeners.
		dops = t->t_tran.tran_dialer;
		if ((dops->d_setopt != NULL) &&
		    ((rv = dops->d_setopt(NULL, name, v, sz, typ)) !=
		        NNG_ENOTSUP)) {
			nni_mtx_unlock(&nni_tran_lk);
			return (rv);
		}
		for (o = dops->d_options; o && o->o_name != NULL; o++) {
			if (strcmp(name, o->o_name) != 0) {
				continue;
			}
			if (o->o_set == NULL) {
				nni_mtx_unlock(&nni_tran_lk);
				return (NNG_EREADONLY);
			}
			nni_mtx_unlock(&nni_tran_lk);
			rv = o->o_set(NULL, v, sz, typ);
			return (rv);
		}
		lops = t->t_tran.tran_listener;
		if ((lops->l_setopt != NULL) &&
		    ((rv = lops->l_setopt(NULL, name, v, sz, typ)) !=
		        NNG_ENOTSUP)) {
			nni_mtx_unlock(&nni_tran_lk);
			return (rv);
		}
		for (o = lops->l_options; o && o->o_name != NULL; o++) {
			if (strcmp(name, o->o_name) != 0) {
				continue;
			}
			if (o->o_set == NULL) {
				nni_mtx_unlock(&nni_tran_lk);
				return (NNG_EREADONLY);
			}
			nni_mtx_unlock(&nni_tran_lk);
			rv = o->o_set(NULL, v, sz, typ);
			return (rv);
		}
	}
	nni_mtx_unlock(&nni_tran_lk);
	return (rv);
}

// nni_tran_sys_init initializes the entire transport subsystem, including
// each individual transport.

typedef int (*nni_tran_ctor)(void);

// These are just the statically compiled in constructors.
// In the future we might want to support dynamic additions.
static nni_tran_ctor nni_tran_ctors[] = {
#ifdef NNG_TRANSPORT_INPROC
	nng_inproc_register,
#endif
#ifdef NNG_TRANSPORT_IPC
	nng_ipc_register,
#endif
#ifdef NNG_TRANSPORT_TCP
	nng_tcp_register,
#endif
#ifdef NNG_TRANSPORT_TLS
	nng_tls_register,
#endif
#ifdef NNG_TRANSPORT_WS
	nng_ws_register,
#endif
#ifdef NNG_TRANSPORT_WSS
	nng_wss_register,
#endif
#ifdef NNG_TRANSPORT_ZEROTIER
	nng_zt_register,
#endif
	NULL,
};

int
nni_tran_sys_init(void)
{
	int i;

	nni_tran_inited = 1;
	NNI_LIST_INIT(&nni_tran_list, nni_transport, t_node);
	nni_mtx_init(&nni_tran_lk);

	for (i = 0; nni_tran_ctors[i] != NULL; i++) {
		int rv;
		if ((rv = (nni_tran_ctors[i])()) != 0) {
			nni_tran_sys_fini();
			return (rv);
		}
	}
	return (0);
}

// nni_tran_sys_fini finalizes the entire transport system, including all
// transports.
void
nni_tran_sys_fini(void)
{
	nni_transport *t;

	while ((t = nni_list_first(&nni_tran_list)) != NULL) {
		nni_list_remove(&nni_tran_list, t);
		t->t_tran.tran_fini();
		NNI_FREE_STRUCT(t);
	}
	nni_mtx_fini(&nni_tran_lk);
	nni_tran_inited = 0;
}
