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
#include "transport/inproc/inproc.h"
#include "transport/ipc/ipc.h"
#include "transport/tcp/tcp.h"
#include "transport/tls/tls.h"
#include "transport/zerotier/zerotier.h"

#include <stdio.h>
#include <string.h>

// For now the list of transports is hard-wired.  Adding new transports
// to the system dynamically is something that might be considered later.
extern nni_tran nni_tcp_tran;
extern nni_tran nni_ipc_tran;

typedef struct nni_transport {
	nni_tran      t_tran;
	char          t_prefix[16]; // e.g. "tcp://" or "tls+tcp://"
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
	size_t         sz;

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
		if (tran->tran_init == t->t_tran.tran_init) {
			nni_mtx_unlock(&nni_tran_lk);
			// Same transport, duplicate registration.
			return (0);
		}
		if (strcmp(tran->tran_scheme, t->t_tran.tran_scheme) == 0) {
			nni_mtx_unlock(&nni_tran_lk);
			return (NNG_ESTATE);
		}
	}
	if ((t = NNI_ALLOC_STRUCT(t)) == NULL) {
		nni_mtx_unlock(&nni_tran_lk);
		return (NNG_ENOMEM);
	}

	t->t_tran = *tran;
	sz        = sizeof(t->t_prefix);
	if ((nni_strlcpy(t->t_prefix, tran->tran_scheme, sz) >= sz) ||
	    (nni_strlcat(t->t_prefix, "://", sz) >= sz)) {
		nni_mtx_unlock(&nni_tran_lk);
		NNI_FREE_STRUCT(t);
		return (NNG_EINVAL);
	}
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
nni_tran_find(const char *addr)
{
	// address is of the form "<scheme>://blah..."
	nni_transport *t;

	nni_mtx_lock(&nni_tran_lk);
	NNI_LIST_FOREACH (&nni_tran_list, t) {
		if (strncmp(addr, t->t_prefix, strlen(t->t_prefix)) == 0) {
			nni_mtx_unlock(&nni_tran_lk);
			return (&t->t_tran);
		}
	}
	nni_mtx_unlock(&nni_tran_lk);
	return (NULL);
}

int
nni_tran_chkopt(const char *name, const void *v, size_t sz)
{
	nni_transport *t;
	int            rv = NNG_ENOTSUP;

	nni_mtx_lock(&nni_tran_lk);
	NNI_LIST_FOREACH (&nni_tran_list, t) {
		const nni_tran_ep *       ep;
		const nni_tran_ep_option *eo;

		// Generally we look for endpoint options.
		ep = t->t_tran.tran_ep;
		for (eo = ep->ep_options; eo && eo->eo_name != NULL; eo++) {
			if (strcmp(name, eo->eo_name) != 0) {
				continue;
			}
			if (eo->eo_setopt == NULL) {
				nni_mtx_unlock(&nni_tran_lk);
				return (NNG_EREADONLY);
			}
			if ((rv = eo->eo_setopt(NULL, v, sz)) != 0) {
				nni_mtx_unlock(&nni_tran_lk);
				return (rv);
			}
		}
	}
	nni_mtx_unlock(&nni_tran_lk);
	return (rv);
}

// nni_tran_sys_init initializes the entire transport subsystem, including
// each individual transport.

typedef int (*nni_tran_ctor)(void);

static nni_tran_ctor nni_tran_ctors[] = {
#ifdef NNG_HAVE_INPROC
	nng_inproc_register,
#endif
#ifdef NNG_HAVE_IPC
	nng_ipc_register,
#endif
#ifdef NNG_HAVE_TCP
	nng_tcp_register,
#endif
#ifdef NNG_HAVE_TLS
	nng_tls_register,
#endif
#ifdef NNI_HAVE_ZEROTIER
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
