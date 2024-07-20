//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdio.h>
#include <string.h>

static nni_list sp_tran_list =
    NNI_LIST_INITIALIZER(sp_tran_list, nni_sp_tran, tran_link);
static nni_rwlock sp_tran_lk = NNI_RWLOCK_INITIALIZER;

void
nni_sp_tran_register(nni_sp_tran *tran)
{
	nni_rwlock_wrlock(&sp_tran_lk);
	if (!nni_list_node_active(&tran->tran_link)) {
		tran->tran_init();
		nni_list_append(&sp_tran_list, tran);
		nng_log_info(
		    "NNG-TRAN", "Registered transport: %s", tran->tran_scheme);
	}
	nni_rwlock_unlock(&sp_tran_lk);
}

nni_sp_tran *
nni_sp_tran_find(nni_url *url)
{
	// address is of the form "<scheme>://blah..."
	nni_sp_tran *t;

	nni_rwlock_rdlock(&sp_tran_lk);
	NNI_LIST_FOREACH (&sp_tran_list, t) {
		if (strcmp(url->u_scheme, t->tran_scheme) == 0) {
			nni_rwlock_unlock(&sp_tran_lk);
			return (t);
		}
	}
	nni_rwlock_unlock(&sp_tran_lk);
	return (NULL);
}

// nni_sp_tran_sys_init initializes the entire transport subsystem, including
// each individual transport.

#ifdef NNG_TRANSPORT_INPROC
extern void nni_sp_inproc_register(void);
#endif
#ifdef NNG_TRANSPORT_IPC
extern void nni_sp_ipc_register(void);
#endif
#ifdef NNG_TRANSPORT_TCP
extern void nni_sp_tcp_register(void);
#endif
#ifdef NNG_TRANSPORT_TLS
extern void nni_sp_tls_register(void);
#endif
#ifdef NNG_TRANSPORT_WS
extern void nni_sp_ws_register(void);
#endif
#ifdef NNG_TRANSPORT_WSS
extern void nni_sp_wss_register(void);
#endif
#ifdef NNG_TRANSPORT_ZEROTIER
extern void nni_sp_zt_register(void);
#endif
#ifdef NNG_TRANSPORT_FDC
extern void nni_sp_sfd_register(void);
#endif
#ifdef NNG_TRANSPORT_UDP
extern void nni_sp_udp_register(void);
#endif

void
nni_sp_tran_sys_init(void)
{
#ifdef NNG_TRANSPORT_INPROC
	nni_sp_inproc_register();
#endif
#ifdef NNG_TRANSPORT_IPC
	nni_sp_ipc_register();
#endif
#ifdef NNG_TRANSPORT_TCP
	nni_sp_tcp_register();
#endif
#ifdef NNG_TRANSPORT_TLS
	nni_sp_tls_register();
#endif
#ifdef NNG_TRANSPORT_WS
	nni_sp_ws_register();
#endif
#ifdef NNG_TRANSPORT_WSS
	nni_sp_wss_register();
#endif
#ifdef NNG_TRANSPORT_ZEROTIER
	nni_sp_zt_register();
#endif
#ifdef NNG_TRANSPORT_FDC
	nni_sp_sfd_register();
#endif
#ifdef NNG_TRANSPORT_UDP
	nni_sp_udp_register();
#endif
}

// nni_sp_tran_sys_fini finalizes the entire transport system, including all
// transports.
void
nni_sp_tran_sys_fini(void)
{
	nni_sp_tran *t;

	while ((t = nni_list_first(&sp_tran_list)) != NULL) {
		nni_list_remove(&sp_tran_list, t);
		t->tran_fini();
	}
}
