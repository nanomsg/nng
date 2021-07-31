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

static nni_list   sp_tran_list;
static nni_rwlock sp_tran_lk;

void
nni_sp_tran_register(nni_sp_tran *tran)
{
	nni_rwlock_wrlock(&sp_tran_lk);
	if (!nni_list_node_active(&tran->tran_link)) {
		tran->tran_init();
		nni_list_append(&sp_tran_list, tran);
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

int
nni_sp_tran_sys_init(void)
{
	NNI_LIST_INIT(&sp_tran_list, nni_sp_tran, tran_link);
	nni_rwlock_init(&sp_tran_lk);

#ifdef NNG_TRANSPORT_INPROC
	nng_inproc_register();
#endif
#ifdef NNG_TRANSPORT_IPC
	nng_ipc_register();
#endif
#ifdef NNG_TRANSPORT_TCP
	nng_tcp_register();
#endif
#ifdef NNG_TRANSPORT_TLS
	nng_tls_register();
#endif
#ifdef NNG_TRANSPORT_WS
	nng_ws_register();
#endif
#ifdef NNG_TRANSPORT_WSS
	nng_wss_register();
#endif
#ifdef NNG_TRANSPORT_ZEROTIER
	nng_zt_register();
#endif
	return (0);
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
	nni_rwlock_fini(&sp_tran_lk);
}
