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
#include "supplemental/mqtt/mqtt_msg.h"

#include <stdio.h>
#include <string.h>

static nni_list   mqtt_tran_list;
static nni_rwlock mqtt_tran_lk;

void
nni_mqtt_tran_register(nni_sp_tran *tran)
{
	nni_rwlock_wrlock(&mqtt_tran_lk);
	if (!nni_list_node_active(&tran->tran_link)) {
		tran->tran_init();
		nni_list_append(&mqtt_tran_list, tran);
	}
	nni_rwlock_unlock(&mqtt_tran_lk);
}

nni_sp_tran *
nni_mqtt_tran_find(nni_url *url)
{
	// address is of the form "<scheme>://blah..."
	nni_sp_tran *t;

	nni_rwlock_rdlock(&mqtt_tran_lk);
	NNI_LIST_FOREACH (&mqtt_tran_list, t) {
		if (strcmp(url->u_scheme, t->tran_scheme) == 0) {
			nni_rwlock_unlock(&mqtt_tran_lk);
			return (t);
		}
	}
	nni_rwlock_unlock(&mqtt_tran_lk);
	return (NULL);
}

// nni_mqtt_tran_sys_init initializes the entire transport subsystem, including
// each individual transport.

#ifdef NNG_TRANSPORT_MQTT_TCP
extern void nni_mqtt_tcp_register();
#endif
#ifdef NNG_TRANSPORT_MQTT_TLS
extern void nni_mqtts_tcp_register();
#endif

void
nni_mqtt_tran_sys_init(void)
{
	NNI_LIST_INIT(&mqtt_tran_list, nni_sp_tran, tran_link);
	nni_rwlock_init(&mqtt_tran_lk);

#ifdef NNG_TRANSPORT_MQTT_TCP
	nni_mqtt_tcp_register();
#endif
#ifdef NNG_TRANSPORT_MQTT_TLS
	nni_mqtts_tcp_register();
#endif
}

// nni_mqtt_tran_sys_fini finalizes the entire transport system, including all
// transports.
void
nni_mqtt_tran_sys_fini(void)
{
	nni_sp_tran *t;

	while ((t = nni_list_first(&mqtt_tran_list)) != NULL) {
		nni_list_remove(&mqtt_tran_list, t);
		t->tran_fini();
	}
	nni_rwlock_fini(&mqtt_tran_lk);
}
