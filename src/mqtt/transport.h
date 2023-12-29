//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PROTOCOL_MQTT_TRANSPORT_H
#define PROTOCOL_MQTT_TRANSPORT_H

#include "core/options.h"

// These APIs are used by the framework internally, and not for use by
// transport implementations.
extern nni_sp_tran *nni_mqtt_tran_find(nni_url *);
extern void         nni_mqtt_tran_sys_init(void);
extern void         nni_mqtt_tran_sys_fini(void);
extern void         nni_mqtt_tran_register(nni_sp_tran *);

#endif // PROTOCOL_MQTT_TRANSPORT_H
