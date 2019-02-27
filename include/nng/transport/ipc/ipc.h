//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_TRANSPORT_IPC_IPC_H
#define NNG_TRANSPORT_IPC_IPC_H

#include <nng/nng.h>

#ifdef __cplusplus
extern "C" {
#endif

// ipc transport.  This is used for inter-process communication on
// the same host computer.

NNG_DECL int nng_ipc_register(void);

#ifdef __cplusplus
}
#endif

#endif // NNG_TRANSPORT_IPC_IPC_H
