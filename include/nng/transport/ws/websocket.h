//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_TRANSPORT_WS_WEBSOCKET_H
#define NNG_TRANSPORT_WS_WEBSOCKET_H

#include <nng/nng.h>

#ifdef __cplusplus
extern "C" {
#endif

// WebSocket transport.  This is used for communication via WebSocket.

// These aliases are for WSS naming consistency.
#define NNG_OPT_WSS_REQUEST_HEADERS NNG_OPT_WS_REQUEST_HEADERS
#define NNG_OPT_WSS_RESPONSE_HEADERS NNG_OPT_WS_RESPONSE_HEADERS

#ifndef NNG_ELIDE_DEPRECATED
NNG_DECL int nng_ws_register(void);
NNG_DECL int nng_wss_register(void);
#endif

#ifdef __cplusplus
}
#endif

#endif // NNG_TRANSPORT_WS_WEBSOCKET_H
