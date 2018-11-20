//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_TRANSPORT_WS_WEBSOCKET_H
#define NNG_TRANSPORT_WS_WEBSOCKET_H

// WebSocket transport.  This is used for communication via WebSocket.

NNG_DECL int nng_ws_register(void);

// NNG_OPT_WS_REQUEST_HEADERS is a string containing the
// request headers, formatted as CRLF terminated lines.
#define NNG_OPT_WS_REQUEST_HEADERS "ws:request-headers"

// NNG_OPT_WS_RESPONSE_HEADERS is a string containing the
// response headers, formatted as CRLF terminated lines.
#define NNG_OPT_WS_RESPONSE_HEADERS "ws:response-headers"

// These aliases are for WSS naming consistency.
#define NNG_OPT_WSS_REQUEST_HEADERS NNG_OPT_WS_REQUEST_HEADERS
#define NNG_OPT_WSS_RESPONSE_HEADERS NNG_OPT_WS_RESPONSE_HEADERS

NNG_DECL int nng_wss_register(void);

#endif // NNG_TRANSPORT_WS_WEBSOCKET_H
