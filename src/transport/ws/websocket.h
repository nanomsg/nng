//
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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

// NNG_OPT_WSS_TLS_CONFIG is a pointer to a an nng_tls_config
// object.  This property is only available for wss:// style
// endpoints.  Note that when configuring the object, a hold
// is placed on the TLS configuration.  When retrieving the
// object, no hold is placed, and so the caller must take care
// not to use the configuration object after the endpoint it
// is associated with is removed.  Furthermore, as this is a
// pointer, applications must take care to pass only valid
// data -- incorrect pointer values will lead to undefined
// behavior.
#define NNG_OPT_WSS_TLS_CONFIG "wss:tls-config"

// These aliases are for WSS naming consistency.
#define NNG_OPT_WSS_REQUEST_HEADERS NNG_OPT_WS_REQUEST_HEADERS
#define NNG_OPT_WSS_RESPONSE_HEADERS NNG_OPT_WS_RESPONSE_HEADERS

NNG_DECL int nng_wss_register(void);

#endif // NNG_TRANSPORT_WS_WEBSOCKET_H
