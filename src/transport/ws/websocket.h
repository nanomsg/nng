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

// NNG_OPT_WSS_TLS_CERT_KEY_FILE names a single file that
// contains a certificate and key identifying ourself.  This
// is a write-only value.  Listeners can call this multiple
// times for different keys/certs corresponding to different
// algorithms, whereas clients only get one.  The file must
// contain both cert and key as PEM blocks, and the key must
// not be encrypted.  (If more flexibility is needed, use the
// TLS configuration directly.)  Note that TLS configuration
// cannot be changed if the listener, or any other from the same
// server and port, is already started.
#define NNG_OPT_WSS_TLS_CERT_KEY_FILE "wss:tls-cert-key-file"

// NNG_OPT_WSS_TLS_CA_FILE names a single file that
// contains certificate(s) for a CA, and optinally CRLs.  This
// is a write-only value.  Listeners can call this multiple
// times for different keys/certs corresponding to different
// algorithms, whereas clients only get one.  The file must
// contain certs as PEM blocks, and may contain CRLs as PEM
// as well.  (If more flexibility is needed, use the
// TLS configuration directly.)  Note that TLS configuration
// cannot be changed if the listener, or any other from the same
// server and port, is already started.
#define NNG_OPT_WSS_TLS_CA_FILE "wss:tls-ca-file"

// NNG_OPT_WSS_TLS_AUTH_MODE is a write-only integer (int) option
// that specifies whether the peer is verified or not.  The option
// can take one of the values of NNG_TLS_AUTH_MODE_NONE,
// NNG_TLS_AUTH_MODE_OPTIONAL, or NNG_TLS_AUTH_MODE_REQUIRED.
// The default is NNG_TLS_AUTH_MODE_NONE for listeners, and
// NNG_TLS_AUTH_MODE_REQUIRED for dialers.
#define NNG_OPT_WSS_TLS_AUTH_MODE "wss:tls-auth-mode"

// NNG_OPT_WSS_TLS_SERVER_NAME is a write-only string that can be
// set on dialers to check the CN of the server for a match.  This
// can also affect SNI (server name indication).
#define NNG_OPT_WSS_TLS_SERVER_NAME "wss:tls-server-name"

// NNG_OPT_WSS_TLS_VERIFIED returns a single integer, indicating
// whether the peer was verified or not.  This is a read-only value
// available only on pipes.
#define NNT_OPT_WSS_TLS_VERIFIED "wss:tls-verified"

// These aliases are for WSS naming consistency.
#define NNG_OPT_WSS_REQUEST_HEADERS NNG_OPT_WS_REQUEST_HEADERS
#define NNG_OPT_WSS_RESPONSE_HEADERS NNG_OPT_WS_RESPONSE_HEADERS

NNG_DECL int nng_wss_register(void);

#endif // NNG_TRANSPORT_WS_WEBSOCKET_H
