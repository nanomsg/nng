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

// TLS transport.  This is used for communication via TLS v1.2 over TCP/IP.

NNG_DECL int nng_ws_register(void);

// TLS options.  Note that these can only be set *before* the endpoint is
// started.  Once started, it is no longer possible to alter the TLS
// configuration.

// NNG_OPT_TLS_CA_CERT is a string with one or more X.509 certificates,
// representing the entire CA chain.  The content may be either PEM or DER
// encoded.
#define NNG_OPT_TLS_CA_CERT "tls:ca-cert"

// NNG_OPT_TLS_CRL is a PEM encoded CRL (revocation list).  Multiple lists
// may be loaded by using this option multiple times.
#define NNG_OPT_TLS_CRL "tls:crl"

// NNG_OPT_TLS_CERT is used to specify our own certificate. At present
// only one certificate may be supplied.  (In the future it may be
// possible to call this multiple times, for servers that select different
// certificates depending upon client capabilities.)
#define NNG_OPT_TLS_CERT "tls:cert"

// NNG_OPT_TLS_PRIVATE_KEY is used to specify the private key used
// with the given certificate.  This should be called after setting
// the certificate.  The private key may be in PEM or DER format.
// If in PEM encoded, a terminating ZERO byte should be included.
#define NNG_OPT_TLS_PRIVATE_KEY "tls:private-key"

// NNG_OPT_TLS_PRIVATE_KEY_PASSWORD is used to specify a password
// used for the private key.  The value is an ASCIIZ string.
#define NNG_OPT_TLS_PRIVATE_KEY_PASSWORD "tls:private-key-password"

// NNG_OPT_TLS_AUTH_MODE is an integer indicating whether our
// peer should be verified or not.  It is required on clients/dialers,
// and off on servers/listeners, by default.
#define NNG_OPT_TLS_AUTH_MODE "tls:auth-mode"

extern int nng_tls_auth_mode_required;
extern int nng_tls_auth_mode_none;
extern int nng_tls_auth_mode_optional;

// NNG_OPT_TLS_AUTH_VERIFIED is a boolean that can be read on pipes,
// indicating whether the peer certificate is verified.
#define NNG_OPT_TLS_AUTH_VERIFIED "tls:auth-verified"

// XXX: TBD: Ciphersuite selection and reporting.  Session reuse?

#endif // NNG_TRANSPORT_WS_WEBSOCKET_H
