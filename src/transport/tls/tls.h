//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_TRANSPORT_TLS_TLS_H
#define NNG_TRANSPORT_TLS_TLS_H

// TLS transport.  This is used for communication via TLS v1.2 over TCP/IP.

NNG_DECL int nng_tls_register(void);

// TLS options.  Note that these can only be set *before* the endpoint is
// started.  Once started, it is no longer possible to alter the TLS
// configuration.

// NNG_OPT_TLS_AUTH_VERIFIED is a boolean that can be read on pipes,
// indicating whether the peer certificate is verified.
#define NNG_OPT_TLS_AUTH_VERIFIED "tls:auth-verified"

// NNG_OPT_TLS_CONFIG is used to access the underlying configuration
// (an nng_tls_config *).
#define NNG_OPT_TLS_CONFIG "tls:config"

#endif // NNG_TRANSPORT_TLS_TLS_H
