//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TLS_TLS_API_H
#define NNG_SUPPLEMENTAL_TLS_TLS_API_H

#include <nng/supplemental/tls/tls.h>

// The implementation supplies this function to create the TLS connection
// object.  All fields will be zeroed.
extern int nni_tls_dialer_alloc(nng_stream_dialer **, const nng_url *);
extern int nni_tls_listener_alloc(nng_stream_listener **, const nng_url *);
extern int nni_tls_checkopt(const char *, const void *, size_t, nni_type);

#endif // NNG_SUPPLEMENTAL_TLS_TLS_API_H
