//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TLS_TLS_API_H
#define NNG_SUPPLEMENTAL_TLS_TLS_API_H

#include <stdbool.h>

#include <nng/supplemental/tls/tls.h>

// nni_tls represents the context for a single TLS stream.
typedef struct nni_tls nni_tls;

// nni_tls_config_init creates a new TLS configuration object.
// The object is created with a reference count of one.
extern int nni_tls_config_init(nng_tls_config **, nng_tls_mode);

// nni_tls_config_fini drops the reference on the configuration
// object, deallocating if this was the last reference.
extern void nni_tls_config_fini(nng_tls_config *);

// nni_tls_config_hold is used to get a hold on the config
// object, preventing it from being released inadvertently.
// The hold is released with a call to nng_tls_config_fini().
// Note that a hold need not be acquired at creation, since
// the configuration object is created with a hold on it.
extern void nni_tls_config_hold(nng_tls_config *);

extern int  nni_tls_init(nni_tls **, nng_tls_config *, nni_tcp_conn *);
extern void nni_tls_close(nni_tls *);
extern void nni_tls_fini(nni_tls *);
extern void nni_tls_send(nni_tls *, nng_aio *);
extern void nni_tls_recv(nni_tls *, nng_aio *);

extern int nni_tls_setopt(
    nni_tls *, const char *, const void *, size_t, nni_type);
extern int nni_tls_getopt(nni_tls *, const char *, void *, size_t *, nni_type);

// TBD: getting additional peer certificate information...

#endif // NNG_SUPPLEMENTAL_TLS_TLS_API_H
