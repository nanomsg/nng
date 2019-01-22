//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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

// This nni_tls_common structure represents the "base" structure for
// an implementation to extend.  One of these must be the first member
// of the implementation specific TLS stream struct.
typedef struct {
	nng_stream      ops;
	nni_aio *       aio;  // system aio for connect/accept
	nni_aio *       uaio; // user aio for connect/accept
	nng_tls_config *cfg;
} nni_tls_common;

// The implementation supplies this function to create the TLS connection
// object.  All fields will be zeroed.
extern int nni_tls_alloc(nng_stream **);
extern int nni_tls_dialer_alloc(nng_stream_dialer **, const nng_url *);
extern int nni_tls_listener_alloc(nng_stream_listener **, const nng_url *);
extern int nni_tls_checkopt(const char *, const void *, size_t, nni_type);

// nni_tls_start is called by the common TLS dialer/listener completions
// to start the TLS stream activity.  This may also do allocations, etc.
extern int nni_tls_start(nng_stream *, nng_stream *);

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

#endif // NNG_SUPPLEMENTAL_TLS_TLS_API_H
