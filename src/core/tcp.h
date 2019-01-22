//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_TCP_H
#define CORE_TCP_H

#include "core/nng_impl.h"

// These are interfaces we use for TCP internally.  These are not exposed
// to the public API.

extern int nni_tcp_dialer_alloc(nng_stream_dialer **, const nng_url *);
extern int nni_tcp_listener_alloc(nng_stream_listener **, const nng_url *);

// nni_tcp_checkopt is used to validate (generically) options.
extern int nni_tcp_checkopt(const char *, const void *, size_t, nni_type);

#endif // CORE_TCP_H
