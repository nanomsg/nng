//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_TCP_H
#define CORE_TCP_H

#include "defs.h"

// These are interfaces we use for TCP internally.  These are not exposed
// to the public API.

extern nng_err nni_tcp_dialer_alloc(nng_stream_dialer **, const nng_url *);
extern nng_err nni_tcp_listener_alloc(nng_stream_listener **, const nng_url *);

#endif // CORE_TCP_H
