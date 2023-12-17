//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_FILE_DESCRIPTOR_H
#define CORE_FILE_DESCRIPTOR_H

#include "core/nng_impl.h"

// These are interfaces we use for FILE_DESCRIPTOR internally.  These are not exposed
// to the public API.

extern int nni_file_descriptor_dialer_alloc(nng_stream_dialer **, const nng_url *);
extern int nni_file_descriptor_listener_alloc(nng_stream_listener **, const nng_url *);

#endif // CORE_FILE_DESCRIPTOR_H
