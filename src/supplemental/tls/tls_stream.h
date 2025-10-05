//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_TLS_TLS_STREAM_H
#define NNG_TLS_TLS_STREAM_H

#include "../../core/nng_impl.h"
#include "tls_common.h"

typedef struct tls_stream_s {
	nng_stream    stream;
	size_t        size;
	nni_reap_node reap;
	nng_aio       conn_aio;
	nng_aio      *user_aio;
	nni_tls_conn  conn; // NB: must be last!
} tls_stream;

extern void nni_tls_stream_free(void *arg);
extern int  nni_tls_stream_alloc(
     tls_stream **tsp, nng_tls_config *cfg, nng_aio *user_aio);

#endif
