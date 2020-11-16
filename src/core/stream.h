//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_STREAM_H
#define CORE_STREAM_H

// This provides an abstraction for byte streams, allowing polymorphic
// use of them in rather flexible contexts.

#include "core/nng_impl.h"

// Private property operations (these include the types.)
extern int nni_stream_get(
    nng_stream *, const char *, void *, size_t *, nni_type);
extern int nni_stream_set(
    nng_stream *, const char *, const void *, size_t, nni_type);

extern int nni_stream_dialer_get(
    nng_stream_dialer *, const char *, void *, size_t *, nni_type);
extern int nni_stream_dialer_set(
    nng_stream_dialer *, const char *, const void *, size_t, nni_type);

extern int nni_stream_listener_get(
    nng_stream_listener *, const char *, void *, size_t *, nni_type);
extern int nni_stream_listener_set(
    nng_stream_listener *, const char *, const void *, size_t, nni_type);

// This is the common implementation of a connected byte stream.  It should be
// the first element of any implementation.  Applications are not permitted to
// access it directly.
struct nng_stream {
	void (*s_free)(void *);
	void (*s_close)(void *);
	void (*s_recv)(void *, nng_aio *);
	void (*s_send)(void *, nng_aio *);
	int (*s_get)(void *, const char *, void *, size_t *, nni_type);
	int (*s_set)(void *, const char *, const void *, size_t, nni_type);
};

// Dialer implementation.  Stream dialers create streams.
struct nng_stream_dialer {
	void (*sd_free)(void *);
	void (*sd_close)(void *);
	void (*sd_dial)(void *, nng_aio *);
	int (*sd_get)(void *, const char *, void *, size_t *, nni_type);
	int (*sd_set)(void *, const char *, const void *, size_t, nni_type);
};

// Listener implementation.  Stream listeners accept connections and create
// streams.
struct nng_stream_listener {
	void (*sl_free)(void *);
	void (*sl_close)(void *);
	int (*sl_listen)(void *);
	void (*sl_accept)(void *, nng_aio *);
	int (*sl_get)(void *, const char *, void *, size_t *, nni_type);
	int (*sl_set)(void *, const char *, const void *, size_t, nni_type);
};

#endif // CORE_STREAM_H
