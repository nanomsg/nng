//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

// This stub file exists to support configuration of the stream subsystem
// when websocket support is unconfigured.

int
nni_ws_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	NNI_ARG_UNUSED(dp);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
}

int
nni_ws_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	NNI_ARG_UNUSED(lp);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
}

int
nni_ws_checkopt(const char *name, const void *data, size_t sz, nni_type t)
{
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}
