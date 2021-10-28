//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <nng/nng.h>
#include <nuts.h>

void
test_ipc_win_sec(void)
{
	char                 address[64];
	nng_stream_listener *l;
	int                  x;

	nuts_scratch_addr("ipc", sizeof(address), address);
	NUTS_PASS(nng_stream_listener_alloc(&l, address));
	NUTS_FAIL(nng_stream_listener_set_ptr(
	              l, NNG_OPT_IPC_SECURITY_DESCRIPTOR, &x),
	    NNG_ENOTSUP);
	nng_stream_listener_free(l);
}

NUTS_TESTS = {
	{ "ipc security descriptor", test_ipc_win_sec },
	{ NULL, NULL },
};
