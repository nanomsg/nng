//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

#if NNG_ENABLE_COMPAT
#include <nng/compat/nanomsg/nn.h>
#endif

void
test_buffer_options(void)
{
	nng_socket s1;
	int        val;
	char      *opt;

	char *cases[] = {
		NNG_OPT_RECVBUF,
		NNG_OPT_SENDBUF,
		NULL,
	};

	NUTS_PASS(nng_pair1_open(&s1));
	for (int i = 0; (opt = cases[i]) != NULL; i++) {

		NUTS_CASE(opt);

		// Can set a valid size
		NUTS_PASS(nng_socket_set_int(s1, opt, 1234));
		NUTS_PASS(nng_socket_get_int(s1, opt, &val));
		NUTS_TRUE(val == 1234);

		// Can't set a negative size
		NUTS_FAIL(nng_socket_set_int(s1, opt, -5), NNG_EINVAL);

		// Buffer sizes are limited to sane levels
		NUTS_FAIL(nng_socket_set_int(s1, opt, 0x100000), NNG_EINVAL);
	}
	NUTS_PASS(nng_close(s1));
}

NUTS_TESTS = {
	{ "buffer options", test_buffer_options },
	{ NULL, NULL },
};
