//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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
	size_t     sz;
	char      *opt;

	char *cases[] = {
		NNG_OPT_RECVBUF,
		NNG_OPT_SENDBUF,
		NULL,
	};

	NUTS_PASS(nng_pair1_open(&s1));
	for (int i = 0; (opt = cases[i]) != NULL; i++) {

		NUTS_CASE(opt);

		// Can't receive a size into zero bytes.
		sz = 0;
		NUTS_FAIL(nng_socket_get(s1, opt, &val, &sz), NNG_EINVAL);

		// Can set a valid size
		NUTS_PASS(nng_socket_set_int(s1, opt, 1234));
		NUTS_PASS(nng_socket_get_int(s1, opt, &val));
		NUTS_TRUE(val == 1234);

		val = 0;
		sz  = sizeof(val);
		NUTS_PASS(nng_socket_get(s1, opt, &val, &sz));
		NUTS_TRUE(val == 1234);
		NUTS_TRUE(sz == sizeof(val));

		// Can't set a negative size
		NUTS_FAIL(nng_socket_set_int(s1, opt, -5), NNG_EINVAL);

		// Can't pass a buf too small for size
		sz  = sizeof(val) - 1;
		val = 1;
		NUTS_FAIL(nng_socket_set(s1, opt, &val, sz), NNG_EINVAL);
		// Buffer sizes are limited to sane levels
		NUTS_FAIL(nng_socket_set_int(s1, opt, 0x100000), NNG_EINVAL);
	}
	NUTS_PASS(nng_close(s1));
}

void
test_buffer_legacy(void)
{
#if NNG_ENABLE_COMPAT
	nng_socket s1;
	char      *opt;

	char *cases[] = {
		NNG_OPT_RECVBUF,
		NNG_OPT_SENDBUF,
		NULL,
	};
	int legacy[] = {
		NN_RCVBUF,
		NN_SNDBUF,
	};

	NUTS_PASS(nng_pair1_open(&s1));
	for (int i = 0; (opt = cases[i]) != NULL; i++) {
		int    cnt;
		int    os = (int) s1.id;
		size_t sz;
		int    nno = legacy[i];

		NUTS_CASE(opt);

		sz = sizeof(cnt);
		NUTS_PASS(nng_socket_set_int(s1, opt, 10));
		NUTS_TRUE(
		    nn_getsockopt(os, NN_SOL_SOCKET, nno, &cnt, &sz) == 0);
		NUTS_TRUE(cnt == 10240); // 1k multiple

		cnt = 1;
		NUTS_TRUE(
		    nn_setsockopt(os, NN_SOL_SOCKET, nno, &cnt, sz) == 0);
		NUTS_TRUE(
		    nn_getsockopt(os, NN_SOL_SOCKET, nno, &cnt, &sz) == 0);
		NUTS_TRUE(cnt == 1024); // round up!
		NUTS_PASS(nng_socket_get_int(s1, opt, &cnt));
		NUTS_TRUE(cnt == 1);

		NUTS_TRUE(
		    nn_setsockopt(os, NN_SOL_SOCKET, nno, &cnt, 100) == -1);
		NUTS_TRUE(nn_errno() == EINVAL);
	}
	NUTS_PASS(nng_close(s1));
#endif
}

NUTS_TESTS = {
	{ "buffer options", test_buffer_options },
#if NNG_ENABLE_COMPAT
	{ "buffer legacy", test_buffer_legacy },
#endif
	{ NULL, NULL },
};
