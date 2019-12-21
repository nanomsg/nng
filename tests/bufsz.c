//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//


#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/supplemental/util/platform.h>

#include <nng/compat/nanomsg/nn.h>

#include "acutest.h"

void
test_buffer_options(void)
{
	nng_socket s1;
	int        val;
	size_t     sz;
	char *     opt;

	char *cases[] = {
		NNG_OPT_RECVBUF,
		NNG_OPT_SENDBUF,
		NULL,
	};

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	for (int i = 0; (opt = cases[i]) != NULL; i++) {

		TEST_CASE(opt);

		// Can't receive a size into zero bytes.
		sz = 0;
		TEST_CHECK(nng_getopt(s1, opt, &val, &sz) == NNG_EINVAL);

		// Can set a valid size
		TEST_CHECK(nng_setopt_int(s1, opt, 1234) == 0);
		TEST_CHECK(nng_getopt_int(s1, opt, &val) == 0);
		TEST_CHECK(val == 1234);

		val = 0;
		sz  = sizeof(val);
		TEST_CHECK(nng_getopt(s1, opt, &val, &sz) == 0);
		TEST_CHECK(val == 1234);
		TEST_CHECK(sz == sizeof(val));

		// Can't set a negative size
		TEST_CHECK(nng_setopt_int(s1, opt, -5) == NNG_EINVAL);

		// Can't pass a buf too small for size
		sz  = sizeof(val) - 1;
		val = 1;
		TEST_CHECK(nng_setopt(s1, opt, &val, sz) == NNG_EINVAL);
		// Buffer sizes are limited to sane levels
		TEST_CHECK(nng_setopt_int(s1, opt, 0x100000) == NNG_EINVAL);
	}
	TEST_CHECK(nng_close(s1) == 0);
}

void
test_buffer_legacy(void)
{
	nng_socket s1;
	char *     opt;

	char *cases[] = {
		NNG_OPT_RECVBUF,
		NNG_OPT_SENDBUF,
		NULL,
	};
	int legacy[] = {
		NN_RCVBUF,
		NN_SNDBUF,
	};

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	for (int i = 0; (opt = cases[i]) != NULL; i++) {
		int    cnt;
		int    os = (int) s1.id;
		size_t sz;
		int    nnopt = legacy[i];

		TEST_CASE(opt);

		sz = sizeof(cnt);
		TEST_CHECK(nng_setopt_int(s1, opt, 10) == 0);
		TEST_CHECK(
		    nn_getsockopt(os, NN_SOL_SOCKET, nnopt, &cnt, &sz) == 0);
		TEST_CHECK(cnt == 10240); // 1k multiple

		cnt = 1;
		TEST_CHECK(
		    nn_setsockopt(os, NN_SOL_SOCKET, nnopt, &cnt, sz) == 0);
		TEST_CHECK(nn_getsockopt(os, NN_SOL_SOCKET, nnopt, &cnt, &sz) == 0);
		TEST_CHECK(cnt == 1024); // round up!
		TEST_CHECK(nng_getopt_int(s1, opt, &cnt) == 0);
		TEST_CHECK(cnt == 1);

		TEST_CHECK(nn_setsockopt(os, NN_SOL_SOCKET, nnopt, &cnt, 100) == -1);
		TEST_CHECK(nn_errno() == EINVAL);
	}
	TEST_CHECK(nng_close(s1) == 0);
}

TEST_LIST = {
    { "buffer options", test_buffer_options },
    { "buffer legacy", test_buffer_legacy },
    { NULL, NULL },
};
