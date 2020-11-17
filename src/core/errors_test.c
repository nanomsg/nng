//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <errno.h>
#include <string.h>

#include <nng/nng.h>

#include <acutest.h>
#include <testutil.h>

static void
test_known_errors(void)
{

	TEST_STREQUAL(nng_strerror(NNG_ECLOSED), "Object closed");
	TEST_STREQUAL(nng_strerror(NNG_ETIMEDOUT), "Timed out");
}

static void
test_unknown_errors(void)
{
	for (unsigned i = 1; i < 0x1000000; i = i * 2 + 100) {
		TEST_CHECK(nng_strerror(i) != NULL);
	}
}

static void
test_system_errors(void)
{
	TEST_STREQUAL(nng_strerror(NNG_ESYSERR + ENOENT), strerror(ENOENT));
	TEST_STREQUAL(nng_strerror(NNG_ESYSERR + EINVAL), strerror(EINVAL));
}

TEST_LIST = {
	{ "known errors", test_known_errors },
	{ "unknown errors", test_unknown_errors },
	{ "system errors", test_system_errors },
	{ NULL, NULL },
};
