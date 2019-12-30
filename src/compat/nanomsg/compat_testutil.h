//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef COMPAT_TESTUTIL_H
#define COMPAT_TESTUTIL_H

#include <stdbool.h>
#include <stdint.h>

// The following headers are provided for test code convenience.
#include <nng/nng.h>

#ifdef __cplusplus
extern "C" {
#endif

// TEST_NNG_PASS tests for NNG success.  It reports the failure if it
// did not.
#define TEST_NN_PASS(cond)                                           \
	do {                                                         \
		int result_ = (cond);                                \
		TEST_CHECK_(result_ >= 0, "%s succeeds", #cond);     \
		TEST_MSG("%s: expected success, got %s (%d)", #cond, \
		    nn_strerror(errno), errno);                      \
	} while (0)

#define TEST_NN_FAIL(cond, expect)                                       \
	do {                                                             \
		int result_ = (cond);                                    \
		int err_    = errno;                                     \
		TEST_CHECK_(result_ < 0, "%s did not succeed", #cond);   \
		TEST_CHECK_(                                             \
		    err_ = expect, "%s fails with %s", #cond, #expect);  \
		TEST_MSG("%s: expected %s, got %s (%d)", #cond, #expect, \
		    expect, nng_strerror(err_), result_);                \
	} while (0)

#ifdef __cplusplus
};
#endif

#endif // COMPAT_TESTUTIL_H
