//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NUTS_COMPAT_H
#define NUTS_COMPAT_H

#include <stdbool.h>
#include <stdint.h>

// The following headers are provided for test code convenience.
#include <nng/nng.h>

#ifdef __cplusplus
extern "C" {
#endif

// NUTS_NN_PASS tests for NN success.  It reports the failure if it did not.
#define NUTS_NN_PASS(cond)                                           \
	do {                                                         \
		int result_ = (cond);                                \
		TEST_CHECK_(result_ >= 0, "%s succeeds", #cond);     \
		TEST_MSG("%s: expected success, got %s (%d)", #cond, \
		    nn_strerror(errno), errno);                      \
	} while (0)

#define NUTS_NN_FAIL(cond, expect)                                            \
	do {                                                                  \
		int result_ = (cond);                                         \
		int err_    = errno;                                          \
		TEST_CHECK_(result_ < 0, "%s did not succeed", #cond);        \
		TEST_CHECK_(                                                  \
		    err_ == (expect), "%s fails with %s", #cond, #expect);    \
		TEST_MSG("%s: expected %s, got %d / %d (%s)", #cond, #expect, \
		    result_, (expect), nng_strerror(err_));                   \
	} while (0)

// These macros use some details of the socket and pipe which are not public.
// We do that to facilitate testing.  Don't rely on this equivalence in your
// own application code.

#define NUTS_NN_MARRY(s1, s2)         \
	do {                          \
		nng_socket s1_, s2_;  \
		s1_.id = s1;          \
		s2_.id = s2;          \
                                      \
		NUTS_MARRY(s1_, s2_); \
	} while (0)

#define NUTS_NN_MARRY_EX(s1, s2, url, p1, p2)             \
	do {                                              \
		nng_socket s1_, s2_;                      \
		nng_pipe   p1_, p2_;                      \
		s1_.id = s1;                              \
		s2_.id = s2;                              \
		NUTS_MARRY_EX(s1_, s2_, url, &p1_, &p2_); \
		(p1) = p1_.id;                            \
		(p2) = p2_.id;                            \
		NUTS_TRUE((p1) >= 0);                     \
		NUTS_TRUE((p2) >= 0);                     \
	} while (0)

#ifdef __cplusplus
};
#endif

#endif // NUTS_COMPAT
