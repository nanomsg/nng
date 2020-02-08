//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/supplemental/tls/tls.h>
#include <testutil.h>

#include <acutest.h>

void
test_tls_config_version(void)
{
	nng_tls_config *cfg;

	TEST_NNG_PASS(nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER));

	// Verify that min ver < max ver
	TEST_NNG_FAIL(nng_tls_config_version(cfg, NNG_TLS_1_3, NNG_TLS_1_0),
	    NNG_ENOTSUP);

	// Verify that we cannot configure SSL 3.0 or older.
	TEST_NNG_FAIL(
	    nng_tls_config_version(cfg, NNG_TLS_1_0 - 1, NNG_TLS_1_0),
	    NNG_ENOTSUP);

	// Verify that we cannot configure TLS > 1.3.
	TEST_NNG_FAIL(
	    nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_3 + 1),
	    NNG_ENOTSUP);

	// Verify that we *can* configure some various ranges.
	TEST_NNG_PASS(nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_0));
	TEST_NNG_PASS(nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_1));
	TEST_NNG_PASS(nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_2));
	TEST_NNG_PASS(nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_3));
	TEST_NNG_PASS(nng_tls_config_version(cfg, NNG_TLS_1_1, NNG_TLS_1_1));
	TEST_NNG_PASS(nng_tls_config_version(cfg, NNG_TLS_1_1, NNG_TLS_1_2));
	TEST_NNG_PASS(nng_tls_config_version(cfg, NNG_TLS_1_1, NNG_TLS_1_3));
	TEST_NNG_PASS(nng_tls_config_version(cfg, NNG_TLS_1_2, NNG_TLS_1_2));
	TEST_NNG_PASS(nng_tls_config_version(cfg, NNG_TLS_1_2, NNG_TLS_1_3));

	nng_tls_config_free(cfg);
}

TEST_LIST = {
	{ "tls config version", test_tls_config_version },
	{ NULL, NULL },
};