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

void
test_tls_conn_refused(void)
{
	nng_stream_dialer *dialer;
	nng_aio *          aio;

	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, 5000); // 5 sec

	// port 8 is generally not used for anything.
	TEST_NNG_PASS(
	    nng_stream_dialer_alloc(&dialer, "tls+tcp://127.0.0.1:8"));
	nng_stream_dialer_dial(dialer, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECONNREFUSED);

	nng_aio_free(aio);
	nng_stream_dialer_free(dialer);
}

void
test_tls_large_message(void)
{
	nng_stream_listener *l;
	nng_stream_dialer *  d;
	nng_aio *            aio1, *aio2;
	nng_stream *         s1;
	nng_stream *         s2;
	nng_tls_config *     c1;
	nng_tls_config *     c2;
	char                 addr[32];
	uint8_t *            buf1;
	uint8_t *            buf2;
	size_t               size = 450001;
	void *               t1;
	void *               t2;

	// allocate messages
	TEST_CHECK((buf1 = nng_alloc(size)) != NULL);
	TEST_CHECK((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	TEST_NNG_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	TEST_NNG_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	testutil_scratch_addr("tls+tcp", sizeof(addr), addr);

	TEST_NNG_PASS(nng_stream_dialer_alloc(&d, addr));
	TEST_NNG_PASS(nng_stream_listener_alloc(&l, addr));

	// set up TLS parameters

	TEST_NNG_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	TEST_NNG_PASS(nng_tls_config_own_cert(
	    c1, testutil_server_crt, testutil_server_key, NULL));

	TEST_NNG_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	TEST_NNG_PASS(nng_tls_config_ca_chain(c2, testutil_server_crt, NULL));
	TEST_NNG_PASS(nng_tls_config_server_name(c2, "localhost"));

	TEST_NNG_PASS(nng_stream_listener_set_ptr(l, NNG_OPT_TLS_CONFIG, c1));
	TEST_NNG_PASS(nng_stream_dialer_set_ptr(d, NNG_OPT_TLS_CONFIG, c2));

	TEST_NNG_PASS(nng_stream_listener_listen(l));
	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	TEST_NNG_PASS(nng_aio_result(aio1));
	TEST_NNG_PASS(nng_aio_result(aio2));

	TEST_CHECK((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	TEST_CHECK((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = testutil_stream_send_start(s1, buf1, size);
	t2 = testutil_stream_recv_start(s2, buf2, size);

	TEST_NNG_PASS(testutil_stream_send_wait(t1));
	TEST_NNG_PASS(testutil_stream_recv_wait(t2));
	TEST_CHECK(memcmp(buf1, buf2, size) == 0);

	nng_free(buf1, size);
	nng_free(buf2, size);
	nng_stream_free(s1);
	nng_stream_free(s2);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
}

TEST_LIST = {
	{ "tls config version", test_tls_config_version },
	{ "tls conn refused", test_tls_conn_refused },
	{ "tls large message", test_tls_large_message },
	{ NULL, NULL },
};