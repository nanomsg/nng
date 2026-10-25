//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Establish the platform header order before acutest includes windows.h.
#include "../tls_common.h"

#include "../../../testing/nuts.h"

#ifdef NNG_WOLFSSL_USE_OPTIONS_H
#include <wolfssl/options.h>
#endif
#include <wolfssl/ssl.h>

static void
test_client_sni(const char *name, const char *expected, nng_tls_auth_mode auth)
{
#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_SERVER)
	const nng_tls_engine_conn_ops *ops = nng_tls_engine_ops.conn_ops;
	nng_tls_config                *cfg;
	nni_tls_conn                  *conn;
	nni_tls_bio_ops                bio = { 0 };
	nng_sockaddr                   sa  = { 0 };
	unsigned char                  sni[256];
	unsigned int                   len = sizeof(sni);
	size_t                         size;
	int                            rv;

	NUTS_PASS(nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_auth_mode(cfg, auth));
	if (name != NULL) {
		NUTS_PASS(nng_tls_config_server_name(cfg, name));
	}
	size = sizeof(*conn) + ops->size;
	NUTS_ASSERT((conn = nni_zalloc(size)) != NULL);
	NUTS_PASS(nni_tls_init(conn, cfg, false));
	NUTS_PASS(nni_tls_start(conn, &bio, NULL, &sa));

	// Capture the actual ClientHello without submitting network I/O.
	conn->bio_send_active = true;
	conn->bio_recv_pend   = true;
	NUTS_FAIL(ops->handshake((void *) (conn + 1)), NNG_EAGAIN);
	NUTS_ASSERT(conn->bio_send_len > 0);
	NUTS_ASSERT(conn->bio_send_tail == 0);
	rv = wolfSSL_SNI_GetFromBuffer(conn->bio_send_buf,
	    (unsigned int) conn->bio_send_len, WOLFSSL_SNI_HOST_NAME, sni,
	    &len);
	if (expected != NULL) {
		NUTS_ASSERT(rv == WOLFSSL_SUCCESS);
		NUTS_ASSERT(len == strlen(expected));
		NUTS_TRUE(memcmp(sni, expected, len) == 0);
	} else {
		NUTS_TRUE(rv == 0);
	}

	nni_tls_fini(conn);
	nni_free(conn, size);
	nng_tls_config_free(cfg);
#else
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(expected);
	NNI_ARG_UNUSED(auth);
	NUTS_SKIP("wolfSSL SNI inspection is unavailable");
#endif
}

static void
test_wolfssl_sni_dns(void)
{
	test_client_sni("localhost", "localhost", NNG_TLS_AUTH_MODE_REQUIRED);
}

static void
test_wolfssl_sni_no_auth(void)
{
	test_client_sni("localhost", "localhost", NNG_TLS_AUTH_MODE_NONE);
}

static void
test_wolfssl_sni_ipv4(void)
{
	test_client_sni("127.0.0.1", NULL, NNG_TLS_AUTH_MODE_REQUIRED);
}

static void
test_wolfssl_sni_ipv6(void)
{
	test_client_sni("::1", NULL, NNG_TLS_AUTH_MODE_REQUIRED);
	test_client_sni("2001:db8::1", NULL, NNG_TLS_AUTH_MODE_REQUIRED);
	test_client_sni("[::1]", NULL, NNG_TLS_AUTH_MODE_REQUIRED);
}

static void
test_wolfssl_sni_no_name(void)
{
	test_client_sni(NULL, NULL, NNG_TLS_AUTH_MODE_NONE);
}

NUTS_TESTS = {
	{ "wolfssl sni dns", test_wolfssl_sni_dns },
	{ "wolfssl sni no auth", test_wolfssl_sni_no_auth },
	{ "wolfssl sni ipv4", test_wolfssl_sni_ipv4 },
	{ "wolfssl sni ipv6", test_wolfssl_sni_ipv6 },
	{ "wolfssl sni no name", test_wolfssl_sni_no_name },
	{ NULL, NULL },
};
