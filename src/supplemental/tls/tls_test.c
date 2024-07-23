//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#include "nng/supplemental/tls/tls.h"
#include <nuts.h>

void
test_tls_config_version(void)
{
	nng_tls_config *cfg;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_PASS(nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER));

	// Verify that min ver < max ver
	NUTS_FAIL(nng_tls_config_version(cfg, NNG_TLS_1_3, NNG_TLS_1_0),
	    NNG_ENOTSUP);

	// Verify that we cannot configure SSL 3.0 or older.
	NUTS_FAIL(nng_tls_config_version(cfg, NNG_TLS_1_0 - 1, NNG_TLS_1_0),
	    NNG_ENOTSUP);

	// Verify that we cannot configure TLS > 1.3.
	NUTS_FAIL(nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_3 + 1),
	    NNG_ENOTSUP);

	// Verify that we *can* configure some various ranges starting with
	// TLS v1.2.  Note that some libraries no longer support TLS 1.0
	// and TLS 1.1, so we don't test for them.
#if 0
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_0));
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_1));
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_2));
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_0, NNG_TLS_1_3));
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_1, NNG_TLS_1_1));
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_1, NNG_TLS_1_2));
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_1, NNG_TLS_1_3));
#endif
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_2, NNG_TLS_1_2));
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_2, NNG_TLS_1_3));

	nng_tls_config_free(cfg);
}

void
test_tls_conn_refused(void)
{
	nng_stream_dialer *dialer;
	nng_aio           *aio;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, 5000); // 5 sec

	// port 8 is generally not used for anything.
	NUTS_PASS(nng_stream_dialer_alloc(&dialer, "tls+tcp://127.0.0.1:8"));
	nng_stream_dialer_dial(dialer, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECONNREFUSED);

	nng_aio_free(aio);
	nng_stream_dialer_free(dialer);
}

void
test_tls_large_message(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 450001;
	void                *t1;
	void                *t2;
	int                  port;

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c1, nuts_server_crt, nuts_server_key, NULL));
	NUTS_PASS(nng_stream_listener_set_ptr(l, NNG_OPT_TLS_CONFIG, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(
	    nng_stream_listener_get_int(l, NNG_OPT_TCP_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_ca_chain(c2, nuts_server_crt, NULL));
	NUTS_PASS(nng_tls_config_server_name(c2, "localhost"));

	NUTS_PASS(nng_stream_dialer_set_ptr(d, NNG_OPT_TLS_CONFIG, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	NUTS_PASS(nuts_stream_wait(t1));
	NUTS_PASS(nuts_stream_wait(t2));
	NUTS_TRUE(memcmp(buf1, buf2, size) == 0);

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

void
test_tls_garbled_cert(void)
{
	nng_stream_listener *l;
	nng_tls_config      *c1;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_FAIL(nng_tls_config_own_cert(
	              c1, nuts_garbled_crt, nuts_server_key, NULL),
	    NNG_ECRYPTO);

	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
}

void
test_tls_psk(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t              key[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 10000;
	void                *t1;
	void                *t2;
	int                  port;

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < sizeof(key); i++) {
		key[i] = rand() & 0xff;
	}
	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_psk(c1, "identity", key, sizeof(key)));
	NUTS_PASS(nng_stream_listener_set_ptr(l, NNG_OPT_TLS_CONFIG, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(
	    nng_stream_listener_get_int(l, NNG_OPT_TCP_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_psk(c2, "identity", key, sizeof(key)));

	NUTS_PASS(nng_stream_dialer_set_ptr(d, NNG_OPT_TLS_CONFIG, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	NUTS_PASS(nuts_stream_wait(t1));
	NUTS_PASS(nuts_stream_wait(t2));
	NUTS_TRUE(memcmp(buf1, buf2, size) == 0);

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

void
test_tls_psk_server_identities(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 10000;
	void                *t1;
	void                *t2;
	int                  port;
	char                *identity = "test_identity";
	uint8_t              key[32];

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < sizeof(key); i++) {
		key[i] = rand() & 0xff;
	}
	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	// Replace the identity .. first write one value, then we change it
	NUTS_PASS(
	    nng_tls_config_psk(c1, "identity2", key + 4, sizeof(key) - 4));
	NUTS_PASS(nng_tls_config_psk(c1, identity, key + 4, sizeof(key) - 4));
	NUTS_PASS(nng_tls_config_psk(c1, identity, key, sizeof(key)));
	NUTS_PASS(nng_stream_listener_set_ptr(l, NNG_OPT_TLS_CONFIG, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(
	    nng_stream_listener_get_int(l, NNG_OPT_TCP_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_psk(c2, identity, key, sizeof(key)));

	NUTS_PASS(nng_stream_dialer_set_ptr(d, NNG_OPT_TLS_CONFIG, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	NUTS_PASS(nuts_stream_wait(t1));
	NUTS_PASS(nuts_stream_wait(t2));
	NUTS_TRUE(memcmp(buf1, buf2, size) == 0);

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

void
test_tls_psk_bad_identity(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 10000;
	void                *t1;
	void                *t2;
	int                  port;
	uint8_t              key[32];

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < sizeof(key); i++) {
		key[i] = rand() & 0xff;
	}
	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	// Replace the identity .. first write one value, then we change it
	NUTS_PASS(nng_tls_config_psk(c1, "identity1", key, sizeof(key)));
	NUTS_PASS(nng_stream_listener_set_ptr(l, NNG_OPT_TLS_CONFIG, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(
	    nng_stream_listener_get_int(l, NNG_OPT_TCP_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_psk(c2, "identity2", key, sizeof(key)));
	NUTS_PASS(nng_tls_config_server_name(c2, "localhost"));

	NUTS_PASS(nng_stream_dialer_set_ptr(d, NNG_OPT_TLS_CONFIG, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	// These can fail due to ECRYPTO, EPEERAUTH, or ECONNSHUT, for example
	NUTS_ASSERT(nuts_stream_wait(t1) != 0);
	NUTS_ASSERT(nuts_stream_wait(t2) != 0);

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

void
test_tls_psk_key_too_big(void)
{
	nng_tls_config *c1;
	uint8_t         key[5000];

	NUTS_ENABLE_LOG(NNG_LOG_INFO);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_CLIENT));
	NUTS_FAIL(
	    nng_tls_config_psk(c1, "identity", key, sizeof(key)), NNG_ECRYPTO);
	nng_tls_config_free(c1);
}

void
test_tls_psk_config_busy(void)
{
	nng_tls_config      *c1;
	uint8_t              key[32];
	nng_stream_listener *l;
	nng_aio             *aio;

	nng_aio_alloc(&aio, NULL, NULL);

	NUTS_ENABLE_LOG(NNG_LOG_INFO);

	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_psk(c1, "identity", key, sizeof(key)));
	NUTS_PASS(nng_stream_listener_set_ptr(l, NNG_OPT_TLS_CONFIG, c1));
	nng_stream_listener_accept(l, aio);
	nng_msleep(100);
	NUTS_FAIL(
	    nng_tls_config_psk(c1, "identity2", key, sizeof(key)), NNG_EBUSY);

	nng_stream_listener_free(l);
	nng_aio_free(aio);
	nng_tls_config_free(c1);
}

TEST_LIST = {
	{ "tls config version", test_tls_config_version },
	{ "tls conn refused", test_tls_conn_refused },
	{ "tls large message", test_tls_large_message },
#ifndef NNG_TLS_ENGINE_WOLFSSL // wolfSSL doesn't validate certas until use
	{ "tls garbled cert", test_tls_garbled_cert },
#endif
#ifdef NNG_SUPP_TLS_PSK
	{ "tls psk", test_tls_psk },
	{ "tls psk server identities", test_tls_psk_server_identities },
	{ "tls psk bad identity", test_tls_psk_bad_identity },
	{ "tls psk key too big", test_tls_psk_key_too_big },
	{ "tls psk key config busy", test_tls_psk_config_busy },
#endif
	{ NULL, NULL },
};
