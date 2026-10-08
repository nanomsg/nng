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

#include <openssl/err.h>

static const nng_tls_engine_conn_ops *ops;

static nni_tls_conn *
test_conn_alloc(nng_tls_config *cfg)
{
	nni_tls_conn   *conn;
	nni_tls_bio_ops bio = { 0 };
	nng_sockaddr    sa  = { 0 };
	size_t          size;

	size = sizeof(*conn) + ops->size;
	conn = nng_alloc(size);
	NUTS_ASSERT(conn != NULL);
	memset(conn, 0, size);
	NUTS_PASS(nni_tls_init(conn, cfg, false));
	NUTS_PASS(nni_tls_start(conn, &bio, NULL, &sa));
	// Drive the engine synchronously, without actual network I/O. These
	// flags keep the common BIO from submitting transport operations.
	conn->bio_send_active = true;
	conn->bio_recv_pend   = true;
	return (conn);
}

static nng_tls_engine_conn *
test_engine(nni_tls_conn *conn)
{
	return ((void *) (conn + 1));
}

static void
test_transfer(nni_tls_conn *from, nni_tls_conn *to)
{
	size_t len = from->bio_send_len;
	NUTS_ASSERT(to->bio_recv_len + len <= NNG_TLS_MAX_RECV_SIZE);
	memmove(to->bio_recv_buf, to->bio_recv_buf + to->bio_recv_off,
	    to->bio_recv_len);
	to->bio_recv_off = 0;
	for (size_t i = 0; i < len; i++) {
		to->bio_recv_buf[to->bio_recv_len++] =
		    from->bio_send_buf[from->bio_send_tail];
		from->bio_send_tail =
		    (from->bio_send_tail + 1) % NNG_TLS_MAX_SEND_SIZE;
	}
	from->bio_send_len = 0;
}

static void
test_error_queue(nng_tls_version version)
{
	nng_tls_config *client_cfg, *server_cfg;
	nni_tls_conn   *client, *server;
	bool            client_done = false, server_done = false;
	uint8_t         buf[32];
	size_t          len;
	int             rv;

	ops = nng_tls_engine_ops.conn_ops;
	NUTS_PASS(nng_tls_config_alloc(&client_cfg, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(
	    nng_tls_config_auth_mode(client_cfg, NNG_TLS_AUTH_MODE_NONE));
	NUTS_PASS(nng_tls_config_alloc(&server_cfg, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_version(client_cfg, version, version));
	NUTS_PASS(nng_tls_config_version(server_cfg, version, version));
	NUTS_PASS(nng_tls_config_own_cert(
	    server_cfg, nuts_server_crt, nuts_server_key, NULL));
	client = test_conn_alloc(client_cfg);
	server = test_conn_alloc(server_cfg);

	for (unsigned i = 0; i < 32 && !(client_done && server_done); i++) {
		ERR_raise(ERR_LIB_USER, 1);
		rv = ops->handshake(test_engine(client));
		NUTS_ASSERT(rv == NNG_OK || rv == NNG_EAGAIN);
		NUTS_TRUE(ERR_peek_error() == 0);
		client_done = rv == NNG_OK;
		test_transfer(client, server);
		ERR_raise(ERR_LIB_USER, 1);
		rv = ops->handshake(test_engine(server));
		NUTS_ASSERT(rv == NNG_OK || rv == NNG_EAGAIN);
		NUTS_TRUE(ERR_peek_error() == 0);
		server_done = rv == NNG_OK;
		test_transfer(server, client);
	}
	NUTS_ASSERT(client_done && server_done);

	// A stale error from another SSL connection on this thread must not
	// turn an ordinary nonblocking read into a fatal SSL error.
	ERR_raise(ERR_LIB_USER, 1);
	len = sizeof(buf);
	NUTS_FAIL(ops->recv(test_engine(client), buf, &len), NNG_EAGAIN);
	NUTS_TRUE(ERR_peek_error() == 0);
	// The first read can consume TLS 1.3 session tickets; repeat once
	// they have been drained to exercise a plain WANT_READ response.
	ERR_raise(ERR_LIB_USER, 1);
	len = sizeof(buf);
	NUTS_FAIL(ops->recv(test_engine(client), buf, &len), NNG_EAGAIN);
	NUTS_TRUE(ERR_peek_error() == 0);

	// Exercise the same rule for a write blocked by a full BIO buffer.
	client->bio_send_len = NNG_TLS_MAX_SEND_SIZE;
	ERR_raise(ERR_LIB_USER, 1);
	len = 5;
	NUTS_FAIL(
	    ops->send(test_engine(client), (const uint8_t *) "hello", &len),
	    NNG_EAGAIN);
	NUTS_TRUE(ERR_peek_error() == 0);
	client->bio_send_len  = 0;
	client->bio_send_head = client->bio_send_tail = 0;
	ERR_raise(ERR_LIB_USER, 1);
	len = 5;
	NUTS_PASS(
	    ops->send(test_engine(client), (const uint8_t *) "hello", &len));
	NUTS_TRUE(ERR_peek_error() == 0);
	test_transfer(client, server);
	ERR_raise(ERR_LIB_USER, 1);
	len = sizeof(buf);
	NUTS_PASS(ops->recv(test_engine(server), buf, &len));
	NUTS_TRUE(ERR_peek_error() == 0);
	NUTS_TRUE(len == 5);
	NUTS_TRUE(memcmp(buf, "hello", 5) == 0);
	ERR_raise(ERR_LIB_USER, 1);
	nni_tls_close(client);
	NUTS_TRUE(ERR_peek_error() == 0);

	nni_tls_fini(client);
	nni_tls_fini(server);
	nng_free(client, sizeof(*client) + ops->size);
	nng_free(server, sizeof(*server) + ops->size);
	nng_tls_config_free(client_cfg);
	nng_tls_config_free(server_cfg);
	ERR_clear_error();
}

void
test_openssl_tls12_error_queue(void)
{
	test_error_queue(NNG_TLS_1_2);
}

void
test_openssl_tls13_error_queue(void)
{
	test_error_queue(NNG_TLS_1_3);
}

NUTS_TESTS = {
	{ "openssl TLS 1.2 error queue", test_openssl_tls12_error_queue },
	{ "openssl TLS 1.3 error queue", test_openssl_tls13_error_queue },
	{ NULL, NULL },
};
