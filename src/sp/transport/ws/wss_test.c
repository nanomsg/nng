//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include <nng/nng.h>

#include "../../../testing/nuts.h"

static nng_tls_config *
wss_server_config(void)
{
	nng_tls_config *c;
	NUTS_PASS(nng_tls_config_alloc(&c, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c, nuts_server_crt, nuts_server_key, NULL));
	return (c);
}

static nng_tls_config *
wss_server_config_ecdsa(void)
{
	nng_tls_config *c;
	NUTS_PASS(nng_tls_config_alloc(&c, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c, nuts_ecdsa_server_crt, nuts_ecdsa_server_key, NULL));
	return (c);
}

static nng_tls_config *
wss_config_psk(nng_tls_mode mode, const char *name, uint8_t *key, size_t len)
{
	nng_tls_config *c;
	NUTS_PASS(nng_tls_config_alloc(&c, mode));
	NUTS_PASS(nng_tls_config_psk(c, name, key, len));
	return (c);
}

static nng_tls_config *
wss_client_config(void)
{
	nng_tls_config *c;
	NUTS_PASS(nng_tls_config_alloc(&c, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_own_cert(
	    c, nuts_client_crt, nuts_client_key, NULL));
	NUTS_PASS(nng_tls_config_ca_chain(c, nuts_server_crt, NULL));
	NUTS_PASS(nng_tls_config_server_name(c, "localhost"));
	return (c);
}

static nng_tls_config *
wss_client_config_ecdsa(void)
{
	nng_tls_config *c;
	NUTS_PASS(nng_tls_config_alloc(&c, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_own_cert(
	    c, nuts_ecdsa_client_crt, nuts_ecdsa_client_key, NULL));
	NUTS_PASS(nng_tls_config_ca_chain(c, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_tls_config_server_name(c, "localhost"));
	return (c);
}

void
test_wss_port_zero_bind(void)
{
	nng_socket      s1;
	nng_socket      s2;
	nng_tls_config *c1, *c2;
	nng_listener    l;
	nng_dialer      d;
	int             port;
	const nng_url  *url;

	c1 = wss_server_config();
	c2 = wss_client_config();
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_listener_create(&l, s1, "wss://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(l, c1));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_PASS(nng_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port <= 65535);
	NUTS_MATCH(nng_url_scheme(url), "wss");
	NUTS_PASS(nng_dialer_create_url(&d, s2, url));
	NUTS_PASS(nng_dialer_set_tls(d, c2));
	NUTS_PASS(nng_dialer_start(d, 0));
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
}

void
test_wss_bad_cert_mutual(void)
{
	nng_socket      s1;
	nng_socket      s2;
	nng_tls_config *c1, *c2;
	nng_listener    l;
	nng_dialer      d;
	const nng_url  *url;

	c1 = wss_server_config();
	c2 = wss_client_config();

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_tls_config_auth_mode(c1, NNG_TLS_AUTH_MODE_REQUIRED));
	// a valid cert, but not the one that signed the config!
	NUTS_PASS(nng_tls_config_ca_chain(c1, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(
	    nng_listener_create(&l, s1, "wss://127.0.0.1:0/bad_cert_mutual"));
	NUTS_PASS(nng_listener_set_tls(l, c1));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_MATCH(nng_url_scheme(url), "wss");
	NUTS_PASS(nng_dialer_create_url(&d, s2, url));
	NUTS_PASS(nng_dialer_set_tls(d, c2));
#ifdef NNG_TLS_ENGINE_MBEDTLS
	NUTS_FAIL(nng_dialer_start(d, 0), NNG_ECRYPTO);
#else
	// WolfSSL doesn't validate this here.
	nng_dialer_start(d, 0);
#endif
	nng_msleep(50);
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
}

void
test_wss_cert_mutual(void)
{
	nng_socket      s1;
	nng_socket      s2;
	nng_tls_config *c1, *c2;
	nng_listener    l;
	nng_dialer      d;
	const nng_url  *url;

	c1 = wss_server_config_ecdsa();
	c2 = wss_client_config_ecdsa();

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_tls_config_auth_mode(c1, NNG_TLS_AUTH_MODE_REQUIRED));
	NUTS_PASS(nng_tls_config_ca_chain(c1, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_tls_config_ca_chain(c2, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_listener_create(&l, s1, "wss://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(l, c1));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_MATCH(nng_url_scheme(url), "wss");
	NUTS_PASS(nng_dialer_create_url(&d, s2, url));
	NUTS_PASS(nng_dialer_set_tls(d, c2));
	NUTS_PASS(nng_dialer_start(d, 0));
	nng_msleep(50);
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
}

void
test_wss_malformed_address(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_dial(s1, "wss://127.0.0.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(nng_dial(s1, "wss://127.0.x.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_listen(s1, "wss://127.0.0.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_listen(s1, "wss://127.0.x.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s1);
}

void
test_wss_no_delay_option(void)
{
	nng_socket      s;
	nng_dialer      d;
	nng_listener    l;
	bool            v;
	int             x;
	char           *addr;
	nng_tls_config *dc, *lc;

	NUTS_ADDR(addr, "wss");
	dc = wss_client_config();
	lc = wss_server_config();

	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));
	NUTS_PASS(nng_dialer_set_tls(d, dc));
	NUTS_PASS(nng_dialer_get_bool(d, NNG_OPT_TCP_NODELAY, &v));
	NUTS_TRUE(v);
	NUTS_PASS(nng_dialer_set_bool(d, NNG_OPT_TCP_NODELAY, false));
	NUTS_PASS(nng_dialer_get_bool(d, NNG_OPT_TCP_NODELAY, &v));
	NUTS_TRUE(v == false);
	NUTS_FAIL(
	    nng_dialer_get_int(d, NNG_OPT_TCP_NODELAY, &x), NNG_EBADTYPE);
	x = 0;
	NUTS_FAIL(nng_dialer_set_int(d, NNG_OPT_TCP_NODELAY, x), NNG_EBADTYPE);

	NUTS_PASS(nng_listener_create(&l, s, addr));
	NUTS_PASS(nng_listener_set_tls(l, lc));
	NUTS_PASS(nng_listener_get_bool(l, NNG_OPT_TCP_NODELAY, &v));
	NUTS_TRUE(v == true);
	x = 0;
	NUTS_FAIL(
	    nng_listener_set_int(l, NNG_OPT_TCP_NODELAY, x), NNG_EBADTYPE);

	NUTS_PASS(nng_dialer_close(d));
	NUTS_PASS(nng_listener_close(l));

	NUTS_CLOSE(s);
	nng_tls_config_free(lc);
	nng_tls_config_free(dc);
}

void
test_wss_keep_alive_option(void)
{
	nng_socket      s;
	nng_dialer      d;
	nng_listener    l;
	nng_tls_config *dc, *lc;
	bool            v;
	int             x;
	char           *addr;

	dc = wss_client_config();
	lc = wss_server_config();
	NUTS_ADDR(addr, "wss");
	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));
	NUTS_PASS(nng_dialer_set_tls(d, dc));
	NUTS_PASS(nng_dialer_get_bool(d, NNG_OPT_TCP_KEEPALIVE, &v));
	NUTS_TRUE(v == false);
	NUTS_PASS(nng_dialer_set_bool(d, NNG_OPT_TCP_KEEPALIVE, true));
	NUTS_PASS(nng_dialer_get_bool(d, NNG_OPT_TCP_KEEPALIVE, &v));
	NUTS_TRUE(v);
	NUTS_FAIL(
	    nng_dialer_get_int(d, NNG_OPT_TCP_KEEPALIVE, &x), NNG_EBADTYPE);
	x = 1;
	NUTS_FAIL(
	    nng_dialer_set_int(d, NNG_OPT_TCP_KEEPALIVE, x), NNG_EBADTYPE);

	NUTS_PASS(nng_listener_create(&l, s, addr));
	NUTS_PASS(nng_listener_set_tls(l, lc));
	NUTS_PASS(nng_listener_get_bool(l, NNG_OPT_TCP_KEEPALIVE, &v));
	NUTS_TRUE(v == false);
	x = 1;
	NUTS_FAIL(
	    nng_listener_set_int(l, NNG_OPT_TCP_KEEPALIVE, x), NNG_EBADTYPE);

	NUTS_PASS(nng_dialer_close(d));
	NUTS_PASS(nng_listener_close(l));

	NUTS_CLOSE(s);
	nng_tls_config_free(lc);
	nng_tls_config_free(dc);
}

void
test_wss_recv_max(void)
{
	char            msg[256];
	char            buf[256];
	nng_socket      s0;
	nng_socket      s1;
	nng_tls_config *c0, *c1;
	nng_listener    l;
	nng_dialer      d;
	size_t          sz;
	char           *addr;
	const nng_url  *url;

	NUTS_ADDR_ZERO(addr, "wss");

	c0 = wss_server_config();
	c1 = wss_client_config();
	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 200));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_listener_set_tls(l, c0));
	NUTS_PASS(nng_socket_get_size(s0, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 200);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 100));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_dialer_create_url(&d, s1, url));
	NUTS_PASS(nng_dialer_set_tls(d, c1));
	NUTS_PASS(nng_dialer_start(d, 0));
	NUTS_PASS(nng_send(s1, msg, 95, 0));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_recv(s0, buf, &sz, 0));
	NUTS_TRUE(sz == 95);
	NUTS_PASS(nng_send(s1, msg, 150, 0));
	NUTS_FAIL(nng_recv(s0, buf, &sz, 0), NNG_ETIMEDOUT);
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c0);
	nng_tls_config_free(c1);
}

void
test_wss_psk(void)
{
#ifdef NNG_SUPP_TLS_PSK
	char            msg[256];
	char            buf[256];
	nng_socket      s0;
	nng_socket      s1;
	nng_tls_config *c0, *c1;
	nng_listener    l;
	nng_dialer      d;
	size_t          sz;
	char           *addr;
	uint8_t         key[32];
	const nng_url  *url;

	for (unsigned i = 0; i < sizeof(key); i++) {
		key[i] = rand() % 0xff;
	}

	NUTS_ADDR_ZERO(addr, "wss");

	c0 = wss_config_psk(NNG_TLS_MODE_SERVER, "identity", key, sizeof key);
	c1 = wss_config_psk(NNG_TLS_MODE_CLIENT, "identity", key, sizeof key);
	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_listener_set_tls(l, c0));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_dialer_create_url(&d, s1, url));
	NUTS_PASS(nng_dialer_set_tls(d, c1));
	NUTS_PASS(nng_dialer_start(d, 0));
	NUTS_PASS(nng_send(s1, msg, 95, 0));
	NUTS_PASS(nng_recv(s0, buf, &sz, 0));
	NUTS_TRUE(sz == 95);
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c0);
	nng_tls_config_free(c1);
#else
	NUTS_SKIP("no PSK support");
#endif
}

void
test_wss_pipe_details(void)
{
	nng_socket      s1;
	nng_socket      s2;
	nng_tls_config *c1, *c2;
	int             port;
	nng_listener    l;
	nng_dialer      d;
	nng_msg        *msg;
	nng_pipe        p;
	const nng_url  *url;

	c1 = wss_server_config_ecdsa();
	c2 = wss_client_config_ecdsa();

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_tls_config_auth_mode(c1, NNG_TLS_AUTH_MODE_REQUIRED));
	NUTS_PASS(nng_tls_config_ca_chain(c1, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_tls_config_ca_chain(c2, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_listener_create(&l, s1, "wss://127.0.0.1:0/test"));
	NUTS_PASS(nng_listener_set_tls(l, c1));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_MATCH(nng_url_scheme(url), "wss");
	NUTS_PASS(nng_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port != 0);
	NUTS_PASS(nng_dialer_create_url(&d, s2, url));
	NUTS_PASS(nng_dialer_set_tls(d, c2));
	NUTS_PASS(nng_dialer_start(d, 0));
	nng_msleep(50);
	NUTS_SEND(s1, "text");
	NUTS_PASS(nng_recvmsg(s2, &msg, 0));
	p = nng_msg_get_pipe(msg);
	NUTS_TRUE(nng_pipe_id(p) >= 0);
#if !defined(NNG_TLS_ENGINE_WOLFSSL) || defined(NNG_WOLFSSL_HAVE_PEER_CERT)
	nng_tls_cert *cert;
	char         *name;
	NUTS_PASS(nng_pipe_peer_cert(p, &cert));
	NUTS_PASS(nng_tls_cert_subject(cert, &name));
	NUTS_ASSERT(name != NULL);
	nng_log_debug(NULL, "SUBJECT: %s", name);
	NUTS_PASS(nng_tls_cert_issuer(cert, &name));
	NUTS_ASSERT(name != NULL);
	nng_log_debug(NULL, "ISSUER: %s", name);
	NUTS_PASS(nng_tls_cert_serial_number(cert, &name));
	NUTS_ASSERT(name != NULL);
	nng_log_debug(NULL, "SERIAL: %s", name);
	NUTS_PASS(nng_tls_cert_subject_cn(cert, &name));
	NUTS_MATCH(name, "127.0.0.1");
	NUTS_PASS(nng_tls_cert_next_alt(cert, &name));
	nng_log_debug(NULL, "FIRST ALT: %s", name);
	NUTS_MATCH(name, "localhost");
	NUTS_FAIL(nng_tls_cert_next_alt(cert, &name), NNG_ENOENT);
	struct tm when;
	NUTS_PASS(nng_tls_cert_not_before(cert, &when));
	nng_log_debug(NULL, "BEGINS: %s", asctime(&when));
	NUTS_PASS(nng_tls_cert_not_after(cert, &when));
	nng_log_debug(NULL, "EXPIRES: %s", asctime(&when));

	nng_tls_cert_free(cert);
#endif
	nng_msg_free(msg);
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
}

NUTS_TESTS = {
	{ "wss port zero bind", test_wss_port_zero_bind },
	{ "wss malformed address", test_wss_malformed_address },
	{ "wss no delay option", test_wss_no_delay_option },
	{ "wss keep alive option", test_wss_keep_alive_option },
	{ "wss recv max", test_wss_recv_max },
	{ "wss pre-shared key", test_wss_psk },
	{ "wss bad cert mutual", test_wss_bad_cert_mutual },
	{ "wss cert mutual", test_wss_cert_mutual },
	{ "wss pipe details", test_wss_pipe_details },

	{ NULL, NULL },
};
