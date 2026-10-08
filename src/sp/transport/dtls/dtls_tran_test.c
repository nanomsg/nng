//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
// Copyright 2018 Cody Piersall <cody.piersall@gmail.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"

#include "../../../testing/nuts.h"

#ifndef _WIN32
#include <arpa/inet.h>
#endif

// TLS tests.

// DTLS retransmissions can outlast a scheduler pause on a loaded CI runner.
#define DTLS_STRESS_TIMEOUT 5000
#define DTLS_PROXY_BUFSIZE 65536

static nng_tls_config *
tls_server_config(void)
{
	nng_tls_config *c;
	NUTS_PASS(nng_tls_config_alloc(&c, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c, nuts_server_crt, nuts_server_key, NULL));
	return (c);
}

static nng_tls_config *
tls_server_config_ecdsa(void)
{
	nng_tls_config *c;
	NUTS_PASS(nng_tls_config_alloc(&c, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c, nuts_ecdsa_server_crt, nuts_ecdsa_server_key, NULL));
	return (c);
}

#ifdef NNG_SUPP_TLS_PSK
static nng_tls_config *
tls_config_psk(nng_tls_mode mode, const char *name, uint8_t *key, size_t len)
{
	nng_tls_config *c;
	NUTS_PASS(nng_tls_config_alloc(&c, mode));
	NUTS_PASS(nng_tls_config_psk(c, name, key, len));
	return (c);
}
#endif

static nng_tls_config *
tls_client_config(void)
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
tls_client_config_ecdsa(void)
{
	nng_tls_config *c;
	NUTS_PASS(nng_tls_config_alloc(&c, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_own_cert(
	    c, nuts_ecdsa_client_crt, nuts_ecdsa_client_key, NULL));
	NUTS_PASS(nng_tls_config_ca_chain(c, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_tls_config_server_name(c, "localhost"));
	return (c);
}

typedef struct {
	nng_udp     *udp;
	nng_aio     *recv;
	nng_aio     *send;
	uint8_t     *buf;
	nng_sockaddr server;
	bool         dropped;
	bool         dropped_server;
	bool         bad_wire;
	unsigned     duplicates;
	int          error;
} dtls_proxy;

static void
dtls_proxy_run(void *arg)
{
	dtls_proxy  *p      = arg;
	nng_sockaddr client = { 0 };
	nng_sockaddr from;
	uint8_t     *buf = p->buf;
	nng_iov      iov;
	int          rv;
	for (;;) {
		iov.iov_buf = buf;
		iov.iov_len = DTLS_PROXY_BUFSIZE;
		nng_aio_set_iov(p->recv, 1, &iov);
		nng_aio_set_input(p->recv, 0, &from);
		nng_udp_recv(p->udp, p->recv);
		nng_aio_wait(p->recv);
		if ((rv = nng_aio_result(p->recv)) != 0) {
			p->error = rv == NNG_ECLOSED ? 0 : rv;
			return;
		}
		iov.iov_len = nng_aio_count(p->recv);
		// DTLS has a 13-byte record header and a 0xfeXX version. TLS
		// records over UDP (which self-peer tests accepted) must fail.
		if (iov.iov_len < 13 || buf[1] != 0xfe ||
		    (buf[2] != 0xff && buf[2] != 0xfd)) {
			p->bad_wire = true;
		}
		bool from_server = from.s_in.sa_port == p->server.s_in.sa_port;
		if (from_server && !p->dropped_server) {
			p->dropped_server = true;
			continue;
		}
		if (!from_server) {
			client = from;
			if (!p->dropped) {
				p->dropped = true;
				continue; // No I/O event will wake the
				          // client's handshake.
			}
		}
		nng_sockaddr to = from_server ? client : p->server;
		nng_aio_set_input(p->send, 0, &to);
		// Replay application records to verify DTLS duplicate
		// suppression.
		unsigned copies = buf[0] == 23 ? 2 : 1;
		if (copies == 2) {
			p->duplicates++;
		}
		for (unsigned i = 0; i < copies; i++) {
			nng_aio_set_iov(p->send, 1, &iov);
			nng_udp_send(p->udp, p->send);
			nng_aio_wait(p->send);
			if ((rv = nng_aio_result(p->send)) != 0) {
				p->error = rv == NNG_ECLOSED ? 0 : rv;
				return;
			}
		}
	}
}

void
test_dtls_wire_loss_replay(void)
{
	dtls_proxy      p    = { 0 };
	nng_sockaddr    addr = { 0 };
	nng_socket      s1, s2, s3, s4;
	nng_listener    l, tl;
	nng_dialer      d, td;
	nng_thread     *thread;
	const nng_url  *url;
	char            proxy_url[80];
	nng_msg        *msg;
	nng_tls_config *c1 = tls_server_config();
	nng_tls_config *c2 = tls_client_config();
	nng_tls_config *c3 = tls_server_config();
	nng_tls_config *c4 = tls_client_config();

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_OPEN(s3);
	NUTS_OPEN(s4);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 15000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 15000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 15000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 15000));
	NUTS_PASS(nng_socket_set_ms(s3, NNG_OPT_RECVTIMEO, 5000));
	NUTS_PASS(nng_socket_set_ms(s4, NNG_OPT_SENDTIMEO, 5000));
	NUTS_PASS(nng_listener_create(&l, s1, "dtls://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(l, c1));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	p.server.s_in.sa_family = NNG_AF_INET;
	p.server.s_in.sa_addr   = htonl(0x7f000001);
	p.server.s_in.sa_port   = htons((uint16_t) nng_url_port(url));
	addr.s_in.sa_family     = NNG_AF_INET;
	addr.s_in.sa_addr       = htonl(0x7f000001);
	NUTS_PASS(nng_udp_open(&p.udp, &addr));
	NUTS_PASS(nng_udp_sockname(p.udp, &addr));
	NUTS_PASS(nng_aio_alloc(&p.recv, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&p.send, NULL, NULL));
	// NNG threads have a small stack on Windows; keep the UDP buffer
	// on the heap, with the proxy's other resources.
	p.buf = nng_alloc(DTLS_PROXY_BUFSIZE);
	NUTS_ASSERT(p.buf != NULL);
	NUTS_PASS(nng_thread_create(&thread, dtls_proxy_run, &p));
	snprintf(proxy_url, sizeof(proxy_url), "dtls://127.0.0.1:%u",
	    (unsigned) ntohs(addr.s_in.sa_port));
	NUTS_PASS(nng_dialer_create(&d, s2, proxy_url));
	NUTS_PASS(nng_dialer_set_tls(d, c2));
	NUTS_PASS(nng_dialer_start(d, NNG_FLAG_NONBLOCK));
	NUTS_SEND(s2, "loss recovery");
	NUTS_RECV(s1, "loss recovery");
	NUTS_SEND(s1, "reply");
	NUTS_RECV(s2, "reply");
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 100));
	int replay_rv = nng_recvmsg(s1, &msg, 0);
	if (replay_rv == 0) {
		nng_msg_free(msg);
	}
	NUTS_FAIL(replay_rv, NNG_ETIMEDOUT);
	replay_rv = nng_recvmsg(s2, &msg, 0);
	if (replay_rv == 0) {
		nng_msg_free(msg);
	}
	NUTS_FAIL(replay_rv, NNG_ETIMEDOUT);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 5000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 5000));

	// Stream TLS uses separate configurations, and still works normally.
	NUTS_PASS(nng_listener_create(&tl, s3, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(tl, c3));
	NUTS_PASS(nng_listener_start(tl, 0));
	NUTS_PASS(nng_listener_get_url(tl, &url));
	NUTS_PASS(nng_dialer_create_url(&td, s4, url));
	NUTS_PASS(nng_dialer_set_tls(td, c4));
	NUTS_PASS(nng_dialer_start(td, 0));
	NUTS_SEND(s4, "separate configuration");
	NUTS_RECV(s3, "separate configuration");

	// Neither direction of cross-transport reuse is permitted. Failure
	// must leave existing users of the configuration working.
	nng_dialer wrong;
	NUTS_PASS(nng_dialer_create_url(&wrong, s4, url));
	NUTS_PASS(nng_dialer_set_tls(wrong, c2));
	NUTS_FAIL(nng_dialer_start(wrong, 0), NNG_EINVAL);
	NUTS_PASS(nng_dialer_close(wrong));
	NUTS_PASS(nng_dialer_create(&wrong, s2, "dtls://127.0.0.1:9"));
	NUTS_PASS(nng_dialer_set_tls(wrong, c4));
	NUTS_FAIL(nng_dialer_start(wrong, 0), NNG_EINVAL);
	NUTS_PASS(nng_dialer_close(wrong));
	NUTS_SEND(s4, "still TLS");
	NUTS_RECV(s3, "still TLS");
	NUTS_SEND(s2, "still DTLS");
	NUTS_RECV(s1, "still DTLS");

	nng_udp_stop(p.udp);
	nng_thread_destroy(thread);
	nng_free(p.buf, DTLS_PROXY_BUFSIZE);
	NUTS_PASS(p.error);
	NUTS_TRUE(p.dropped);
	NUTS_TRUE(p.dropped_server);
	NUTS_TRUE(!p.bad_wire);
	NUTS_TRUE(p.duplicates > 0);
	nng_aio_free(p.recv);
	nng_aio_free(p.send);
	nng_udp_close(p.udp);
	NUTS_CLOSE(s4);
	NUTS_CLOSE(s3);
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_tls_config_free(c3);
	nng_tls_config_free(c4);
}

void
test_dtls_tls13_only(void)
{
	nng_tls_config *c = tls_client_config();
	nng_tls_config *server;
	nng_socket      s, peer;
	nng_listener    l;
	nng_dialer      d;
	const nng_url  *url;
	int rv = nng_tls_config_version(c, NNG_TLS_1_3, NNG_TLS_1_3);
	if (rv == NNG_ENOTSUP) {
		nng_tls_config_free(c);
		// The engine cannot require TLS 1.3, so there is no such
		// configuration to test with DTLS (e.g. mbedTLS 2.x).
		NUTS_FAIL(rv, NNG_ENOTSUP);
		return;
	}
	NUTS_PASS(rv);
	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, "dtls://127.0.0.1:9"));
	NUTS_PASS(nng_dialer_set_tls(d, c));
	NUTS_FAIL(nng_dialer_start(d, 0), NNG_ENOTSUP);
	NUTS_PASS(nng_dialer_close(d));

	// Failed preparation must not bind or damage the configuration.
	// A TLS 1.3-only client can still use it for stream TLS afterward.
	server = tls_server_config();
	NUTS_OPEN(peer);
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_SENDTIMEO, 5000));
	NUTS_PASS(nng_socket_set_ms(peer, NNG_OPT_RECVTIMEO, 5000));
	NUTS_PASS(nng_listener_create(&l, peer, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(l, server));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_PASS(nng_dialer_create_url(&d, s, url));
	NUTS_PASS(nng_dialer_set_tls(d, c));
	NUTS_PASS(nng_dialer_start(d, 0));
	NUTS_SEND(s, "still TLS 1.3");
	NUTS_RECV(peer, "still TLS 1.3");
	NUTS_CLOSE(peer);
	NUTS_CLOSE(s);
	nng_tls_config_free(server);
	nng_tls_config_free(c);
}

void
test_dtls_port_zero_bind(void)
{
	nng_socket      s1;
	nng_socket      s2;
	nng_tls_config *c1, *c2;
	nng_listener    l;
	nng_dialer      d;
	const nng_url  *url;

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	c1 = tls_server_config();
	c2 = tls_client_config();
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_listener_create(&l, s1, "dtls://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(l, c1));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_MATCH(nng_url_scheme(url), "dtls");
	NUTS_PASS(nng_dialer_create_url(&d, s2, url));
	NUTS_PASS(nng_dialer_set_tls(d, c2));
	// NUTS_PASS(nng_dialer_start(d, NNG_FLAG_NONBLOCK));
	NUTS_PASS(nng_dialer_start(d, 0));
	nng_msleep(1000);
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
}

void
test_dtls_bad_cert_mutual(void)
{
	nng_socket      s1;
	nng_socket      s2;
	nng_tls_config *c1, *c2;
	nng_listener    l;
	nng_dialer      d;
	const nng_url  *url;

	c1 = tls_server_config();
	c2 = tls_client_config();

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_tls_config_auth_mode(c1, NNG_TLS_AUTH_MODE_REQUIRED));
	// a valid cert, but not the one that signed the config!
	NUTS_PASS(nng_tls_config_ca_chain(c1, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_listener_create(&l, s1, "dtls://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(l, c1));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_MATCH(nng_url_scheme(url), "dtls");
	NUTS_PASS(nng_dialer_create_url(&d, s2, url));
	NUTS_PASS(nng_dialer_set_tls(d, c2));
	// With DTLS we are not guaranteed to get the connection failure.
	nng_dialer_start(d, NNG_FLAG_NONBLOCK);
	nng_msleep(500);
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
}

void
test_dtls_cert_mutual(void)
{
	nng_socket      s1;
	nng_socket      s2;
	nng_tls_config *c1, *c2;
	nng_listener    l;
	nng_dialer      d;
	const nng_url  *url;

	c1 = tls_server_config_ecdsa();
	c2 = tls_client_config_ecdsa();

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_tls_config_auth_mode(c1, NNG_TLS_AUTH_MODE_REQUIRED));
	NUTS_PASS(nng_tls_config_ca_chain(c1, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_tls_config_ca_chain(c2, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_listener_create(&l, s1, "dtls://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(l, c1));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_MATCH(nng_url_scheme(url), "dtls");
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
test_dtls_malformed_address(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_dial(s1, "dtls://127.0.0.1", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_dial(s1, "dtls://127.0.0.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_dial(s1, "dtls://127.0.x.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_listen(s1, "dtls://127.0.0.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_listen(s1, "dtls://127.0.x.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s1);
}

// DTLS does not support TCP_NODELAY because it's based on UDP.
void
test_dtls_no_delay_option(void)
{
	nng_socket      s;
	nng_dialer      d;
	nng_listener    l;
	bool            v;
	char           *addr;
	nng_tls_config *dc, *lc;

	NUTS_ADDR(addr, "dtls");
	dc = tls_client_config();
	lc = tls_server_config();

	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));
	NUTS_PASS(nng_dialer_set_tls(d, dc));
	NUTS_FAIL(
	    nng_dialer_get_bool(d, NNG_OPT_TCP_NODELAY, &v), NNG_ENOTSUP);
	NUTS_FAIL(nng_dialer_set_bool(d, NNG_OPT_TCP_NODELAY, v), NNG_ENOTSUP);

	NUTS_PASS(nng_listener_create(&l, s, addr));
	NUTS_PASS(nng_listener_set_tls(l, lc));
	NUTS_FAIL(
	    nng_listener_get_bool(l, NNG_OPT_TCP_NODELAY, &v), NNG_ENOTSUP);
	NUTS_FAIL(
	    nng_listener_set_bool(l, NNG_OPT_TCP_NODELAY, v), NNG_ENOTSUP);

	NUTS_PASS(nng_dialer_close(d));
	NUTS_PASS(nng_listener_close(l));

	NUTS_CLOSE(s);
	nng_tls_config_free(lc);
	nng_tls_config_free(dc);
}

void
test_dtls_max_peers_option(void)
{
	nng_socket   s;
	nng_listener l;
	size_t       max_peers;
	char        *addr;

	NUTS_ADDR(addr, "dtls");
	NUTS_OPEN(s);
	NUTS_PASS(nng_listener_create(&l, s, addr));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_UDP_MAX_PEERS, &max_peers));
	NUTS_TRUE(max_peers == 1024);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_UDP_MAX_PEERS, 1));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_UDP_MAX_PEERS, &max_peers));
	NUTS_TRUE(max_peers == 1);
	NUTS_PASS(nng_listener_close(l));
	NUTS_CLOSE(s);
}

void
test_dtls_conn_tunables(void)
{
	nng_socket   s;
	nng_dialer   d;
	nng_duration retry;
	nng_duration expire;
	char        *addr;

	NUTS_ADDR(addr, "dtls4");
	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));
	NUTS_PASS(nng_dialer_get_ms(d, NNG_OPT_UDP_CONN_RETRY, &retry));
	NUTS_PASS(nng_dialer_get_ms(d, NNG_OPT_UDP_CONN_EXPIRE, &expire));
	NUTS_TRUE(retry == 200);
	NUTS_TRUE(expire == 5000);
	NUTS_PASS(nng_dialer_set_ms(d, NNG_OPT_UDP_CONN_RETRY, 50));
	NUTS_PASS(nng_dialer_set_ms(d, NNG_OPT_UDP_CONN_EXPIRE, 250));
	NUTS_PASS(nng_dialer_get_ms(d, NNG_OPT_UDP_CONN_RETRY, &retry));
	NUTS_PASS(nng_dialer_get_ms(d, NNG_OPT_UDP_CONN_EXPIRE, &expire));
	NUTS_TRUE(retry == 50);
	NUTS_TRUE(expire == 250);
	NUTS_FAIL(nng_dialer_set_ms(d, NNG_OPT_UDP_CONN_RETRY, 0), NNG_EINVAL);
	NUTS_FAIL(
	    nng_dialer_set_ms(d, NNG_OPT_UDP_CONN_EXPIRE, 0), NNG_EINVAL);
	NUTS_PASS(nng_dialer_close(d));
	NUTS_CLOSE(s);
}

void
test_dtls_recv_max(void)
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

	NUTS_ADDR_ZERO(addr, "dtls");

	c0 = tls_server_config();
	c1 = tls_client_config();
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
test_dtls_recv_large(void)
{
	char            msg[1024];
	char            buf[1024];
	nng_socket      s0;
	nng_socket      s1;
	nng_tls_config *c0, *c1;
	nng_listener    l;
	nng_dialer      d;
	size_t          sz;
	char           *addr;
	const nng_url  *url;

	NUTS_ADDR_ZERO(addr, "dtls");

	c0 = tls_server_config();
	c1 = tls_client_config();
	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_listener_set_tls(l, c0));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));

	memset(buf, 0, sizeof(buf));
	memset(msg, 'A', sizeof(msg));
	NUTS_OPEN(s1);
	NUTS_PASS(nng_dialer_create_url(&d, s1, url));
	NUTS_PASS(nng_dialer_set_tls(d, c1));
	NUTS_PASS(nng_dialer_start(d, 0));
	NUTS_PASS(nng_send(s1, msg, sizeof(msg), 0));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	sz = sizeof(buf);
	NUTS_PASS(nng_recv(s0, buf, &sz, 0));
	NUTS_TRUE(sz == sizeof(msg));
	int mismatch = 0;
	for (int i = 0; i < (int) sizeof(msg); i++) {
		if (buf[i] != msg[i]) {
			mismatch++;
			if (mismatch < 6) {
				NUTS_MSG(
				    "Mismatch at index %d, sent %x recv %x", i,
				    msg[i], buf[i]);
			}
		}
	}
	NUTS_MSG("total mismatches %d", mismatch);
	NUTS_TRUE(mismatch == 0);
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c0);
	nng_tls_config_free(c1);
}

void
test_dtls_exchange_many(void)
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

	NUTS_ADDR_ZERO(addr, "dtls");

	c0 = tls_server_config();
	c1 = tls_client_config();
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

	NUTS_PASS(
	    nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, DTLS_STRESS_TIMEOUT));

	// send a bunch of messages - we're hoping that by serializing we won't
	// overwhelm the network.
	for (int i = 0; i < 100; i++) {
		NUTS_PASS(nng_send(s1, msg, 95, 0));
		NUTS_PASS(nng_recv(s0, buf, &sz, 0));
		NUTS_TRUE(sz == 95);
		NUTS_PASS(nng_send(s0, msg, 63, 0));
		NUTS_PASS(nng_recv(s1, buf, &sz, 0));
		NUTS_TRUE(sz == 63);
	}
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
	nng_tls_config_free(c0);
	nng_tls_config_free(c1);
}

void
test_dtls_reqrep_multi(void)
{
	char            msg[1024];
	char            buf[1024];
	nng_socket      s0;
	nng_socket      s1;
	nng_socket      s2;
	nng_tls_config *c0, *c1;
	nng_listener    l;
	nng_dialer      d1;
	nng_dialer      d2;
	size_t          sz;
	char           *addr;
	const nng_url  *url;

	NUTS_ADDR_ZERO(addr, "dtls");

	c0 = tls_server_config();
	c1 = tls_client_config();
	NUTS_PASS(nng_rep0_open(&s0));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 200));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_listener_set_tls(l, c0));
	NUTS_PASS(nng_socket_get_size(s0, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 200);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 100));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));

	NUTS_PASS(nng_req0_open(&s1));
	NUTS_PASS(nng_dialer_create_url(&d1, s1, url));
	NUTS_PASS(nng_dialer_set_tls(d1, c1));
	NUTS_PASS(nng_dialer_start(d1, 0));

	NUTS_PASS(nng_req0_open(&s2));
	NUTS_PASS(nng_dialer_create_url(&d2, s2, url));
	NUTS_PASS(nng_dialer_set_tls(d2, c1));
	NUTS_PASS(nng_dialer_start(d2, 0));

	NUTS_PASS(
	    nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, DTLS_STRESS_TIMEOUT));

	// send a bunch of messages - we're hoping that by serializing we won't
	// overwhelm the network.
	for (int i = 0; i < 100; i++) {
		NUTS_PASS(nng_send(s1, msg, 95, 0));
		NUTS_PASS(nng_recv(s0, buf, &sz, 0));
		NUTS_TRUE(sz == 95);
		NUTS_PASS(nng_send(s0, msg, 63, 0));
		NUTS_PASS(nng_recv(s1, buf, &sz, 0));
		NUTS_TRUE(sz == 63);

		NUTS_PASS(nng_send(s2, msg, 92, 0));
		NUTS_PASS(nng_recv(s0, buf, &sz, 0));
		NUTS_TRUE(sz == 92);
		NUTS_PASS(nng_send(s0, msg, 62, 0));
		NUTS_PASS(nng_recv(s2, buf, &sz, 0));
		NUTS_TRUE(sz == 62);
	}
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	nng_tls_config_free(c0);
	nng_tls_config_free(c1);
}

#define NCLIENT 10
void
test_dtls_pub_multi(void)
{
	char            msg[1024];
	char            buf[1024];
	nng_socket      s0;
	nng_tls_config *c0, *c1;
	nng_listener    l;
	size_t          sz;
	char           *addr;
	const nng_url  *url;
	nng_socket      cs[NCLIENT];
	nng_dialer      cd[NCLIENT];

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);

	NUTS_ADDR_ZERO(addr, "dtls");

	c0 = tls_server_config();
	c1 = tls_client_config();
	NUTS_PASS(nng_pub0_open(&s0));
	NUTS_PASS(
	    nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 200));
	NUTS_PASS(
	    nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, DTLS_STRESS_TIMEOUT));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_listener_set_tls(l, c0));
	NUTS_PASS(nng_socket_get_size(s0, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 200);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 100));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));

	for (int i = 0; i < NCLIENT; i++) {
		NUTS_PASS(nng_sub0_open(&cs[i]));
		NUTS_PASS(nng_socket_set_ms(
		    cs[i], NNG_OPT_RECVTIMEO, DTLS_STRESS_TIMEOUT));
		NUTS_PASS(nng_sub0_socket_subscribe(cs[i], "", 0));
		NUTS_PASS(nng_dialer_create_url(&cd[i], cs[i], url));
		NUTS_PASS(nng_dialer_set_tls(cd[i], c1));
		NUTS_PASS(nng_dialer_start(cd[i], 0));
	}

	// send a bunch of messages - we're hoping that by serializing we won't
	// overwhelm the network.
	for (int i = 0; i < 1000; i++) {
		size_t len = nng_random() % (sizeof(msg) - 1);
		memset(msg, 'a' + i % 26, sizeof(buf));
		msg[len] = 0;
		NUTS_PASS(nng_send(s0, msg, len + 1, 0));
		for (int j = 0; j < NCLIENT; j++) {
			sz = sizeof(msg);
			memset(buf, 0, sizeof(buf));
			NUTS_PASS(nng_recv(cs[j], buf, &sz, 0));
			NUTS_TRUE(sz == len + 1);
			NUTS_MATCH(msg, buf);
			memset(buf, 0, sizeof(buf));
		}
	}
	NUTS_CLOSE(s0);
	for (int i = 0; i < NCLIENT; i++) {
		NUTS_CLOSE(cs[i]);
	}
	nng_tls_config_free(c0);
	nng_tls_config_free(c1);
}

void
test_dtls_psk(void)
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

	NUTS_ADDR_ZERO(addr, "dtls");
	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);

	c0 = tls_config_psk(NNG_TLS_MODE_SERVER, "identity", key, sizeof key);
	c1 = tls_config_psk(NNG_TLS_MODE_CLIENT, "identity", key, sizeof key);
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
	NUTS_SLEEP(1000); // make sure connection has time to form!
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
test_dtls_pipe_details(void)
{
	nng_socket      s1;
	nng_socket      s2;
	nng_tls_config *c1, *c2;
	nng_listener    l;
	nng_dialer      d;
	nng_msg        *msg;
	nng_pipe        p;
	const nng_url  *url;

	c1 = tls_server_config_ecdsa();
	c2 = tls_client_config_ecdsa();

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_tls_config_auth_mode(c1, NNG_TLS_AUTH_MODE_REQUIRED));
	NUTS_PASS(nng_tls_config_ca_chain(c1, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_tls_config_ca_chain(c2, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_listener_create(&l, s1, "dtls://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(l, c1));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_MATCH(nng_url_scheme(url), "dtls");
	NUTS_PASS(nng_dialer_create_url(&d, s2, url));
	NUTS_PASS(nng_dialer_set_tls(d, c2));
	NUTS_PASS(nng_dialer_start(d, 0));
	nng_msleep(50);
	NUTS_SEND(s1, "text");
	NUTS_PASS(nng_recvmsg(s2, &msg, 0));
	p = nng_msg_get_pipe(msg);
	NUTS_TRUE(nng_pipe_id(p) >= 0);
#if !defined(NNG_TLS_ENGINE_WOLFSSL) || defined(NNG_WOLFSSL_HAVE_PEER_CERT)
	// TOOD: maybe implement this -- although I think we want to move away
	// from it.
	//
	// char *cn; NUTS_PASS(nng_pipe_get_string(p,
	// NNG_OPT_TLS_PEER_CN, &cn)); NUTS_ASSERT(cn != NULL); NUTS_MATCH(cn,
	// "127.0.0.1"); nng_strfree(cn);

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

	{ "dtls wire loss replay", test_dtls_wire_loss_replay },
	{ "dtls TLS 1.3 only", test_dtls_tls13_only },
	{ "dtls port zero bind", test_dtls_port_zero_bind },
	{ "dtls malformed address", test_dtls_malformed_address },
	{ "dtls no delay option", test_dtls_no_delay_option },
	{ "dtls max peers option", test_dtls_max_peers_option },
	{ "dtls connection tunables", test_dtls_conn_tunables },
	{ "dtls recv max", test_dtls_recv_max },
	{ "dtls recv large", test_dtls_recv_large },
	{ "dtls exchange many", test_dtls_exchange_many },
	{ "dtls reqrep multi", test_dtls_reqrep_multi },
	{ "dtls pub multi", test_dtls_pub_multi },
	{ "dtls pre-shared key", test_dtls_psk },
	{ "dtls bad cert mutual", test_dtls_bad_cert_mutual },
	{ "dtls cert mutual", test_dtls_cert_mutual },
	{ "dtls pipe details", test_dtls_pipe_details },
	{ NULL, NULL },
};
