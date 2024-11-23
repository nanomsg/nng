//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
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
#include <nuts.h>

// TCP tests.

static void
test_tcp_wild_card_connect_fail(void)
{
	nng_socket s;
	char       addr[NNG_MAXADDRLEN];

	NUTS_OPEN(s);
	(void) snprintf(addr, sizeof(addr), "tcp://*:%u", nuts_next_port());
	NUTS_FAIL(nng_dial(s, addr, NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s);
}

void
test_tcp_wild_card_bind(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_listen(s1, "tcp4://*:8080", NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s1);
}

void
test_tcp_port_zero_bind(void)
{
	nng_socket     s1;
	nng_socket     s2;
	nng_sockaddr   sa;
	nng_listener   l;
	const nng_url *u;
	char           addr[NNG_MAXADDRSTRLEN];

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_listen(s1, "tcp://127.0.0.1:0", &l, 0));
	NUTS_PASS(nng_listener_get_url(l, &u));
	NUTS_MATCH(nng_url_scheme(u), "tcp");
	nng_url_sprintf(addr, sizeof(addr), u);
	NUTS_TRUE(memcmp(addr, "tcp://", 6) == 0);
	NUTS_PASS(nng_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	NUTS_TRUE(sa.s_in.sa_family == NNG_AF_INET);
	NUTS_TRUE(sa.s_in.sa_port != 0);
	NUTS_TRUE(sa.s_in.sa_addr = nuts_be32(0x7f000001));
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
}

void
test_tcp_non_local_address(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_dial(s1, "tcp://8.8.8.8;127.0.0.1:80", NULL, 0),
	    NNG_EADDRINVAL);
	NUTS_CLOSE(s1);
}

void
test_tcp_malformed_address(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_dial(s1, "tcp://127.0.0.1", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(nng_dial(s1, "tcp://127.0.0.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(nng_dial(s1, "tcp://127.0.x.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_listen(s1, "tcp://127.0.0.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_listen(s1, "tcp://127.0.x.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s1);
}

void
test_tcp_no_delay_option(void)
{
	nng_socket   s;
	nng_dialer   d;
	nng_listener l;
	bool         v;
	int          x;
	char        *addr;

	NUTS_ADDR(addr, "tcp");

	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));
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
	NUTS_PASS(nng_listener_get_bool(l, NNG_OPT_TCP_NODELAY, &v));
	NUTS_TRUE(v == true);
	x = 0;
	NUTS_FAIL(
	    nng_listener_set_int(l, NNG_OPT_TCP_NODELAY, x), NNG_EBADTYPE);

	NUTS_PASS(nng_dialer_close(d));
	NUTS_PASS(nng_listener_close(l));

	NUTS_CLOSE(s);
}

static bool
has_v6(void)
{
	nng_sockaddr sa;
	nng_udp     *u;
	int          rv;

	sa.s_in6.sa_family = NNG_AF_INET6;
	sa.s_in6.sa_port   = 0;
	memset(sa.s_in6.sa_addr, 0, 16);
	sa.s_in6.sa_addr[15] = 1;

	rv = nng_udp_open(&u, &sa);
	if (rv == 0) {
		nng_udp_close(u);
	}
	return (rv == 0 ? 1 : 0);
}

void
test_tcp_ipv6(void)
{
	if (!has_v6()) {
		NUTS_SKIP("No IPv6 support");
		return;
	}
	nng_socket s;
	NUTS_OPEN(s);
	// this should have a [::1] bracket
	NUTS_FAIL(nng_dial(s, "tcp://::1", NULL, 0), NNG_EINVAL);
	NUTS_FAIL(nng_dial(s, "tcp://::1:5055", NULL, 0), NNG_EINVAL);
	// this requires a port, but otherwise its ok, so address is invalid
	NUTS_FAIL(nng_dial(s, "tcp://[::1]", NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s);
}

void
test_tcp_keep_alive_option(void)
{
	nng_socket   s;
	nng_dialer   d;
	nng_listener l;
	bool         v;
	int          x;
	char        *addr;
	nng_url     *url;

	NUTS_ADDR(addr, "tcp");
	// next cases are just to exercise nng_dialer_create_url
	NUTS_PASS(nng_url_parse(&url, addr));
	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create_url(&d, s, url));
	nng_url_free(url);
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
	NUTS_PASS(nng_listener_get_bool(l, NNG_OPT_TCP_KEEPALIVE, &v));
	NUTS_TRUE(v == false);
	x = 1;
	NUTS_FAIL(
	    nng_listener_set_int(l, NNG_OPT_TCP_KEEPALIVE, x), NNG_EBADTYPE);

	NUTS_PASS(nng_dialer_close(d));
	NUTS_PASS(nng_listener_close(l));

	NUTS_CLOSE(s);
}

void
test_tcp_recv_max(void)
{
	char         msg[256];
	char         buf[256];
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l;
	size_t       sz;
	char        *addr;

	NUTS_ADDR(addr, "tcp");

	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 200));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_socket_get_size(s0, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 200);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 100));
	NUTS_PASS(nng_listener_start(l, 0));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_dial(s1, addr, NULL, 0));
	NUTS_PASS(nng_send(s1, msg, 95, 0));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_recv(s0, buf, &sz, 0));
	NUTS_TRUE(sz == 95);
	NUTS_PASS(nng_send(s1, msg, 150, 0));
	NUTS_FAIL(nng_recv(s0, buf, &sz, 0), NNG_ETIMEDOUT);
	NUTS_PASS(nng_close(s0));
	NUTS_CLOSE(s1);
}

NUTS_TESTS = {

	{ "tcp wild card connect fail", test_tcp_wild_card_connect_fail },
	{ "tcp wild card bind", test_tcp_wild_card_bind },
	{ "tcp port zero bind", test_tcp_port_zero_bind },
	{ "tcp non-local address", test_tcp_non_local_address },
	{ "tcp malformed address", test_tcp_malformed_address },
	{ "tcp no delay option", test_tcp_no_delay_option },
	{ "tcp keep alive option", test_tcp_keep_alive_option },
	{ "tcp recv max", test_tcp_recv_max },
	{ "tcp ipv6", test_tcp_ipv6 },
	{ NULL, NULL },
};
