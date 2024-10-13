//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
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
test_udp_wild_card_connect_fail(void)
{
	nng_socket s;
	char       addr[NNG_MAXADDRLEN];

	NUTS_OPEN(s);
	(void) snprintf(addr, sizeof(addr), "udp://*:%u", nuts_next_port());
	NUTS_FAIL(nng_dial(s, addr, NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s);
}

void
test_udp_wild_card_bind(void)
{
	nng_socket s1;
	nng_socket s2;
	char       addr[NNG_MAXADDRLEN];
	uint16_t   port;

	port = nuts_next_port();

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	(void) snprintf(addr, sizeof(addr), "udp4://*:%u", port);
	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	nng_msleep(500);
	(void) snprintf(addr, sizeof(addr), "udp://127.0.0.1:%u", port);
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
}

void
test_udp_local_address_connect(void)
{

	nng_socket s1;
	nng_socket s2;
	char       addr[NNG_MAXADDRLEN];
	uint16_t   port;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	port = nuts_next_port();
	(void) snprintf(addr, sizeof(addr), "udp://127.0.0.1:%u", port);
	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	(void) snprintf(addr, sizeof(addr), "udp://127.0.0.1:%u", port);
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
}

void
test_udp_port_zero_bind(void)
{
	nng_socket   s1;
	nng_socket   s2;
	nng_sockaddr sa;
	nng_listener l;
	char        *addr;
	int          port;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_listen(s1, "udp://127.0.0.1:0", &l, 0));
	nng_msleep(100);
	NUTS_PASS(nng_listener_get_string(l, NNG_OPT_URL, &addr));
	NUTS_TRUE(memcmp(addr, "udp://", 6) == 0);
	NUTS_PASS(nng_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	NUTS_TRUE(sa.s_in.sa_family == NNG_AF_INET);
	NUTS_TRUE(sa.s_in.sa_port != 0);
	NUTS_TRUE(sa.s_in.sa_addr == nuts_be32(0x7f000001));
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));
	NUTS_PASS(nng_listener_get_int(l, NNG_OPT_TCP_BOUND_PORT, &port));
	NUTS_TRUE(port == nuts_be16(sa.s_in.sa_port));
	nng_strfree(addr);

	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
}

void
test_udp_non_local_address(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_listen(s1, "udp://8.8.8.8", NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s1);
}

void
test_udp_malformed_address(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_dial(s1, "udp://127.0.0.1", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(nng_dial(s1, "udp://127.0.0.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(nng_dial(s1, "udp://127.0.x.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_listen(s1, "udp://127.0.0.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(
	    nng_listen(s1, "udp://127.0.x.1.32", NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s1);
}

void
test_udp_recv_max(void)
{
	char         msg[256];
	char         buf[256];
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l;
	size_t       sz;
	char        *addr;

	NUTS_ADDR(addr, "udp");

	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 200));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_socket_get_size(s0, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 200);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 100));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 100);
	NUTS_PASS(nng_listener_start(l, 0));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_dial(s1, addr, NULL, 0));
	nng_msleep(1000);
	NUTS_PASS(nng_send(s1, msg, 95, 0));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_recv(s0, buf, &sz, 0));
	NUTS_TRUE(sz == 95);
	NUTS_PASS(nng_send(s1, msg, 150, 0));
	NUTS_FAIL(nng_recv(s0, buf, &sz, 0), NNG_ETIMEDOUT);
	NUTS_PASS(nng_close(s0));
	NUTS_CLOSE(s1);
}

void
test_udp_recv_copy(void)
{
	char         msg[256];
	char         buf[256];
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l;
	size_t       sz;
	char        *addr;

	NUTS_ADDR(addr, "udp");

	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_UDP_COPY_MAX, 100));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_UDP_COPY_MAX, &sz));
	NUTS_TRUE(sz == 100);
	NUTS_PASS(nng_listener_start(l, 0));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_dial(s1, addr, NULL, 0));
	nng_msleep(100);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_send(s1, msg, 95, 0));
	NUTS_PASS(nng_recv(s0, buf, &sz, 0));
	NUTS_TRUE(sz == 95);
	NUTS_PASS(nng_send(s1, msg, 150, 0));
	NUTS_PASS(nng_recv(s0, buf, &sz, 0));
	NUTS_TRUE(sz == 150);
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
}

void
test_udp_multi_send_recv(void)
{
	char         msg[256];
	char         buf[256];
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l;
	nng_dialer   d;
	size_t       sz;
	char        *addr;

	NUTS_ADDR(addr, "udp");

	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_UDP_COPY_MAX, 100));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_UDP_COPY_MAX, &sz));
	NUTS_TRUE(sz == 100);
	NUTS_PASS(nng_listener_start(l, 0));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_dialer_create(&d, s1, addr));
	NUTS_PASS(nng_dialer_set_size(d, NNG_OPT_UDP_COPY_MAX, 100));
	NUTS_PASS(nng_dialer_get_size(d, NNG_OPT_UDP_COPY_MAX, &sz));
	NUTS_PASS(nng_dialer_start(d, 0));
	nng_msleep(100);

	for (int i = 0; i < 1000; i++) {
		NUTS_PASS(nng_send(s1, msg, 95, 0));
		NUTS_PASS(nng_recv(s0, buf, &sz, 0));
		NUTS_TRUE(sz == 95);
		NUTS_PASS(nng_send(s0, msg, 95, 0));
		NUTS_PASS(nng_recv(s1, buf, &sz, 0));
		NUTS_TRUE(sz == 95);
	}
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
}

void
test_udp_multi_small_burst(void)
{
	char         msg[256];
	char         buf[256];
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l;
	nng_dialer   d;
	size_t       sz;
	char        *addr;

	NUTS_ADDR(addr, "udp");

	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 10));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_UDP_COPY_MAX, 100));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_UDP_COPY_MAX, &sz));
	NUTS_TRUE(sz == 100);
	NUTS_PASS(nng_listener_start(l, 0));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 10));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_dialer_create(&d, s1, addr));
	NUTS_PASS(nng_dialer_set_size(d, NNG_OPT_UDP_COPY_MAX, 100));
	NUTS_PASS(nng_dialer_get_size(d, NNG_OPT_UDP_COPY_MAX, &sz));
	NUTS_PASS(nng_dialer_start(d, 0));
	nng_msleep(100);

	float actual = 0;
	float expect = 0;
	int   burst  = 4;
	int   count  = 20;

#ifdef NNG_PLATFORM_WINDOWS
	// Windows seems to drop a lot - maybe because of virtualization
	burst = 2;
	count = 10;
#endif

	// Experimentally at least on Darwin, we see some packet losses
	// even for loopback.  Loss rates appear depressingly high.
	for (int i = 0; i < count; i++) {
		for (int j = 0; j < burst; j++) {
			NUTS_PASS(nng_send(s1, msg, 95, 0));
			expect++;
		}
		for (int j = 0; j < burst; j++) {
			if (nng_recv(s0, buf, &sz, 0) == 0) {
				NUTS_TRUE(sz == 95);
				actual++;
			}
		}
		NUTS_PASS(nng_send(s0, msg, 95, 0));
		NUTS_PASS(nng_recv(s1, buf, &sz, 0));
		NUTS_TRUE(sz == 95);
	}
	NUTS_TRUE(actual <= expect);
#if !defined(NNG_SANITIZER) && !defined(NNG_COVERAGE)
	// Under sanitizer runs we lose a lot, maybe even majority, of packets
	NUTS_TRUE(
	    actual / expect > 0.50); // maximum reasonable packet loss of 20%
	NUTS_MSG("Packet loss: %.02f (got %.f of %.f)", 1.0 - actual / expect,
	    actual, expect);
#endif
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
}

NUTS_TESTS = {

	{ "udp wild card connect fail", test_udp_wild_card_connect_fail },
	{ "udp wild card bind", test_udp_wild_card_bind },
	{ "udp port zero bind", test_udp_port_zero_bind },
	{ "udp local address connect", test_udp_local_address_connect },
	{ "udp non-local address", test_udp_non_local_address },
	{ "udp malformed address", test_udp_malformed_address },
	{ "udp recv max", test_udp_recv_max },
	{ "udp recv copy", test_udp_recv_copy },
	{ "udp multi send recv", test_udp_multi_send_recv },
	{ "udp multi small burst", test_udp_multi_small_burst },
	{ NULL, NULL },
};
