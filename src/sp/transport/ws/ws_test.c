//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Cody Piersall <cody.piersall@gmail.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

static void
test_ws_url_path_filters(void)
{
	nng_socket s1;
	nng_socket s2;
	char       addr[NNG_MAXADDRLEN];

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	nuts_scratch_addr("ws", sizeof(addr), addr);
	NUTS_PASS(nng_listen(s1, addr, NULL, 0));

	// Now try we just remove the last character for now.
	// This will make the path different.
	addr[strlen(addr) - 1] = '\0';
	NUTS_FAIL(nng_dial(s2, addr, NULL, 0), NNG_ECONNREFUSED);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

static void
test_wild_card_port(void)
{
	nng_socket s1;
	nng_socket s2;
	nng_socket s3;
	nng_socket s4;
	nng_socket s5;
	nng_socket s6;

	nng_listener l1;
	nng_listener l2;
	nng_listener l3;
	int          port1;
	int          port2;
	int          port3;
	char         ws_url[128];
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_OPEN(s3);
	NUTS_OPEN(s4);
	NUTS_OPEN(s5);
	NUTS_OPEN(s6);
	NUTS_PASS(nng_listen(s1, "ws://127.0.0.1:0/one", &l1, 0));
	NUTS_PASS(nng_listener_get_int(l1, NNG_OPT_TCP_BOUND_PORT, &port1));
	NUTS_TRUE(port1 != 0);
	snprintf(ws_url, sizeof(ws_url), "ws4://127.0.0.1:%d/two", port1);
	NUTS_PASS(nng_listen(s2, ws_url, &l2, 0));
	NUTS_PASS(nng_listener_get_int(l2, NNG_OPT_TCP_BOUND_PORT, &port2));
	NUTS_TRUE(port1 != 0);
	NUTS_TRUE(port1 == port2);
	// Now try a different wild card port.
	NUTS_PASS(nng_listen(s3, "ws4://127.0.0.1:0/three", &l3, 0));
	NUTS_PASS(nng_listener_get_int(l3, NNG_OPT_TCP_BOUND_PORT, &port3));
	NUTS_TRUE(port3 != 0);
	NUTS_TRUE(port3 != port1);

	// Let's make sure can dial to each.
	snprintf(ws_url, sizeof(ws_url), "ws://127.0.0.1:%d/one", port1);
	NUTS_PASS(nng_dial(s4, ws_url, NULL, 0));
	snprintf(ws_url, sizeof(ws_url), "ws://127.0.0.1:%d/two", port2);
	NUTS_PASS(nng_dial(s6, ws_url, NULL, 0));
	snprintf(ws_url, sizeof(ws_url), "ws://127.0.0.1:%d/three", port3);
	NUTS_PASS(nng_dial(s6, ws_url, NULL, 0));

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s3);
	NUTS_CLOSE(s4);
	NUTS_CLOSE(s5);
	NUTS_CLOSE(s6);
}

static void
test_wild_card_host(void)
{
	nng_socket s1;
	nng_socket s2;
	char       addr[NNG_MAXADDRLEN];
	uint16_t   port;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	port = nuts_next_port();

	// we use ws4 to ensure 127.0.0.1 binding
	snprintf(addr, sizeof(addr), "ws4://*:%u/test", port);
	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	nng_msleep(100);

	snprintf(addr, sizeof(addr), "ws://127.0.0.1:%u/test", port);
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));

	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
}

static void
test_empty_host(void)
{
	nng_socket s1;
	nng_socket s2;
	char       addr[NNG_MAXADDRLEN];
	uint16_t   port;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	port = nuts_next_port();

	// we use ws4 to ensure 127.0.0.1 binding
	snprintf(addr, sizeof(addr), "ws4://:%u/test", port);
	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	nng_msleep(100);

	snprintf(addr, sizeof(addr), "ws://127.0.0.1:%u/test", port);
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));

	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
}

void
test_ws_recv_max(void)
{
	char         msg[256];
	char         buf[256];
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l;
	size_t       sz;
	char        *addr;

	memset(msg, 0, sizeof(msg)); // required to silence valgrind

	NUTS_ADDR(addr, "ws");
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
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
}

TEST_LIST = {
	{ "ws url path filters", test_ws_url_path_filters },
	{ "ws wild card port", test_wild_card_port },
	{ "ws wild card host", test_wild_card_host },
	{ "ws empty host", test_empty_host },
	{ "ws recv max", test_ws_recv_max },
	{ NULL, NULL },
};
