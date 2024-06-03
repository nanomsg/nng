//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Basic UDP tests.

#include "nng/nng.h"

#ifndef _WIN32
#include <arpa/inet.h> // for endianness functions
#endif

#include "core/nng_impl.h"

#include <nuts.h>

void
test_udp_pair(void)
{
	nng_sockaddr sa1;
	nng_sockaddr sa2;
	nng_udp     *u1;
	nng_udp     *u2;
	uint32_t     loopback;
	nng_aio     *aio1;
	nng_aio     *aio2;
	nng_iov      iov1, iov2;
	char         msg[] = "hello";
	char         rbuf[1024];
	nng_sockaddr to;
	nng_sockaddr from;

	loopback = htonl(0x7f000001); // 127.0.0.1

	sa1.s_in.sa_family = NNG_AF_INET;
	sa1.s_in.sa_addr   = loopback;
	sa1.s_in.sa_port   = 0; // wild card port binding

	sa2.s_in.sa_family = NNG_AF_INET;
	sa2.s_in.sa_addr   = loopback;
	sa2.s_in.sa_port   = 0;

	NUTS_PASS(nng_udp_open(&u1, &sa1));
	NUTS_PASS(nng_udp_open(&u2, &sa2));

	NUTS_PASS(nng_udp_sockname(u1, &sa1));
	NUTS_PASS(nng_udp_sockname(u2, &sa2));

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	to           = sa2;
	iov1.iov_buf = msg;
	iov1.iov_len = strlen(msg) + 1;
	NUTS_PASS(nng_aio_set_iov(aio1, 1, &iov1));
	NUTS_PASS(nng_aio_set_input(aio1, 0, &to));

	iov2.iov_buf = rbuf;
	iov2.iov_len = 1024;
	NUTS_PASS(nng_aio_set_iov(aio2, 1, &iov2));
	NUTS_PASS(nng_aio_set_input(aio2, 0, &from));

	nng_udp_recv(u2, aio2);
	nng_udp_send(u1, aio1);
	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));
	NUTS_ASSERT(nng_aio_count(aio2) == strlen(msg) + 1);
	NUTS_ASSERT(strcmp(rbuf, msg) == 0);
	NUTS_ASSERT(from.s_in.sa_family == sa1.s_in.sa_family);
	NUTS_ASSERT(from.s_in.sa_addr == sa1.s_in.sa_addr);
	NUTS_ASSERT(from.s_in.sa_port == sa1.s_in.sa_port);

	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_udp_close(u1);
	nng_udp_close(u2);
}

void
test_udp_multi_send_recv(void)
{
	nng_sockaddr sa1, sa2, sa3, sa4;
	nng_udp     *u1;
	nng_udp     *u2;
	uint32_t     loopback;
	nng_aio     *aio1, *aio2, *aio3, *aio4;
	nng_iov      iov1, iov2, iov3, iov4;
	char         msg1[] = "hello";
	char         msg2[] = "there";
	char         rbuf1[32];
	char         rbuf2[32];
	nng_sockaddr to;

	loopback = htonl(0x7f000001); // 127.0.0.1

	sa1.s_in.sa_family = NNG_AF_INET;
	sa1.s_in.sa_addr   = loopback;
	sa1.s_in.sa_port   = 0; // wild card port binding

	sa2.s_in.sa_family = NNG_AF_INET;
	sa2.s_in.sa_addr   = loopback;
	sa2.s_in.sa_port   = 0;

	NUTS_PASS(nng_udp_open(&u1, &sa1));
	NUTS_PASS(nng_udp_open(&u2, &sa2));

	NUTS_PASS(nng_udp_sockname(u1, &sa1));
	NUTS_PASS(nng_udp_sockname(u2, &sa2));

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio3, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio4, NULL, NULL));

	to           = sa2;
	iov1.iov_buf = msg1;
	iov1.iov_len = strlen(msg1) + 1;
	NUTS_PASS(nng_aio_set_iov(aio1, 1, &iov1));
	NUTS_PASS(nng_aio_set_input(aio1, 0, &to));

	to           = sa2;
	iov2.iov_buf = msg2;
	iov2.iov_len = strlen(msg2) + 1;
	NUTS_PASS(nng_aio_set_iov(aio2, 1, &iov2));
	NUTS_PASS(nng_aio_set_input(aio2, 0, &to));

	iov3.iov_buf = rbuf1;
	iov3.iov_len = sizeof(rbuf1);
	NUTS_PASS(nng_aio_set_iov(aio3, 1, &iov3));
	NUTS_PASS(nng_aio_set_input(aio3, 0, &sa3));

	iov4.iov_buf = rbuf2;
	iov4.iov_len = sizeof(rbuf2);
	NUTS_PASS(nng_aio_set_iov(aio4, 1, &iov4));
	NUTS_PASS(nng_aio_set_input(aio4, 0, &sa4));

	nng_udp_recv(u2, aio4);
	nng_udp_recv(u2, aio3);
	nng_udp_send(u1, aio2);
	nng_msleep(100); // to keep order clear
	nng_udp_send(u1, aio1);
	nng_aio_wait(aio1);
	nng_aio_wait(aio2);
	nng_aio_wait(aio3);
	nng_aio_wait(aio4);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));
	NUTS_PASS(nng_aio_result(aio3));
	NUTS_PASS(nng_aio_result(aio4));
	NUTS_ASSERT(nng_aio_count(aio3) == strlen(msg1) + 1);
	NUTS_ASSERT(nng_aio_count(aio4) == strlen(msg2) + 1);
	NUTS_ASSERT(strcmp(rbuf1, msg1) == 0);
	NUTS_ASSERT(strcmp(rbuf2, msg2) == 0);

	NUTS_PASS(nng_udp_sockname(u1, &sa2));
	NUTS_ASSERT(sa2.s_in.sa_family == sa3.s_in.sa_family);
	NUTS_ASSERT(sa2.s_in.sa_addr == sa3.s_in.sa_addr);
	NUTS_ASSERT(sa2.s_in.sa_port == sa3.s_in.sa_port);

	NUTS_ASSERT(sa2.s_in.sa_family == sa4.s_in.sa_family);
	NUTS_ASSERT(sa2.s_in.sa_addr == sa4.s_in.sa_addr);
	NUTS_ASSERT(sa2.s_in.sa_port == sa4.s_in.sa_port);

	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_aio_free(aio3);
	nng_aio_free(aio4);
	nng_udp_close(u1);
	nng_udp_close(u2);
}

void
test_udp_send_no_addr(void)
{
	nng_sockaddr sa1;
	nng_udp     *u1;
	uint32_t     loopback;
	nng_aio     *aio1;
	nng_iov      iov1;
	char         msg[] = "hello";

	loopback = htonl(0x7f000001); // 127.0.0.1

	sa1.s_in.sa_family = NNG_AF_INET;
	sa1.s_in.sa_addr   = loopback;
	sa1.s_in.sa_port   = 0; // wild card port binding

	NUTS_PASS(nng_udp_open(&u1, &sa1));
	NUTS_PASS(nng_udp_sockname(u1, &sa1));

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));

	iov1.iov_buf = msg;
	iov1.iov_len = strlen(msg) + 1;
	NUTS_PASS(nng_aio_set_iov(aio1, 1, &iov1));

	nng_udp_send(u1, aio1);
	nng_aio_wait(aio1);

	NUTS_FAIL(nng_aio_result(aio1), NNG_EADDRINVAL);

	nng_aio_free(aio1);
	nng_udp_close(u1);
}

void
test_udp_send_ipc(void)
{
	nng_sockaddr sa1 = { 0 };
	nng_sockaddr sa2 = { 0 };
	nng_udp     *u1;
	uint32_t     loopback;
	nng_aio     *aio1;
	nng_iov      iov1;
	char         msg[] = "hello";
	int          rv;

	loopback = htonl(0x7f000001); // 127.0.0.1

	sa1.s_in.sa_family = NNG_AF_INET;
	sa1.s_in.sa_addr   = loopback;
	sa1.s_in.sa_port   = 0; // wild card port binding

	sa2.s_ipc.sa_family = NNG_AF_IPC;
	strcat(sa2.s_ipc.sa_path, "/tmp/bogus");

	NUTS_PASS(nng_udp_open(&u1, &sa1));
	NUTS_PASS(nng_udp_sockname(u1, &sa1));

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));

	iov1.iov_buf = msg;
	iov1.iov_len = strlen(msg) + 1;
	NUTS_PASS(nng_aio_set_iov(aio1, 1, &iov1));
	NUTS_PASS(nng_aio_set_input(aio1, 0, &sa2));

	nng_udp_send(u1, aio1);
	nng_aio_wait(aio1);

	rv = nng_aio_result(aio1);
	NUTS_ASSERT(rv == NNG_EADDRINVAL || rv == NNG_ENOTSUP);

	nng_aio_free(aio1);
	nng_udp_close(u1);
}

void
test_udp_bogus_bind(void)
{
	nng_udp     *u;
	nng_sockaddr sa = { 0 };
	int          rv;

	sa.s_ipc.sa_family = NNG_AF_IPC;
	strcpy(sa.s_ipc.sa_path, "/tmp/t");
	rv = nng_udp_open(&u, &sa);
	// Some platforms reject IPC addresses altogether (Windows),
	// whereas others just say it's not supported with UDP.
	NUTS_ASSERT((rv == NNG_ENOTSUP) || (rv == NNG_EADDRINVAL));

	// NULL address also bad.
	NUTS_FAIL(nng_udp_open(&u, NULL), NNG_EADDRINVAL);
}

void
test_udp_duplicate_bind(void)
{
	nng_udp     *u1;
	nng_udp     *u2;
	nng_sockaddr sa = { 0 };

	sa.s_in.sa_family = NNG_AF_INET;
	sa.s_in.sa_addr   = htonl(0x7f000001);

	NUTS_PASS(nng_udp_open(&u1, &sa));
	NUTS_PASS(nng_udp_sockname(u1, &sa));
	NUTS_FAIL(nng_udp_open(&u2, &sa), NNG_EADDRINUSE);
	nng_udp_close(u1);
}

void
test_udp_multicast_membership(void)
{
	nng_udp     *u1;
	nng_sockaddr sa = { 0 };
	nng_sockaddr mc = { 0 };

	mc.s_in.sa_family = NNG_AF_INET;
	mc.s_in.sa_addr   = htonl(0xe0000001); // 224.0.0.1 ... all hosts

	sa.s_in.sa_family = NNG_AF_INET;
	sa.s_in.sa_addr   = htonl(0x7f000001);

	NUTS_PASS(nng_udp_open(&u1, &sa));
	NUTS_PASS(nng_udp_sockname(u1, &sa));
	NUTS_PASS(nng_udp_multicast_membership(u1, &mc, true));
	NUTS_PASS(nng_udp_multicast_membership(u1, &mc, false));
	nng_udp_close(u1);
}

void
test_udp_multicast_send_recv(void)
{
	nng_udp     *u1;
	nng_udp     *u2;
	nng_sockaddr sa1 = { 0 };
	nng_sockaddr sa2 = { 0 };
	nng_sockaddr ra2 = { 0 };
	nng_sockaddr mc  = { 0 };
	char        *msg = "multi";
	nng_iov      iov1;
	nng_iov      iov2;
	nng_aio     *aio1;
	nng_aio     *aio2;
	char         rbuf[32];

	mc.s_in.sa_family = NNG_AF_INET;
	mc.s_in.sa_addr   = htonl(0xe0000001); // 224.0.0.1 ... all hosts

	sa1.s_in.sa_family = NNG_AF_INET;
	sa1.s_in.sa_addr   = htonl(0x7f000001);

	sa2.s_in.sa_family = NNG_AF_INET;
	sa2.s_in.sa_addr   = htonl(0x7f000001);

	NUTS_PASS(nng_udp_open(&u1, &sa1));
	NUTS_PASS(nng_udp_sockname(u1, &sa1));
	NUTS_PASS(nng_udp_open(&u2, &sa2));
	NUTS_PASS(nng_udp_sockname(u2, &sa2));
	NUTS_PASS(nng_udp_multicast_membership(u1, &mc, true));
	NUTS_PASS(nng_udp_multicast_membership(u2, &mc, true));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	iov1.iov_buf = msg;
	iov1.iov_len = strlen(msg) + 1;
	NUTS_PASS(nng_aio_set_iov(aio1, 1, &iov1));
	NUTS_PASS(nng_aio_set_input(aio1, 0, &sa2));

	iov2.iov_buf = rbuf;
	iov2.iov_len = sizeof(rbuf);
	NUTS_PASS(nng_aio_set_iov(aio2, 1, &iov2));
	NUTS_PASS(nng_aio_set_input(aio2, 0, &ra2));

	nng_udp_recv(u2, aio2);
	nng_udp_send(u1, aio1);
	nng_aio_wait(aio1);
	nng_aio_wait(aio2);
	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_MATCH(msg, rbuf);
	nng_udp_close(u1);
	nng_udp_close(u2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
}

#ifdef NNG_ENABLE_IPV6
void
test_udp_send_v6_from_v4(void)
{
	int           rv;
	nng_udp      *u1;
	nng_sockaddr  sa = { 0 };
	nng_aio      *aio1;
	nng_iov       iov1;
	char         *msg        = "nope";
	const uint8_t google[16] = { 0x26, 0x07, 0xf8, 0xb0, 0x40, 0x07, 0x40,
		0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e };

	memset(&sa, 0, sizeof(sa));
	sa.s_in.sa_family = NNG_AF_INET;
	sa.s_in.sa_addr   = htonl(0x7f000001);

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_udp_open(&u1, &sa));

	sa.s_in6.sa_family = NNG_AF_INET6;
	memcpy(sa.s_in6.sa_addr, google, 16);
	sa.s_in6.sa_port = htons(80);

	iov1.iov_len = strlen(msg) + 1;
	iov1.iov_buf = msg;
	nng_aio_set_iov(aio1, 1, &iov1);
	nng_aio_set_input(aio1, 0, &sa);

	nng_udp_send(u1, aio1);
	nng_aio_wait(aio1);
	rv = nng_aio_result(aio1);
	NUTS_ASSERT((rv == NNG_EADDRINVAL) || (rv == NNG_ENOTSUP) ||
	    (rv == NNG_EUNREACHABLE));

	nng_aio_free(aio1);
	nng_udp_close(u1);
}
#endif // NNG_ENABLE_IPV6

NUTS_TESTS = {
	{ "udp pair", test_udp_pair },
	{ "udp send recv multi", test_udp_multi_send_recv },
	{ "udp send no address", test_udp_send_no_addr },
	{ "udp send ipc address", test_udp_send_ipc },
	{ "udp bogus bind", test_udp_bogus_bind },
	{ "udp duplicate bind", test_udp_duplicate_bind },
	{ "udp multicast membership", test_udp_multicast_membership },
	{ "udp multicast send recv", test_udp_multicast_send_recv },
#ifdef NNG_ENABLE_IPV6
	{ "udp send v6 from v4", test_udp_send_v6_from_v4 },
#endif
	{ NULL, NULL },
};
