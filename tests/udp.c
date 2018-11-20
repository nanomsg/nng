//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Basic UDP tests.

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "convey.h"
#include "core/nng_impl.h"
#include "trantest.h"

TestMain("UDP support", {
	nni_init();
	atexit(nng_fini);

	trantest_port = trantest_port ? trantest_port : 5555;

	Convey("We can start a pair of UDP ports", {
		nng_sockaddr  sa1;
		nng_sockaddr  sa2;
		uint16_t      p1;
		uint16_t      p2;
		nni_plat_udp *u1;
		nni_plat_udp *u2;
		uint32_t      loopback;

		loopback = htonl(0x7f000001); // 127.0.0.1

		p1 = trantest_port++;
		p2 = trantest_port++;

		sa1.s_in.sa_family = NNG_AF_INET;
		sa1.s_in.sa_addr   = loopback;
		sa1.s_in.sa_port   = htons(p1);

		sa2.s_in.sa_family = NNG_AF_INET;
		sa2.s_in.sa_addr   = loopback;
		sa2.s_in.sa_port   = htons(p2);

		So(nni_plat_udp_open(&u1, &sa1) == 0);
		So(nni_plat_udp_open(&u2, &sa2) == 0);
		Reset({
			nni_plat_udp_close(u1);
			nni_plat_udp_close(u2);
		});

		Convey("They can talk to each other", {
			char         msg[] = "hello";
			char         rbuf[1024];
			nng_sockaddr to;
			nng_sockaddr from;
			nng_aio *    aio1;
			nng_aio *    aio2;
			nng_iov      iov1;
			nng_iov      iov2;

			So(nng_aio_alloc(&aio1, NULL, NULL) == 0);
			So(nng_aio_alloc(&aio2, NULL, NULL) == 0);

			to           = sa2;
			iov1.iov_buf = msg;
			iov1.iov_len = strlen(msg) + 1;
			So(nng_aio_set_iov(aio1, 1, &iov1) == 0);
			nng_aio_set_input(aio1, 0, &to);

			iov2.iov_buf = rbuf;
			iov2.iov_len = 1024;
			So(nng_aio_set_iov(aio2, 1, &iov2) == 0);
			nng_aio_set_input(aio2, 0, &from);

			nni_plat_udp_recv(u2, aio2);
			nni_plat_udp_send(u1, aio1);
			nng_aio_wait(aio1);
			nng_aio_wait(aio2);

			So(nng_aio_result(aio1) == 0);
			So(nng_aio_result(aio2) == 0);

			So(nng_aio_count(aio2) == strlen(msg) + 1);
			So(strcmp(msg, rbuf) == 0);

			So(from.s_in.sa_family == sa1.s_in.sa_family);
			So(from.s_in.sa_port == sa1.s_in.sa_port);
			So(from.s_in.sa_addr == sa1.s_in.sa_addr);

			// Set up some calls that will ever complete, so
			// we test cancellation, etc.
			nni_plat_udp_recv(u2, aio2);
			nni_plat_udp_send(u2, aio1);

			nng_aio_free(aio1);
			nng_aio_free(aio2);
		});

		Convey("Sending without an address fails", {
			nng_aio *aio1;
			char *   msg = "nope";
			nng_iov  iov;

			So(nng_aio_alloc(&aio1, NULL, NULL) == 0);

			iov.iov_buf = msg;
			iov.iov_len = strlen(msg) + 1;
			So(nng_aio_set_iov(aio1, 1, &iov) == 0);

			nni_plat_udp_send(u1, aio1);
			nng_aio_wait(aio1);
			So(nng_aio_result(aio1) == NNG_EADDRINVAL);
			nng_aio_free(aio1);
		});

		Convey("Multiple operations work", {
			char         msg1[] = "hello";
			char         msg2[] = "there";
			char         rbuf1[32];
			char         rbuf2[32];
			nng_sockaddr to1;
			nng_sockaddr to2;
			nng_sockaddr from1;
			nng_sockaddr from2;
			nng_aio *    aio1;
			nng_aio *    aio2;
			nng_aio *    aio3;
			nng_aio *    aio4;
			nng_iov      iov1;
			nng_iov      iov2;
			nng_iov      iov3;
			nng_iov      iov4;

			So(nng_aio_alloc(&aio1, NULL, NULL) == 0);
			So(nng_aio_alloc(&aio2, NULL, NULL) == 0);
			So(nng_aio_alloc(&aio3, NULL, NULL) == 0);
			So(nng_aio_alloc(&aio4, NULL, NULL) == 0);

			to1          = sa2;
			iov1.iov_buf = msg1;
			iov1.iov_len = strlen(msg1) + 1;
			So(nng_aio_set_iov(aio1, 1, &iov1) == 0);
			nng_aio_set_input(aio1, 0, &to1);

			to2          = sa2;
			iov2.iov_buf = msg2;
			iov2.iov_len = strlen(msg2) + 1;
			So(nng_aio_set_iov(aio2, 1, &iov2) == 0);
			nng_aio_set_input(aio2, 0, &to2);

			iov3.iov_buf = rbuf1;
			iov3.iov_len = 1024;
			So(nng_aio_set_iov(aio3, 1, &iov3) == 0);
			nng_aio_set_input(aio3, 0, &from1);

			iov4.iov_buf = rbuf2;
			iov4.iov_len = 1024;
			So(nng_aio_set_iov(aio4, 1, &iov4) == 0);
			nng_aio_set_input(aio4, 0, &from2);

			nni_plat_udp_recv(u2, aio4);
			nni_plat_udp_recv(u2, aio3);
			nni_plat_udp_send(u1, aio2);
			// This delay here is required to test for a race
			// condition that does not occur if it is absent.
			nng_msleep(1);
			nni_plat_udp_send(u1, aio1);

			nng_aio_wait(aio2);
			nng_aio_wait(aio1);
			nng_aio_wait(aio3);
			nng_aio_wait(aio4);

			So(nng_aio_result(aio1) == 0);
			So(nng_aio_result(aio2) == 0);
			So(nng_aio_result(aio3) == 0);
			So(nng_aio_result(aio4) == 0);

			So(from1.s_in.sa_family == sa1.s_in.sa_family);
			So(from1.s_in.sa_port == sa1.s_in.sa_port);
			So(from1.s_in.sa_addr == sa1.s_in.sa_addr);

			nng_aio_free(aio1);
			nng_aio_free(aio2);
			nng_aio_free(aio3);
			nng_aio_free(aio4);
		});

		Convey("Sending without an address fails", {
			nng_aio *aio1;
			char *   msg = "nope";
			nng_iov  iov;

			So(nng_aio_alloc(&aio1, NULL, NULL) == 0);
			iov.iov_buf = msg;
			iov.iov_len = strlen(msg) + 1;
			So(nng_aio_set_iov(aio1, 1, &iov) == 0);

			nni_plat_udp_send(u1, aio1);
			nng_aio_wait(aio1);
			So(nng_aio_result(aio1) == NNG_EADDRINVAL);
			nng_aio_free(aio1);
		});

		Convey("Sending to an IPv6 address on IPv4 fails", {
			nng_aio *    aio1;
			char *       msg = "nope";
			nng_sockaddr sa;
			int          rv;
			nng_iov      iov;

			sa.s_in6.sa_family = NNG_AF_INET6;
			// address is for google.com
			inet_ntop(AF_INET6, "2607:f8b0:4007:804::200e",
			    (void *) sa.s_in6.sa_addr, 16);
			sa.s_in6.sa_port = 80;
			So(nng_aio_alloc(&aio1, NULL, NULL) == 0);
			iov.iov_buf = msg;
			iov.iov_len = strlen(msg) + 1;
			So(nng_aio_set_iov(aio1, 1, &iov) == 0);
			nng_aio_set_input(aio1, 0, &sa);

			nni_plat_udp_send(u1, aio1);
			nng_aio_wait(aio1);
			So((rv = nng_aio_result(aio1)) != 0);
			So(rv == NNG_EADDRINVAL || rv == NNG_ENOTSUP ||
			    rv == NNG_EUNREACHABLE);
			nng_aio_free(aio1);
		});

		Convey("Sending to an IPC address fails", {
			nng_aio *    aio1;
			char *       msg = "nope";
			nng_sockaddr sa;
			int          rv;
			nng_iov      iov;

			sa.s_in6.sa_family = NNG_AF_INET6;
			// address is for google.com
			inet_ntop(AF_INET6, "2607:f8b0:4007:804::200e",
			    (void *) sa.s_in6.sa_addr, 16);
			sa.s_in6.sa_port = 80;
			So(nng_aio_alloc(&aio1, NULL, NULL) == 0);
			iov.iov_buf = msg;
			iov.iov_len = strlen(msg) + 1;
			So(nng_aio_set_iov(aio1, 1, &iov) == 0);
			nng_aio_set_input(aio1, 0, &sa);

			nni_plat_udp_send(u1, aio1);
			nng_aio_wait(aio1);
			So((rv = nng_aio_result(aio1)) != 0);
			So(rv == NNG_EADDRINVAL || rv == NNG_ENOTSUP ||
			    rv == NNG_EUNREACHABLE);
			nng_aio_free(aio1);
		});
	});

	Convey("Cannot open using bogus sockaddr", {
		nni_plat_udp *u;
		nng_sockaddr  sa;
		int           rv;

		sa.s_ipc.sa_family = NNG_AF_IPC;
		strcpy(sa.s_ipc.sa_path, "/tmp/t");
		So((rv = nni_plat_udp_open(&u, &sa)) != 0);
		// Some platforms reject IPC addresses altogether (Windows),
		// whereas others just say it's not supported with UDP.
		So((rv == NNG_ENOTSUP) || (rv == NNG_EADDRINVAL));

		// NULL address also bad.
		So((rv = nni_plat_udp_open(&u, NULL)) == NNG_EADDRINVAL);
	});

	Convey("Duplicate binds fail", {
		nni_plat_udp *u1;
		nni_plat_udp *u2;
		nng_sockaddr  sa;
		uint16_t      p1;

		p1                = trantest_port++;
		sa.s_in.sa_family = NNG_AF_INET;
		sa.s_in.sa_port   = htons(p1);
		sa.s_in.sa_addr   = htonl(0x7f000001);
		So(nni_plat_udp_open(&u1, &sa) == 0);
		So(nni_plat_udp_open(&u2, &sa) == NNG_EADDRINUSE);
		nni_plat_udp_close(u1);
	});
})
