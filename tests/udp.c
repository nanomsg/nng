//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "trantest.h"

#ifndef _WIN32
#include <arpa/inet.h>
#endif

// Basic UDP tests.
#include "core/nng_impl.h"

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

		sa1.s_un.s_in.sa_family = NNG_AF_INET;
		sa1.s_un.s_in.sa_addr   = loopback;
		sa1.s_un.s_in.sa_port   = htons(p1);

		sa2.s_un.s_in.sa_family = NNG_AF_INET;
		sa2.s_un.s_in.sa_addr   = loopback;
		sa2.s_un.s_in.sa_port   = htons(p2);

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
			nni_aio *    aio1;
			nni_aio *    aio2;

			nni_aio_init(&aio1, NULL, NULL);
			nni_aio_init(&aio2, NULL, NULL);

			to                     = sa2;
			aio1->a_niov           = 1;
			aio1->a_iov[0].iov_buf = (void *) msg;
			aio1->a_iov[0].iov_len = strlen(msg) + 1;
			aio1->a_addr           = &to;

			aio2->a_niov           = 1;
			aio2->a_iov[0].iov_buf = (void *) rbuf;
			aio2->a_iov[0].iov_len = 1024;
			aio2->a_addr           = &from;

			nni_plat_udp_recv(u2, aio2);
			nni_plat_udp_send(u1, aio1);
			nni_aio_wait(aio1);
			nni_aio_wait(aio2);

			So(nni_aio_result(aio1) == 0);
			So(nni_aio_result(aio2) == 0);

			So(nni_aio_count(aio2) == strlen(msg) + 1);
			So(strcmp(msg, rbuf) == 0);

			So(from.s_un.s_in.sa_family ==
			    sa1.s_un.s_in.sa_family);
			So(from.s_un.s_in.sa_port == sa1.s_un.s_in.sa_port);
			So(from.s_un.s_in.sa_addr == sa1.s_un.s_in.sa_addr);

			// Set up some calls that will ever complete, so
			// we test cancellation, etc.
			nni_plat_udp_recv(u2, aio2);
			nni_plat_udp_send(u2, aio1);

			nni_aio_fini(aio1);
			nni_aio_fini(aio2);
		});

		Convey("Sending without an address fails", {
			nni_aio *aio1;
			char *   msg = "nope";

			nni_aio_init(&aio1, NULL, NULL);
			aio1->a_niov           = 1;
			aio1->a_iov[0].iov_buf = (void *) msg;
			aio1->a_iov[0].iov_len = strlen(msg) + 1;

			nni_plat_udp_send(u1, aio1);
			nni_aio_wait(aio1);
			So(nni_aio_result(aio1) == NNG_EADDRINVAL);
			nni_aio_fini(aio1);
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
			nni_aio *    aio1;
			nni_aio *    aio2;
			nni_aio *    aio3;
			nni_aio *    aio4;

			nni_aio_init(&aio1, NULL, NULL);
			nni_aio_init(&aio2, NULL, NULL);
			nni_aio_init(&aio3, NULL, NULL);
			nni_aio_init(&aio4, NULL, NULL);

			to1                    = sa2;
			aio1->a_niov           = 1;
			aio1->a_iov[0].iov_buf = (void *) msg1;
			aio1->a_iov[0].iov_len = strlen(msg1) + 1;
			aio1->a_addr           = &to1;

			to2                    = sa2;
			aio2->a_niov           = 1;
			aio2->a_iov[0].iov_buf = (void *) msg2;
			aio2->a_iov[0].iov_len = strlen(msg2) + 1;
			aio2->a_addr           = &to2;

			aio3->a_niov           = 1;
			aio3->a_iov[0].iov_buf = (void *) rbuf1;
			aio3->a_iov[0].iov_len = 1024;
			aio3->a_addr           = &from1;

			aio4->a_niov           = 1;
			aio4->a_iov[0].iov_buf = (void *) rbuf2;
			aio4->a_iov[0].iov_len = 1024;
			aio4->a_addr           = &from2;

			nni_plat_udp_recv(u2, aio4);
			nni_plat_udp_recv(u2, aio3);
			nni_plat_udp_send(u1, aio2);
			// This delay here is required to test for a race
			// condition that does not occur if it is absent.
			nng_msleep(1);
			nni_plat_udp_send(u1, aio1);

			nni_aio_wait(aio2);
			nni_aio_wait(aio1);
			nni_aio_wait(aio3);
			nni_aio_wait(aio4);

			So(nni_aio_result(aio1) == 0);
			So(nni_aio_result(aio2) == 0);
			So(nni_aio_result(aio3) == 0);
			So(nni_aio_result(aio4) == 0);

			So(from1.s_un.s_in.sa_family ==
			    sa1.s_un.s_in.sa_family);
			So(from1.s_un.s_in.sa_port == sa1.s_un.s_in.sa_port);
			So(from1.s_un.s_in.sa_addr == sa1.s_un.s_in.sa_addr);

			nni_aio_fini(aio1);
			nni_aio_fini(aio2);
			nni_aio_fini(aio3);
			nni_aio_fini(aio4);
		});

		Convey("Sending without an address fails", {
			nni_aio *aio1;
			char *   msg = "nope";

			nni_aio_init(&aio1, NULL, NULL);
			aio1->a_niov           = 1;
			aio1->a_iov[0].iov_buf = (void *) msg;
			aio1->a_iov[0].iov_len = strlen(msg) + 1;

			nni_plat_udp_send(u1, aio1);
			nni_aio_wait(aio1);
			So(nni_aio_result(aio1) == NNG_EADDRINVAL);
			nni_aio_fini(aio1);
		});

		Convey("Sending to an IPv6 address on IPv4 fails", {
			nni_aio *    aio1;
			char *       msg = "nope";
			nng_sockaddr sa;
			int          rv;

			sa.s_un.s_in6.sa_family = NNG_AF_INET6;
			// address is for google.com
			inet_ntop(AF_INET6, "2607:f8b0:4007:804::200e",
			    (void *) sa.s_un.s_in6.sa_addr, 16);
			sa.s_un.s_in6.sa_port = 80;
			nni_aio_init(&aio1, NULL, NULL);
			aio1->a_niov           = 1;
			aio1->a_iov[0].iov_buf = (void *) msg;
			aio1->a_iov[0].iov_len = strlen(msg) + 1;
			aio1->a_addr           = &sa;

			nni_plat_udp_send(u1, aio1);
			nni_aio_wait(aio1);
			So((rv = nni_aio_result(aio1)) != 0);
			So(rv == NNG_EADDRINVAL || rv == NNG_ENOTSUP ||
			    rv == NNG_EUNREACHABLE);
			nni_aio_fini(aio1);
		});

		Convey("Sending to an IPC address fails", {
			nni_aio *    aio1;
			char *       msg = "nope";
			nng_sockaddr sa;
			int          rv;

			sa.s_un.s_in6.sa_family = NNG_AF_INET6;
			// address is for google.com
			inet_ntop(AF_INET6, "2607:f8b0:4007:804::200e",
			    (void *) sa.s_un.s_in6.sa_addr, 16);
			sa.s_un.s_in6.sa_port = 80;
			nni_aio_init(&aio1, NULL, NULL);
			aio1->a_niov           = 1;
			aio1->a_iov[0].iov_buf = (void *) msg;
			aio1->a_iov[0].iov_len = strlen(msg) + 1;
			aio1->a_addr           = &sa;

			nni_plat_udp_send(u1, aio1);
			nni_aio_wait(aio1);
			So((rv = nni_aio_result(aio1)) != 0);
			So(rv == NNG_EADDRINVAL || rv == NNG_ENOTSUP ||
			    rv == NNG_EUNREACHABLE);
			nni_aio_fini(aio1);
		});

	});

	Convey("Cannot open using bogus sockaddr", {
		nni_plat_udp *u;
		nng_sockaddr  sa;
		int           rv;

		sa.s_un.s_path.sa_family = NNG_AF_IPC;
		strcpy(sa.s_un.s_path.sa_path, "/tmp/t");
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

		p1                     = trantest_port++;
		sa.s_un.s_in.sa_family = NNG_AF_INET;
		sa.s_un.s_in.sa_port   = htons(p1);
		sa.s_un.s_in.sa_addr   = htonl(0x7f000001);
		So(nni_plat_udp_open(&u1, &sa) == 0);
		So(nni_plat_udp_open(&u2, &sa) == NNG_EADDRINUSE);
		nni_plat_udp_close(u1);
	});

});
