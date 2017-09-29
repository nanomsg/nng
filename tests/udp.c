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

		sa1.s_un.s_in.sa_family = NNG_AF_INET;
		sa1.s_un.s_in.sa_addr   = loopback;
		sa1.s_un.s_in.sa_port   = trantest_port++;

		sa2.s_un.s_in.sa_family = NNG_AF_INET;
		sa2.s_un.s_in.sa_addr   = loopback;
		sa2.s_un.s_in.sa_port   = trantest_port++;

		p1 = sa1.s_un.s_in.sa_port;
		p2 = sa2.s_un.s_in.sa_port;

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
			aio1->a_iov[0].iov_buf = msg;
			aio1->a_iov[0].iov_len = strlen(msg) + 1;
			aio1->a_addr           = &to;

			aio2->a_niov           = 1;
			aio2->a_iov[0].iov_buf = rbuf;
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

			nni_aio_fini(aio1);
			nni_aio_fini(aio2);
		});
	});

});
