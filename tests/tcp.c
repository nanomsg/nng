//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "protocol/pair1/pair.h"
#include "trantest.h"

#include "stubs.h"
// TCP tests.

#ifndef _WIN32
#include <arpa/inet.h>
#endif

static int
check_props_v4(nng_msg *msg, nng_listener l, nng_dialer d)
{
	nng_pipe     p;
	size_t       z;
	nng_sockaddr la;
	nng_sockaddr ra;

	p = nng_msg_get_pipe(msg);
	So(p > 0);
	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_LOCADDR, &la, &z) == 0);
	So(z == sizeof(la));
	So(la.s_un.s_family == NNG_AF_INET);
	So(la.s_un.s_in.sa_port == htons(trantest_port - 1));
	So(la.s_un.s_in.sa_port != 0);
	So(la.s_un.s_in.sa_addr == htonl(0x7f000001));

	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_un.s_family == NNG_AF_INET);
	So(ra.s_un.s_in.sa_port != 0);
	So(ra.s_un.s_in.sa_addr == htonl(0x7f000001));

	return (0);
}

TestMain("TCP Transport", {

	trantest_test_extended("tcp://127.0.0.1:%u", check_props_v4);

	Convey("We cannot connect to wild cards", {
		nng_socket s;
		char       addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		trantest_next_address(addr, "tcp://*:%u");
		So(nng_dial(s, addr, NULL, 0) == NNG_EADDRINVAL);
	});

	Convey("We can bind to wild card", {
		nng_socket s1;
		nng_socket s2;
		char       addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tcp://*:%u");
		So(nng_listen(s1, addr, NULL, 0) == 0);
		// reset port back one
		trantest_prev_address(addr, "tcp://127.0.0.1:%u");
		So(nng_dial(s2, addr, NULL, 0) == 0);
	});

	Convey("Malformed TCP addresses do not panic", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });
		So(nng_dial(s1, "tcp://127.0.0.1", NULL, 0) == NNG_EADDRINVAL);
		So(nng_dial(s1, "tcp://127.0.0.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_dial(s1, "tcp://127.0.x.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_listen(s1, "tcp://127.0.0.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_listen(s1, "tcp://127.0.x.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
	});

	nng_fini();
})
