//
// Copyright 2018 Staysail Systems, Inc. <info@staystail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// TCP tests for IPv6.

#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>

#include "convey.h"
#include "core/nng_impl.h"
#include "trantest.h"

#include "stubs.h"

static int
has_v6(void)
{
	nng_sockaddr  sa;
	nni_plat_udp *u;
	int           rv;

	sa.s_in6.sa_family = NNG_AF_INET6;
	sa.s_in6.sa_port   = 0;
	memset(sa.s_in6.sa_addr, 0, 16);
	sa.s_in6.sa_addr[15] = 1;

	rv = nni_plat_udp_open(&u, &sa);
	if (rv == 0) {
		nni_plat_udp_close(u);
	}
	return (rv == 0 ? 1 : 0);
}

static int
check_props_v6(nng_msg *msg)
{
	nng_pipe p;
	size_t   z;
	uint8_t  loopback[16];

	memset(loopback, 0, sizeof(loopback));
	loopback[15] = 1;

	// IPv6 Local address property works
	nng_sockaddr la;
	z = sizeof(nng_sockaddr);
	p = nng_msg_get_pipe(msg);
	So(nng_pipe_id(p) > 0);
	So(nng_pipe_getopt(p, NNG_OPT_LOCADDR, &la, &z) == 0);
	So(z == sizeof(la));
	So(la.s_family == NNG_AF_INET6);
	// So(la.s_in.sa_port == (trantest_port - 1));
	So(la.s_in6.sa_port != 0);
	So(memcmp(la.s_in6.sa_addr, loopback, 16) == 0);

	// IPv6 Remote address property works
	nng_sockaddr ra;
	z = sizeof(nng_sockaddr);
	p = nng_msg_get_pipe(msg);
	So(nng_pipe_id(p) > 0);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_family == NNG_AF_INET6);
	So(ra.s_in6.sa_port != 0);
	So(memcmp(ra.s_in6.sa_addr, loopback, 16) == 0);

	return (0);
}

TestMain("TCP (IPv6) Transport", {
	nni_init();

	if (has_v6()) {
		trantest_test_extended("tcp://[::1]:%u", check_props_v6);
	} else {
		SkipSo("IPv6 not available");
	}

	Convey("Malformed TCPv6 addresses do not panic", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });
		So(nng_dial(s1, "tcp://::1", NULL, 0) == NNG_EADDRINVAL);
		So(nng_dial(s1, "tcp://::1:5055", NULL, 0) == NNG_EADDRINVAL);
		So(nng_dial(s1, "tcp://[::1]", NULL, 0) == NNG_EADDRINVAL);
	});

	nng_fini();
})
