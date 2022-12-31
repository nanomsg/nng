//
// Copyright 2022 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>

#include "convey.h"
#include "stubs.h"
#include "trantest.h"

// TCP tests.

static int
check_props_v4(nng_msg *msg)
{
	nng_pipe     p;
	size_t       z;
	nng_sockaddr la;
	nng_sockaddr ra;
	bool         b;

	p = nng_msg_get_pipe(msg);
	So(nng_pipe_id(p) > 0);
	So(nng_pipe_get_addr(p, NNG_OPT_LOCADDR, &la) == 0);
	So(la.s_family == NNG_AF_INET);
	So(la.s_in.sa_port == htons(trantest_port - 1));
	So(la.s_in.sa_port != 0);
	So(la.s_in.sa_addr == htonl(0x7f000001));

	// untyped
	z = sizeof(nng_sockaddr);
	So(nng_pipe_get(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_family == NNG_AF_INET);
	So(ra.s_in.sa_port != 0);
	So(ra.s_in.sa_addr == htonl(0x7f000001));

	So(nng_pipe_get_size(p, NNG_OPT_REMADDR, &z) == NNG_EBADTYPE);
	z = 1;
	So(nng_pipe_get(p, NNG_OPT_REMADDR, &ra, &z) == NNG_EINVAL);

	So(nng_pipe_get_bool(p, NNG_OPT_TCP_KEEPALIVE, &b) == 0);
	So(b == false); // default

	So(nng_pipe_get_bool(p, NNG_OPT_TCP_NODELAY, &b) == 0);
	So(b == true); // default

	return (0);
}

TestMain("TCP Transport", {
	trantest_test_extended("tcp://127.0.0.1:", check_props_v4);
})
