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
#include "transport/ws/websocket.h"
#include "trantest.h"

#include "stubs.h"
// TCP tests.

#ifndef _WIN32
#include <arpa/inet.h>
#endif

static int
check_props_v4(nng_msg *msg)
{
	nng_pipe     p;
	size_t       z;
	nng_sockaddr la;
	nng_sockaddr ra;
	char *       buf;
	size_t       len;

	p = nng_msg_get_pipe(msg);
	So(nng_pipe_id(p) > 0);

	So(nng_pipe_getopt_sockaddr(p, NNG_OPT_LOCADDR, &la) == 0);
	So(la.s_family == NNG_AF_INET);
	So(la.s_in.sa_port == htons(trantest_port - 1));
	So(la.s_in.sa_port != 0);
	So(la.s_in.sa_addr == htonl(0x7f000001));

	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_family == NNG_AF_INET);
	So(ra.s_in.sa_port != 0);
	So(ra.s_in.sa_addr == htonl(0x7f000001));

	// Request Header
	z   = 0;
	buf = NULL;
	So(nng_pipe_getopt(p, NNG_OPT_WS_REQUEST_HEADERS, buf, &z) ==
	    NNG_EINVAL);
	So(z > 0);
	len = z;
	So((buf = nng_alloc(len)) != NULL);
	So(nng_pipe_getopt(p, NNG_OPT_WS_REQUEST_HEADERS, buf, &z) == 0);
	So(strstr(buf, "Sec-WebSocket-Key") != NULL);
	So(z == len);
	nng_free(buf, len);
	So(nng_pipe_getopt_string(p, NNG_OPT_WS_REQUEST_HEADERS, &buf) == 0);
	So(strlen(buf) == len - 1);
	nng_strfree(buf);

	// Response Header
	z   = 0;
	buf = NULL;
	So(nng_pipe_getopt(p, NNG_OPT_WS_RESPONSE_HEADERS, buf, &z) ==
	    NNG_EINVAL);
	So(z > 0);
	len = z;
	So((buf = nng_alloc(len)) != NULL);
	So(nng_pipe_getopt(p, NNG_OPT_WS_RESPONSE_HEADERS, buf, &z) == 0);
	So(strstr(buf, "Sec-WebSocket-Accept") != NULL);
	So(z == len);
	nng_free(buf, len);
	So(nng_pipe_getopt_string(p, NNG_OPT_WS_RESPONSE_HEADERS, &buf) == 0);
	So(strlen(buf) == len - 1);
	nng_strfree(buf);

	return (0);
}

TestMain("WebSocket Transport", {

	trantest_test_extended("ws://127.0.0.1:%u/test", check_props_v4);

	Convey("Empty hostname works", {
		nng_socket s1;
		nng_socket s2;
		char       addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "ws://:%u/test");
		So(nng_listen(s1, addr, NULL, 0) == 0);
		nng_msleep(100);
		// reset port back one
		trantest_prev_address(addr, "ws://127.0.0.1:%u/test");
		So(nng_dial(s2, addr, NULL, 0) == 0);
	});

	Convey("Incorrect URL paths do not work", {
		nng_socket s1;
		nng_socket s2;
		char       addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "ws://:%u/test");
		So(nng_listen(s1, addr, NULL, 0) == 0);
		// reset port back one
		trantest_prev_address(addr, "ws://localhost:%u/nothere");
		So(nng_dial(s2, addr, NULL, 0) == NNG_ECONNREFUSED);
	});

	nng_fini();
})
