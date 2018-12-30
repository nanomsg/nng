//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
	So(nng_pipe_getopt_sockaddr(p, NNG_OPT_LOCADDR, &la) == 0);
	So(la.s_family == NNG_AF_INET);
	So(la.s_in.sa_port == htons(trantest_port - 1));
	So(la.s_in.sa_port != 0);
	So(la.s_in.sa_addr == htonl(0x7f000001));

	// untyped
	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_family == NNG_AF_INET);
	So(ra.s_in.sa_port != 0);
	So(ra.s_in.sa_addr == htonl(0x7f000001));

	So(nng_pipe_getopt_size(p, NNG_OPT_REMADDR, &z) == NNG_EBADTYPE);
	z = 1;
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == NNG_EINVAL);

	So(nng_pipe_getopt_bool(p, NNG_OPT_TCP_KEEPALIVE, &b) == 0);
	So(b == false); // default

	So(nng_pipe_getopt_bool(p, NNG_OPT_TCP_NODELAY, &b) == 0);
	So(b == true); // default

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

	Convey("We can bind to port zero", {
		nng_socket   s1;
		nng_socket   s2;
		nng_sockaddr sa;
		nng_listener l;
		char *       addr;

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		So(nng_listen(s1, "tcp://127.0.0.1:0", &l, 0) == 0);
		So(nng_listener_getopt_string(l, NNG_OPT_URL, &addr) == 0);
		So(memcmp(addr, "tcp://", 6) == 0);
		So(nng_listener_getopt_sockaddr(l, NNG_OPT_LOCADDR, &sa) == 0);
		So(sa.s_in.sa_family == NNG_AF_INET);
		So(sa.s_in.sa_port != 0);
		So(sa.s_in.sa_addr = htonl(0x7f000001));
		So(nng_dial(s2, addr, NULL, 0) == 0);
		nng_strfree(addr);
	});

	Convey("We can use local interface to connect", {
		nng_socket s1;
		nng_socket s2;
		char       addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tcp://127.0.0.1:%u");
		So(nng_listen(s1, addr, NULL, 0) == 0);
		// reset port back one
		trantest_prev_address(addr, "tcp://127.0.0.1;127.0.0.1:%u");
		So(nng_dial(s2, addr, NULL, 0) == 0);
	});

	Convey("Botched local interfaces fail resonably", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });
		So(nng_dial(s1, "tcp://1x.2;127.0.0.1:80", NULL, 0) ==
		    NNG_EADDRINVAL);
	});

	Convey("Can't specify address that isn't ours", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });
		So(nng_dial(s1, "tcp://8.8.8.8;127.0.0.1:80", NULL, 0) ==
		    NNG_EADDRINVAL);
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

	Convey("No delay option", {
		nng_socket   s;
		nng_dialer   d;
		nng_listener l;
		bool         v;
		int          x;

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_getopt_bool(s, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		So(nng_dialer_setopt_bool(d, NNG_OPT_TCP_NODELAY, false) == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == false);
		So(nng_dialer_getopt_int(d, NNG_OPT_TCP_NODELAY, &x) ==
		    NNG_EBADTYPE);
		x = 0;
		So(nng_dialer_setopt_int(d, NNG_OPT_TCP_NODELAY, x) ==
		    NNG_EBADTYPE);
		// This assumes sizeof (bool) != sizeof (int)
		So(nng_dialer_setopt(d, NNG_OPT_TCP_NODELAY, &x, sizeof(x)) ==
		    NNG_EINVAL);

		So(nng_listener_create(&l, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_listener_getopt_bool(l, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		x = 0;
		So(nng_listener_setopt_int(l, NNG_OPT_TCP_NODELAY, x) ==
		    NNG_EBADTYPE);
		// This assumes sizeof (bool) != sizeof (int)
		So(nng_listener_setopt(
		       l, NNG_OPT_TCP_NODELAY, &x, sizeof(x)) == NNG_EINVAL);

		nng_dialer_close(d);
		nng_listener_close(l);

		// Make sure socket wide defaults apply.
		So(nng_setopt_bool(s, NNG_OPT_TCP_NODELAY, true) == 0);
		v = false;
		So(nng_getopt_bool(s, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		So(nng_setopt_bool(s, NNG_OPT_TCP_NODELAY, false) == 0);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == false);
	});

	Convey("Keepalive option", {
		nng_socket   s;
		nng_dialer   d;
		nng_listener l;
		bool         v;
		int          x;

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_getopt_bool(s, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == false);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == false);
		So(nng_dialer_setopt_bool(d, NNG_OPT_TCP_KEEPALIVE, true) ==
		    0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == true);
		So(nng_dialer_getopt_int(d, NNG_OPT_TCP_KEEPALIVE, &x) ==
		    NNG_EBADTYPE);
		x = 1;
		So(nng_dialer_setopt_int(d, NNG_OPT_TCP_KEEPALIVE, x) ==
		    NNG_EBADTYPE);

		So(nng_listener_create(&l, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_listener_getopt_bool(l, NNG_OPT_TCP_KEEPALIVE, &v) ==
		    0);
		So(v == false);
		x = 1;
		So(nng_listener_setopt_int(l, NNG_OPT_TCP_KEEPALIVE, x) ==
		    NNG_EBADTYPE);

		nng_dialer_close(d);
		nng_listener_close(l);

		// Make sure socket wide defaults apply.
		So(nng_setopt_bool(s, NNG_OPT_TCP_KEEPALIVE, false) == 0);
		v = true;
		So(nng_getopt_bool(s, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == false);
		So(nng_setopt_bool(s, NNG_OPT_TCP_KEEPALIVE, true) == 0);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == true);
	});

	nng_fini();
})
