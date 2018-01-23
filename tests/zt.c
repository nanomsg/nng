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
#include "protocol/pair0/pair.h"
#include "transport/zerotier/zerotier.h"
#include "trantest.h"

#include "stubs.h"

// zerotier tests.

// This network is an open network setup exclusively for nng testing.
// Do not attach to it in production.
#define NWID "a09acf02337b057b"

// This network is a closed network, which nothing can join.  We use it for
// testing permission denied.
#define CLOSED_NWID "17d709436ce162a3"

#ifdef _WIN32

int
mkdir(const char *path, int mode)
{
	CreateDirectory(path, NULL);
	return (0);
}
#else
#include <sys/stat.h>
#include <unistd.h>
#endif // WIN32

#ifndef NNG_TRANSPORT_ZEROTIER
#define nng_zt_network_status_ok 0
#endif

static int
check_props(nng_msg *msg, nng_listener l, nng_dialer d)
{
	nng_sockaddr la, ra;
	nng_pipe     p;
	size_t       z;
	p = nng_msg_get_pipe(msg);
	So(p > 0);

	// Check local address.
	Convey("Local address property works", {
		z = sizeof(nng_sockaddr);
		So(nng_pipe_getopt(p, NNG_OPT_LOCADDR, &la, &z) == 0);
		So(z == sizeof(la));
		So(la.s_un.s_family == NNG_AF_ZT);
		So(la.s_un.s_zt.sa_port == (trantest_port - 1));
		So(la.s_un.s_zt.sa_nwid == 0xa09acf02337b057bull);
		So(la.s_un.s_zt.sa_nodeid != 0);
	});

	Convey("Remote address property works", {
		// Check remote address.
		uint64_t mynode;

		z = sizeof(nng_sockaddr);
		So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
		So(z == sizeof(ra));
		So(ra.s_un.s_family == NNG_AF_ZT);
		So(ra.s_un.s_zt.sa_port != 0);
		So(ra.s_un.s_zt.sa_nwid == 0xa09acf02337b057bull);

		z = sizeof(mynode);
		So(nng_pipe_getopt(p, NNG_OPT_ZT_NODE, &mynode, &z) == 0);
		So(mynode != 0);
		So(ra.s_un.s_zt.sa_nodeid == mynode);

		So(nng_dialer_getopt(d, NNG_OPT_REMADDR, &ra, &z) != 0);
	});

	Convey("NWID property works", {
		uint64_t nwid;

		z    = sizeof(nwid);
		nwid = 0;
		So(nng_pipe_getopt(p, NNG_OPT_ZT_NWID, &nwid, &z) == 0);
		So(nwid = 0xa09acf02337b057bull);

		z    = sizeof(nwid);
		nwid = 0;
		So(nng_dialer_getopt(d, NNG_OPT_ZT_NWID, &nwid, &z) == 0);
		So(nwid = 0xa09acf02337b057bull);

		z    = sizeof(nwid);
		nwid = 0;
		So(nng_listener_getopt(l, NNG_OPT_ZT_NWID, &nwid, &z) == 0);
		So(nwid = 0xa09acf02337b057bull);
	});

	Convey("Network status property works", {
		int s;
		z = sizeof(s);
		s = 0;
		So(nng_pipe_getopt(p, NNG_OPT_ZT_NETWORK_STATUS, &s, &z) == 0);
		So(s == nng_zt_network_status_ok);

		z = sizeof(s);
		s = 0;
		So(nng_dialer_getopt(d, NNG_OPT_ZT_NETWORK_STATUS, &s, &z) ==
		    0);
		So(s == nng_zt_network_status_ok);

		z = sizeof(s);
		s = 0;
		So(nng_listener_getopt(l, NNG_OPT_ZT_NETWORK_STATUS, &s, &z) ==
		    0);
		So(s == nng_zt_network_status_ok);

		So(nng_dialer_setopt(d, NNG_OPT_ZT_NETWORK_STATUS, &s, z) ==
		    NNG_EREADONLY);
		So(nng_listener_setopt(l, NNG_OPT_ZT_NETWORK_STATUS, &s, z) ==
		    NNG_EREADONLY);
	});

	Convey("Ping properties work", {
		int          c;
		nng_duration t;

		z = sizeof(c);
		c = 0;
		So(nng_pipe_getopt(p, NNG_OPT_ZT_PING_COUNT, &c, &z) == 0);
		So(c > 0 && c < 10); // actually 5...

		t = 0;
		So(nng_pipe_getopt_ms(p, NNG_OPT_ZT_PING_TIME, &t) == 0);
		So(t > 1000 && t < 3600000); // 1 sec - 1 hour

		c = 0;
		So(nng_dialer_getopt_int(d, NNG_OPT_ZT_PING_COUNT, &c) == 0);
		So(c > 0 && c < 10); // actually 5...

		t = 0;
		So(nng_dialer_getopt_ms(d, NNG_OPT_ZT_PING_TIME, &t) == 0);
		So(t > 1000 && t < 3600000); // 1 sec - 1 hour

		So(nng_dialer_setopt_int(d, NNG_OPT_ZT_PING_COUNT, 20) == 0);
		So(nng_dialer_setopt_int(d, NNG_OPT_ZT_PING_COUNT, 20) == 0);
		So(nng_dialer_setopt_ms(d, NNG_OPT_ZT_PING_TIME, 2000) == 0);
		So(nng_listener_setopt_int(l, NNG_OPT_ZT_PING_COUNT, 0) == 0);
		So(nng_listener_setopt_ms(l, NNG_OPT_ZT_PING_TIME, 0) == 0);
	});

	Convey("Home property works", {
		char v[256];
		z = sizeof(v);
		So(nng_pipe_getopt(p, NNG_OPT_ZT_HOME, v, &z) == 0);
		So(strlen(v) < sizeof(v));

		z = sizeof(v);
		So(nng_dialer_getopt(d, NNG_OPT_ZT_HOME, v, &z) == 0);
		So(strlen(v) < sizeof(v));

		z = sizeof(v);
		So(nng_listener_getopt(l, NNG_OPT_ZT_HOME, v, &z) == 0);
		So(strlen(v) < sizeof(v));

		z = strlen("/tmp/bogus") + 1;
		So(nng_dialer_setopt(d, NNG_OPT_ZT_HOME, "/tmp/bogus", z) ==
		    NNG_ESTATE);
		So(nng_listener_setopt(l, NNG_OPT_ZT_HOME, "/tmp/bogus", z) ==
		    NNG_ESTATE);
	});

	Convey("MTU property works", {
		size_t mtu;

		// Check MTU
		z = sizeof(mtu);
		So(nng_pipe_getopt(p, NNG_OPT_ZT_MTU, &mtu, &z) == 0);
		So(mtu >= 1000 && mtu <= 10000);
	});

	return (0);
}

TestMain("ZeroTier Transport", {

	char     path1[NNG_MAXADDRLEN] = "/tmp/zt_server";
	char     path2[NNG_MAXADDRLEN] = "/tmp/zt_client";
	unsigned port;

	port = 5555;
	atexit(nng_fini);

	Convey("We can register the zero tier transport",
	    { So(nng_zt_register() == 0); });

	Convey("We can create a zt listener", {
		nng_listener l;
		nng_socket   s;
		char         addr[NNG_MAXADDRLEN];

		So(nng_zt_register() == 0);

		snprintf(addr, sizeof(addr), "zt://*." NWID ":%u", port);

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });

		So(nng_listener_create(&l, s, addr) == 0);

		Convey("And it can be started...", {

			mkdir(path1, 0700);

			So(nng_listener_setopt(l, NNG_OPT_ZT_HOME, path1,
			       strlen(path1) + 1) == 0);

			So(nng_listener_start(l, 0) == 0);

			Convey("And we can orbit a moon", {
				uint64_t ids[2];
				// Provided by Janjaap...
				ids[0] = 0x622514484aull;
				ids[1] = 0x622514484aull;

				So(nng_listener_setopt(l, NNG_OPT_ZT_ORBIT,
				       ids, sizeof(ids)) == 0);

			});
			Convey("And we can deorbit anything", {
				uint64_t id;
				id = 0x12345678;
				So(nng_listener_setopt(l, NNG_OPT_ZT_DEORBIT,
				       &id, sizeof(id)) == 0);
			});
		});
	});

	Convey("We can create a zt dialer", {
		nng_dialer d;
		nng_socket s;
		char       addr[NNG_MAXADDRLEN];
		// uint64_t   node = 0xb000072fa6ull; // my personal host
		uint64_t node = 0x2d2f619cccull; // my personal host

		So(nng_zt_register() == 0);

		snprintf(addr, sizeof(addr), "zt://%llx." NWID ":%u",
		    (unsigned long long) node, port);

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });

		So(nng_dialer_create(&d, s, addr) == 0);
	});

	Convey("We can create an ephemeral listener", {
		nng_dialer   d;
		nng_listener l;
		nng_socket   s;
		char         addr[NNG_MAXADDRLEN];
		uint64_t     node1 = 0;
		uint64_t     node2 = 0;

		So(nng_zt_register() == 0);

		snprintf(addr, sizeof(addr), "zt://*." NWID ":%u", port);

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });

		So(nng_listener_create(&l, s, addr) == 0);

		So(nng_listener_getopt_uint64(l, NNG_OPT_ZT_NODE, &node1) ==
		    0);
		So(node1 != 0);

		Convey("Network name & status options work", {
			char   name[NNG_MAXADDRLEN];
			size_t namesz;
			int    status;

			namesz = sizeof(name);
			nng_msleep(10000);
			So(nng_listener_getopt(l, NNG_OPT_ZT_NETWORK_NAME,
			       name, &namesz) == 0);
			So(strcmp(name, "nng_test_open") == 0);
			So(nng_listener_getopt_int(
			       l, NNG_OPT_ZT_NETWORK_STATUS, &status) == 0);
			So(status == nng_zt_network_status_ok);
		});
		Convey("Connection refused works", {
			snprintf(addr, sizeof(addr), "zt://%llx." NWID ":%u",
			    (unsigned long long) node1, 42u);
			So(nng_dialer_create(&d, s, addr) == 0);
			So(nng_dialer_getopt_uint64(
			       d, NNG_OPT_ZT_NODE, &node2) == 0);
			So(node2 == node1);
			So(nng_dialer_start(d, 0) == NNG_ECONNREFUSED);
		});
	});

	Convey("We can create a zt pair (dialer & listener)", {
		nng_dialer   d;
		nng_listener l;
		nng_socket   s1;
		nng_socket   s2;
		char         addr1[NNG_MAXADDRLEN];
		char         addr2[NNG_MAXADDRLEN];
		uint64_t     node;

		port = 9944;
		// uint64_t   node = 0xb000072fa6ull; // my personal host
		So(nng_zt_register() == 0);

		snprintf(addr1, sizeof(addr1), "zt://*." NWID ":%u", port);

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s1);
			// This sleep allows us to ensure disconnect
			// messages work.
			nng_msleep(500);
			nng_close(s2);
		});

		So(nng_listener_create(&l, s1, addr1) == 0);
		So(nng_listener_setopt(
		       l, NNG_OPT_ZT_HOME, path1, strlen(path1) + 1) == 0);

		So(nng_listener_start(l, 0) == 0);
		node = 0;
		So(nng_listener_getopt_uint64(l, NNG_OPT_ZT_NODE, &node) == 0);
		So(node != 0);
		nng_msleep(40);
		snprintf(addr2, sizeof(addr2), "zt://%llx." NWID ":%u",
		    (unsigned long long) node, port);
		So(nng_dialer_create(&d, s2, addr2) == 0);
		So(nng_dialer_setopt(
		       d, NNG_OPT_ZT_HOME, path2, strlen(path2) + 1) == 0);
		So(nng_dialer_start(d, 0) == 0);
		nng_msleep(2000);
	});

	trantest_test_extended("zt://*." NWID ":%u", check_props);

})
