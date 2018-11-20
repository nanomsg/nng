//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/nng.h>
#include <nng/protocol/pair0/pair.h>
#include <nng/transport/zerotier/zerotier.h>

#include "convey.h"
#include "trantest.h"
#include "stubs.h"

// zerotier tests.

// This network is an open network setup exclusively for nng testing.
// Do not attach to it in production.
#define NWID "a09acf02337b057b"
#define NWID_NUM 0xa09acf02337b057bull

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

static int
check_props(nng_msg *msg)
{
	nng_pipe p;
	p = nng_msg_get_pipe(msg);
	So(nng_pipe_id(p) > 0);

	// Check local address.
	Convey("Local address property works", {
		nng_sockaddr la;
		So(nng_pipe_getopt_sockaddr(p, NNG_OPT_LOCADDR, &la) == 0);

		So(la.s_family == NNG_AF_ZT);
		So(la.s_zt.sa_port == (trantest_port - 1));
		So(la.s_zt.sa_nwid == NWID_NUM);
		So(la.s_zt.sa_nodeid != 0);
	});

	Convey("Remote address property works", {
		// Check remote address.
		uint64_t     mynode;
		nng_sockaddr ra;

		So(nng_pipe_getopt_sockaddr(p, NNG_OPT_REMADDR, &ra) == 0);
		So(ra.s_family == NNG_AF_ZT);
		So(ra.s_zt.sa_port != 0);
		So(ra.s_zt.sa_nwid == NWID_NUM);

		So(nng_pipe_getopt_uint64(p, NNG_OPT_ZT_NODE, &mynode) == 0);
		So(mynode != 0);
		So(ra.s_zt.sa_nodeid == mynode);
	});

	Convey("NWID property works", {
		uint64_t nwid = 0;

		So(nng_pipe_getopt_uint64(p, NNG_OPT_ZT_NWID, &nwid) == 0);
		So(nwid = 0xa09acf02337b057bull);
	});

	Convey("Network status property works", {
		int s = 0;

		So(nng_pipe_getopt_int(p, NNG_OPT_ZT_NETWORK_STATUS, &s) == 0);
		So(s == NNG_ZT_STATUS_UP);
	});

	Convey("Ping properties work", {
		int          c = 0;
		nng_duration t = 0;

		So(nng_pipe_getopt_int(p, NNG_OPT_ZT_PING_TRIES, &c) == 0);
		So(c > 0 && c < 10); // actually 5...

		So(nng_pipe_getopt_ms(p, NNG_OPT_ZT_PING_TIME, &t) == 0);
		So(t > 1000 && t < 3600000); // 1 sec - 1 hour
	});

	Convey("Home property works", {
		char *v;
		So(nng_pipe_getopt_string(p, NNG_OPT_ZT_HOME, &v) == 0);
		nng_strfree(v);
	});

	Convey("MTU property works", {
		size_t mtu;

		// Check MTU
		So(nng_pipe_getopt_size(p, NNG_OPT_ZT_MTU, &mtu) == 0);
		So(mtu >= 1000 && mtu <= 10000);
	});

	Convey("Network name property works", {
		char *name;

		So(nng_pipe_getopt_string(p, NNG_OPT_ZT_NETWORK_NAME, &name) ==
		    0);
		So(strcmp(name, "nng_test_open") == 0);
		nng_strfree(name);
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

			Convey("It has the right local address", {
				nng_sockaddr sa;
				So(nng_listener_getopt_sockaddr(
				       l, NNG_OPT_LOCADDR, &sa) == 0);
				So(sa.s_zt.sa_family == NNG_AF_ZT);
				So(sa.s_zt.sa_nwid == NWID_NUM);
				So(sa.s_zt.sa_port == port);
				So(sa.s_zt.sa_nodeid != 0);
			});
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
		So(nng_zt_register() == 0);

		snprintf(addr1, sizeof(addr1), "zt://*." NWID ":%u", port);

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s1);
			// This sleep ensures disconnect messages work.
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
		mkdir(path2, 0700);
		So(nng_dialer_setopt(
		       d, NNG_OPT_ZT_HOME, path2, strlen(path2) + 1) == 0);
		So(nng_dialer_start(d, 0) == 0);
		nng_msleep(2000); // to give dialer time to start up
	});

	// We need to determine our ephemeral ID:

	nng_socket   s_test;
	nng_listener l_test;
	uint64_t     node;
	char         fmt[128];

	So(nng_pair_open(&s_test) == 0);
	So(nng_listener_create(&l_test, s_test, "zt://*." NWID ":0") == 0);
	So(nng_listener_start(l_test, 0) == 0);
	So(nng_listener_getopt_uint64(l_test, NNG_OPT_ZT_NODE, &node) == 0);
	snprintf(fmt, sizeof(fmt), "zt://%llx." NWID ":%%u",
	    (unsigned long long) node);
	nng_listener_close(l_test);

	trantest_test_extended(fmt, check_props);
})
