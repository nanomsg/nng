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

extern int         nng_zt_register(void);
extern const char *nng_opt_zt_home;
extern const char *nng_opt_zt_node;
extern const char *nng_opt_zt_status;
extern const char *nng_opt_zt_network_name;
extern int         nng_zt_status_ok;

// zerotier tests.

// This network is an open network setup exclusively for nng testing.
// Do not attach to it in production.
#define NWID "a09acf02337b057b"

#ifdef _WIN32

int
mkdir(const char *path, int mode)
{
	CreateDirectory(path, NULL);
}
#else
#include <sys/stat.h>
#include <unistd.h>
#endif // WIN32

static int
check_props(nng_msg *msg, nng_listener l, nng_dialer d)
{
	nng_sockaddr la, ra;
	nng_pipe     p;
	size_t       z;
	size_t       mtu;
	uint64_t     nwid;
	p = nng_msg_get_pipe(msg);
	So(p > 0);

	// Check local address.
	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_LOCADDR, &la, &z) == 0);
	So(z == sizeof(la));
	So(la.s_un.s_family == NNG_AF_ZT);
	So(la.s_un.s_zt.sa_port == (trantest_port - 1));
	So(la.s_un.s_zt.sa_nwid == 0xa09acf02337b057bull);
	So(la.s_un.s_zt.sa_nodeid != 0);

	// Check remote address.
	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_un.s_family == NNG_AF_ZT);
	So(ra.s_un.s_zt.sa_port != 0);
	So(ra.s_un.s_zt.sa_nwid == 0xa09acf02337b057bull);
	So(ra.s_un.s_zt.sa_nodeid == la.s_un.s_zt.sa_nodeid);

	// Check network ID.
	z    = sizeof(nwid);
	nwid = 0;
	So(nng_pipe_getopt(p, "zt:nwid", &nwid, &z) == 0);
	So(nwid = 0xa09acf02337b057bull);

	z    = sizeof(nwid);
	nwid = 0;
	So(nng_dialer_getopt(d, "zt:nwid", &nwid, &z) == 0);
	So(nwid = 0xa09acf02337b057bull);

	z    = sizeof(nwid);
	nwid = 0;
	So(nng_listener_getopt(l, "zt:nwid", &nwid, &z) == 0);
	So(nwid = 0xa09acf02337b057bull);

	// Check MTU
	z = sizeof(mtu);
	So(nng_pipe_getopt(p, "zt:mtu", &mtu, &z) == 0);
	So(mtu >= 1000 && mtu <= 10000);

	return (0);
}

TestMain("ZeroTier Transport", {

	char     path1[NNG_MAXADDRLEN] = "/tmp/zt_server";
	char     path2[NNG_MAXADDRLEN] = "/tmp/zt_client";
	unsigned port;

	port = 5555;

	Convey("We can register the zero tier transport",
	    { So(nng_zt_register() == 0); });

	Convey("We can create a zt listener", {
		nng_listener l;
		nng_socket   s;
		char         addr[NNG_MAXADDRLEN];
		int          rv;

		snprintf(addr, sizeof(addr), "zt://" NWID ":%u", port);

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });

		So(nng_listener_create(&l, s, addr) == 0);

		Convey("And it can be started...", {

			mkdir(path1, 0700);

			So(nng_listener_setopt(l, nng_opt_zt_home, path1,
			       strlen(path1) + 1) == 0);

			So(nng_listener_start(l, 0) == 0);
		})
	});

	Convey("We can create a zt dialer", {
		nng_dialer d;
		nng_socket s;
		char       addr[NNG_MAXADDRLEN];
		int        rv;
		// uint64_t   node = 0xb000072fa6ull; // my personal host
		uint64_t node = 0x2d2f619cccull; // my personal host

		snprintf(addr, sizeof(addr), "zt://" NWID "/%llx:%u",
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
		int          rv;
		uint64_t     node1 = 0;
		uint64_t     node2 = 0;

		snprintf(addr, sizeof(addr), "zt://" NWID ":%u", port);

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });

		So(nng_listener_create(&l, s, addr) == 0);

		So(nng_listener_getopt_usec(l, nng_opt_zt_node, &node1) == 0);
		So(node1 != 0);

		Convey("Network name & status options work", {
			char   name[NNG_MAXADDRLEN];
			size_t namesz;
			int    status;

			namesz = sizeof(name);
			nng_usleep(10000000);
			So(nng_listener_getopt(l, nng_opt_zt_network_name,
			       name, &namesz) == 0);
			So(strcmp(name, "nng_test_open") == 0);
			So(nng_listener_getopt_int(
			       l, nng_opt_zt_status, &status) == 0);
			So(status == nng_zt_status_ok);
		});
		Convey("Connection refused works", {
			snprintf(addr, sizeof(addr), "zt://" NWID "/%llx:%u",
			    (unsigned long long) node1, 42u);
			So(nng_dialer_create(&d, s, addr) == 0);
			So(nng_dialer_getopt_usec(
			       d, nng_opt_zt_node, &node2) == 0);
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
		int          rv;
		uint64_t     node;

		port = 9944;
		// uint64_t   node = 0xb000072fa6ull; // my personal host

		snprintf(addr1, sizeof(addr1), "zt://" NWID ":%u", port);

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s1);
			// This sleep allows us to ensure disconnect
			// messages work.
			nng_usleep(1000000);
			nng_close(s2);
		});

		So(nng_listener_create(&l, s1, addr1) == 0);
		So(nng_listener_setopt(
		       l, nng_opt_zt_home, path1, strlen(path1) + 1) == 0);

		So(nng_listener_start(l, 0) == 0);
		node = 0;
		So(nng_listener_getopt_usec(l, nng_opt_zt_node, &node) == 0);
		So(node != 0);

		snprintf(addr2, sizeof(addr2), "zt://" NWID "/%llx:%u",
		    (unsigned long long) node, port);
		So(nng_dialer_create(&d, s2, addr2) == 0);
		So(nng_dialer_setopt(
		       d, nng_opt_zt_home, path2, strlen(path2) + 1) == 0);
		So(nng_dialer_start(d, 0) == 0);

	});

	trantest_test_extended("zt://" NWID "/*:%u", check_props);

	nng_fini();
})
