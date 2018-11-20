//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef _WIN32
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/transport/ipc/ipc.h>

#include "convey.h"
#include "stubs.h"
#include "trantest.h"

#define ADDR "/tmp/ipc_perms_test"

#if defined(__sun)
#define honor_chmod() false
#else
#define honor_chmod() true
#endif

// Inproc tests.

#ifdef _WIN32
TestMain("IPC Permissions", {
	atexit(nng_fini);
	Convey("Given a socket and an IPC listener", {
		nng_socket   s;
		nng_listener l;

		So(nng_rep0_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_listener_create(&l, s, "ipc://" ADDR) == 0);
		Convey("We cannot set perms on Windows", {
			So(nng_listener_setopt_int(l, NNG_OPT_IPC_PERMISSIONS,
			       0444) == NNG_ENOTSUP);
		});
	});
})
#else
TestMain("IPC Permissions", {
	atexit(nng_fini);

	Convey("Given a socket and an IPC listener", {
		nng_socket   s;
		nng_listener l;

		So(nng_rep0_open(&s) == 0);
		Reset({
			nng_close(s);
			unlink(ADDR);
		});
		So(nng_listener_create(&l, s, "ipc://" ADDR) == 0);
		Convey("We can set perms on POSIX", {
			struct stat st;
			So(nng_listener_setopt_int(
			       l, NNG_OPT_IPC_PERMISSIONS, 0444) == 0);
			So(nng_listener_start(l, 0) == 0);
			So(stat(ADDR, &st) == 0);
			So((st.st_mode & 0777) == 0444);

			Convey("And permissions are honored", {
				struct sockaddr_un sa;
				int                cfd;

				if (geteuid() == 0) {
					Skip("Running as root");
				}
				if (!honor_chmod()) {
					Skip("System does not honor chmod");
				}
				strcpy(sa.sun_path, ADDR);
				sa.sun_family = AF_UNIX;
				So((cfd = socket(AF_UNIX, SOCK_STREAM, 0)) >=
				    0);
				Reset({ close(cfd); });
				So(connect(cfd, (void *) &sa, sizeof(sa)) < 0);
				So(errno == EACCES);
			});
		});

		Convey("We cannot set perms after it is started", {
			So(nng_listener_start(l, 0) == 0);
			So(nng_listener_setopt_int(
			       l, NNG_OPT_IPC_PERMISSIONS, 0444) == NNG_EBUSY);
		});

		Convey("We cannot set bogus permissions", {
			So(nng_listener_setopt_int(l, NNG_OPT_IPC_PERMISSIONS,
			       S_IFREG) == NNG_EINVAL);
		});
	});

	Convey("We cannot set perms on an IPC dialer", {
		nng_socket s;
		nng_dialer d;

		So(nng_rep0_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_dialer_create(&d, s, "ipc://" ADDR) == 0);
		So(nng_dialer_setopt_int(d, NNG_OPT_IPC_PERMISSIONS, 0444) ==
		    NNG_ENOTSUP);
	});
})
#endif
