//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#ifndef _WIN32
#include <poll.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#else

#define poll WSAPoll
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>

#include <mswsock.h>
#include <ws2tcpip.h>

#endif

#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

TestMain("Poll FDs", {
	Convey("Given a connected pair of sockets", {
		nng_socket s1;
		nng_socket s2;

		So(nng_pair1_open(&s1) == 0);
		So(nng_pair1_open(&s2) == 0);
		Reset({
			nng_close(s1);
			nng_close(s2);
		});
		So(nng_listen(s1, "inproc://yeahbaby", NULL, 0) == 0);
		So(nng_dial(s2, "inproc://yeahbaby", NULL, 0) == 0);
		nng_msleep(50);

		Convey("We can get a recv FD", {
			int    fd;
			size_t sz;

			sz = sizeof(fd);
			So(nng_getopt(s1, NNG_OPT_RECVFD, &fd, &sz) == 0);
			So(fd != (int) INVALID_SOCKET);

			Convey("And it is always the same fd", {
				int fd2;
				sz = sizeof(fd2);
				So(nng_getopt(s1, NNG_OPT_RECVFD, &fd2, &sz) ==
				    0);
				So(fd2 == fd);
			});

			Convey("And they start non pollable", {
				struct pollfd pfd;
				pfd.fd      = fd;
				pfd.events  = POLLIN;
				pfd.revents = 0;

				So(poll(&pfd, 1, 0) == 0);
				So(pfd.revents == 0);
			});

			Convey("But if we write they are pollable", {
				struct pollfd pfd;
				pfd.fd      = fd;
				pfd.events  = POLLIN;
				pfd.revents = 0;

				So(nng_send(s2, "kick", 5, 0) == 0);
				So(poll(&pfd, 1, 1000) == 1);
				So((pfd.revents & POLLIN) != 0);
			});
		});

		Convey("We can get a send FD", {
			int    fd;
			size_t sz;

			sz = sizeof(fd);
			So(nng_getopt(s1, NNG_OPT_SENDFD, &fd, &sz) == 0);
			So(fd != (int) INVALID_SOCKET);
			So(nng_send(s1, "oops", 4, 0) == 0);
		});

		Convey("Must have a big enough size", {
			int    fd;
			size_t sz;
			sz = 1;
			So(nng_getopt(s1, NNG_OPT_RECVFD, &fd, &sz) ==
			    NNG_EINVAL);
			sz = 128;
			So(nng_getopt(s1, NNG_OPT_RECVFD, &fd, &sz) == 0);
			So(sz == sizeof(fd));
		});
	});

	Convey("We cannot get a send FD for PULL", {
		nng_socket s3;
		int        fd;
		So(nng_pull0_open(&s3) == 0);
		Reset({ nng_close(s3); });
		So(nng_getopt_int(s3, NNG_OPT_SENDFD, &fd) == NNG_ENOTSUP);
	});

	Convey("We cannot get a recv FD for PUSH", {
		nng_socket s3;
		int        fd;
		So(nng_push0_open(&s3) == 0);
		Reset({ nng_close(s3); });
		So(nng_getopt_int(s3, NNG_OPT_RECVFD, &fd) == NNG_ENOTSUP);
	});
})
