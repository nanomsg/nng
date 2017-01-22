//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#else
#include <unistd.h>
#define	INVALID_SOCKET -1
#endif

// Inproc tests.

TestMain("Poll FDs", {

	Convey("Given a connected pair of sockets", {
		nng_socket s1;
		nng_socket s2;

		So(nng_open(&s1, NNG_PROTO_PAIR) == 0);
		So(nng_open(&s2, NNG_PROTO_PAIR) == 0);
		Reset({
			nng_close(s1);
			nng_close(s2);
		})
		So(nng_listen(s1, "inproc://yeahbaby", NULL, 0) == 0);
		So(nng_dial(s2, "inproc://yeahbaby", NULL, NNG_FLAG_SYNCH) == 0);

		Convey("We can get a recv FD", {
			int fd;
			size_t sz;

			sz = sizeof (fd);
			So(nng_getopt(s1, NNG_OPT_RECVFD, &fd, &sz) == 0);
			So(fd != INVALID_SOCKET);
		})

		Convey("We can get a send FD", {
			int fd;
			size_t sz;

			sz = sizeof (fd);
			So(nng_getopt(s1, NNG_OPT_SENDFD, &fd, &sz) == 0);
			So(fd != INVALID_SOCKET);
		})
	})
})
