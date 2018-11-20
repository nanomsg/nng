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
#include <poll.h>
#include <unistd.h>
#define SOCKET int
#else

#define poll WSAPoll
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>

#include <mswsock.h>
#endif

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

bool
isready(SOCKET fd)
{
	struct pollfd pfd;
	pfd.fd      = fd;
	pfd.events  = POLLRDNORM;
	pfd.revents = 0;

	switch (poll(&pfd, 1, 0)) {
	case 0:
		return (false);
	case 1:
		return (true);
	default:
		printf("BAD POLL RETURN!\n");
		abort();
	}
}

TestMain("REQ pollable", {
	atexit(nng_fini);

	Convey("Given a REQ/REP pair", {
		nng_socket req;
		nng_socket rep;
		nng_ctx    ctx;

		So(nng_req0_open(&req) == 0);
		So(nng_rep0_open(&rep) == 0);
		So(nng_ctx_open(&ctx, req) == 0);

		Reset({
			nng_ctx_close(ctx);
			nng_close(req);
			nng_close(rep);
		});
		So(nng_listen(rep, "inproc://ctx1", NULL, 0) == 0);

		Convey("REQ ctx not pollable", {
			int fd;
			So(nng_ctx_open(&ctx, req) == 0);
			Reset({ nng_ctx_close(ctx); });
			So(nng_ctx_getopt_int(ctx, NNG_OPT_SENDFD, &fd) ==
			    NNG_ENOTSUP);
			So(nng_ctx_getopt_int(ctx, NNG_OPT_RECVFD, &fd) ==
			    NNG_ENOTSUP);
		});

		Convey("REQ starts not writable", {
			int fd;

			So(nng_getopt_int(req, NNG_OPT_SENDFD, &fd) == 0);
			So(isready(fd) == false);

			Convey("And becomes writable on connect", {
				So(nng_dial(req, "inproc://ctx1", NULL, 0) ==
				    0);
				nng_msleep(100);
				So(isready(fd) == true);

				Convey("Not writable with message pending", {
					for (int i = 0; i < 10; i++) {
						nng_msg *m;
						So(nng_msg_alloc(&m, 0) == 0);
						// Fill intermediate queues.
						if (nng_sendmsg(req, m,
						        NNG_FLAG_NONBLOCK) !=
						    0) {
							nng_msg_free(m);
						}
					}
					So(isready(fd) == false);
				});
			});
		});

		Convey("REQ starts not readable", {
			int fd;

			So(nng_getopt_int(req, NNG_OPT_RECVFD, &fd) == 0);
			So(isready(fd) == false);

			Convey("And doesn't become readable on connect", {
				So(nng_dial(req, "inproc://ctx1", NULL, 0) ==
				    0);
				nng_msleep(100);
				So(isready(fd) == false);
			});
		});

		Convey("REQ becomes readable", {
			int      fd;
			nng_msg *msg;

			So(nng_dial(req, "inproc://ctx1", NULL, 0) == 0);

			So(nng_msg_alloc(&msg, 0) == 0);
			So(nng_getopt_int(req, NNG_OPT_RECVFD, &fd) == 0);
			So(isready(fd) == false);
			So(nng_msg_append(msg, "xyz", 3) == 0);
			So(nng_sendmsg(req, msg, 0) == 0);
			So(nng_recvmsg(rep, &msg, 0) == 0); // recv on rep
			So(nng_sendmsg(rep, msg, 0) == 0);  // echo it back
			nng_msleep(200); // give time for message to arrive
			So(isready(fd) == true);
			Convey("And is no longer readable after receive", {
				So(nng_recvmsg(req, &msg, 0) == 0);
				nng_msg_free(msg);
				So(isready(fd) == false);
			});
		});
	});
})
