//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/select.h>
#include <sys/time.h>
#endif

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

const char *addr = "inproc://bug346";

void
repthr(void *arg)
{
	nng_socket   rep = *(nng_socket *) arg;
	nng_listener l;
	int          ifd;
	PLATFD       fd;

	nng_listen(rep, addr, &l, NNG_FLAG_NONBLOCK);

	nng_getopt_int(rep, NNG_OPT_RECVFD, &ifd);
	fd = ifd;

	for (;;) {
		fd_set         fset;
		struct timeval tmo;
		char *         msgbuf;
		size_t         msglen;

		FD_ZERO(&fset);
		FD_SET(fd, &fset);

		tmo.tv_sec  = 0;
		tmo.tv_usec = 20 * 1000; // 20 msec

		select(1, &fset, NULL, NULL, &tmo);

		for (;;) {
			int rv;
			rv = nng_recv(rep, &msgbuf, &msglen,
			    NNG_FLAG_NONBLOCK | NNG_FLAG_ALLOC);
			if (rv != 0) {
				return;
			}
			nng_free(msgbuf, msglen);
			int ok = 0;
			rv     = nng_send(rep, &ok, 4, NNG_FLAG_NONBLOCK);
			if (rv == NNG_ECLOSED) {
				return;
			}
		}
	}
}

void
reqthr(void *arg)
{
	nng_socket req = *(nng_socket *) arg;

	nng_dial(req, addr, NULL, NNG_FLAG_NONBLOCK);

	int query = 0;
	// We just keep pounding out requests, no wait for response.
	for (;;) {
		int rv;
		rv = nng_send(req, &query, sizeof(query), 0);
		if (rv == NNG_ECLOSED) {
			return;
		}
		nng_msleep(50);
	}
}

#define NCLIENTS 10
nng_socket reqs[NCLIENTS];
nng_socket rep;

TestMain("Nonblocking Works", {
	atexit(nng_fini);

	Convey("Running for 15 sec", {
		nng_thread *server;
		nng_thread *clients[NCLIENTS];

		So(nng_rep0_open(&rep) == 0);
		for (int i = 0; i < NCLIENTS; i++) {
			So(nng_req0_open(&reqs[i]) == 0);
		}

		nng_thread_create(&server, repthr, &rep);
		for (int i = 0; i < NCLIENTS; i++) {
			nng_thread_create(&clients[i], reqthr, &reqs[i]);
		}

		nng_msleep(15000);
		nng_close(rep);
		nng_thread_destroy(server);
		for (int i = 0; i < NCLIENTS; i++) {
			nng_close(reqs[i]);
			nng_thread_destroy(clients[i]);
		}
	});
})
