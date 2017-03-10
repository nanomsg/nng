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

#include <string.h>

static int count = 1;
static int nthrs = 100;
static char *addr = "inproc:///atscale";

static void
client(void *arg)
{
	int *result = arg;
	nng_socket s;
	int rv;
	uint64_t timeo;
	nng_msg *msg;
	int i;

	*result = 0;

	if ((rv = nng_open(&s, NNG_PROTO_REQ)) != 0) {
		*result = rv;
		return;
	}

	if ((rv = nng_dial(s, addr, NULL, NNG_FLAG_SYNCH)) != 0) {
		*result = rv;
		nng_close(s);
		return;
	}

	timeo = 40000; // 4 seconds
	if (((rv = nng_setopt(s, NNG_OPT_RCVTIMEO, &timeo, sizeof (timeo))) != 0) ||
	    ((rv = nng_setopt(s, NNG_OPT_SNDTIMEO, &timeo, sizeof (timeo))) != 0)) {
		*result = rv;
		nng_close(s);
		return;
	}

	// Sleep for up to a second before issuing requests to avoid saturating
	// the CPU with bazillions of requests at the same time.

	if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
		*result = rv;
		nng_close(s);
		return;
	}
	if ((rv = nng_msg_append(msg, "abc", strlen("abc"))) != 0) {
		*result = rv;
		nng_msg_free(msg);
		nng_close(s);
		return;
	}

	for (i = 0; i < count; i++) {
		// Sleep for up to a 1ms before issuing requests to
		// avoid saturating the CPU with bazillions of requests at
		// the same time.
		nng_usleep(rand() % 1000);

		// Reusing the same message causes problems as a result of
		// header reuse.
		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			*result = rv;
			nng_close(s);
			return;
		}

		if ((rv = nng_sendmsg(s, msg, 0)) != 0) {
			*result = rv;
			nng_msg_free(msg);
			nng_close(s);
			return;
		}

		if ((rv = nng_recvmsg(s, &msg, 0)) != 0) {
			*result = rv;
			nng_close(s);
			return;
		}

		nng_msg_free(msg);
	}

	nng_close(s);
	*result = 0;
}

void
serve(void *arg)
{
	nng_socket rep = *(nng_socket *)arg;
	nng_msg *msg;

	for (;;) {
		if (nng_recvmsg(rep, &msg, 0) != 0) {
			nng_close(rep);
			return;
		}

		if (nng_sendmsg(rep, msg, 0) != 0) {
			nng_close(rep);
			return;
		}
	}
}

Main({
	int rv;
	void **clients;
	void *server;
	int *results;

	clients = calloc(nthrs, sizeof (void *));
	results = calloc(nthrs, sizeof (int));

	Test("Scalability", {

		Convey("Given a server socket", {
			nng_socket rep;
			int depth = 256;

			So(nng_open(&rep, NNG_PROTO_REP) == 0);

			Reset({
				nng_close(rep);
			})

			So(nng_setopt(rep, NNG_OPT_RCVBUF, &depth, sizeof (depth)) == 0);
			So(nng_setopt(rep, NNG_OPT_SNDBUF, &depth, sizeof (depth)) == 0);
			So(nng_listen(rep, addr, NULL, NNG_FLAG_SYNCH) == 0);

			So(nng_thread_create(&server, serve, &rep) == 0);

			nng_usleep(100000);

			Convey("We can run many many clients", {
				int fails = 0;
				int i;
				for (i = 0; i < nthrs; i++) {
					if ((rv = nng_thread_create(&clients[i], client, &results[i])) != 0) {
						printf("thread create failed: %s", nng_strerror(rv));
						break;
					}
				}
				So(i == nthrs);

				for (i = 0; i < nthrs; i++) {
					nng_thread_destroy(clients[i]);
					fails += (results[i] == 0 ? 0 : 1);
					if (results[i] != 0) {
						printf("%d (%d): %s\n",
							fails, i,
							nng_strerror(results[i]));
					}
				}
				So(fails == 0);

				nng_shutdown(rep);

				nng_thread_destroy(server);
			})
		})

	})
})
