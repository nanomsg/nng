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
#include "nng.h"

#include <string.h>

static int nclients = 200;

static char *addr = "inproc:///atscale";
nng_socket   rep;
void *       server;

void
serve(void *arg)
{
	nng_msg *msg;

	for (;;) {
		msg = NULL;
		if ((nng_recvmsg(rep, &msg, 0) != 0) ||
		    (nng_sendmsg(rep, msg, 0) != 0)) {
			break;
		}
	}
	if (msg != NULL) {
		nng_msg_free(msg);
	}
	nng_close(rep);
}

void
stop(void)
{
	nng_closeall();
	nng_thread_destroy(server);
	nng_fini();
}

int
openclients(nng_socket *clients, int num)
{
	int      rv;
	int      i;
	uint64_t t;
	for (i = 0; i < num; i++) {
		if ((rv = nng_req_open(&clients[i])) != 0) {
			printf("open #%d: %s\n", i, nng_strerror(rv));
			return (rv);
		}
		t  = 100000; // 100ms
		rv = nng_setopt(clients[i], NNG_OPT_RCVTIMEO, &t, sizeof(t));
		if (rv != 0) {
			printf(
			    "setopt(RCVTIMEO) #%d: %s\n", i, nng_strerror(rv));
			return (rv);
		}
		t  = 100000; // 100ms
		rv = nng_setopt(clients[i], NNG_OPT_SNDTIMEO, &t, sizeof(t));
		if (rv != 0) {
			printf(
			    "setopt(SNDTIMEO) #%d: %s\n", i, nng_strerror(rv));
			return (rv);
		}
		rv = nng_dial(clients[i], addr, NULL, 0);
		if (rv != 0) {
			printf("dial #%d: %s\n", i, nng_strerror(rv));
			return (rv);
		}
	}
	return (0);
}

int
transact(nng_socket *clients, int num)
{
	nng_msg *msg;
	int      rv;
	int      i;

	for (i = 0; i < num; i++) {

		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			break;
		}

		if ((rv = nng_sendmsg(clients[i], msg, 0)) != 0) {
			break;
		}

		msg = NULL;
		if ((rv = nng_recvmsg(clients[i], &msg, 0)) != 0) {
			break;
		}
		nng_msg_free(msg);
		msg = NULL;
	}
	if (msg != NULL) {
		nng_msg_free(msg);
	}
	return (rv);
}

Main({
	nng_socket *clients;
	int *       results;
	int         depth = 256;

	atexit(stop);

	clients = calloc(nclients, sizeof(nng_socket));
	results = calloc(nclients, sizeof(int));

	if ((nng_rep_open(&rep) != 0) ||
	    (nng_setopt(rep, NNG_OPT_RCVBUF, &depth, sizeof(depth)) != 0) ||
	    (nng_setopt(rep, NNG_OPT_SNDBUF, &depth, sizeof(depth)) != 0) ||
	    (nng_listen(rep, addr, NULL, 0) != 0) ||
	    (nng_thread_create(&server, serve, NULL) != 0)) {
		fprintf(stderr, "Unable to set up server!\n");
		exit(1);
	}

	Test("Scalability", {
		Convey("We can handle many many clients", {
			int i;
			So(openclients(clients, nclients) == 0);
			So(transact(clients, nclients) == 0);
			for (i = 0; i < nclients; i++) {
				So(nng_close(clients[i]) == 0);
			}
		});
	});
});
