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

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

static int nclients = 200;

static char *addr = "inproc:///atscale";
nng_socket   rep;
nng_thread * server;

void
serve(void *arg)
{
	nng_msg *msg;
	(void) arg; // unused

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
	int          rv;
	int          i;
	nng_duration t;
	for (i = 0; i < num; i++) {
		t = 100; // 100ms
		nng_socket c;
		if (((rv = nng_req_open(&c)) != 0) ||
		    ((rv = nng_setopt_ms(c, NNG_OPT_RECVTIMEO, t)) != 0) ||
		    ((rv = nng_setopt_ms(c, NNG_OPT_SENDTIMEO, t)) != 0) ||
		    ((rv = nng_dial(c, addr, NULL, 0)) != 0)) {
			return (rv);
		}
		clients[i] = c;
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

		if (((rv = nng_msg_alloc(&msg, 0)) != 0) ||
		    ((rv = nng_sendmsg(clients[i], msg, 0)) != 0) ||
		    ((rv = nng_recvmsg(clients[i], &msg, 0)) != 0)) {
			// We may leak a message, but this is an
			// error case anyway.
			break;
		}
		nng_msg_free(msg);
		msg = NULL;
	}
	return (rv);
}

Main({
	nng_socket *clients;
	int *       results;

	atexit(stop);

	clients = calloc(nclients, sizeof(nng_socket));
	results = calloc(nclients, sizeof(int));

	if ((nng_rep_open(&rep) != 0) ||
	    (nng_setopt_int(rep, NNG_OPT_RECVBUF, 256) != 0) ||
	    (nng_setopt_int(rep, NNG_OPT_SENDBUF, 256) != 0) ||
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

	free(clients);
	free(results);
})
