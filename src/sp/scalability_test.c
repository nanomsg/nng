//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
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

#include <nuts.h>

static int nclients = 200;

static char *addr = "inproc:///atscale";
nng_socket   rep;
nng_thread  *server;

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

int
openclients(nng_socket *clients, int num)
{
	int          i;
	nng_duration t;
	for (i = 0; i < num; i++) {
		t = 100; // 100ms
		nng_socket c;
		NUTS_PASS(nng_req_open(&c));
		NUTS_PASS(nng_socket_set_ms(c, NNG_OPT_RECVTIMEO, t));
		NUTS_PASS(nng_socket_set_ms(c, NNG_OPT_SENDTIMEO, t));
		NUTS_PASS(nng_dial(c, addr, NULL, 0));
		clients[i] = c;
	}
	return (0);
}

int
transact(nng_socket *clients, int num)
{
	nng_msg *msg;
	int      rv = 0;
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

void
test_scalability(void)
{
	nng_socket *clients;
	int        *results;

	clients = calloc(nclients, sizeof(nng_socket));
	results = calloc(nclients, sizeof(int));

	NUTS_PASS(nng_rep_open(&rep));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_RECVBUF, 256));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_SENDBUF, 256));
	NUTS_PASS(nng_listen(rep, addr, NULL, 0));
	NUTS_PASS(nng_thread_create(&server, serve, NULL));

	int i;
	NUTS_TRUE(openclients(clients, nclients) == 0);
	NUTS_TRUE(transact(clients, nclients) == 0);
	for (i = 0; i < nclients; i++) {
		NUTS_CLOSE(clients[i]);
	}
	NUTS_CLOSE(rep);
	nng_thread_destroy(server);

	free(clients);
	free(results);
}

NUTS_TESTS = {
	{ "scalability", test_scalability },
	{ NULL, NULL },
};
