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

static int   nclients = 2000;
static char *addr     = "inproc:///atscale";

void
serve(void *arg)
{
	nng_socket rep = *(nng_socket *) arg;
	nng_msg *  msg;

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

int
openclients(nng_socket *clients, int num)
{
	int rv;
	int i;
	for (i = 0; i < num; i++) {
		if ((rv = nng_open(&clients[i], NNG_PROTO_REQ)) != 0) {
			printf("open #%d: %s\n", i, nng_strerror(rv));
			return (rv);
		}
		rv = nng_dial(clients[i], addr, NULL, NNG_FLAG_SYNCH);
		if (rv != 0) {
			printf("dial #%d: %s\n", i, nng_strerror(rv));
			return (rv);
		}
	}
	return (0);
}

int
sendreqs(nng_socket *clients, int num)
{
	nng_msg *msg;
	int      rv;
	int      i;
	for (i = 0; i < num; i++) {

		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			printf("alloc #%d: %s\n", i, nng_strerror(rv));
			return (rv);
		}

		if ((rv = nng_sendmsg(clients[i], msg, 0)) != 0) {
			nng_msg_free(msg);
			printf("sendmsg #%d: %s", i, nng_strerror(rv));
			return (rv);
		}
	}
	return (0);
}

int
recvreps(nng_socket *clients, int num)
{
	nng_msg *msg;
	int      rv;
	int      i;
	for (i = 0; i < num; i++) {

		if ((rv = nng_recvmsg(clients[i], &msg, 0)) != 0) {
			printf("sendmsg #%d: %s", i, nng_strerror(rv));
			return (rv);
		}
		nng_msg_free(msg);
	}
	return (0);
}

void
closeclients(nng_socket *clients, int num)
{
	int i;
	for (i = 0; i < num; i++) {
		if (clients[i] > 0) {
			nng_close(clients[i]);
		}
	}
}

Main({
	int         rv;
	nng_socket *clients;
	void *      server;
	int *       results;

	clients = calloc(nclients, sizeof(nng_socket));
	results = calloc(nclients, sizeof(int));

	Test("Scalability", {
		Convey("Given a server socket", {
			nng_socket rep;
			int        depth = 256;

			So(nng_open(&rep, NNG_PROTO_REP) == 0);
			So(nng_setopt(rep, NNG_OPT_RCVBUF, &depth,
			       sizeof(depth)) == 0);
			So(nng_setopt(rep, NNG_OPT_SNDBUF, &depth,
			       sizeof(depth)) == 0);
			So(nng_listen(rep, addr, NULL, NNG_FLAG_SYNCH) == 0);

			So(nng_thread_create(&server, serve, &rep) == 0);

			Reset({
				nng_usleep(1000);
				if (rep != 0) {
					nng_close(rep);
					rep = 0;
				}
			});

			Convey("We can open many many clients", {
				So(openclients(clients, nclients) == 0);
				Reset({ closeclients(clients, nclients); });

				Convey("And we send them messages", {
					So(sendreqs(clients, nclients) == 0);
					Convey("And they receive", {
						So(recvreps(clients,
						       nclients) == 0);
					});
				});
			});
		});
	});
});
