//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"

#include "protocol/bus0/bus.h"
#include "protocol/pair0/pair.h"
#include "protocol/pair1/pair.h"
#include "protocol/pipeline0/pull.h"
#include "protocol/pipeline0/push.h"
#include "protocol/pubsub0/pub.h"
#include "protocol/pubsub0/sub.h"
#include "protocol/reqrep0/rep.h"
#include "protocol/reqrep0/req.h"
#include "protocol/survey0/respond.h"
#include "protocol/survey0/survey.h"
#include "supplemental/util/platform.h"
#include "transport/inproc/inproc.h"
#include "transport/ipc/ipc.h"
#include "transport/tcp/tcp.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "stubs.h"

#ifdef NDEBUG
#define dprintf(...)
#else
#define dprintf printf
#endif

static int next_port = 20000; // port number kind of.

const char *tcp4_template   = "tcp://127.0.0.1:%d";
const char *tcp6_template   = "tcp://[::1]:%d";
const char *inproc_template = "inproc://nng_multistress_%d";
const char *ipc_template    = "ipc:///tmp/nng_multistress_%d";

const char *templates[] = {
#ifdef NNG_TRANSPORT_TCP
	"tcp://127.0.0.1:%d",
#endif
// It would be nice to test TCPv6, but CI doesn't support it.
// Outside of CI, it does seem to work though.
#ifdef NNG_TEST_TCPV6
	"tcp://[::1]:%d",
#endif
#ifdef NNG_TRANSPORT_INPROC
	"inproc://nng_multistress_%d",
#endif
#ifdef NNG_TRANSPORT_IPC
	"ipc:///tmp/nng_multistress_%d",
#endif
};

#define NTEMPLATES (sizeof(templates) / sizeof(templates[0]))

char **addresses;
int    naddresses;
int    allocaddrs;

typedef struct test_case {
	nng_socket  socket;
	const char *name;
	nng_thread *thr;
	int         nrecv;
	int         nsend;
	int         nfail;
} test_case;

static test_case *cases;
int               ncases;
int               curcase;

void
fatal(const char *msg, int rv)
{
	fprintf(stderr, "%s: %s\n", msg, nng_strerror(rv));
	abort();
}

void
error(test_case *c, const char *msg, int rv)
{
	if (rv == NNG_ECLOSED) {
		return;
	}
	fprintf(
	    stderr, "%s: %s: %s (%d)\n", c->name, msg, nng_strerror(rv), rv);
	c->nfail++;
}

// Get a random address -- TCP, IP, whatever.
char *
getaddr(char *buf)
{
	int i;
	i = rand() % NTEMPLATES;

	snprintf(buf, NNG_MAXADDRLEN, templates[i], next_port++);
	return (buf);
}

// Request/Reply test.  For this test, we open a server socket,
// and bind it to each protocol.  Then we run a bunch of clients
// against it.  The

// Simple rep echo server.
static void
rep_server(void *arg)
{
	test_case *c = arg;
	for (;;) {
		int        rv;
		nng_msg *  msg;
		nng_socket rep = c->socket;

		if ((rv = nng_recvmsg(rep, &msg, 0)) != 0) {
			error(c, "recvmsg", rv);
			return;
		}
		c->nrecv++;
		if ((rv = nng_sendmsg(rep, msg, 0)) != 0) {
			nng_msg_free(msg);
			error(c, "sendmsg", rv);
			return;
		}
		c->nsend++;
	}
}

static void
req_client(void *arg)
{
	test_case *c = arg;
	for (;;) {
		int        rv;
		nng_socket req = c->socket;
		int        num = 0;
		nng_msg *  msg;
		char       buf[32];

		(void) snprintf(buf, sizeof(buf), "%u-%d", req.id, num++);

		nng_msleep(rand() % 10);

		if (((rv = nng_msg_alloc(&msg, 0)) != 0) ||
		    ((rv = nng_msg_append(msg, buf, strlen(buf) + 1)) != 0)) {
			error(c, "alloc fail", rv);
			return;
		}

		if ((rv = nng_sendmsg(req, msg, 0)) != 0) {
			error(c, "sendmsg", rv);
			return;
		}
		c->nsend++;
		if ((rv = nng_recvmsg(req, &msg, 0)) != 0) {
			error(c, "recvmsg", rv);
			return;
		}
		c->nrecv++;

		if (strcmp(nng_msg_body(msg), buf) != 0) {
			error(c, "mismatched message", NNG_EINTERNAL);
			return;
		}

		nng_msg_free(msg);
	}
}

void
reqrep_test(int ntests)
{
	test_case *srv, *cli;
	int        i;
	char       addr[NNG_MAXADDRLEN];
	int        rv;

	if (ntests < 2) {
		// Need a client *and* a server.
		return;
	}

	srv       = &cases[curcase++];
	srv->name = "rep";

	if ((rv = nng_rep0_open(&srv->socket)) != 0) {
		fatal("nng_rep0_open", rv);
	}

	if ((rv = nng_thread_create(&srv->thr, rep_server, srv)) != 0) {
		fatal("nng_thread_create", rv);
	}

	for (i = 1; i < ntests; i++) {
		cli = &cases[curcase++];
		if ((rv = nng_req0_open(&cli->socket)) != 0) {
			fatal("nng_req0_open", rv);
		}

		cli->name = "req";
		getaddr(addr);
		dprintf("DOING reqrep0 (req %u rep %u) address: %s\n",
		    cli->socket.id, srv->socket.id, addr);

		if ((rv = nng_listen(srv->socket, addr, NULL, 0)) != 0) {
			fatal("nng_listen", rv);
		}
		if ((rv = nng_dial(cli->socket, addr, NULL, 0)) != 0) {
			fatal("nng_dial", rv);
		}

		if ((rv = nng_thread_create(&cli->thr, req_client, cli)) !=
		    0) {
			fatal("nng_thread_create", rv);
		}
	}
}

void
pair0_bouncer(void *arg)
{
	test_case *c = arg;
	for (;;) {
		nng_msg *msg;
		int      r;
		int      rv;

		nng_msleep(rand() % 10);

		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			error(c, "alloc", rv);
			return;
		}

		r = rand();
		if ((rv = nng_msg_append(msg, &r, sizeof(r))) != 0) {
			error(c, "msg_append", rv);
			return;
		}

		if ((rv = nng_sendmsg(c->socket, msg, 0)) != 0) {
			error(c, "sendmsg", rv);
			return;
		}
		c->nsend++;

		if ((rv = nng_recvmsg(c->socket, &msg, 0)) != 0) {
			error(c, "recvmsg", rv);
			return;
		}
		c->nrecv++;
		nng_msg_free(msg);
	}
}

void
pair0_test(void)
{
	test_case *srv, *cli;
	char       addr[NNG_MAXADDRLEN];
	int        rv;

	srv       = &cases[curcase++];
	srv->name = "pair0";

	if ((rv = nng_pair0_open(&srv->socket)) != 0) {
		fatal("nng_pair0_open", rv);
	}

	if ((rv = nng_thread_create(&srv->thr, pair0_bouncer, srv)) != 0) {
		fatal("nng_thread_create", rv);
	}

	cli       = &cases[curcase++];
	cli->name = "pair0";

	if ((rv = nng_pair0_open(&cli->socket)) != 0) {
		fatal("nng_pair0_open", rv);
	}

	if ((rv = nng_thread_create(&cli->thr, pair0_bouncer, cli)) != 0) {
		fatal("nng_thread_create", rv);
	}

	getaddr(addr);
	dprintf("DOING pair0 (%u, %u) address: %s\n", cli->socket.id,
	    srv->socket.id, addr);

	if ((rv = nng_listen(srv->socket, addr, NULL, 0)) != 0) {
		fatal("nng_listen", rv);
	}
	if ((rv = nng_dial(cli->socket, addr, NULL, 0)) != 0) {
		fatal("nng_dial", rv);
	}
}

void
bus0_bouncer(void *arg)
{
	test_case *c = arg;
	for (;;) {
		nng_msg *msg;
		int      r;
		int      rv;

		nng_msleep(rand() % 10);

		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			error(c, "alloc", rv);
			return;
		}

		r = rand();
		if ((rv = nng_msg_append(msg, &r, sizeof(r))) != 0) {
			error(c, "msg_append", rv);
			return;
		}

		if ((rv = nng_sendmsg(c->socket, msg, 0)) != 0) {
			error(c, "sendmsg", rv);
			return;
		}
		c->nsend++;

		if ((rv = nng_recvmsg(c->socket, &msg, 0)) != 0) {
			error(c, "recvmsg", rv);
			return;
		}
		c->nrecv++;
		nng_msg_free(msg);
	}
}

// We just do 1:1 for bus for now.
void
bus_test(void)
{
	test_case *srv, *cli;
	char       addr[NNG_MAXADDRLEN];
	int        rv;

	srv       = &cases[curcase++];
	srv->name = "bus0";

	if ((rv = nng_bus0_open(&srv->socket)) != 0) {
		fatal("nng_bus0_open", rv);
	}

	if ((rv = nng_thread_create(&srv->thr, bus0_bouncer, srv)) != 0) {
		fatal("nng_thread_create", rv);
	}

	cli       = &cases[curcase++];
	cli->name = "pair0";

	if ((rv = nng_bus0_open(&cli->socket)) != 0) {
		fatal("nng_bus0_open", rv);
	}

	if ((rv = nng_thread_create(&cli->thr, pair0_bouncer, cli)) != 0) {
		fatal("nng_thread_create", rv);
	}

	getaddr(addr);
	dprintf("DOING bus0 (%u, %u) address: %s\n", cli->socket.id,
	    srv->socket.id, addr);

	if ((rv = nng_listen(srv->socket, addr, NULL, 0)) != 0) {
		fatal("nng_listen", rv);
	}
	if ((rv = nng_dial(cli->socket, addr, NULL, 0)) != 0) {
		fatal("nng_dial", rv);
	}
}

void
pub0_sender(void *arg)
{
	test_case *c = arg;
	for (;;) {
		nng_msg *msg;
		int      rv;

		nng_msleep(rand() % 10);

		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			error(c, "alloc", rv);
			return;
		}

		if ((rv = nng_msg_append(msg, "SUB", 4)) != 0) {
			error(c, "msg_append", rv);
			return;
		}

		if ((rv = nng_sendmsg(c->socket, msg, 0)) != 0) {
			error(c, "sendmsg", rv);
			return;
		}
		c->nsend++;
	}
}

void
sub0_receiver(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_setopt(c->socket, NNG_OPT_SUB_SUBSCRIBE, "", 0)) != 0) {
		error(c, "subscribe", rv);
		return;
	}
	for (;;) {
		nng_msg *msg;

		if ((rv = nng_recvmsg(c->socket, &msg, 0)) != 0) {
			error(c, "recvmsg", rv);
			return;
		}
		c->nrecv++;
		nng_msg_free(msg);
	}
}

void
pubsub_test(int ntests)
{
	test_case *srv, *cli;
	int        i;
	char       addr[NNG_MAXADDRLEN];
	int        rv;

	if (ntests < 2) {
		// Need a client *and* a server.
		return;
	}

	srv       = &cases[curcase++];
	srv->name = "pub";

	if ((rv = nng_pub0_open(&srv->socket)) != 0) {
		fatal("nng_pub0_open", rv);
	}

	if ((rv = nng_thread_create(&srv->thr, pub0_sender, srv)) != 0) {
		fatal("nng_thread_create", rv);
	}

	for (i = 1; i < ntests; i++) {
		cli = &cases[curcase++];
		if ((rv = nng_sub0_open(&cli->socket)) != 0) {
			fatal("nng_sub0_open", rv);
		}

		cli->name = "sub";
		getaddr(addr);
		dprintf("DOING pubsub0 (pub %u sub %u) address: %s\n",
		    cli->socket.id, srv->socket.id, addr);

		if ((rv = nng_listen(srv->socket, addr, NULL, 0)) != 0) {
			fatal("nng_listen", rv);
		}
		if ((rv = nng_dial(cli->socket, addr, NULL, 0)) != 0) {
			fatal("nng_dial", rv);
		}

		if ((rv = nng_thread_create(&cli->thr, sub0_receiver, cli)) !=
		    0) {
			fatal("nng_thread_create", rv);
		}
	}
}

void
pipeline0_pusher(void *arg)
{
	test_case *c = arg;
	for (;;) {
		nng_msg *msg;
		int      rv;

		nng_msleep(rand() % 10);

		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			error(c, "alloc", rv);
			return;
		}

		if ((rv = nng_msg_append(msg, "PUSH", 5)) != 0) {
			error(c, "msg_append", rv);
			return;
		}

		if ((rv = nng_sendmsg(c->socket, msg, 0)) != 0) {
			error(c, "sendmsg", rv);
			return;
		}
		c->nsend++;
	}
}

void
pipeline0_puller(void *arg)
{
	test_case *c = arg;
	int        rv;

	for (;;) {
		nng_msg *msg;

		if ((rv = nng_recvmsg(c->socket, &msg, 0)) != 0) {
			error(c, "recvmsg", rv);
			return;
		}
		c->nrecv++;
		nng_msg_free(msg);
	}
}

void
pipeline0_test(int ntests)
{
	test_case *srv, *cli;
	int        i;
	char       addr[NNG_MAXADDRLEN];
	int        rv;

	if (ntests < 2) {
		// Need a client *and* a server.
		return;
	}

	srv       = &cases[curcase++];
	srv->name = "push";

	if ((rv = nng_push0_open(&srv->socket)) != 0) {
		fatal("nng_push0_open", rv);
	}

	if ((rv = nng_thread_create(&srv->thr, pipeline0_pusher, srv)) != 0) {
		fatal("nng_thread_create", rv);
	}

	for (i = 1; i < ntests; i++) {
		cli = &cases[curcase++];
		if ((rv = nng_pull0_open(&cli->socket)) != 0) {
			fatal("nng_pull0_open", rv);
		}

		cli->name = "pull";
		getaddr(addr);
		dprintf("DOING pipeline0 (pull %u push %u) address: %s\n",
		    cli->socket.id, srv->socket.id, addr);

		if ((rv = nng_listen(srv->socket, addr, NULL, 0)) != 0) {
			fatal("nng_listen", rv);
		}
		if ((rv = nng_dial(cli->socket, addr, NULL, 0)) != 0) {
			fatal("nng_dial", rv);
		}

		if ((rv = nng_thread_create(
		         &cli->thr, pipeline0_puller, cli)) != 0) {
			fatal("nng_thread_create", rv);
		}
	}
}

Main({
	int i;

	// Each run should truly be random.
	srand((int) time(NULL));

	// Reduce the likelihood of address in use conflicts between
	// subsequent runs.
	next_port += (rand() % 100) * 100;

	// We have to keep this relatively low because some platforms
	// don't support large numbers of threads.
	ncases = 32;

	i = ncases;

	cases = calloc(ncases, sizeof(test_case));
	while (i > 1) {
		int x = rand() % NTEMPLATES;
		if (x > i) {
			x = i;
		}
		switch (rand() % 5) {
		case 0:
			reqrep_test(x);
			break;
		case 1:
			pair0_test();
			x = 2; // pair is always 2
			break;
		case 2:
			pubsub_test(x);
			break;
		case 3:
			bus_test();
			x = 2; // pair is always 2
			break;
		case 4:
			pipeline0_test(x);
			break;
		default:
			// that didn't work
			break;
		}
		i -= x;
	}

	dprintf("WAITING for 30 sec...\n");
	nng_msleep(30000); // sleep 30 sec
	nng_closeall();

	Test("MultiProtocol/Transport Stress", {
		Convey("All tests worked", {
			for (i = 0; i < ncases; i++) {
				if (cases[i].thr != NULL) {
					nng_thread_destroy(cases[i].thr);
					dprintf(
					    "RESULT socket %u (%s) sent %d "
					    "recd "
					    "%d fail %d\n",
					    cases[i].socket.id, cases[i].name,
					    cases[i].nsend, cases[i].nrecv,
					    cases[i].nfail);
					So(cases[i].nfail == 0);
					So(cases[i].nsend > 0 ||
					    cases[i].nrecv > 0);
				}
			}
		});
	});
})
