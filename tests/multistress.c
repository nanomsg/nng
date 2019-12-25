//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <nng/nng.h>
#include <nng/protocol/bus0/bus.h>
#include <nng/protocol/pair0/pair.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/pubsub0/sub.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/supplemental/util/platform.h>
#include <nng/transport/inproc/inproc.h>
#include <nng/transport/ipc/ipc.h>
#include <nng/transport/tcp/tcp.h>

#include "convey.h"
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
nng_time    end_time;

const char *templates[] = {
	"tcp://127.0.0.1:%d",
// It would be nice to test TCPv6, but CI doesn't support it.
// Outside of CI, it does seem to work though.
#ifdef NNG_TEST_TCPV6
	"tcp://[::1]:%d",
#endif
	"inproc://nng_multistress_%d",
	"ipc:///tmp/nng_multistress_%d",
};

#define NTEMPLATES (sizeof(templates) / sizeof(templates[0]))

char **addresses;
int    naddresses;
int    allocaddrs;

typedef struct test_case {
	nng_socket  sock;
	const char *name;
	int         nrecv;
	int         nsend;
	int         nfail;
	nng_aio *   recd;
	nng_aio *   sent;
	nng_aio *   woke;
	char        addr[NNG_MAXADDRLEN];
	char        buf[32];

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
	if ((rv == NNG_ECLOSED) || (rv == NNG_ECANCELED)) {
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
// against it.

// REP server implemented via callbacks.
static void
rep0_recd(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_aio_result(c->recd)) != 0) {
		error(c, "recv", rv);
		return;
	}
	c->nrecv++;
	nng_aio_set_msg(c->sent, nng_aio_get_msg(c->recd));
	nng_aio_set_msg(c->recd, NULL);
	nng_send_aio(c->sock, c->sent);
}

static void
rep0_sent(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_aio_result(c->sent)) != 0) {
		error(c, "send", rv);
		nng_msg_free(nng_aio_get_msg(c->sent));
		nng_aio_set_msg(c->sent, NULL);
		return;
	}
	c->nsend++;
	nng_recv_aio(c->sock, c->recd);
}

static void
req0_woke(void *arg)
{
	test_case *c   = arg;
	nng_msg *  msg = NULL;
	int        rv;

	if ((rv = nng_aio_result(c->woke)) != 0) {
		error(c, "sleep", rv);
		return;
	}
	(void) snprintf(c->buf, sizeof(c->buf), "%u-%d", c->sock.id, c->nsend);
	if (((rv = nng_msg_alloc(&msg, 0)) != 0) ||
	    ((rv = nng_msg_append(msg, c->buf, strlen(c->buf) + 1)) != 0)) {
		error(c, "alloc", rv);
		nng_msg_free(msg);
		return;
	}
	nng_aio_set_msg(c->sent, msg);
	nng_send_aio(c->sock, c->sent);
}

static void
req0_recd(void *arg)
{
	test_case *c   = arg;
	nng_msg *  msg = NULL;
	int        rv;

	if ((rv = nng_aio_result(c->recd)) != 0) {
		error(c, "recv", rv);
		return;
	}

	msg = nng_aio_get_msg(c->recd);
	if ((nng_msg_len(msg) != (strlen(c->buf) + 1)) ||
	    (strcmp(c->buf, nng_msg_body(msg)) != 0)) {
		error(c, "msg mismatch", rv);
		nng_msg_free(msg);
		return;
	}

	nng_msg_free(msg);
	memset(c->buf, 0, sizeof(c->buf));

	c->nrecv++;
	nng_sleep_aio(rand() % 10, c->woke);
}

static void
req0_sent(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_aio_result(c->sent)) != 0) {
		error(c, "send", rv);
		nng_msg_free(nng_aio_get_msg(c->sent));
		nng_aio_set_msg(c->sent, NULL);
		return;
	}
	c->nsend++;
	nng_recv_aio(c->sock, c->recd);
}

void
reqrep0_test(int ntests)
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
	srv->name = "rep0";

	if ((rv = nng_rep0_open(&srv->sock)) != 0) {
		fatal("nng_rep0_open", rv);
	}

	if (((rv = nng_aio_alloc(&srv->sent, rep0_sent, srv)) != 0) ||
	    ((rv = nng_aio_alloc(&srv->recd, rep0_recd, srv)) != 0)) {
		fatal("nng_aio_alloc", rv);
	}

	nng_recv_aio(srv->sock, srv->recd);

	for (i = 1; i < ntests; i++) {
		cli       = &cases[curcase++];
		cli->name = "req0";

		if (((rv = nng_aio_alloc(&cli->sent, req0_sent, cli)) != 0) ||
		    ((rv = nng_aio_alloc(&cli->recd, req0_recd, cli)) != 0) ||
		    ((rv = nng_aio_alloc(&cli->woke, req0_woke, cli)) != 0)) {
			fatal("nng_aio_alloc", rv);
		}

		if ((rv = nng_req0_open(&cli->sock)) != 0) {
			fatal("nng_req0_open", rv);
		}

		getaddr(addr);
		dprintf("DOING reqrep0 (req %u rep %u) address: %s\n",
		    cli->sock.id, srv->sock.id, addr);

		if ((rv = nng_listen(srv->sock, addr, NULL, 0)) != 0) {
			fatal("nng_listen", rv);
		}
		if ((rv = nng_dial(cli->sock, addr, NULL, 0)) != 0) {
			fatal("nng_dial", rv);
		}

		nng_sleep_aio(1, cli->woke);
	}
}

// PAIRv0 test.  We just bind two sockets together, and bounce messages at
// each other.  As we don't need to run synchronously, the receive is not
// linked to the send.

static void
pair0_recd(void *arg)
{
	test_case *c = arg;
	int        rv;
	if ((rv = nng_aio_result(c->recd)) != 0) {
		error(c, "recv", rv);
		return;
	}
	c->nrecv++;
	nng_msg_free(nng_aio_get_msg(c->recd));
	nng_recv_aio(c->sock, c->recd);
}

static void
pair0_woke(void *arg)
{
	test_case *c   = arg;
	nng_msg *  msg = NULL;
	int        rv;

	if ((rv = nng_aio_result(c->woke)) != 0) {
		error(c, "sleep", rv);
		return;
	}
	if (((rv = nng_msg_alloc(&msg, 0)) != 0) ||
	    ((rv = nng_msg_append_u32(msg, (unsigned) rand())) != 0)) {
		error(c, "alloc", rv);
		nng_msg_free(msg);
		return;
	}
	nng_aio_set_msg(c->sent, msg);
	nng_send_aio(c->sock, c->sent);
}

static void
pair0_sent(void *arg)
{
	test_case *c = arg;
	int        rv;
	if ((rv = nng_aio_result(c->sent)) != 0) {
		error(c, "send", rv);
		nng_msg_free(nng_aio_get_msg(c->sent));
		nng_aio_set_msg(c->sent, NULL);
		return;
	}
	c->nsend++;
	nng_sleep_aio(rand() % 10, c->woke);
}

void
pair0_test(int ntests)
{
	test_case *srv, *cli;
	char       addr[NNG_MAXADDRLEN];
	int        rv;

	if (ntests < 2) {
		return;
	}
	srv       = &cases[curcase++];
	srv->name = "pair0";
	cli       = &cases[curcase++];
	cli->name = "pair0";

	if (((rv = nng_pair0_open(&srv->sock)) != 0) ||
	    ((rv = nng_pair0_open(&cli->sock)) != 0)) {
		fatal("nng_pair0_open", rv);
	}

	if (((rv = nng_aio_alloc(&srv->sent, pair0_sent, srv)) != 0) ||
	    ((rv = nng_aio_alloc(&srv->recd, pair0_recd, srv)) != 0) ||
	    ((rv = nng_aio_alloc(&srv->woke, pair0_woke, srv)) != 0) ||
	    ((rv = nng_aio_alloc(&cli->sent, pair0_sent, cli)) != 0) ||
	    ((rv = nng_aio_alloc(&cli->recd, pair0_recd, cli)) != 0) ||
	    ((rv = nng_aio_alloc(&cli->woke, pair0_woke, cli)) != 0)) {
		fatal("nng_aio_alloc", rv);
	}

	getaddr(addr);
	dprintf("DOING pair0 (%u, %u) address: %s\n", cli->sock.id,
	    srv->sock.id, addr);

	if ((rv = nng_listen(srv->sock, addr, NULL, 0)) != 0) {
		fatal("nng_listen", rv);
	}
	if ((rv = nng_dial(cli->sock, addr, NULL, 0)) != 0) {
		fatal("nng_dial", rv);
	}

	nng_recv_aio(srv->sock, srv->recd);
	nng_recv_aio(cli->sock, cli->recd);
	nng_sleep_aio(1, srv->woke);
	nng_sleep_aio(1, cli->woke);
}

// BUSv0 test.  We just bind sockets together into a full mesh, and bounce
// messages at each other.  As we don't need to run synchronously, the
// receive is not linked to the send.

static void
bus0_recd(void *arg)
{
	test_case *c = arg;
	int        rv;
	if ((rv = nng_aio_result(c->recd)) != 0) {
		error(c, "recv", rv);
		return;
	}
	c->nrecv++;
	nng_msg_free(nng_aio_get_msg(c->recd));
	nng_recv_aio(c->sock, c->recd);
}

static void
bus0_woke(void *arg)
{
	test_case *c   = arg;
	nng_msg *  msg = NULL;
	int        rv;

	if ((rv = nng_aio_result(c->woke)) != 0) {
		error(c, "sleep", rv);
		return;
	}
	if (((rv = nng_msg_alloc(&msg, 0)) != 0) ||
	    ((rv = nng_msg_append_u32(msg, (unsigned) rand())) != 0)) {
		nng_msg_free(msg);
		error(c, "alloc", rv);
		return;
	}
	nng_aio_set_msg(c->sent, msg);
	nng_send_aio(c->sock, c->sent);
}

static void
bus0_sent(void *arg)
{
	test_case *c = arg;
	int        rv;
	if ((rv = nng_aio_result(c->sent)) != 0) {
		nng_msg_free(nng_aio_get_msg(c->sent));
		nng_aio_set_msg(c->sent, NULL);
		error(c, "send", rv);
		return;
	}
	c->nsend++;
	nng_sleep_aio(rand() % 10, c->woke);
}

void
bus0_test(int ntests)
{

	if (ntests < 2) {
		return;
	}
	for (int i = 0; i < ntests; i++) {
		test_case *c = &cases[curcase + i];
		int        rv;

		getaddr(c->addr);

		c->name = "bus0";
		if (((rv = nng_aio_alloc(&c->recd, bus0_recd, c)) != 0) ||
		    ((rv = nng_aio_alloc(&c->sent, bus0_sent, c)) != 0) ||
		    ((rv = nng_aio_alloc(&c->woke, bus0_woke, c)) != 0)) {
			fatal("nng_aio_alloc", rv);
		}
		if ((rv = nng_bus0_open(&c->sock)) != 0) {
			fatal("nng_bus0_open", rv);
		}
		if ((rv = nng_listen(c->sock, c->addr, NULL, 0)) != 0) {
			fatal("nng_listen", rv);
		}
		dprintf("DOING bus0 (%u) address: %s\n", c->sock.id, c->addr);

		// We dial to everyone else who already listened.
		for (int j = 0; j < i; j++) {
			rv = nng_dial(
			    c->sock, cases[curcase + j].addr, NULL, 0);
			if (rv != 0) {
				fatal("nng_dial", rv);
			}
		}
	}

	for (int i = 0; i < ntests; i++) {
		test_case *c = &cases[curcase++];
		nng_recv_aio(c->sock, c->recd);
		nng_sleep_aio(1, c->woke);
	}
}

void
pub0_woke(void *arg)
{
	test_case *c   = arg;
	nng_msg *  msg = NULL;
	int        rv;

	if ((rv = nng_aio_result(c->woke)) != 0) {
		error(c, "sleep", rv);
		return;
	}
	if (((rv = nng_msg_alloc(&msg, 0)) != 0) ||
	    ((rv = nng_msg_append(msg, "SUB", 4)) != 0)) {
		nng_msg_free(msg);
		error(c, "alloc", rv);
		return;
	}
	nng_aio_set_msg(c->sent, msg);
	nng_send_aio(c->sock, c->sent);
}

void
pub0_sent(void *arg)
{
	test_case *c = arg;
	int        rv;
	if ((rv = nng_aio_result(c->sent)) != 0) {
		nng_msg_free(nng_aio_get_msg(c->sent));
		nng_aio_set_msg(c->sent, NULL);
		error(c, "send", rv);
		return;
	}
	c->nsend++;
	nng_sleep_aio(rand() % 10, c->woke);
}

void
sub0_recd(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_aio_result(c->recd)) != 0) {
		error(c, "recv", rv);
		return;
	}
	c->nrecv++;
	nng_msg_free(nng_aio_get_msg(c->recd));
	nng_aio_set_msg(c->recd, NULL);
	nng_recv_aio(c->sock, c->recd);
}

void
pub0_sender(void *arg)
{
	test_case *c = arg;
	for (;;) {
		nng_msg *msg;
		int      rv;

		nng_msleep(rand() % 10);
		if (nng_clock() > end_time) {
			break;
		}

		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			error(c, "alloc", rv);
			return;
		}

		if ((rv = nng_msg_append(msg, "SUB", 4)) != 0) {
			nng_msg_free(msg);
			error(c, "msg_append", rv);
			return;
		}

		if ((rv = nng_sendmsg(c->sock, msg, 0)) != 0) {
			nng_msg_free(msg);
			error(c, "sendmsg", rv);
			return;
		}
		c->nsend++;
	}
}

void
pubsub0_test(int ntests)
{
	test_case *srv;
	int        rv;

	if (ntests < 2) {
		// Need a client *and* a server.
		return;
	}

	srv       = &cases[curcase++];
	srv->name = "pub0";

	if ((rv = nng_pub0_open(&srv->sock)) != 0) {
		fatal("nng_pub0_open", rv);
	}
	if (((rv = nng_aio_alloc(&srv->sent, pub0_sent, srv)) != 0) ||
	    ((rv = nng_aio_alloc(&srv->woke, pub0_woke, srv)) != 0)) {
		fatal("nng_aio_alloc", rv);
	}

	for (int i = 1; i < ntests; i++) {
		test_case *cli = &cases[curcase++];

		cli->name = "sub0";
		getaddr(cli->addr);

		if ((rv = nng_sub0_open(&cli->sock)) != 0) {
			fatal("nng_sub0_open", rv);
		}
		if ((rv = nng_aio_alloc(&cli->recd, sub0_recd, cli)) != 0) {
			fatal("nng_aio_alloc", rv);
		}
		rv = nng_setopt(cli->sock, NNG_OPT_SUB_SUBSCRIBE, "", 0);
		if (rv != 0) {
			fatal("subscribe", rv);
		}

		dprintf("DOING pubsub0 (pub %u sub %u) address: %s\n",
		    cli->sock.id, srv->sock.id, cli->addr);

		if ((rv = nng_listen(srv->sock, cli->addr, NULL, 0)) != 0) {
			fatal("nng_listen", rv);
		}
		if ((rv = nng_dial(cli->sock, cli->addr, NULL, 0)) != 0) {
			fatal("nng_dial", rv);
		}

		nng_recv_aio(cli->sock, cli->recd);
	}

	nng_sleep_aio(1, srv->woke);
}

void
push0_sent(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_aio_result(c->sent)) != 0) {
		nng_msg_free(nng_aio_get_msg(c->sent));
		nng_aio_set_msg(c->sent, NULL);
		error(c, "send", rv);
		return;
	}

	c->nsend++;
	nng_sleep_aio(rand() % 10, c->woke);
}

void
push0_woke(void *arg)
{
	test_case *c   = arg;
	nng_msg *  msg = NULL;
	int        rv;

	if ((rv = nng_aio_result(c->woke)) != 0) {
		error(c, "sleep", rv);
		return;
	}
	if (((rv = nng_msg_alloc(&msg, 0)) != 0) ||
	    ((rv = nng_msg_append_u32(msg, (unsigned) rand())) != 0)) {
		nng_msg_free(msg);
		error(c, "alloc", rv);
		return;
	}
	nng_aio_set_msg(c->sent, msg);
	nng_send_aio(c->sock, c->sent);
}

void
pull0_recd(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_aio_result(c->recd)) != 0) {
		error(c, "recv", rv);
		return;
	}
	c->nrecv++;
	nng_msg_free(nng_aio_get_msg(c->recd));
	nng_aio_set_msg(c->recd, NULL);
	nng_recv_aio(c->sock, c->recd);
}

void
pipeline0_pusher(void *arg)
{
	test_case *c = arg;
	for (;;) {
		nng_msg *msg;
		int      rv;

		nng_msleep(rand() % 10);
		if (nng_clock() > end_time) {
			break;
		}

		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			error(c, "alloc", rv);
			return;
		}

		if ((rv = nng_msg_append(msg, "PUSH", 5)) != 0) {
			nng_msg_free(msg);
			error(c, "msg_append", rv);
			return;
		}

		if ((rv = nng_sendmsg(c->sock, msg, 0)) != 0) {
			nng_msg_free(msg);
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
		if (nng_clock() > end_time) {
			break;
		}

		if ((rv = nng_recvmsg(c->sock, &msg, 0)) != 0) {
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
	test_case *srv;
	int        rv;

	if (ntests < 2) {
		// Need a client *and* a server.
		return;
	}

	srv       = &cases[curcase++];
	srv->name = "push0";

	if ((rv = nng_push0_open(&srv->sock)) != 0) {
		fatal("nng_push0_open", rv);
	}
	if (((rv = nng_aio_alloc(&srv->sent, push0_sent, srv)) != 0) ||
	    ((rv = nng_aio_alloc(&srv->woke, push0_woke, srv)) != 0)) {
		fatal("nng_aio_alloc", rv);
	}

	for (int i = 1; i < ntests; i++) {
		test_case *cli = &cases[curcase++];

		cli->name = "pull0";
		getaddr(cli->addr);

		if ((rv = nng_pull0_open(&cli->sock)) != 0) {
			fatal("nng_sub0_open", rv);
		}
		if ((rv = nng_aio_alloc(&cli->recd, pull0_recd, cli)) != 0) {
			fatal("nng_aio_alloc", rv);
		}

		dprintf("DOING pipeline0 (pull %u push %u) address: %s\n",
		    cli->sock.id, srv->sock.id, cli->addr);

		if ((rv = nng_listen(srv->sock, cli->addr, NULL, 0)) != 0) {
			fatal("nng_listen", rv);
		}
		if ((rv = nng_dial(cli->sock, cli->addr, NULL, 0)) != 0) {
			fatal("nng_dial", rv);
		}

		nng_recv_aio(cli->sock, cli->recd);
	}

	nng_sleep_aio(1, srv->woke);
}

Main({
	int   i;
	char *str;
	int   tmo;

	atexit(nng_fini);

	// Each run should truly be random.
	srand((int) time(NULL));

	if (((str = ConveyGetEnv("STRESSTIME")) == NULL) ||
	    ((tmo = atoi(str)) < 1)) {
		tmo = 30;
	}
	// We have to keep this relatively low by default because some
	// platforms have limited resources.
	if (((str = ConveyGetEnv("STRESSPRESSURE")) == NULL) ||
	    ((ncases = atoi(str)) < 1)) {
		ncases = 32;
	}

	// Reduce the likelihood of address in use conflicts between
	// subsequent runs.
	next_port += (rand() % 100) * 100;

	i = ncases;

	cases    = calloc(ncases, sizeof(test_case));
	end_time = nng_clock() + (tmo * 1000);
	while (i > 1) {
		int x = rand() % NTEMPLATES;
		if (x > i) {
			x = i;
		}
		switch (rand() % 5) {
		case 0:
			reqrep0_test(x);
			break;
		case 1:
			pair0_test(x);
			break;
		case 2:
			pubsub0_test(x);
			break;
		case 3:
			bus0_test(x);
			break;
		case 4:
			pipeline0_test(x);
			break;
		default:
			// that didn't work
			break;
		}
		i = ncases - curcase;
	}

	dprintf("WAITING for %d sec...\n", tmo);
	nng_msleep(tmo * 1000); // sleep 30 sec
	for (i = 0; i < ncases; i++) {
		nng_aio_stop(cases[i].woke);
	}
	nng_closeall();

	Test("MultiProtocol/Transport Stress", {
		Convey("All tests worked", {
			for (i = 0; i < ncases; i++) {
				test_case *c = &cases[i];
				if (c->name == NULL) {
					break;
				}
				nng_aio_stop(c->sent);
				nng_aio_stop(c->recd);
				nng_aio_stop(c->woke);
				nng_aio_free(c->sent);
				nng_aio_free(c->recd);
				nng_aio_free(c->woke);

				dprintf("RESULT socket %u (%s) sent %d "
				        "recd %d fail %d\n",
				    c->sock.id, c->name, c->nsend, c->nrecv,
				    c->nfail);
				So(c->nfail == 0);
				So((c->sent == NULL) || (c->nsend > 0));
				So((c->recd == NULL) || (c->nrecv > 0));
			}
		});
	});

	free(cases);
})
