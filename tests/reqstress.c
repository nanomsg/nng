//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
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

char tcp4_template[]   = "tcp://127.0.0.1:%d";
char tcp6_template[]   = "tcp://[::1]:%d";
char inproc_template[] = "inproc://nng_reqstress_%d";
char ipc_template[]    = "ipc:///tmp/nng_reqstress_%d";
char ws_template[]     = "ws://127.0.0.1:%d/nng_reqstress";

char *templates[] = {
	tcp4_template,
// It would be nice to test TCPv6, but CI doesn't support it.
// Outside of CI, it does seem to work though.
#ifdef NNG_TEST_TCPV6
	tcp6_template,
#endif
	inproc_template,
	ipc_template,
#ifdef NNG_TRANSPORT_WS
	ws_template,
#endif
};

#define NTEMPLATES (sizeof(templates) / sizeof(templates[0]))

char **addresses;
int    naddresses;
int    allocaddrs;

typedef struct test_case {
	nng_socket  socket;
	const char *name;
	int         nrecv;
	int         nsend;
	int         nfail;
	nng_aio *   recv_aio;
	nng_aio *   send_aio;
	nng_aio *   time_aio;
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
rep_recv_cb(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_aio_result(c->recv_aio)) != 0) {
		error(c, "recv", rv);
		return;
	}
	c->nrecv++;
	nng_aio_set_msg(c->send_aio, nng_aio_get_msg(c->recv_aio));
	nng_aio_set_msg(c->recv_aio, NULL);
	nng_send_aio(c->socket, c->send_aio);
}

static void
rep_send_cb(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_aio_result(c->send_aio)) != 0) {
		error(c, "send", rv);
		nng_msg_free(nng_aio_get_msg(c->send_aio));
		nng_aio_set_msg(c->send_aio, NULL);
		return;
	}
	c->nsend++;
	nng_recv_aio(c->socket, c->recv_aio);
}

static void
req_time_cb(void *arg)
{
	test_case *c   = arg;
	nng_msg *  msg = NULL;
	int        rv;

	if ((rv = nng_aio_result(c->time_aio)) != 0) {
		error(c, "sleep", rv);
		return;
	}
	(void) snprintf(
	    c->buf, sizeof(c->buf), "%u-%d", c->socket.id, c->nsend);
	if (((rv = nng_msg_alloc(&msg, 0)) != 0) ||
	    ((rv = nng_msg_append(msg, c->buf, strlen(c->buf) + 1)) != 0)) {
		error(c, "alloc", rv);
		nng_msg_free(msg);
		return;
	}
	nng_aio_set_msg(c->send_aio, msg);
	nng_send_aio(c->socket, c->send_aio);
}

static void
req_recv_cb(void *arg)
{
	test_case *c   = arg;
	nng_msg *  msg = NULL;
	int        rv;

	if ((rv = nng_aio_result(c->recv_aio)) != 0) {
		error(c, "recv", rv);
		return;
	}

	msg = nng_aio_get_msg(c->recv_aio);
	if ((nng_msg_len(msg) != (strlen(c->buf) + 1)) ||
	    (strcmp(c->buf, nng_msg_body(msg)) != 0)) {
		error(c, "msg mismatch", rv);
		nng_msg_free(msg);
		return;
	}

	nng_msg_free(msg);
	memset(c->buf, 0, sizeof(c->buf));

	c->nrecv++;
	nng_sleep_aio(rand() % 10, c->time_aio);
}

static void
req_send_cb(void *arg)
{
	test_case *c = arg;
	int        rv;

	if ((rv = nng_aio_result(c->send_aio)) != 0) {
		error(c, "send", rv);
		nng_msg_free(nng_aio_get_msg(c->send_aio));
		nng_aio_set_msg(c->send_aio, NULL);
		return;
	}
	c->nsend++;
	nng_recv_aio(c->socket, c->recv_aio);
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

	if (((rv = nng_aio_alloc(&srv->send_aio, rep_send_cb, srv)) != 0) ||
	    ((rv = nng_aio_alloc(&srv->recv_aio, rep_recv_cb, srv)) != 0)) {
		fatal("nng_aio_alloc", rv);
	}

	nng_recv_aio(srv->socket, srv->recv_aio);

	for (i = 1; i < ntests; i++) {
		cli = &cases[curcase++];

		if (((rv = nng_aio_alloc(&cli->send_aio, req_send_cb, cli)) !=
		        0) ||
		    ((rv = nng_aio_alloc(&cli->recv_aio, req_recv_cb, cli)) !=
		        0) ||
		    ((rv = nng_aio_alloc(&cli->time_aio, req_time_cb, cli)) !=
		        0)) {
			fatal("nng_aio_alloc", rv);
		}

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

		nng_sleep_aio(1, cli->time_aio);
	}
}

Main({
	int   i;
	int   tmo;
	char *str;

	atexit(nng_fini);

	if (((str = ConveyGetEnv("STRESSTIME")) == NULL) ||
	    ((tmo = atoi(str)) < 1)) {
		tmo = 30;
	}
	// We have to keep this relatively low by default because some
	// platforms don't support large numbers of sockets.  (On macOS
	// laptop I can run this with 500 though.)
	if (((str = ConveyGetEnv("STRESSPRESSURE")) == NULL) ||
	    ((ncases = atoi(str)) < 1)) {
		ncases = 32;
	}

	// Each run should truly be random.
	srand((int) time(NULL));

	// Reduce the likelihood of address in use conflicts between
	// subsequent runs.
	next_port += (rand() % 100) * 100;

	i = ncases;

	cases = calloc(ncases, sizeof(test_case));
	while (i > 1) {
		int x = rand() % NTEMPLATES;
		if (x > i) {
			x = i;
		}
		reqrep_test(x);
		i -= x;
	}

	dprintf("WAITING for %d sec...\n", tmo);
	nng_msleep(tmo * 1000); // sleep 30 sec

	// Close the timeouts first, before closing sockets.  This tends to
	// ensure that we complete exchanges.
	for (i = 0; i < ncases; i++) {
		nng_aio_stop(cases[i].time_aio);
	}
	nng_msleep(100);
	nng_closeall();

	Test("Req/Rep Stress", {
		Convey("All tests worked", {
			for (i = 0; i < ncases; i++) {
				nng_aio_stop(cases[i].recv_aio);
				nng_aio_stop(cases[i].send_aio);
				nng_aio_stop(cases[i].time_aio);
				nng_aio_free(cases[i].recv_aio);
				nng_aio_free(cases[i].send_aio);
				nng_aio_free(cases[i].time_aio);
				if (cases[i].name != NULL) {
					dprintf(
					    "RESULT socket %u (%s) sent %d "
					    "recd %d fail %d\n",
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

	free(cases);
})
