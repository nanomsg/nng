// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitoar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This program serves as an example for how to write an async RPC service,
// using the RAW request/reply pattern and nn_poll.  The server receives
// messages and keeps them on a list, replying to them.

// Our demonstration application layer protocol is simple.  The client sends
// a number of milliseconds to wait before responding.  The server just gives
// back an empty reply after waiting that long.

// To run this program, start the server as async_demo <url> -s
// Then connect to it with the client as async_client <url> <msec>.
//
//  For example:
//
//  % ./async tcp://127.0.0.1:5555 -s &
//  % ./async tcp://127.0.0.1:5555 323
//  Request took 324 milliseconds.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

// Parallel is the maximum number of outstanding requests we can handle.
// This is *NOT* the number of threads in use, but instead represents
// outstanding work items.  Select a small number to reduce memory size.
// (Each one of these can be thought of as a request-reply loop.)
#ifndef PARALLEL
#define PARALLEL 32
#endif

// The server keeps a list of work items, sorted by expiration time,
// so that we can use this to set the timeout to the correct value for
// use in poll.
struct work {
	enum { INIT, RECV, WAIT, SEND } state;
	nng_aio *  aio;
	nng_socket sock;
	nng_msg *  msg;
};

void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

void
server_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg;
	int          rv;
	uint32_t     when;

	switch (work->state) {
	case INIT:
		work->state = RECV;
		nng_recv_aio(work->sock, work->aio);
		break;
	case RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			fatal("nng_recv_aio", rv);
		}
		msg = nng_aio_get_msg(work->aio);
		if ((rv = nng_msg_trim_u32(msg, &when)) != 0) {
			// bad message, just ignore it.
			nng_msg_free(msg);
			nng_recv_aio(work->sock, work->aio);
			return;
		}
		work->msg   = msg;
		work->state = WAIT;
		nng_sleep_aio(when, work->aio);
		break;
	case WAIT:
		// We could add more data to the message here.
		nng_aio_set_msg(work->aio, work->msg);
		work->msg   = NULL;
		work->state = SEND;
		nng_send_aio(work->sock, work->aio);
		break;
	case SEND:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			fatal("nng_send_aio", rv);
		}
		work->state = RECV;
		nng_recv_aio(work->sock, work->aio);
		break;
	default:
		fatal("bad state!", NNG_ESTATE);
		break;
	}
}

struct work *
alloc_work(nng_socket sock)
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, server_cb, w)) != 0) {
		fatal("nng_aio_alloc", rv);
	}
	w->state = INIT;
	w->sock  = sock;
	return (w);
}

// The server runs forever.
int
server(const char *url)
{
	nng_socket   sock;
	struct work *works[PARALLEL];
	int          rv;
	int          i;

	/*  Create the socket. */
	rv = nng_rep0_open_raw(&sock);
	if (rv != 0) {
		fatal("nng_rep0_open", rv);
	}

	for (i = 0; i < PARALLEL; i++) {
		works[i] = alloc_work(sock);
	}

	if ((rv = nng_listen(sock, url, NULL, 0)) != 0) {
		fatal("nng_listen", rv);
	}

	for (i = 0; i < PARALLEL; i++) {
		server_cb(works[i]); // this starts them going (INIT state)
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
}

/*  The client runs just once, and then returns. */
int
client(const char *url, const char *msecstr)
{
	nng_socket sock;
	int        rv;
	nng_msg *  msg;
	nng_time   start;
	nng_time   end;
	unsigned   msec;

	msec = atoi(msecstr) * 1000;

	if ((rv = nng_req0_open(&sock)) != 0) {
		fatal("nng_req0_open", rv);
	}

	if ((rv = nng_dial(sock, url, NULL, 0)) != 0) {
		fatal("nng_dial", rv);
	}

	start = nng_clock();

	if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
		fatal("nng_msg_alloc", rv);
	}
	if ((rv = nng_msg_append_u32(msg, msec)) != 0) {
		fatal("nng_msg_append_u32", rv);
	}

	if ((rv = nng_sendmsg(sock, msg, 0)) != 0) {
		fatal("nng_send", rv);
	}

	if ((rv = nng_recvmsg(sock, &msg, 0)) != 0) {
		fatal("nng_recvmsg", rv);
	}
	end = nng_clock();
	nng_msg_free(msg);
	nng_close(sock);

	printf("Request took %u milliseconds.\n", (uint32_t)(end - start));
	return (0);
}

int
main(int argc, char **argv)
{
	int rc;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <url> [-s|<secs>]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	if (strcmp(argv[2], "-s") == 0) {
		rc = server(argv[1]);
	} else {
		rc = client(argv[1], argv[2]);
	}
	exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
