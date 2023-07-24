// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitoar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This program is just a simple client application for our demo server.
// It is in a separate file to keep the server code clearer to understand.
//
// Our demonstration application layer protocol is simple.  The client sends
// a number of milliseconds to wait before responding.  The server just gives
// back an empty reply after waiting that long.

//  For example:
//
//  % ./server tcp://127.0.0.1:5555 &
//  % ./client tcp://127.0.0.1:5555 323
//  Request took 324 milliseconds.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
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

	msec = atoi(msecstr);

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
		fatal("nng_sendmsg", rv);
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

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <url> <secs>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	rc = client(argv[1], argv[2]);
	exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
