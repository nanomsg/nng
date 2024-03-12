// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitoar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This program is an asynchronous client application for our demo
// server. It is in a separate file to keep the server code easier to
// understand.
//
// Our demonstration application layer protocol is simple.  The client
// sends a number of milliseconds to wait before responding.  The client
// does this over three passes, increasing the number of milliseconds to
// wait by 1ms each pass.  The server just sends back an empty reply
// after waiting that long.

//  For example:
//
//  % ./server tcp://127.0.0.1:5555 &
//  % ./aioclient tcp://127.0.0.1:5555 323
//  Client:  (323+0)ms request took 324ms.
//  Client:  (323+1)ms request took 325ms.
//  Client:  (323+2)ms request took 326ms.
//  %

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

// Maintain state within this module; a "work" structure as is done in
// server.c might be better, but for this one-client per run demo this
// is good enough.
static nng_aio *aio  = NULL; // Asynchronous I/O operations
static uint32_t msec = 0;    // Int value of wait in command line, ms
static uint32_t pass = 0;    // Pass number
static nng_ctx  ctx;         // Context
static nng_time start;       // nng_clock at time of request callback
static enum { SEND, RECV, DONE } step = SEND; // Logic state

// Log fatal errors and exit
void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

// Wrapper for asynchronous send of msec (wait, ms) value in request
void
client_send(void)
{
	nng_msg *msg;
	int      rv;

	// Allocate memory for message
	if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
		fatal("nng_msg_alloc", rv);
	}

	// Clear message and append milliseconds wait time
	nng_msg_clear(msg);

	if ((rv = nng_msg_append_u32(msg, msec + pass)) != 0) {
		nng_msg_free(msg);
		fatal("nng_msg_append_u32", rv);
	}

	// Assign message to the aio object
	nng_aio_set_msg(aio, msg);

	// Assign step as SEND ***before*** initiating initiating async
	// send.  Assigning step ***after*** occasionally causes
	// nng_aio_result in client_cb callback below to return invalid
	// NNG state (NNG_ESTATE).  What happens is the callback gets
	// called immediately, ***before*** this async send returns,
	// which sets step to RECV and initiates the async receive, and
	// when the callback later gets called from the async receive,
	// the step is SEND instead of RECV, so the callback issues
	// another async receive, when the req/rep pattern requires it
	// to issue an async send.
	step = SEND;

	// Initiate the asynchronous send
	nng_ctx_send(ctx, aio);

#ifdef ASSIGN_STEP_AFTER
	// This is diagnostic code to causes the intermittent error
	// described above.

	// To compile this code, use [gcc -DASSIGN_STEP_AFTER ...]

	// Pre-iagnose the problem
	if (step == RECV) {
		fprintf(stderr, "Step is RECV in client_send!\n");
	}

	// Assign step ***after*** the asynchronous send
	step = SEND;
#endif
}

// Callback for asynchronous I/O
void
client_cb(void *nul)
{
	int rv;

	switch (step) {
	case RECV:

		// Waited-for message has been received
		fprintf(stderr, "Client:  (%u+%u)ms request took %ums.\n",
		    msec, pass, (uint32_t)(nng_clock() - start));

		// Check result; exit if error occurred
		if ((rv = nng_aio_result(aio)) != 0) {
			fatal("RECV:nng_aio_result", rv);
		}

		// Get, and free memory of, (empty) message from server
		nng_msg *msg = nng_aio_get_msg(aio);
		if (msg) {
			nng_msg_free(msg);
		}

		if (++pass < 3) {
			// Passes not yet complete; send another message
			client_send();

		} else {
			// Trigger exit of [while...nng_msleep] loop
			step = DONE;
		}

		break;

	case SEND:

		// Sent message was queued; check result
		if ((rv = nng_aio_result(aio)) != 0) {
			// On error, (1) Free sent message memory ...
			nng_msg *msg = nng_aio_get_msg(aio);
			if (msg) {
				nng_msg_free(msg);
			}
			// (2) ... and exit
			fatal("SEND:nng_aio_result", rv);
		}

		// Set up for receipt of reply from server
		step = RECV;
		nng_ctx_recv(ctx, aio);

		// Start clock to time duration of server response
		start = nng_clock();
		break;

	default:
		fatal("bad step!", NNG_ESTATE);
		break;
	}
}

// The client routine:  runs just once, until all passes are complete,
// and then returns when the step enumerated value is DONE.
int
client(const char *url, const char *msecstr)
{
	nng_socket sock;
	int        rv;

	// Parse time argument
	msec = atoi(msecstr);

	// Open socket, dial (non-blocking, if envvar NONBLOCK exists),
	if ((rv = nng_req0_open(&sock)) != 0) {
		fatal("nng_req0_open", rv);
	}

	if ((rv = nng_dial(sock, url, NULL,
	         getenv("NONBLOCK") ? NNG_FLAG_NONBLOCK : 0)) != 0) {
		fatal("nng_dial", rv);
	}

	// Allocate asyncs I/O; open context
	if ((rv = nng_aio_alloc(&aio, client_cb, NULL)) != 0) {
		fatal("nng_aio_alloc", rv);
	}

	if ((rv = nng_ctx_open(&ctx, sock)) != 0) {
		fatal("nng_ctx_open", rv);
	}

	// Send initial request to server
	client_send();

	// Loop until done (or exit)
	while (step != DONE) {
		nng_msleep(100);
	}

	// Clean up, and return
	nng_aio_free(aio);
	nng_close(sock);

	return (0);
}

int
main(int argc, char **argv)
{
	int rc;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <url> <wait, ms>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	rc = client(argv[1], argv[2]);
	exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
