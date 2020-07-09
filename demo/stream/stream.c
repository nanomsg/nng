// Copyright 2020 Hugo Lindström <hugolm84@gmail.com>

// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This program serves as an example for how to write async communication with
// an arbitrary socket using nng_stream. The server receives a connection and
// sends a hello message to the nng_stream iov.

// To run this program, start the server as stream -s <portnumber>
// Then connect to it with the client as stream -c <url>
//
//  For example:
//
//  % ./stream -s 5555 &
//  % ./stream -c tcp://127.0.0.1:5555

#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
nng_fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

int server(int port);
int client(const char *url);

int
main(int argc, char **argv)
{
	int rc;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-s port|-c url]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "-s") == 0) {
		rc = server(atoi(argv[2]));
	} else {
		rc = client(argv[2]);
	}
	exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

int
client(const char *url)
{
	nng_stream_dialer *dialer;
	nng_aio *          aio;
	nng_iov            iov;
	int                rv;

	// Allocatate dialer and aio assoicated with this connection
	if ((rv = nng_stream_dialer_alloc(&dialer, url)) != 0) {
		nng_fatal("call to nng_stream_dialer_alloc failed", rv);
	}

	if ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0) {
		nng_fatal("call to nng_aio_alloc", rv);
	}
	nng_aio_set_timeout(aio, 5000); // 5 sec

	// Allocatate a buffer to recv
	iov.iov_len = 100;
	iov.iov_buf = (char *) malloc(sizeof(char) * iov.iov_len);
	if ((rv = nng_aio_set_iov(aio, 1, &iov)) != 0) {
		nng_fatal("call to nng_aio_alloc", rv);
	}
	// Connect to the socket via url provided to alloc
	nng_stream_dialer_dial(dialer, aio);

	// Wait for connection
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		nng_fatal("waiting for ng_stream_dialer_dial failed", rv);
	}

	// Get the stream (connection) at position 0
	nng_stream *c1 = (nng_stream *) nng_aio_get_output(aio, 0);
	nng_stream_recv(c1, aio);
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		nng_fatal("waiting for nng_stream_recv failed", rv);
	}

	size_t recv_count = nng_aio_count(aio);
	if (recv_count <= 0) {
		nng_fatal("Recv count was 0!", NNG_ECONNABORTED);
	} else {
		printf("received %zu bytes, message: '%s'\n", recv_count,
		    (char *) iov.iov_buf);
	}

	// Send ELCOSE to send/recv associated wit this stream
	free(iov.iov_buf);
	nng_stream_free(c1);
	nng_aio_free(aio);
	nng_stream_dialer_free(dialer);
	return 0;
}
