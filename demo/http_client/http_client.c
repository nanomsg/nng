//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This is a very simple HTTP client.  It only performs HTTP GET
// operations, and does not follow HTTP redirects.  Think of it as
// a trivialized version of CURL.  It is super simple, taking the
// URL on the command line, and emitting the results to stdout.
// For clarity, we are eliding TLS support.

// It may not work on all systems, but it should work anywhere that
// both the standard C library and nng itself are available.

// We check for errors, but no effort is made to clean up resources,
// since this program just exits.  In longer running programs or libraries,
// callers should take care to clean up things that they allocate.

// Unfortunately many famous sites use redirects, so you won't see that
// emitted.

// Example usage:
//
// % export CPPFLAGS="-I /usr/local/include"
// % export LDFLAGS="-L /usr/local/lib -lnng"
// % export CC="cc"
// % ${CC} ${CPPFLAGS} http_client.c -o http_client ${LDFLAGS}
// % ./http_client http://httpbin.org/ip
//

#include <nng/nng.h>
#include <nng/supplemental/http/http.h>
#include <stdio.h>
#include <stdlib.h>

void
fatal(int rv)
{
	fprintf(stderr, "%s\n", nng_strerror(rv));
	exit(1);
}

int
main(int argc, char **argv)
{
	nng_http_client *client;
	nng_http_conn *  conn;
	nng_url *        url;
	nng_aio *        aio;
	nng_http_req *   req;
	nng_http_res *   res;
	const char *     hdr;
	int              rv;
	int              len;
	void *           data;
	nng_iov          iov;

	if (argc < 2) {
		fprintf(stderr, "No URL supplied!\n");
		exit(1);
	}

	if (((rv = nng_url_parse(&url, argv[1])) != 0) ||
	    ((rv = nng_http_client_alloc(&client, url)) != 0) ||
	    ((rv = nng_http_req_alloc(&req, url)) != 0) ||
	    ((rv = nng_http_res_alloc(&res)) != 0) ||
	    ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0)) {
		fatal(rv);
	}

	// Start connection process...
	nng_http_client_connect(client, aio);

	// Wait for it to finish.
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		fatal(rv);
	}

	// Get the connection, at the 0th output.
	conn = nng_aio_get_output(aio, 0);

	// Request is already set up with URL, and for GET via HTTP/1.1.
	// The Host: header is already set up too.

	// Send the request, and wait for that to finish.
	nng_http_conn_write_req(conn, req, aio);
	nng_aio_wait(aio);

	if ((rv = nng_aio_result(aio)) != 0) {
		fatal(rv);
	}

	// Read a response.
	nng_http_conn_read_res(conn, res, aio);
	nng_aio_wait(aio);

	if ((rv = nng_aio_result(aio)) != 0) {
		fatal(rv);
	}

	if (nng_http_res_get_status(res) != NNG_HTTP_STATUS_OK) {
		fprintf(stderr, "HTTP Server Responded: %d %s\n",
		    nng_http_res_get_status(res),
		    nng_http_res_get_reason(res));
	}

	// This only supports regular transfer encoding (no Chunked-Encoding,
	// and a Content-Length header is required.)
	if ((hdr = nng_http_res_get_header(res, "Content-Length")) == NULL) {
		fprintf(stderr, "Missing Content-Length header.\n");
		exit(1);
	}

	len = atoi(hdr);
	if (len == 0) {
		return (0);
	}

	// Allocate a buffer to receive the body data.
	data = malloc(len);

	// Set up a single iov to point to the buffer.
	iov.iov_len = len;
	iov.iov_buf = data;

	// Following never fails with fewer than 5 elements.
	nng_aio_set_iov(aio, 1, &iov);

	// Now attempt to receive the data.
	nng_http_conn_read_all(conn, aio);

	// Wait for it to complete.
	nng_aio_wait(aio);

	if ((rv = nng_aio_result(aio)) != 0) {
		fatal(rv);
	}

	fwrite(data, 1, len, stdout);
	return (0);
}
