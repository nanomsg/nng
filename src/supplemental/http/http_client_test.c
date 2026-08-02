//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Basic HTTP client tests.

#include <nng/http.h>
#include <nng/nng.h>

#include "../../testing/nuts.h"
#include "http_api.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct scripted_server {
	nng_stream_listener *listener;
	nng_thread          *thread;
	const char         **responses;
	int                 *delays;
	size_t               nresponses;
	size_t               requests;
	int                  rv;
	bool                 ignore_send_errors;
	char                 url[128];
};

static int
stream_recv_some(nng_stream *stream, nng_aio *aio, void *buf, size_t len,
    size_t *count)
{
	nng_iov iov;
	int     rv;

	iov.iov_buf = buf;
	iov.iov_len = len;
	if ((rv = nng_aio_set_iov(aio, 1, &iov)) != 0) {
		return (rv);
	}
	nng_stream_recv(stream, aio);
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		return (rv);
	}
	*count = nng_aio_count(aio);
	return (0);
}

static int
server_read_request(nng_stream *stream, nng_aio *aio)
{
	char   buf[4097];
	size_t used = 0;
	size_t n;
	int    rv;

	for (;;) {
		if (used >= sizeof(buf) - 1) {
			return (NNG_EMSGSIZE);
		}
		rv = stream_recv_some(stream, aio, buf + used,
		    sizeof(buf) - 1 - used, &n);
		if (rv != 0) {
			return (rv);
		}
		if (n == 0) {
			return (NNG_ECLOSED);
		}
		used += n;
		if (used >= 4) {
			buf[used] = '\0';
			if (strstr(buf, "\r\n\r\n") != NULL) {
				return (0);
			}
		}
	}
}

static int
server_send_all(nng_stream *stream, nng_aio *aio, const char *data)
{
	size_t len = strlen(data);
	size_t off = 0;

	while (off < len) {
		nng_iov iov;
		int     rv;

		iov.iov_buf = (void *) (data + off);
		iov.iov_len = len - off;
		if ((rv = nng_aio_set_iov(aio, 1, &iov)) != 0) {
			return (rv);
		}
		nng_stream_send(stream, aio);
		nng_aio_wait(aio);
		if ((rv = nng_aio_result(aio)) != 0) {
			return (rv);
		}
		off += nng_aio_count(aio);
	}
	return (0);
}

static void
scripted_server_main(void *arg)
{
	struct scripted_server *srv = arg;
	nng_aio                *aio = NULL;
	nng_stream             *stream;
	int                     rv;

	if ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0) {
		srv->rv = rv;
		return;
	}
	nng_aio_set_timeout(aio, 5000);
	nng_stream_listener_accept(srv->listener, aio);
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		nng_aio_free(aio);
		srv->rv = rv;
		return;
	}
	stream = nng_aio_get_output(aio, 0);

	for (size_t i = 0; i < srv->nresponses; i++) {
		if ((rv = server_read_request(stream, aio)) != 0) {
			srv->rv = rv;
			break;
		}
		srv->requests++;
		if ((srv->delays != NULL) && (srv->delays[i] > 0)) {
			nng_msleep(srv->delays[i]);
		}
		rv = server_send_all(stream, aio, srv->responses[i]);
		if (rv != 0) {
			if (!srv->ignore_send_errors) {
				srv->rv = rv;
			}
			break;
		}
	}

	nng_stream_close(stream);
	nng_stream_stop(stream);
	nng_stream_free(stream);
	nng_aio_free(aio);
}

static void
scripted_server_start(struct scripted_server *srv, const char **responses,
    int *delays, size_t nresponses)
{
	int port;

	memset(srv, 0, sizeof(*srv));
	srv->responses  = responses;
	srv->delays     = delays;
	srv->nresponses = nresponses;

	NUTS_PASS(nng_stream_listener_alloc(
	    &srv->listener, "tcp://127.0.0.1:0"));
	NUTS_PASS(nng_stream_listener_listen(srv->listener));
	NUTS_PASS(
	    nng_stream_listener_get_int(srv->listener, NNG_OPT_BOUND_PORT, &port));
	snprintf(srv->url, sizeof(srv->url), "http://127.0.0.1:%d", port);
	NUTS_PASS(nng_thread_create(&srv->thread, scripted_server_main, srv));
}

static void
scripted_server_stop(struct scripted_server *srv)
{
	if (srv->listener != NULL) {
		nng_stream_listener_close(srv->listener);
	}
	if (srv->thread != NULL) {
		nng_thread_destroy(srv->thread);
	}
	if (srv->listener != NULL) {
		nng_stream_listener_free(srv->listener);
	}
}

static void
client_connect(const char *urlstr, nng_url **urlp, nng_aio **aiop,
    nng_http_client **clip, nng_http **connp)
{
	NUTS_PASS(nng_url_parse(urlp, urlstr));
	NUTS_PASS(nng_aio_alloc(aiop, NULL, NULL));
	nng_aio_set_timeout(*aiop, 5000);
	NUTS_PASS(nng_http_client_alloc(clip, *urlp));
	nng_http_client_connect(*clip, *aiop);
	nng_aio_wait(*aiop);
	NUTS_PASS(nng_aio_result(*aiop));
	*connp = nng_aio_get_output(*aiop, 0);
	NUTS_TRUE(*connp != NULL);
}

static void
client_free(nng_url *url, nng_aio *aio, nng_http_client *cli, nng_http *conn)
{
	if (conn != NULL) {
		nng_http_close(conn);
	}
	if (cli != NULL) {
		nng_http_client_free(cli);
	}
	if (aio != NULL) {
		nng_aio_free(aio);
	}
	if (url != NULL) {
		nng_url_free(url);
	}
}

static void
test_http_client_request_response(void)
{
	static const char *response =
	    "HTTP/1.1 200 OK\r\n"
	    "Content-Type: application/json\r\n"
	    "Content-Length: 14\r\n"
	    "Connection: keep-alive\r\n"
	    "\r\n"
	    "{\"ok\": true}\r\n";
	struct scripted_server srv;
	nng_aio               *aio = NULL;
	nng_http_client       *cli = NULL;
	nng_http              *conn = NULL;
	nng_url               *url = NULL;
	char                   body[16];
	nng_iov                iov;
	const char            *ptr;

	scripted_server_start(&srv, &response, NULL, 1);
	client_connect(srv.url, &url, &aio, &cli, &conn);

	NUTS_PASS(nng_http_set_uri(conn, "/get", NULL));
	nng_http_write_request(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));

	nng_http_read_response(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_HTTP_STATUS(conn, NNG_HTTP_STATUS_OK);
	ptr = nng_http_get_header(conn, "Content-Length");
	NUTS_TRUE(ptr != NULL);
	NUTS_TRUE(atoi(ptr) == 14);

	memset(body, 0, sizeof(body));
	iov.iov_buf = body;
	iov.iov_len = 14;
	NUTS_PASS(nng_aio_set_iov(aio, 1, &iov));
	nng_http_read_all(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(nng_aio_count(aio) == 14);
	NUTS_MATCH(body, "{\"ok\": true}\r\n");

	client_free(url, aio, cli, conn);
	scripted_server_stop(&srv);
	NUTS_PASS(srv.rv);
	NUTS_TRUE(srv.requests == 1);
}

static void
test_http_client_transact(void)
{
	static const char *response =
	    "HTTP/1.1 200 OK\r\n"
	    "Content-Type: text/plain\r\n"
	    "Content-Length: 11\r\n"
	    "Connection: keep-alive\r\n"
	    "\r\n"
	    "hello nng\r\n";
	struct scripted_server srv;
	nng_aio               *aio = NULL;
	nng_http_client       *cli = NULL;
	nng_http              *conn = NULL;
	nng_url               *url = NULL;
	void                  *data;
	size_t                 len;

	scripted_server_start(&srv, &response, NULL, 1);
	client_connect(srv.url, &url, &aio, &cli, &conn);

	NUTS_PASS(nng_http_set_uri(conn, "/", NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_HTTP_STATUS(conn, NNG_HTTP_STATUS_OK);
	nng_http_get_body(conn, &data, &len);
	NUTS_TRUE(len == 11);
	NUTS_TRUE(memcmp(data, "hello nng\r\n", len) == 0);

	client_free(url, aio, cli, conn);
	scripted_server_stop(&srv);
	NUTS_PASS(srv.rv);
	NUTS_TRUE(srv.requests == 1);
}

static void
test_http_client_reuse(void)
{
	static const char *responses[] = {
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 5\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"one\r\n",
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 5\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"two\r\n",
	};
	struct scripted_server srv;
	nng_aio               *aio = NULL;
	nng_http_client       *cli = NULL;
	nng_http              *conn = NULL;
	nng_url               *url = NULL;
	void                  *data;
	size_t                 len;

	scripted_server_start(&srv, responses, NULL, 2);
	client_connect(srv.url, &url, &aio, &cli, &conn);

	NUTS_PASS(nng_http_set_uri(conn, "/", NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_HTTP_STATUS(conn, NNG_HTTP_STATUS_OK);
	nng_http_get_body(conn, &data, &len);
	NUTS_TRUE(len == 5);
	NUTS_TRUE(memcmp(data, "one\r\n", len) == 0);

	nng_http_reset(conn);
	NUTS_PASS(nng_http_set_uri(conn, "/", NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_HTTP_STATUS(conn, NNG_HTTP_STATUS_OK);
	nng_http_get_body(conn, &data, &len);
	NUTS_TRUE(len == 5);
	NUTS_TRUE(memcmp(data, "two\r\n", len) == 0);

	client_free(url, aio, cli, conn);
	scripted_server_stop(&srv);
	NUTS_PASS(srv.rv);
	NUTS_TRUE(srv.requests == 2);
}

static void
test_http_client_timeout(void)
{
	static const char *response =
	    "HTTP/1.1 200 OK\r\n"
	    "Content-Length: 6\r\n"
	    "\r\n"
	    "late\r\n";
	struct scripted_server srv;
	nng_aio               *aio = NULL;
	nng_http_client       *cli = NULL;
	nng_http              *conn = NULL;
	nng_url               *url = NULL;
	int                    delay = 200;

	scripted_server_start(&srv, &response, &delay, 1);
	srv.ignore_send_errors = true;
	client_connect(srv.url, &url, &aio, &cli, &conn);

	nng_aio_set_timeout(aio, 20);
	NUTS_PASS(nng_http_set_uri(conn, "/delay", NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_TRUE(nng_aio_result(aio) == NNG_ETIMEDOUT);

	client_free(url, aio, cli, conn);
	scripted_server_stop(&srv);
	NUTS_TRUE(srv.requests == 1);
}

static void
test_http_client_chunked(void)
{
	static const char *response =
	    "HTTP/1.1 200 OK\r\n"
	    "Content-Type: text/plain\r\n"
	    "Transfer-Encoding: chunked\r\n"
	    "Connection: keep-alive\r\n"
	    "\r\n"
	    "5\r\nhello\r\n"
	    "6\r\n world\r\n"
	    "0\r\n\r\n";
	struct scripted_server srv;
	nng_aio               *aio = NULL;
	nng_http_client       *cli = NULL;
	nng_http              *conn = NULL;
	nng_url               *url = NULL;
	void                  *data;
	size_t                 len;

	scripted_server_start(&srv, &response, NULL, 1);
	client_connect(srv.url, &url, &aio, &cli, &conn);

	NUTS_PASS(nng_http_set_uri(conn, "/chunked", NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_HTTP_STATUS(conn, NNG_HTTP_STATUS_OK);
	nng_http_get_body(conn, &data, &len);
	NUTS_TRUE(len == 11);
	NUTS_TRUE(memcmp(data, "hello world", len) == 0);

	client_free(url, aio, cli, conn);
	scripted_server_stop(&srv);
	NUTS_PASS(srv.rv);
	NUTS_TRUE(srv.requests == 1);
}

static void
test_http_client_chunked_size_overflow(void)
{
	static const char *response =
	    "HTTP/1.1 200 OK\r\n"
	    "Transfer-Encoding: chunked\r\n"
	    "\r\n"
	    "10000000000000000\r\n"
	    "\r\n";
	struct scripted_server srv;
	nng_aio               *aio = NULL;
	nng_http_client       *cli = NULL;
	nng_http              *conn = NULL;
	nng_url               *url = NULL;

	scripted_server_start(&srv, &response, NULL, 1);
	srv.ignore_send_errors = true;
	client_connect(srv.url, &url, &aio, &cli, &conn);

	NUTS_PASS(nng_http_set_uri(conn, "/chunked-overflow", NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_EMSGSIZE);

	client_free(url, aio, cli, conn);
	scripted_server_stop(&srv);
	NUTS_PASS(srv.rv);
	NUTS_TRUE(srv.requests == 1);
}

static void
test_http_client_chunked_alloc_overflow(void)
{
	static const char *response =
	    "HTTP/1.1 200 OK\r\n"
	    "Transfer-Encoding: chunked\r\n"
	    "\r\n"
	    "ffffffffffffffff\r\n"
	    "\r\n";
	struct scripted_server srv;
	nng_aio               *aio = NULL;
	nng_http_client       *cli = NULL;
	nng_http              *conn = NULL;
	nng_url               *url = NULL;

	scripted_server_start(&srv, &response, NULL, 1);
	srv.ignore_send_errors = true;
	client_connect(srv.url, &url, &aio, &cli, &conn);

	NUTS_PASS(nng_http_set_uri(conn, "/chunked-alloc-overflow", NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_EMSGSIZE);

	client_free(url, aio, cli, conn);
	scripted_server_stop(&srv);
	NUTS_PASS(srv.rv);
	NUTS_TRUE(srv.requests == 1);
}

static void
test_http_chunk_parser_extensions(void)
{
	nni_http_chunks *chunks = NULL;
	nni_http_chunk  *chunk  = NULL;
	char             body[] =
	    "1;foo=bar\r\n"
	    "x\r\n"
	    "0\r\n"
	    "Some-Trailer: ok\r\n"
	    "\r\n";
	size_t n = 0;

	NUTS_PASS(nni_http_chunks_init(&chunks, 8));
	NUTS_PASS(nni_http_chunks_parse(chunks, body, strlen(body), &n));
	NUTS_TRUE(n == strlen(body));
	NUTS_TRUE(nni_http_chunks_size(chunks) == 1);
	chunk = nni_http_chunks_iter(chunks, NULL);
	NUTS_TRUE(chunk != NULL);
	NUTS_TRUE(nni_http_chunk_size(chunk) == 1);
	NUTS_TRUE(memcmp(nni_http_chunk_data(chunk), "x", 1) == 0);
	NUTS_TRUE(nni_http_chunks_iter(chunks, chunk) == NULL);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_max_size(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] =
	    "1\r\n"
	    "a\r\n"
	    "1\r\n"
	    "b\r\n"
	    "0\r\n"
	    "\r\n";
	size_t n = 0;

	NUTS_PASS(nni_http_chunks_init(&chunks, 1));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &n),
	    NNG_EMSGSIZE);
	NUTS_TRUE(n == 8);
	NUTS_TRUE(nni_http_chunks_size(chunks) == 1);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_bad_data_crlf(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] =
	    "1\r\n"
	    "aXX";
	size_t n = 0;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &n),
	    NNG_EPROTO);
	NUTS_TRUE(n == strlen(body));
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_bad_extension(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] = "1;\001\r\nx\r\n0\r\n\r\n";
	size_t           n      = 99;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &n),
	    NNG_EPROTO);
	NUTS_TRUE(n == 2);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_bad_trailer(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] = "0\r\nBad:\001\r\n\r\n";
	size_t           n      = 99;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &n),
	    NNG_EPROTO);
	NUTS_TRUE(n == 7);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_uppercase_hex(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] =
	    "A\r\n"
	    "1234567890\r\n"
	    "0\r\n"
	    "\r\n";
	size_t n = 0;

	NUTS_PASS(nni_http_chunks_init(&chunks, 16));
	NUTS_PASS(nni_http_chunks_parse(chunks, body, strlen(body), &n));
	NUTS_TRUE(n == strlen(body));
	NUTS_TRUE(nni_http_chunks_size(chunks) == 10);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_partial_data(void)
{
	nni_http_chunks *chunks = NULL;
	char             part1[] =
	    "3\r\n"
	    "ab";
	char   part2[] = "c\r\n0\r\n\r\n";
	size_t n       = 0;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, part1, strlen(part1), &n),
	    NNG_EAGAIN);
	NUTS_TRUE(n == strlen(part1));
	NUTS_PASS(nni_http_chunks_parse(chunks, part2, strlen(part2), &n));
	NUTS_TRUE(n == strlen(part2));
	NUTS_TRUE(nni_http_chunks_size(chunks) == 3);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_bad_length(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] = "g\r\n";
	size_t           n      = 99;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &n),
	    NNG_EPROTO);
	NUTS_TRUE(n == 0);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_bad_newline(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] = "1\rx";
	size_t           n      = 99;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &n),
	    NNG_EPROTO);
	NUTS_TRUE(n == 2);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_bad_initial(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] = "\r\n";
	size_t           n      = 99;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &n),
	    NNG_EPROTO);
	NUTS_TRUE(n == 0);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_parser_bad_trailer_cr(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] = "0\r\nX\rx";
	size_t           n      = 99;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &n),
	    NNG_EPROTO);
	NUTS_TRUE(n == 5);
	nni_http_chunks_free(chunks);
}

NUTS_TESTS = {
	{ "http client request response", test_http_client_request_response },
	{ "http client transact", test_http_client_transact },
	{ "http client reuse", test_http_client_reuse },
	{ "http client timeout", test_http_client_timeout },
	{ "http client chunked", test_http_client_chunked },
	{ "http client chunked size overflow",
	    test_http_client_chunked_size_overflow },
	{ "http client chunked alloc overflow",
	    test_http_client_chunked_alloc_overflow },
	{ "http chunk parser extensions", test_http_chunk_parser_extensions },
	{ "http chunk parser max size", test_http_chunk_parser_max_size },
	{ "http chunk parser bad data crlf",
	    test_http_chunk_parser_bad_data_crlf },
	{ "http chunk parser bad extension",
	    test_http_chunk_parser_bad_extension },
	{ "http chunk parser bad trailer", test_http_chunk_parser_bad_trailer },
	{ "http chunk parser uppercase hex",
	    test_http_chunk_parser_uppercase_hex },
	{ "http chunk parser partial data",
	    test_http_chunk_parser_partial_data },
	{ "http chunk parser bad length", test_http_chunk_parser_bad_length },
	{ "http chunk parser bad newline", test_http_chunk_parser_bad_newline },
	{ "http chunk parser bad initial", test_http_chunk_parser_bad_initial },
	{ "http chunk parser bad trailer cr",
	    test_http_chunk_parser_bad_trailer_cr },
	{ NULL, NULL },
};
