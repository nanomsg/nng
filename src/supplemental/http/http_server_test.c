//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2020 Dirac Research <robert.bielik@dirac.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Basic HTTP server tests.
#include "../../core/defs.h"
#include <complex.h>
#include <nng/http.h>
#include <nng/nng.h>
#ifndef _WIN32
#include <arpa/inet.h> // for endianness functions
#endif

#include "../../testing/nuts.h"

const char *doc1 = "<html><body>Someone <b>is</b> home!</body></html>";
const char *doc2 = "This is a text file.";
const char *doc3 = "<html><body>This is doc number 3.</body></html>";
const char *doc4 = "<html><body>Whoops, Errored!</body></html>";

struct server_test {
	nng_url          *url;
	nng_aio          *aio;
	nng_http_server  *s;
	nng_http_handler *h;
	nng_http_client  *cli;
	nng_http         *conn;
	char              urlstr[2048];
};

static int
httpdo(struct server_test *st, void **datap, size_t *sizep)
{
	int         rv;
	size_t      clen = 0;
	void       *data = NULL;
	const char *ptr;

	nng_http_write_request(st->conn, st->aio);
	nng_aio_wait(st->aio);
	if ((rv = nng_aio_result(st->aio)) != 0) {
		return (rv);
	}
	nng_http_read_response(st->conn, st->aio);
	nng_aio_wait(st->aio);
	if ((rv = nng_aio_result(st->aio)) != 0) {
		return (rv);
	}

	clen = 0;
	if ((ptr = nng_http_get_header(st->conn, "Content-Length")) != NULL) {
		clen = atoi(ptr);
	}

	if (clen > 0) {
		nng_iov iov;
		data        = nng_alloc(clen);
		iov.iov_buf = data;
		iov.iov_len = clen;
		nng_aio_set_iov(st->aio, 1, &iov);
		nng_http_read_all(st->conn, st->aio);
		nng_aio_wait(st->aio);
		if ((rv = nng_aio_result(st->aio)) != 0) {
			return (rv);
		}
	}

	*datap = data;
	*sizep = clen;

	return (rv);
}

static int
httpget(struct server_test *st, void **datap, size_t *sizep, uint16_t *statp,
    char **ctypep)
{
	int         rv;
	size_t      clen  = 0;
	void       *data  = NULL;
	char       *ctype = NULL;
	nng_http   *conn  = st->conn;
	const char *ptr;

	if ((rv = httpdo(st, &data, &clen)) != 0) {
		goto fail;
	}

	*statp = nng_http_get_status(conn);

	if (clen > 0) {
		if ((ptr = nng_http_get_header(conn, "Content-Type")) !=
		    NULL) {
			ctype = nng_strdup(ptr);
		}
	}

	*datap  = data;
	*sizep  = clen;
	*ctypep = ctype;

fail:
	if (rv != 0) {
		if (data != NULL) {
			nng_free(data, clen);
		}
		free(ctype);
	}

	return (rv);
}

static void
httpecho(nng_http *conn, void *arg, nng_aio *aio)
{
	int    rv;
	void  *body;
	size_t len;
	NNI_ARG_UNUSED(arg);

	nng_http_get_body(conn, &body, &len);

	if (((rv = nng_http_copy_body(conn, body, len)) != 0) ||
	    ((rv = nng_http_set_header(conn, "Content-type", "text/plain")) !=
	        0)) {
		nng_aio_finish(aio, rv);
		return;
	}
	nng_http_set_status(conn, NNG_HTTP_STATUS_OK, NULL);
	nng_aio_finish(aio, 0);
}

static void
httpaddrcheck(nng_http *conn, void *arg, nng_aio *aio)
{
	nng_err      rv;
	void        *body;
	size_t       len;
	nng_sockaddr loc;
	nng_sockaddr rem;

	NNI_ARG_UNUSED(arg);

	if (((rv = nng_http_local_address(conn, &loc)) != NNG_OK) ||
	    ((rv = nng_http_remote_address(conn, &rem)) != NNG_OK)) {
		nng_aio_finish(aio, rv);
		return;
	}
	if ((loc.s_family != NNG_AF_INET) || (rem.s_family != NNG_AF_INET)) {
		nng_http_set_status(conn, NNG_HTTP_STATUS_BAD_REQUEST,
		    "Adddresses were not INET");
		nng_aio_finish(aio, 0);
		return;
	}
	if ((loc.s_in.sa_addr != htonl(0x7F000001)) ||
	    (rem.s_in.sa_addr != htonl(0x7F000001))) {
		nng_http_set_status(conn, NNG_HTTP_STATUS_BAD_REQUEST,
		    "Adddresses were not localhost");
		nng_aio_finish(aio, 0);
		return;
	}
	if ((loc.s_in.sa_port == 0) || (rem.s_in.sa_port == 0) ||
	    (loc.s_in.sa_port == rem.s_in.sa_port)) {
		nng_http_set_status(
		    conn, NNG_HTTP_STATUS_BAD_REQUEST, "Port checks failed");
		nng_aio_finish(aio, 0);
		return;
	}

	nng_http_get_body(conn, &body, &len);

	if (((rv = nng_http_copy_body(conn, body, len)) != 0) ||
	    ((rv = nng_http_set_header(conn, "Content-type", "text/plain")) !=
	        0)) {
		nng_aio_finish(aio, rv);
		return;
	}

	nng_http_set_status(conn, NNG_HTTP_STATUS_OK, NULL);
	nng_aio_finish(aio, 0);
}

static void
server_setup(struct server_test *st, nng_http_handler *h)
{
	int port;
	memset(st, 0, sizeof(*st));
	NUTS_PASS(nng_url_parse(&st->url, "http://127.0.0.1:0"));
	NUTS_PASS(nng_aio_alloc(&st->aio, NULL, NULL));
	NUTS_PASS(nng_http_server_hold(&st->s, st->url));
	if (h != NULL) {
		st->h = h;
		NUTS_PASS(nng_http_server_add_handler(st->s, h));
	}
	NUTS_PASS(nng_http_server_start(st->s));
	NUTS_PASS(nng_http_server_get_port(st->s, &port));
	nng_url_resolve_port(st->url, (uint32_t) port);
	nng_url_sprintf(st->urlstr, sizeof(st->urlstr), st->url);

	NUTS_PASS(nng_http_client_alloc(&st->cli, st->url));
	nng_http_client_connect(st->cli, st->aio);
	nng_aio_wait(st->aio);

	NUTS_PASS(nng_aio_result(st->aio));
	st->conn = nng_aio_get_output(st->aio, 0);
	NUTS_TRUE(st->conn != NULL);
	NUTS_PASS(nng_http_set_uri(st->conn, "/", NULL));
}

static void
server_reset(struct server_test *st)
{
	if (st->conn) {
		nng_http_close(st->conn);
	}
	nng_http_client_connect(st->cli, st->aio);
	nng_aio_wait(st->aio);
	NUTS_PASS(nng_aio_result(st->aio));
	st->conn = nng_aio_get_output(st->aio, 0);
	NUTS_PASS(nng_http_set_uri(st->conn, "/", NULL));
}

static void
server_free(struct server_test *st)
{
	if (st->aio != NULL) {
		nng_aio_free(st->aio);
	}
	if (st->cli != NULL) {
		nng_http_client_free(st->cli);
	}
	if (st->conn != NULL) {
		nng_http_close(st->conn);
	}
	if (st->s != NULL) {
		nng_http_server_release(st->s);
	}
	if (st->url != NULL) {
		nng_url_free(st->url);
	}
}

static void
test_server_basic(void)
{
	struct server_test st;
	char               chunk[256];
	const void        *ptr;
	nng_iov            iov;
	nng_http_handler  *h;

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/home.html", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_OK);

	ptr = nng_http_get_header(st.conn, "Content-Length");
	NUTS_TRUE(ptr != NULL);
	NUTS_TRUE(atoi(ptr) == (int) strlen(doc1));

	iov.iov_len = strlen(doc1);
	iov.iov_buf = chunk;
	NUTS_PASS(nng_aio_set_iov(st.aio, 1, &iov));
	nng_http_read_all(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));
	NUTS_TRUE(nng_aio_count(st.aio) == strlen(doc1));
	NUTS_TRUE(memcmp(chunk, doc1, strlen(doc1)) == 0);

	server_free(&st);
}

static void
test_server_static_bin(void)
{
	struct server_test st;
	char               chunk[256];
	const void        *ptr;
	nng_iov            iov;
	nng_http_handler  *h;
	static uint8_t     data[3] = { 1, 0, 2 };

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/data.bin", data, sizeof(data), NULL));

	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/data.bin", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_OK);

	ptr = nng_http_get_header(st.conn, "Content-Type");
	NUTS_TRUE(ptr != NULL);
	NUTS_TRUE(strcmp(ptr, "application/octet-stream") == 0);

	ptr = nng_http_get_header(st.conn, "Content-Length");
	NUTS_TRUE(ptr != NULL);
	NUTS_TRUE(atoi(ptr) == (int) sizeof(data));

	iov.iov_len = sizeof(data);
	iov.iov_buf = chunk;
	NUTS_PASS(nng_aio_set_iov(st.aio, 1, &iov));
	nng_http_read_all(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));
	NUTS_TRUE(nng_aio_count(st.aio) == sizeof(data));
	NUTS_TRUE(memcmp(chunk, data, sizeof(data)) == 0);

	server_free(&st);
}

static void
test_server_canonify(void)
{
	struct server_test st;
	char               chunk[256];
	const void        *ptr;
	nng_iov            iov;
	nng_http_handler  *h;

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home/index.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(
	    st.conn, "/someplace/..////home/./%69ndex.html", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_TRUE(nng_http_get_status(st.conn) == NNG_HTTP_STATUS_OK);

	ptr = nng_http_get_header(st.conn, "Content-Length");
	NUTS_TRUE(ptr != NULL);
	NUTS_TRUE(atoi(ptr) == (int) strlen(doc1));

	iov.iov_len = strlen(doc1);
	iov.iov_buf = chunk;
	NUTS_PASS(nng_aio_set_iov(st.aio, 1, &iov));
	nng_http_read_all(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));
	NUTS_TRUE(nng_aio_count(st.aio) == strlen(doc1));
	NUTS_TRUE(memcmp(chunk, doc1, strlen(doc1)) == 0);

	server_free(&st);
}

static void
test_server_head(void)
{
	struct server_test st;
	void              *ptr;
	size_t             size;
	nng_http_handler  *h;

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/home.html", NULL));
	nng_http_set_method(st.conn, "HEAD");
	nng_http_transact(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_TRUE(nng_http_get_status(st.conn) == NNG_HTTP_STATUS_OK);

	ptr = (char *) nng_http_get_header(st.conn, "Content-Length");
	NUTS_TRUE(ptr != NULL);
	NUTS_TRUE(atoi(ptr) == (int) strlen(doc1));
	NUTS_TRUE(nng_http_get_status(st.conn) == NNG_HTTP_STATUS_OK);

	nng_http_get_body(st.conn, &ptr, &size);
	NUTS_TRUE(size == 0);
	NUTS_TRUE(ptr == NULL);

	nng_http_reset(st.conn);
	nng_http_set_uri(st.conn, "/home.html", NULL);
	nng_http_set_method(st.conn, "GET");
	nng_http_transact(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));
	NUTS_TRUE(nng_http_get_status(st.conn) == NNG_HTTP_STATUS_OK);
	nng_http_get_body(st.conn, &ptr, &size);

	NUTS_TRUE(size == strlen(doc1));
	NUTS_TRUE(memcmp(ptr, doc1, strlen(doc1)) == 0);

	server_free(&st);
}

static void
test_server_404(void)
{
	struct server_test st;

	server_setup(&st, NULL);

	NUTS_PASS(nng_http_set_uri(st.conn, "/bogus", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_NOT_FOUND);

	server_free(&st);
}

static void
test_server_no_authoritative_form(void)
{
	struct server_test st;
	nng_http_handler  *h;

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	NUTS_PASS(
	    nng_http_set_uri(st.conn, "http://127.0.0.1/home.html", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_BAD_REQUEST);

	server_free(&st);
}

static void
test_server_bad_canonify(void)
{
	struct server_test st;
	nng_http_handler  *h;

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/%home.html", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_BAD_REQUEST);

	server_free(&st);
}

static void
test_server_bad_version(void)
{
	struct server_test st;

	server_setup(&st, NULL);

	NUTS_PASS(nng_http_set_version(st.conn, "HTTP/0.9"));
	NUTS_PASS(nng_http_set_uri(st.conn, "/bogus", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP);

	server_free(&st);
}

void
test_server_missing_host(void)
{
	struct server_test st;
	server_setup(&st, NULL);

	nng_http_del_header(st.conn, "Host");
	NUTS_PASS(nng_http_set_uri(st.conn, "/bogus", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_BAD_REQUEST);

	server_free(&st);
}

void
test_server_method_too_long(void)
{
	nng_http_handler *h;

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	nng_http_handler_set_method(h,
	    "THISMETHODISFARFARTOOLONGTOBEVALIDASAMETHODASITISLONGER"
	    "THANTHIRTYTWOBYTES");

	nng_http_handler_free(h);
}

void
test_server_wrong_method(void)
{
	struct server_test st;
	nng_http_handler  *h;

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	nng_http_set_method(st.conn, "POST");
	NUTS_PASS(nng_http_set_uri(st.conn, "/home.html", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED);

	server_free(&st);
}

static void
test_server_uri_too_long(void)
{
	struct server_test st;
	nng_http_handler  *h;
	char               buf[32768];

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	memset(buf, 'a', sizeof(buf) - 1);
	buf[0]               = '/';
	buf[sizeof(buf) - 1] = 0;

	NUTS_PASS(nng_http_set_uri(st.conn, buf, NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_URI_TOO_LONG);

	server_free(&st);
}

static void
test_server_header_too_long(void)
{
	struct server_test st;
	nng_http_handler  *h;
	char               buf[32768];

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	memset(buf, 'a', sizeof(buf) - 1);
	buf[0]               = '/';
	buf[sizeof(buf) - 1] = 0;

	NUTS_PASS(nng_http_set_uri(st.conn, "/home.html", NULL));
	NUTS_PASS(nng_http_set_header(st.conn, "Referrer", buf));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_HEADERS_TOO_LARGE);

	server_free(&st);
}

static void
test_server_invalid_utf8(void)
{
	struct server_test st;
	nng_http_handler  *h;

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/home\xFF.html", NULL));
	nng_http_write_request(st.conn, st.aio);

	nng_aio_wait(st.aio);

	nng_http_read_response(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_BAD_REQUEST);

	server_free(&st);
}

static void
test_server_post_handler(void)
{
	struct server_test st;
	nng_http_handler  *h;
	char               txdata[5];
	char              *rxdata;
	size_t             size;
	void              *data;

	NUTS_PASS(nng_http_handler_alloc(&h, "/post", httpecho));
	nng_http_handler_set_method(h, "POST");

	server_setup(&st, h);

	snprintf(txdata, sizeof(txdata), "1234");

	NUTS_PASS(nng_http_set_uri(st.conn, "/post", NULL));
	nng_http_set_body(st.conn, txdata, strlen(txdata));
	nng_http_set_method(st.conn, "POST");
	NUTS_PASS(httpdo(&st, (void **) &rxdata, &size));
	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(txdata));
	NUTS_TRUE(strncmp(txdata, rxdata, size) == 0);
	nng_free(rxdata, size);

	server_reset(&st);

	NUTS_PASS(nng_http_set_uri(st.conn, "/post", NULL));
	nng_http_set_method(st.conn, "GET");
	nng_http_set_body(st.conn, txdata, strlen(txdata));

	NUTS_PASS(httpdo(&st, &data, &size));
	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED);
	nng_free(data, size);

	server_free(&st);
}

static void
test_server_addrs_handler(void)
{
	struct server_test st;
	nng_http_handler  *h;
	char               txdata[5];
	char              *rxdata;
	size_t             size;

	NUTS_PASS(nng_http_handler_alloc(&h, "/addrs", httpaddrcheck));
	nng_http_handler_set_method(h, "POST");

	server_setup(&st, h);

	snprintf(txdata, sizeof(txdata), "1234");

	NUTS_PASS(nng_http_set_uri(st.conn, "/addrs", NULL));
	nng_http_set_body(st.conn, txdata, strlen(txdata));
	nng_http_set_method(st.conn, "POST");
	NUTS_PASS(httpdo(&st, (void **) &rxdata, &size));
	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(txdata));
	NUTS_TRUE(strncmp(txdata, rxdata, size) == 0);
	nng_free(rxdata, size);

	server_free(&st);
}

static void
test_server_get_redirect(void)
{
	const char        *dest;
	void              *data;
	size_t             size;
	nng_http_handler  *h;
	struct server_test st;

	// We'll use a 303 (SEE OTHER) to ensure codes carry thru
	NUTS_PASS(nng_http_handler_alloc_redirect(
	    &h, "/here", NNG_HTTP_STATUS_SEE_OTHER, "http://127.0.0.1/there"));
	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/here", NULL));
	nng_http_set_method(st.conn, "GET");

	NUTS_PASS(httpdo(&st, &data, &size));
	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_SEE_OTHER);
	NUTS_TRUE((dest = nng_http_get_header(st.conn, "Location")) != NULL);
	NUTS_MATCH(dest, "http://127.0.0.1/there");
	nng_free(data, size);

	server_free(&st);
}

static void
test_server_tree_redirect(void)
{
	const char        *dest;
	void              *data;
	size_t             size;
	nng_http_handler  *h;
	struct server_test st;

	// We'll use a permanent redirect to ensure codes carry thru
	NUTS_PASS(nng_http_handler_alloc_redirect(&h, "/here",
	    NNG_HTTP_STATUS_PERMANENT_REDIRECT, "http://127.0.0.1/there"));
	nng_http_handler_set_tree(h);
	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/here/i/go/again", NULL));
	nng_http_set_method(st.conn, "GET");

	NUTS_PASS(httpdo(&st, &data, &size));
	NUTS_HTTP_STATUS(st.conn, NNG_HTTP_STATUS_PERMANENT_REDIRECT);
	NUTS_TRUE((dest = nng_http_get_header(st.conn, "Location")) != NULL);
	NUTS_MATCH(dest, "http://127.0.0.1/there/i/go/again");
	nng_free(data, size);

	server_free(&st);
}

static void
test_server_post_redirect(void)
{
	size_t      size;
	char        txdata[5];
	const char *dest;
	void       *data;

	struct server_test st;
	nng_http_handler  *h;

	NUTS_PASS(nng_http_handler_alloc_redirect(
	    &h, "/here", 301, "http://127.0.0.1/there"));
	server_setup(&st, h);

	snprintf(txdata, sizeof(txdata), "1234");
	NUTS_PASS(nng_http_set_uri(st.conn, "/here", NULL));
	nng_http_set_body(st.conn, txdata, strlen(txdata));
	nng_http_set_method(st.conn, "POST");
	NUTS_PASS(httpdo(&st, (void **) &data, &size));
	NUTS_TRUE(nng_http_get_status(st.conn) == 301);
	dest = nng_http_get_header(st.conn, "Location");
	NUTS_TRUE(dest != NULL);
	NUTS_MATCH(dest, "http://127.0.0.1/there");
	nng_free(data, size);
	server_free(&st);
}

void
test_server_post_echo_tree(void)
{
	struct server_test st;
	nng_http_handler  *h;
	size_t             size;
	char               txdata[5];
	char              *rxdata;

	NUTS_PASS(nng_http_handler_alloc(&h, "/", httpecho));
	nng_http_handler_set_method(h, "POST");
	nng_http_handler_set_tree(h);

	server_setup(&st, h);

	snprintf(txdata, sizeof(txdata), "1234");
	nng_http_set_body(st.conn, txdata, strlen(txdata));
	nng_http_set_method(st.conn, "POST");
	NUTS_PASS(nng_http_set_uri(st.conn, "/some_sub/directory", NULL));
	NUTS_PASS(httpdo(&st, (void **) &rxdata, &size));
	NUTS_TRUE(nng_http_get_status(st.conn) == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(txdata));
	NUTS_TRUE(strncmp(txdata, rxdata, size) == 0);
	nng_free(rxdata, size);

	server_free(&st);
}

void
test_server_error_page(void)
{
	struct server_test st;
	void              *data;
	size_t             size;
	uint16_t           stat;
	char              *ctype;

	server_setup(&st, NULL);
	NUTS_PASS(nng_http_server_set_error_page(
	    st.s, NNG_HTTP_STATUS_NOT_FOUND, doc4));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_NOT_FOUND);
	NUTS_TRUE(size == strlen(doc4));
	NUTS_TRUE(memcmp(data, doc4, size) == 0);
	nng_strfree(ctype);
	nng_free(data, size);
	server_free(&st);
}

// internal functions we need for now
extern char *nni_plat_temp_dir(void);
extern char *nni_file_join(const char *, const char *);
extern int   nni_file_put(const char *, const void *, size_t);
extern int   nni_file_delete(const char *);

void
test_server_multiple_trees(void)
{
	char *tmpdir;
	char *workdir;
	char *workdir2;
	char *file1;
	char *file2;

	struct server_test st;
	nng_http_handler  *h;

	NUTS_TRUE((tmpdir = nni_plat_temp_dir()) != NULL);
	NUTS_TRUE((workdir = nni_file_join(tmpdir, "httptest")) != NULL);
	NUTS_TRUE((workdir2 = nni_file_join(tmpdir, "httptest2")) != NULL);
	NUTS_TRUE((file1 = nni_file_join(workdir, "file1.txt")) != NULL);
	NUTS_TRUE((file2 = nni_file_join(workdir2, "file2.txt")) != NULL);

	NUTS_PASS(nni_file_put(file1, doc1, strlen(doc1)));
	NUTS_PASS(nni_file_put(file2, doc2, strlen(doc2)));

	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/", workdir));
	nng_http_handler_set_tree(h);
	server_setup(&st, h);

	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/", workdir));
	nng_http_handler_set_tree(h);
	NUTS_FAIL(nng_http_server_add_handler(st.s, h), NNG_EADDRINUSE);
	nng_http_handler_free(h);

	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/subdir", workdir2));
	nng_http_handler_set_tree(h);
	NUTS_PASS(nng_http_server_add_handler(st.s, h));

	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/subdir", workdir2));
	nng_http_handler_set_tree(h);
	NUTS_FAIL(nng_http_server_add_handler(st.s, h), NNG_EADDRINUSE);
	nng_http_handler_free(h);

	nng_msleep(100);

	void    *data;
	size_t   size;
	uint16_t stat;
	char    *ctype;

	NUTS_CASE("Directory 1");
	NUTS_PASS(nng_http_set_uri(st.conn, "/file1.txt", NULL));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc1));
	NUTS_TRUE(memcmp(data, doc1, size) == 0);
	NUTS_MATCH(ctype, "text/plain");
	nng_strfree(ctype);
	nng_free(data, size);

	server_reset(&st);

	NUTS_CASE("Directory 2");
	NUTS_PASS(nng_http_set_uri(st.conn, "/subdir/file2.txt", NULL));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc2));
	NUTS_TRUE(memcmp(data, doc2, size) == 0);
	NUTS_MATCH(ctype, "text/plain");
	nng_strfree(ctype);
	nng_free(data, size);

	server_free(&st);
	free(tmpdir);
	nni_file_delete(file1);
	nni_file_delete(file2);
	nni_file_delete(workdir);
	nni_file_delete(workdir2);
	free(workdir2);
	free(workdir);
	free(file1);
	free(file2);
}

struct serve_directory {
	char *tmpdir;
	char *workdir;
	char *file1;
	char *file2;
	char *file3;
	char *subdir1;
	char *subdir2;
};

void
setup_directory(struct serve_directory *sd)
{
	NUTS_TRUE((sd->tmpdir = nni_plat_temp_dir()) != NULL);
	NUTS_TRUE(
	    (sd->workdir = nni_file_join(sd->tmpdir, "httptest")) != NULL);
	NUTS_TRUE(
	    (sd->subdir1 = nni_file_join(sd->workdir, "subdir1")) != NULL);
	NUTS_TRUE(
	    (sd->subdir2 = nni_file_join(sd->workdir, "subdir2")) != NULL);
	NUTS_TRUE(
	    (sd->file1 = nni_file_join(sd->subdir1, "index.html")) != NULL);
	NUTS_TRUE(
	    (sd->file2 = nni_file_join(sd->workdir, "file.txt")) != NULL);
	NUTS_TRUE(
	    (sd->file3 = nni_file_join(sd->subdir2, "index.htm")) != NULL);
	NUTS_PASS(nni_file_put(sd->file1, doc1, strlen(doc1)));
	NUTS_PASS(nni_file_put(sd->file2, doc2, strlen(doc2)));
	NUTS_PASS(nni_file_put(sd->file3, doc3, strlen(doc3)));
}

void
clean_directory(struct serve_directory *sd)
{
	free(sd->tmpdir);
	nni_file_delete(sd->file1);
	nni_file_delete(sd->file2);
	nni_file_delete(sd->file3);
	nni_file_delete(sd->subdir1);
	nni_file_delete(sd->subdir2);
	nni_file_delete(sd->workdir);
	free(sd->workdir);
	free(sd->file1);
	free(sd->file2);
	free(sd->file3);
	free(sd->subdir1);
	free(sd->subdir2);
}

void
test_serve_directory(void)
{
	void                  *data;
	size_t                 size;
	uint16_t               stat;
	char                  *ctype;
	nng_http_handler      *h;
	struct server_test     st;
	struct serve_directory sd;

	setup_directory(&sd);
	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/", sd.workdir));
	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/subdir1/index.html", NULL));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc1));
	NUTS_TRUE(memcmp(data, doc1, size) == 0);
	NUTS_MATCH(ctype, "text/html");
	nng_strfree(ctype);
	nng_free(data, size);

	server_free(&st);

	clean_directory(&sd);
}

void
test_serve_directory_index(void)
{
	void                  *data;
	size_t                 size;
	uint16_t               stat;
	char                  *ctype;
	nng_http_handler      *h;
	struct server_test     st;
	struct serve_directory sd;

	setup_directory(&sd);
	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/", sd.workdir));
	server_setup(&st, h);

	NUTS_CASE("Directory 1: index.html");
	NUTS_PASS(nng_http_set_uri(st.conn, "/subdir1/", NULL));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc1));
	NUTS_TRUE(memcmp(data, doc1, size) == 0);
	NUTS_MATCH(ctype, "text/html");
	nng_strfree(ctype);
	nng_free(data, size);

	server_reset(&st);

	NUTS_CASE("Directory 2: index.htm");
	NUTS_PASS(nng_http_set_uri(st.conn, "/subdir2/", NULL));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc3));
	NUTS_TRUE(memcmp(data, doc3, size) == 0);
	NUTS_MATCH(ctype, "text/html");
	nng_strfree(ctype);
	nng_free(data, size);

	server_free(&st);

	clean_directory(&sd);
}

void
test_serve_plain_text(void)
{
	void                  *data;
	size_t                 size;
	uint16_t               stat;
	char                  *ctype;
	nng_http_handler      *h;
	struct server_test     st;
	struct serve_directory sd;

	setup_directory(&sd);
	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/", sd.workdir));
	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/file.txt", NULL));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc2));
	NUTS_TRUE(memcmp(data, doc2, size) == 0);
	NUTS_MATCH(ctype, "text/plain");
	nng_strfree(ctype);
	nng_free(data, size);

	server_free(&st);

	clean_directory(&sd);
}

void
test_serve_file_parameters(void)
{
	void                  *data;
	size_t                 size;
	uint16_t               stat;
	char                  *ctype;
	nng_http_handler      *h;
	struct server_test     st;
	struct serve_directory sd;

	setup_directory(&sd);
	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/", sd.workdir));
	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/file.txt?param=1234", NULL));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc2));
	NUTS_TRUE(memcmp(data, doc2, size) == 0);
	NUTS_MATCH(ctype, "text/plain");
	nng_free(data, size);
	nng_strfree(ctype);

	// again but this time pass parameter as arg
	nng_http_reset(st.conn);
	NUTS_PASS(nng_http_set_uri(st.conn, "/file.txt", "param=1234"));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc2));
	NUTS_TRUE(memcmp(data, doc2, size) == 0);
	NUTS_MATCH(ctype, "text/plain");

	nng_strfree(ctype);
	nng_free(data, size);

	server_free(&st);

	clean_directory(&sd);
}

void
test_serve_missing_index(void)
{
	void                  *data;
	size_t                 size;
	uint16_t               stat;
	char                  *ctype;
	nng_http_handler      *h;
	struct server_test     st;
	struct serve_directory sd;

	setup_directory(&sd);
	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/", sd.workdir));
	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/index.html", NULL));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_NOT_FOUND);
	nng_strfree(ctype);
	nng_free(data, size);

	server_free(&st);

	clean_directory(&sd);
}

void
test_serve_index_not_post(void)
{
	void                  *data;
	size_t                 size;
	uint16_t               stat;
	char                  *ctype;
	nng_http_handler      *h;
	struct server_test     st;
	struct serve_directory sd;

	setup_directory(&sd);
	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/", sd.workdir));
	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/subdir2/index.html", NULL));
	nng_http_set_method(st.conn, "POST");
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_METHOD_NOT_ALLOWED);
	nng_strfree(ctype);
	nng_free(data, size);

	server_free(&st);

	clean_directory(&sd);
}

void
test_serve_subdir_index(void)
{
	void                  *data;
	size_t                 size;
	uint16_t               stat;
	char                  *ctype;
	nng_http_handler      *h;
	struct server_test     st;
	struct serve_directory sd;

	setup_directory(&sd);
	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/docs", sd.workdir));
	server_setup(&st, h);

	NUTS_PASS(nng_http_set_uri(st.conn, "/docs/subdir1/", NULL));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc1));
	NUTS_TRUE(memcmp(data, doc1, size) == 0);
	NUTS_MATCH(ctype, "text/html");
	nng_strfree(ctype);
	nng_free(data, size);

	server_free(&st);

	clean_directory(&sd);
}

NUTS_TESTS = {
	{ "server basic", test_server_basic },
	{ "server static binary", test_server_static_bin },
	{ "server canonify", test_server_canonify },
	{ "server head", test_server_head },
	{ "server 404", test_server_404 },
	{ "server authoritiative form", test_server_no_authoritative_form },
	{ "server bad canonify", test_server_bad_canonify },
	{ "server bad version", test_server_bad_version },
	{ "server missing host", test_server_missing_host },
	{ "server wrong method", test_server_wrong_method },
	{ "server method too long", test_server_method_too_long },
	{ "server uri too long", test_server_uri_too_long },
	{ "server header too long", test_server_header_too_long },
	{ "server invalid utf", test_server_invalid_utf8 },
	{ "server post handler", test_server_post_handler },
	{ "server get redirect", test_server_get_redirect },
	{ "server tree redirect", test_server_tree_redirect },
	{ "server post redirect", test_server_post_redirect },
	{ "server post echo tree", test_server_post_echo_tree },
	{ "server address checks", test_server_addrs_handler },
	{ "server error page", test_server_error_page },
	{ "server multiple trees", test_server_multiple_trees },
	{ "server serve directory", test_serve_directory },
	{ "server serve index", test_serve_directory_index },
	{ "server plain text", test_serve_plain_text },
	{ "server file parameters", test_serve_file_parameters },
	{ "server index not post", test_serve_index_not_post },
	{ "server subdir index", test_serve_subdir_index },
	{ NULL, NULL },
};
