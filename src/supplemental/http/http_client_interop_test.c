//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// HTTP client interoperability tests.  These tests require a local httpbin
// compatible server and use the NNG_HTTPBIN_URL environment variable.

#include <nng/http.h>
#include <nng/nng.h>

#include "../../testing/nuts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *
httpbin_url(void)
{
	const char *url = getenv("NNG_HTTPBIN_URL");

	if ((url == NULL) || (url[0] == '\0')) {
		NUTS_SKIP("NNG_HTTPBIN_URL is not set");
		return (NULL);
	}
	return (url);
}

static void
make_url(char *dst, size_t dstsz, const char *base, const char *path)
{
	size_t len = strlen(base);

	if ((len > 0) && (base[len - 1] == '/')) {
		snprintf(dst, dstsz, "%.*s%s", (int) (len - 1), base, path);
	} else {
		snprintf(dst, dstsz, "%s%s", base, path);
	}
}

static void
connect_url(const char *urlstr, nng_url **urlp, nng_aio **aiop,
    nng_http_client **clip, nng_http **connp)
{
	NUTS_PASS(nng_url_parse(urlp, urlstr));
	NUTS_PASS(nng_aio_alloc(aiop, NULL, NULL));
	nng_aio_set_timeout(*aiop, 10000);
	NUTS_PASS(nng_http_client_alloc(clip, *urlp));
	nng_http_client_connect(*clip, *aiop);
	nng_aio_wait(*aiop);
	NUTS_PASS(nng_aio_result(*aiop));
	*connp = nng_aio_get_output(*aiop, 0);
	NUTS_TRUE(*connp != NULL);
}

static void
free_client(nng_url *url, nng_aio *aio, nng_http_client *cli, nng_http *conn)
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
test_httpbin_get(void)
{
	const char      *base = httpbin_url();
	char             urlstr[512];
	nng_url         *url = NULL;
	nng_aio         *aio = NULL;
	nng_http_client *cli = NULL;
	nng_http        *conn = NULL;
	void            *data;
	size_t           len;

	if (base == NULL) {
		return;
	}
	make_url(urlstr, sizeof(urlstr), base, "/get");
	connect_url(urlstr, &url, &aio, &cli, &conn);
	NUTS_PASS(nng_http_set_uri(conn, nng_url_path(url), NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_HTTP_STATUS(conn, NNG_HTTP_STATUS_OK);
	nng_http_get_body(conn, &data, &len);
	NUTS_TRUE(data != NULL);
	NUTS_TRUE(len > 0);
	free_client(url, aio, cli, conn);
}

static void
test_httpbin_reuse(void)
{
	const char      *base = httpbin_url();
	char             urlstr[512];
	nng_url         *url = NULL;
	nng_aio         *aio = NULL;
	nng_http_client *cli = NULL;
	nng_http        *conn = NULL;
	void            *data;
	size_t           len;

	if (base == NULL) {
		return;
	}
	make_url(urlstr, sizeof(urlstr), base, "/get");
	connect_url(urlstr, &url, &aio, &cli, &conn);

	NUTS_PASS(nng_http_set_uri(conn, nng_url_path(url), NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_HTTP_STATUS(conn, NNG_HTTP_STATUS_OK);
	nng_http_get_body(conn, &data, &len);
	NUTS_TRUE(data != NULL);
	NUTS_TRUE(len > 0);

	nng_http_reset(conn);
	NUTS_PASS(nng_http_set_uri(conn, nng_url_path(url), NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_HTTP_STATUS(conn, NNG_HTTP_STATUS_OK);
	nng_http_get_body(conn, &data, &len);
	NUTS_TRUE(data != NULL);
	NUTS_TRUE(len > 0);

	free_client(url, aio, cli, conn);
}

static void
test_httpbin_chunked_stream(void)
{
	const char      *base = httpbin_url();
	char             urlstr[512];
	nng_url         *url = NULL;
	nng_aio         *aio = NULL;
	nng_http_client *cli = NULL;
	nng_http        *conn = NULL;
	void            *data;
	size_t           len;

	if (base == NULL) {
		return;
	}
	make_url(urlstr, sizeof(urlstr), base, "/stream/2");
	connect_url(urlstr, &url, &aio, &cli, &conn);
	NUTS_PASS(nng_http_set_uri(conn, nng_url_path(url), NULL));
	nng_http_transact(conn, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_HTTP_STATUS(conn, NNG_HTTP_STATUS_OK);
	nng_http_get_body(conn, &data, &len);
	NUTS_TRUE(data != NULL);
	NUTS_TRUE(len > 0);
	free_client(url, aio, cli, conn);
}

NUTS_TESTS = {
	{ "httpbin get", test_httpbin_get },
	{ "httpbin reuse", test_httpbin_reuse },
	{ "httpbin chunked stream", test_httpbin_chunked_stream },
	{ NULL, NULL },
};
