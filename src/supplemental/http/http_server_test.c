//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2020 Dirac Research <robert.bielik@dirac.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Basic HTTP server tests.
#include <nng/nng.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/tls/tls.h>

#include <nuts.h>

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
	nng_http_conn    *conn;
	nng_http_req     *req;
	nng_http_res     *res;
	char              urlstr[2048];
};

static int
httpdo(nng_url *url, nng_http_req *req, nng_http_res *res, void **datap,
    size_t *sizep)
{
	int              rv;
	nng_aio         *aio  = NULL;
	nng_http_client *cli  = NULL;
	nng_http_conn   *h    = NULL;
	size_t           clen = 0;
	void            *data = NULL;
	const char      *ptr;

	if (((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0) ||
	    ((rv = nng_http_client_alloc(&cli, url)) != 0)) {
		goto fail;
	}
	nng_http_client_connect(cli, aio);
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		goto fail;
	}

	h = nng_aio_get_output(aio, 0);

	nng_http_conn_write_req(h, req, aio);
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		goto fail;
	}
	nng_http_conn_read_res(h, res, aio);
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		goto fail;
	}

	clen = 0;
	if ((ptr = nng_http_res_get_header(res, "Content-Length")) != NULL) {
		clen = atoi(ptr);
	}

	if (clen > 0) {
		nng_iov iov;
		data        = nng_alloc(clen);
		iov.iov_buf = data;
		iov.iov_len = clen;
		nng_aio_set_iov(aio, 1, &iov);
		nng_http_conn_read_all(h, aio);
		nng_aio_wait(aio);
		if ((rv = nng_aio_result(aio)) != 0) {
			goto fail;
		}
	}

	*datap = data;
	*sizep = clen;

fail:
	if (aio != NULL) {
		nng_aio_free(aio);
	}
	if (h != NULL) {
		nng_http_conn_close(h);
	}
	if (cli != NULL) {
		nng_http_client_free(cli);
	}

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
	const char *ptr;

	if ((rv = httpdo(st->url, st->req, st->res, &data, &clen)) != 0) {
		goto fail;
	}

	*statp = nng_http_res_get_status(st->res);

	if (clen > 0) {
		if ((ptr = nng_http_res_get_header(st->res, "Content-Type")) !=
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
httpecho(nng_aio *aio)
{
	nng_http_req *req = nng_aio_get_input(aio, 0);
	nng_http_res *res;
	int           rv;
	void         *body;
	size_t        len;

	nng_http_req_get_data(req, &body, &len);

	if (((rv = nng_http_res_alloc(&res)) != 0) ||
	    ((rv = nng_http_res_copy_data(res, body, len)) != 0) ||
	    ((rv = nng_http_res_set_header(
	          res, "Content-type", "text/plain")) != 0) ||
	    ((rv = nng_http_res_set_status(res, NNG_HTTP_STATUS_OK)) != 0)) {
		nng_http_res_free(res);
		nng_aio_finish(aio, rv);
		return;
	}
	nng_aio_set_output(aio, 0, res);
	nng_aio_finish(aio, 0);
}

static void
server_setup(struct server_test *st, nng_http_handler *h)
{
	nng_sockaddr sa;
	memset(st, 0, sizeof(*st));
	NUTS_PASS(nng_url_parse(&st->url, "http://127.0.0.1:0"));
	NUTS_PASS(nng_aio_alloc(&st->aio, NULL, NULL));
	NUTS_PASS(nng_http_server_hold(&st->s, st->url));
	if (h != NULL) {
		st->h = h;
		NUTS_PASS(nng_http_server_add_handler(st->s, h));
	}
	NUTS_PASS(nng_http_server_start(st->s));
	NUTS_PASS(nng_http_server_get_addr(st->s, &sa));
	nng_url_resolve_port(st->url, nng_sockaddr_port(&sa));
	nng_url_sprintf(st->urlstr, sizeof(st->urlstr), st->url);

	NUTS_PASS(nng_http_client_alloc(&st->cli, st->url));
	nng_http_client_connect(st->cli, st->aio);
	nng_aio_wait(st->aio);

	NUTS_PASS(nng_aio_result(st->aio));
	st->conn = nng_aio_get_output(st->aio, 0);
	NUTS_TRUE(st->conn != NULL);
	NUTS_PASS(nng_http_req_alloc(&st->req, st->url));
	NUTS_PASS(nng_http_res_alloc(&st->res));
}

static void
server_reset(struct server_test *st)
{
	nng_http_req_free(st->req);
	nng_http_res_free(st->res);
	nng_http_req_alloc(&st->req, st->url);
	nng_http_res_alloc(&st->res);
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
		nng_http_conn_close(st->conn);
	}
	if (st->s != NULL) {
		nng_http_server_release(st->s);
	}
	if (st->url != NULL) {
		nng_url_free(st->url);
	}
	if (st->req != NULL) {
		nng_http_req_free(st->req);
	}
	if (st->res != NULL) {
		nng_http_res_free(st->res);
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

	NUTS_PASS(nng_http_req_set_uri(st.req, "/home.html"));
	nng_http_conn_write_req(st.conn, st.req, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_conn_read_res(st.conn, st.res, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_TRUE(nng_http_res_get_status(st.res) == NNG_HTTP_STATUS_OK);

	ptr = nng_http_res_get_header(st.res, "Content-Length");
	NUTS_TRUE(ptr != NULL);
	NUTS_TRUE(atoi(ptr) == (int) strlen(doc1));

	iov.iov_len = strlen(doc1);
	iov.iov_buf = chunk;
	NUTS_PASS(nng_aio_set_iov(st.aio, 1, &iov));
	nng_http_conn_read_all(st.conn, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));
	NUTS_TRUE(nng_aio_count(st.aio) == strlen(doc1));
	NUTS_TRUE(memcmp(chunk, doc1, strlen(doc1)) == 0);

	server_free(&st);
}

static void
test_server_404(void)
{
	struct server_test st;

	server_setup(&st, NULL);

	NUTS_PASS(nng_http_req_set_uri(st.req, "/bogus"));
	nng_http_conn_write_req(st.conn, st.req, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_conn_read_res(st.conn, st.res, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_TRUE(
	    nng_http_res_get_status(st.res) == NNG_HTTP_STATUS_NOT_FOUND);

	server_free(&st);
}

static void
test_server_bad_version(void)
{
	struct server_test st;

	server_setup(&st, NULL);

	NUTS_PASS(nng_http_req_set_version(st.req, "HTTP/0.9"));
	NUTS_PASS(nng_http_req_set_uri(st.req, "/bogus"));
	nng_http_conn_write_req(st.conn, st.req, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_conn_read_res(st.conn, st.res, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_TRUE(nng_http_res_get_status(st.res) == 505);

	server_free(&st);
}

void
test_server_missing_host(void)
{
	struct server_test st;
	server_setup(&st, NULL);

	nng_http_req_del_header(st.req, "Host");
	NUTS_PASS(nng_http_req_set_uri(st.req, "/bogus"));
	nng_http_conn_write_req(st.conn, st.req, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_conn_read_res(st.conn, st.res, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_TRUE(nng_http_res_get_status(st.res) == 400);

	server_free(&st);
}

void
test_server_wrong_method(void)
{
	struct server_test st;
	nng_http_handler  *h;

	NUTS_PASS(nng_http_handler_alloc_static(
	    &h, "/home.html", doc1, strlen(doc1), "text/html"));

	server_setup(&st, h);

	NUTS_PASS(nng_http_req_set_method(st.req, "POST"));
	NUTS_PASS(nng_http_req_set_uri(st.req, "/home.html"));
	nng_http_conn_write_req(st.conn, st.req, st.aio);

	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	nng_http_conn_read_res(st.conn, st.res, st.aio);
	nng_aio_wait(st.aio);
	NUTS_PASS(nng_aio_result(st.aio));

	NUTS_TRUE(nng_http_res_get_status(st.res) ==
	    NNG_HTTP_STATUS_METHOD_NOT_ALLOWED);
	NUTS_MSG("Got result %d: %s", nng_http_res_get_status(st.res),
	    nng_http_res_get_reason(st.res));

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
	NUTS_PASS(nng_http_handler_set_method(h, "POST"));

	server_setup(&st, h);

	snprintf(txdata, sizeof(txdata), "1234");
	nng_http_req_set_uri(st.req, "/post");
	nng_http_req_set_data(st.req, txdata, strlen(txdata));
	NUTS_PASS(nng_http_req_set_method(st.req, "POST"));
	NUTS_PASS(httpdo(st.url, st.req, st.res, (void **) &rxdata, &size));
	NUTS_TRUE(nng_http_res_get_status(st.res) == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(txdata));
	NUTS_TRUE(strncmp(txdata, rxdata, size) == 0);
	nng_free(rxdata, size);

	server_reset(&st);

	NUTS_PASS(nng_http_req_set_uri(st.req, "/post"));
	NUTS_PASS(nng_http_req_set_method(st.req, "GET"));
	NUTS_PASS(nng_http_req_set_data(st.req, txdata, strlen(txdata)));

	NUTS_PASS(httpdo(st.url, st.req, st.res, &data, &size));
	NUTS_TRUE(nng_http_res_get_status(st.res) ==
	    NNG_HTTP_STATUS_METHOD_NOT_ALLOWED);
	NUTS_MSG("HTTP status was %u", nng_http_res_get_status(st.res));
	nng_free(data, size);

	server_free(&st);
}

static void
test_server_get_redirect(void)
{
	char               fullurl[256];
	const char        *dest;
	void              *data;
	size_t             size;
	nng_http_handler  *h;
	struct server_test st;

	// We'll use a 303 to ensure codes carry thru
	NUTS_PASS(nng_http_handler_alloc_redirect(
	    &h, "/here", 303, "http://127.0.0.1/there"));
	server_setup(&st, h);

	NUTS_PASS(nng_http_req_set_uri(st.req, "/here"));
	nng_http_req_set_method(st.req, "GET");

	NUTS_PASS(httpdo(st.url, st.req, st.res, &data, &size));
	NUTS_TRUE(nng_http_res_get_status(st.res) == 303);
	NUTS_MSG("HTTP status got %d, expected %d (url %s)",
	    nng_http_res_get_status(st.res), 303, fullurl);
	NUTS_TRUE(
	    (dest = nng_http_res_get_header(st.res, "Location")) != NULL);
	NUTS_MATCH(dest, "http://127.0.0.1/there");
	nng_free(data, size);

	server_free(&st);
}

static void
test_server_tree_redirect(void)
{
	char               fullurl[256];
	const char        *dest;
	void              *data;
	size_t             size;
	nng_http_handler  *h;
	struct server_test st;

	// We'll use a 303 to ensure codes carry thru
	NUTS_PASS(nng_http_handler_alloc_redirect(
	    &h, "/here", 303, "http://127.0.0.1/there"));
	NUTS_PASS(nng_http_handler_set_tree(h));
	server_setup(&st, h);

	NUTS_PASS(nng_http_req_set_uri(st.req, "/here/i/go/again"));
	nng_http_req_set_method(st.req, "GET");

	NUTS_PASS(httpdo(st.url, st.req, st.res, &data, &size));
	NUTS_TRUE(nng_http_res_get_status(st.res) == 303);
	NUTS_MSG("HTTP status got %d, expected %d (url %s)",
	    nng_http_res_get_status(st.res), 303, fullurl);
	NUTS_TRUE(
	    (dest = nng_http_res_get_header(st.res, "Location")) != NULL);
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
	NUTS_PASS(nng_http_req_set_uri(st.req, "/here"));
	nng_http_req_set_data(st.req, txdata, strlen(txdata));
	NUTS_PASS(nng_http_req_set_method(st.req, "POST"));
	NUTS_PASS(httpdo(st.url, st.req, st.res, (void **) &data, &size));
	NUTS_TRUE(nng_http_res_get_status(st.res) == 301);
	dest = nng_http_res_get_header(st.res, "Location");
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
	NUTS_PASS(nng_http_handler_set_method(h, "POST"));
	NUTS_PASS(nng_http_handler_set_tree(h));

	server_setup(&st, h);

	snprintf(txdata, sizeof(txdata), "1234");
	nng_http_req_set_data(st.req, txdata, strlen(txdata));
	NUTS_PASS(nng_http_req_set_method(st.req, "POST"));
	NUTS_PASS(nng_http_req_set_uri(st.req, "/some_sub/directory"));
	NUTS_PASS(httpdo(st.url, st.req, st.res, (void **) &rxdata, &size));
	NUTS_TRUE(nng_http_res_get_status(st.res) == NNG_HTTP_STATUS_OK);
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
	NUTS_PASS(nng_http_handler_set_tree(h));
	server_setup(&st, h);

	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/", workdir));
	NUTS_PASS(nng_http_handler_set_tree(h));
	NUTS_FAIL(nng_http_server_add_handler(st.s, h), NNG_EADDRINUSE);
	nng_http_handler_free(h);

	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/subdir", workdir2));
	NUTS_PASS(nng_http_handler_set_tree(h));
	NUTS_PASS(nng_http_server_add_handler(st.s, h));

	NUTS_PASS(nng_http_handler_alloc_directory(&h, "/subdir", workdir2));
	NUTS_PASS(nng_http_handler_set_tree(h));
	NUTS_FAIL(nng_http_server_add_handler(st.s, h), NNG_EADDRINUSE);
	nng_http_handler_free(h);

	nng_msleep(100);

	void    *data;
	size_t   size;
	uint16_t stat;
	char    *ctype;

	NUTS_CASE("Directory 1");
	NUTS_PASS(nng_http_req_set_uri(st.req, "/file1.txt"));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc1));
	NUTS_TRUE(memcmp(data, doc1, size) == 0);
	NUTS_MATCH(ctype, "text/plain");
	nng_strfree(ctype);
	nng_free(data, size);

	server_reset(&st);

	NUTS_CASE("Directory 2");
	NUTS_PASS(nng_http_req_set_uri(st.req, "/subdir/file2.txt"));
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

	NUTS_PASS(nng_http_req_set_uri(st.req, "/subdir1/index.html"));
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
	NUTS_PASS(nng_http_req_set_uri(st.req, "/subdir1/"));
	NUTS_PASS(httpget(&st, &data, &size, &stat, &ctype));
	NUTS_TRUE(stat == NNG_HTTP_STATUS_OK);
	NUTS_TRUE(size == strlen(doc1));
	NUTS_TRUE(memcmp(data, doc1, size) == 0);
	NUTS_MATCH(ctype, "text/html");
	nng_strfree(ctype);
	nng_free(data, size);

	server_reset(&st);

	NUTS_CASE("Directory 2: index.htm");
	NUTS_PASS(nng_http_req_set_uri(st.req, "/subdir2/"));
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

	NUTS_PASS(nng_http_req_set_uri(st.req, "/file.txt"));
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

	NUTS_PASS(nng_http_req_set_uri(st.req, "/file.txt?param=1234"));
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

	NUTS_PASS(nng_http_req_set_uri(st.req, "/index.html"));
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

	NUTS_PASS(nng_http_req_set_uri(st.req, "/subdir2/index.html"));
	NUTS_PASS(nng_http_req_set_method(st.req, "POST"));
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

	NUTS_PASS(nng_http_req_set_uri(st.req, "/docs/subdir1/"));
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
	{ "server 404", test_server_404 },
	{ "server bad version", test_server_bad_version },
	{ "server missing host", test_server_missing_host },
	{ "server wrong method", test_server_wrong_method },
	{ "server post handler", test_server_post_handler },
	{ "server get redirect", test_server_get_redirect },
	{ "server tree redirect", test_server_tree_redirect },
	{ "server post redirect", test_server_post_redirect },
	{ "server post echo tree", test_server_post_echo_tree },
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
