//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "trantest.h"

#ifndef _WIN32
#include <arpa/inet.h>
#endif

// Basic HTTP server tests.
#include "core/nng_impl.h"
#include "supplemental/http/http.h"
#include "supplemental/tls/tls.h"

const char *doc1 = "<html><body>Someone <b>is</b> home!</body</html>";
const char *doc2 = "This is a text file.";
const char *doc3 = "<html><body>This is doc number 3.</body></html>";

void
cleanup(void)
{
	nng_fini();
}

static int
httpdo(nng_url *url, nng_http_req *req, nng_http_res *res, void **datap,
    size_t *sizep)
{
	int              rv;
	nng_aio *        aio  = NULL;
	nng_http_client *cli  = NULL;
	nng_http_conn *  h    = NULL;
	size_t           clen = 0;
	void *           data = NULL;
	const char *     ptr;

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
	if ((nng_http_res_get_status(res) == NNG_HTTP_STATUS_OK) &&
	    ((ptr = nng_http_res_get_header(res, "Content-Length")) != NULL)) {
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
httpget(const char *addr, void **datap, size_t *sizep, uint16_t *statp,
    char **ctypep)
{
	int           rv;
	nng_http_req *req   = NULL;
	nng_http_res *res   = NULL;
	nng_url *     url   = NULL;
	size_t        clen  = 0;
	void *        data  = NULL;
	char *        ctype = NULL;
	const char *  ptr;

	if (((rv = nng_url_parse(&url, addr)) != 0) ||
	    ((rv = nng_http_req_alloc(&req, url)) != 0) ||
	    ((rv = nng_http_res_alloc(&res)) != 0)) {
		goto fail;
	}
	if ((rv = httpdo(url, req, res, &data, &clen)) != 0) {
		goto fail;
	}

	*statp = nng_http_res_get_status(res);

	if (clen > 0) {
		if ((ptr = nng_http_res_get_header(res, "Content-Type")) !=
		    NULL) {
			ctype = strdup(ptr);
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
	if (url != NULL) {
		nni_url_free(url);
	}
	if (req != NULL) {
		nng_http_req_free(req);
	}
	if (res != NULL) {
		nng_http_res_free(res);
	}

	return (rv);
}

TestMain("HTTP Server", {
	nng_http_server * s;
	nng_http_handler *h;

	nni_init();
	atexit(cleanup);

	Convey("We can start an HTTP server", {
		nng_aio *aio;
		char     portbuf[16];
		char     urlstr[48];
		nng_url *url;

		trantest_next_address(portbuf, "%u");

		snprintf(
		    urlstr, sizeof(urlstr), "http://127.0.0.1:%s", portbuf);

		So(nng_url_parse(&url, urlstr) == 0);
		So(nng_aio_alloc(&aio, NULL, NULL) == 0);

		So(nng_http_server_hold(&s, url) == 0);

		Reset({
			nng_aio_free(aio);
			nng_http_server_release(s);
			nng_url_free(url);
		});

		So(nng_http_handler_alloc_static(&h, "/home.html", doc1,
		       strlen(doc1), "text/html") == 0);
		So(nng_http_server_add_handler(s, h) == 0);
		So(nng_http_server_start(s) == 0);

		Convey("We can connect a client to it", {
			nng_http_client *cli;
			nng_http_conn *  h;
			nng_http_req *   req;
			nng_http_res *   res;

			So(nng_http_client_alloc(&cli, url) == 0);
			nng_http_client_connect(cli, aio);
			nng_aio_wait(aio);

			So(nng_aio_result(aio) == 0);
			h = nng_aio_get_output(aio, 0);
			So(h != NULL);
			So(nng_http_req_alloc(&req, url) == 0);
			So(nng_http_res_alloc(&res) == 0);

			Reset({
				nng_http_client_free(cli);
				nng_http_conn_close(h);
				nng_http_req_free(req);
				nng_http_res_free(res);
			});

			Convey("404 works", {
				So(nng_http_req_set_uri(req, "/bogus") == 0);
				nng_http_conn_write_req(h, req, aio);

				nng_aio_wait(aio);
				So(nng_aio_result(aio) == 0);

				nng_http_conn_read_res(h, res, aio);
				nng_aio_wait(aio);
				So(nng_aio_result(aio) == 0);

				So(nng_http_res_get_status(res) == 404);
			});

			Convey("Valid data works", {
				char        chunk[256];
				const void *ptr;
				nng_iov     iov;

				So(nng_http_req_set_uri(req, "/home.html") ==
				    0);
				nng_http_conn_write_req(h, req, aio);

				nng_aio_wait(aio);
				So(nng_aio_result(aio) == 0);

				nng_http_conn_read_res(h, res, aio);
				nng_aio_wait(aio);
				So(nng_aio_result(aio) == 0);

				So(nng_http_res_get_status(res) == 200);

				ptr = nng_http_res_get_header(
				    res, "Content-Length");
				So(ptr != NULL);
				So(atoi(ptr) == (int) strlen(doc1));

				iov.iov_len = strlen(doc1);
				iov.iov_buf = chunk;
				So(nng_aio_set_iov(aio, 1, &iov) == 0);
				nng_http_conn_read_all(h, aio);
				nng_aio_wait(aio);
				So(nng_aio_result(aio) == 0);
				So(nng_aio_count(aio) == strlen(doc1));
				So(memcmp(chunk, doc1, strlen(doc1)) == 0);
			});
		});
	});
	Convey("Directory serving works", {
		char     urlstr[32];
		nng_url *url;
		char *   tmpdir;
		char *   workdir;
		char *   file1;
		char *   file2;
		char *   file3;
		char *   subdir1;
		char *   subdir2;

		trantest_next_address(urlstr, "http://127.0.0.1:%u");
		So(nng_url_parse(&url, urlstr) == 0);
		So(nng_http_server_hold(&s, url) == 0);
		So((tmpdir = nni_plat_temp_dir()) != NULL);
		So((workdir = nni_file_join(tmpdir, "httptest")) != NULL);
		So((subdir1 = nni_file_join(workdir, "subdir1")) != NULL);
		So((subdir2 = nni_file_join(workdir, "subdir2")) != NULL);
		So((file1 = nni_file_join(subdir1, "index.html")) != NULL);
		So((file2 = nni_file_join(workdir, "file.txt")) != NULL);
		So((file3 = nni_file_join(subdir2, "index.htm")) != NULL);

		So(nni_file_put(file1, doc1, strlen(doc1)) == 0);
		So(nni_file_put(file2, doc2, strlen(doc2)) == 0);
		So(nni_file_put(file3, doc3, strlen(doc3)) == 0);

		Reset({
			nng_http_server_release(s);
			free(tmpdir);
			nni_file_delete(file1);
			nni_file_delete(file2);
			nni_file_delete(file3);
			nni_file_delete(subdir1);
			nni_file_delete(subdir2);
			nni_file_delete(workdir);
			free(workdir);
			free(file1);
			free(file2);
			free(file3);
			free(subdir1);
			free(subdir2);
			nng_url_free(url);
		});

		So(nng_http_handler_alloc_directory(&h, "/docs", workdir) ==
		    0);
		So(nng_http_server_add_handler(s, h) == 0);
		So(nng_http_server_start(s) == 0);
		nng_msleep(100);

		Convey("Index.html works", {
			char     fullurl[256];
			void *   data;
			size_t   size;
			uint16_t stat;
			char *   ctype;

			snprintf(fullurl, sizeof(fullurl),
			    "%s/docs/subdir1/index.html", urlstr);
			So(httpget(fullurl, &data, &size, &stat, &ctype) == 0);
			So(stat == NNG_HTTP_STATUS_OK);
			So(size == strlen(doc1));
			So(memcmp(data, doc1, size) == 0);
			So(strcmp(ctype, "text/html") == 0);
			free(ctype);
			nng_free(data, size);
		});

		Convey("Index.htm works", {
			char     fullurl[256];
			void *   data;
			size_t   size;
			uint16_t stat;
			char *   ctype;

			snprintf(fullurl, sizeof(fullurl), "%s/docs/subdir2",
			    urlstr);
			So(httpget(fullurl, &data, &size, &stat, &ctype) == 0);
			So(stat == NNG_HTTP_STATUS_OK);
			So(size == strlen(doc3));
			So(memcmp(data, doc3, size) == 0);
			So(strcmp(ctype, "text/html") == 0);
			nni_strfree(ctype);
			nng_free(data, size);
		});

		Convey("Named file works", {
			char     fullurl[256];
			void *   data;
			size_t   size;
			uint16_t stat;
			char *   ctype;

			snprintf(fullurl, sizeof(fullurl), "%s/docs/file.txt",
			    urlstr);
			So(httpget(fullurl, &data, &size, &stat, &ctype) == 0);
			So(stat == NNG_HTTP_STATUS_OK);
			So(size == strlen(doc2));
			So(memcmp(data, doc2, size) == 0);
			So(strcmp(ctype, "text/plain") == 0);
			nni_strfree(ctype);
			nng_free(data, size);
		});

		Convey("Missing index gives 404", {
			char     fullurl[256];
			void *   data;
			size_t   size;
			uint16_t stat;
			char *   ctype;

			snprintf(fullurl, sizeof(fullurl), "%s/docs/", urlstr);
			So(httpget(fullurl, &data, &size, &stat, &ctype) == 0);
			So(stat == NNG_HTTP_STATUS_NOT_FOUND);
			So(size == 0);
		});

		Convey("Bad method gives 405", {
			char          fullurl[256];
			void *        data;
			size_t        size;
			nng_http_req *req;
			nng_http_res *res;
			nng_url *     curl;

			So(nng_http_res_alloc(&res) == 0);
			snprintf(fullurl, sizeof(fullurl), "%s/docs/", urlstr);
			So(nng_url_parse(&curl, fullurl) == 0);
			So(nng_http_req_alloc(&req, curl) == 0);
			So(nng_http_req_set_method(req, "POST") == 0);

			So(httpdo(curl, req, res, &data, &size) == 0);
			So(nng_http_res_get_status(res) ==
			    NNG_HTTP_STATUS_METHOD_NOT_ALLOWED);
			So(size == 0);
			nng_http_req_free(req);
			nng_http_res_free(res);
			nng_url_free(curl);
		});
		Convey("Version 0.9 gives 505", {
			char          fullurl[256];
			void *        data;
			size_t        size;
			nng_http_req *req;
			nng_http_res *res;
			nng_url *     curl;

			So(nng_http_res_alloc(&res) == 0);
			snprintf(fullurl, sizeof(fullurl), "%s/docs/", urlstr);
			So(nng_url_parse(&curl, fullurl) == 0);
			So(nng_http_req_alloc(&req, curl) == 0);
			So(nng_http_req_set_version(req, "HTTP/0.9") == 0);

			So(httpdo(curl, req, res, &data, &size) == 0);
			So(nng_http_res_get_status(res) ==
			    NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP);
			So(size == 0);
			nng_http_req_free(req);
			nng_http_res_free(res);
			nng_url_free(curl);
		});
		Convey("Missing Host gives 400", {
			char          fullurl[256];
			void *        data;
			size_t        size;
			nng_http_req *req;
			nng_http_res *res;
			nng_url *     curl;

			So(nng_http_res_alloc(&res) == 0);
			snprintf(fullurl, sizeof(fullurl), "%s/docs/", urlstr);
			So(nng_url_parse(&curl, fullurl) == 0);
			So(nng_http_req_alloc(&req, curl) == 0);
			So(nng_http_req_del_header(req, "Host") == 0);

			So(httpdo(curl, req, res, &data, &size) == 0);
			So(nng_http_res_get_status(res) ==
			    NNG_HTTP_STATUS_BAD_REQUEST);
			So(size == 0);
			nng_http_req_free(req);
			nng_http_res_free(res);
			nng_url_free(curl);
		});
	});
})
