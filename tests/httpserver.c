//
// Copyright 2018 Garrett D'Amore <garrett@damore.org>
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

const char *doc1 = "<html><body>Someone <b>is</b> home!</body</html>";
const char *doc2 = "This is a text file.";
const char *doc3 = "<html><body>This is doc number 3.</body></html>";

void
cleanup(void)
{
	nng_fini();
}

static int
httpget(const char *addr, void **datap, size_t *sizep, uint16_t *statp,
    char **ctypep)
{
	int              rv;
	nni_aio *        aio   = NULL;
	nni_http_client *cli   = NULL;
	nni_http *       h     = NULL;
	nni_http_req *   req   = NULL;
	nni_http_res *   res   = NULL;
	nni_url *        url   = NULL;
	size_t           clen  = 0;
	void *           data  = NULL;
	char *           ctype = NULL;
	const char *     ptr;

	if (((rv = nni_url_parse(&url, addr)) != 0) ||
	    ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) ||
	    ((rv = nni_http_req_init(&req)) != 0) ||
	    ((rv = nni_http_res_init(&res)) != 0) ||
	    ((rv = nni_http_client_init(&cli, url)) != 0)) {
		goto fail;
	}
	nni_http_client_connect(cli, aio);
	nni_aio_wait(aio);
	if ((rv = nni_aio_result(aio)) != 0) {
		goto fail;
	}

	h = nni_aio_get_output(aio, 0);
	if (((rv = nni_http_req_set_method(req, "GET")) != 0) ||
	    ((rv = nni_http_req_set_version(req, "HTTP/1.1")) != 0) ||
	    ((rv = nni_http_req_set_uri(req, url->u_path)) != 0) ||
	    ((rv = nni_http_req_set_header(req, "Host", url->u_host)) != 0)) {
		goto fail;
	}
	nni_http_write_req(h, req, aio);
	nni_aio_wait(aio);
	if ((rv = nni_aio_result(aio)) != 0) {
		goto fail;
	}
	nni_http_read_res(h, res, aio);
	nni_aio_wait(aio);
	if ((rv = nni_aio_result(aio)) != 0) {
		goto fail;
	}

	*statp = nni_http_res_get_status(res);
	clen   = 0;
	if ((*statp == NNI_HTTP_STATUS_OK) &&
	    ((ptr = nni_http_res_get_header(res, "Content-Length")) != NULL)) {
		clen = atoi(ptr);
	}

	if (clen > 0) {
		data                  = nni_alloc(clen);
		aio->a_niov           = 1;
		aio->a_iov[0].iov_len = clen;
		aio->a_iov[0].iov_buf = data;
		nni_http_read_full(h, aio);
		nni_aio_wait(aio);
		if ((rv = nni_aio_result(aio)) != 0) {
			goto fail;
		}
		if ((ptr = nni_http_res_get_header(res, "Content-Type")) !=
		    NULL) {
			ctype = nni_strdup(ptr);
		}
	}

	*datap  = data;
	*sizep  = clen;
	*ctypep = ctype;

fail:
	if (rv != 0) {
		if (data != NULL) {
			nni_free(data, clen);
		}
		nni_strfree(ctype);
	}
	if (url != NULL) {
		nni_url_free(url);
	}
	if (aio != NULL) {
		nni_aio_fini(aio);
	}
	if (req != NULL) {
		nni_http_req_fini(req);
	}
	if (res != NULL) {
		nni_http_res_fini(res);
	}
	if (h != NULL) {
		nni_http_fini(h);
	}
	if (cli != NULL) {
		nni_http_client_fini(cli);
	}

	return (rv);
}

TestMain("HTTP Client", {

	nni_http_server * s;
	nni_http_handler *h;

	nni_init();
	atexit(cleanup);

	Convey("We can start an HTTP server", {
		nni_aio *aio;
		char     portbuf[16];
		char     urlstr[32];
		nni_url *url;

		trantest_next_address(portbuf, "%u");

		snprintf(
		    urlstr, sizeof(urlstr), "http://127.0.0.1:%s", portbuf);

		So(nni_url_parse(&url, urlstr) == 0);
		So(nni_aio_init(&aio, NULL, NULL) == 0);

		So(nni_http_server_init(&s, url) == 0);

		Reset({
			nni_aio_fini(aio);
			nni_http_server_fini(s);
			nni_url_free(url);
		});

		So(nni_http_handler_init_static(&h, "/home.html", doc1,
		       strlen(doc1), "text/html") == 0);
		So(nni_http_server_add_handler(s, h) == 0);
		So(nni_http_server_start(s) == 0);

		Convey("We can connect a client to it", {
			nni_http_client *cli;
			nni_http *       h;
			nni_http_req *   req;
			nni_http_res *   res;

			So(nni_http_client_init(&cli, url) == 0);
			nni_http_client_connect(cli, aio);
			nni_aio_wait(aio);

			So(nni_aio_result(aio) == 0);
			h = nni_aio_get_output(aio, 0);
			So(h != NULL);
			So(nni_http_req_init(&req) == 0);
			So(nni_http_res_init(&res) == 0);

			Reset({
				nni_http_client_fini(cli);
				nni_http_fini(h);
				nni_http_req_fini(req);
				nni_http_res_fini(res);
			});

			Convey("404 works", {
				So(nni_http_req_set_method(req, "GET") == 0);
				So(nni_http_req_set_version(req, "HTTP/1.1") ==
				    0);
				So(nni_http_req_set_uri(req, "/bogus") == 0);
				So(nni_http_req_set_header(
				       req, "Host", "localhost") == 0);
				nni_http_write_req(h, req, aio);

				nni_aio_wait(aio);
				So(nni_aio_result(aio) == 0);

				nni_http_read_res(h, res, aio);
				nni_aio_wait(aio);
				So(nni_aio_result(aio) == 0);

				So(nni_http_res_get_status(res) == 404);
			});

			Convey("Valid data works", {
				char        chunk[256];
				const void *ptr;

				So(nni_http_req_set_method(req, "GET") == 0);
				So(nni_http_req_set_version(req, "HTTP/1.1") ==
				    0);
				So(nni_http_req_set_uri(req, "/home.html") ==
				    0);
				So(nni_http_req_set_header(
				       req, "Host", "localhost") == 0);
				nni_http_write_req(h, req, aio);

				nni_aio_wait(aio);
				So(nni_aio_result(aio) == 0);

				nni_http_read_res(h, res, aio);
				nni_aio_wait(aio);
				So(nni_aio_result(aio) == 0);

				So(nni_http_res_get_status(res) == 200);

				ptr = nni_http_res_get_header(
				    res, "Content-Length");
				So(ptr != NULL);
				So(atoi(ptr) == strlen(doc1));

				aio->a_niov           = 1;
				aio->a_iov[0].iov_len = strlen(doc1);
				aio->a_iov[0].iov_buf = (void *) chunk;
				nni_http_read_full(h, aio);
				nni_aio_wait(aio);
				So(nni_aio_result(aio) == 0);
				So(nni_aio_count(aio) == strlen(doc1));
				So(memcmp(chunk, doc1, strlen(doc1)) == 0);
			});

		});
	});
	Convey("Directory serving works", {
		nni_aio *aio;
		char     portbuf[16];
		char     urlstr[32];
		nni_url *url;
		char *   tmpdir;
		char *   workdir;
		char *   file1;
		char *   file2;
		char *   file3;
		char *   subdir1;
		char *   subdir2;

		trantest_next_address(urlstr, "http://127.0.0.1:%u");
		So(nni_url_parse(&url, urlstr) == 0);
		So(nni_aio_init(&aio, NULL, NULL) == 0);
		So(nni_http_server_init(&s, url) == 0);
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
			nni_aio_fini(aio);
			nni_http_server_fini(s);
			nni_strfree(tmpdir);
			nni_file_delete(file1);
			nni_file_delete(file2);
			nni_file_delete(file3);
			nni_file_delete(subdir1);
			nni_file_delete(subdir2);
			nni_file_delete(workdir);
			nni_strfree(workdir);
			nni_strfree(file1);
			nni_strfree(file2);
			nni_strfree(file3);
			nni_strfree(subdir1);
			nni_strfree(subdir2);
			nni_url_free(url);
		});

		So(nni_http_handler_init_directory(&h, "/docs", workdir) == 0);
		So(nni_http_server_add_handler(s, h) == 0);
		So(nni_http_server_start(s) == 0);
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
			So(stat == NNI_HTTP_STATUS_OK);
			So(size == strlen(doc1));
			So(memcmp(data, doc1, size) == 0);
			So(strcmp(ctype, "text/html") == 0);
			nni_strfree(ctype);
			nni_free(data, size);
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
			So(stat == NNI_HTTP_STATUS_OK);
			So(size == strlen(doc3));
			So(memcmp(data, doc3, size) == 0);
			So(strcmp(ctype, "text/html") == 0);
			nni_strfree(ctype);
			nni_free(data, size);
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
			So(stat == NNI_HTTP_STATUS_OK);
			So(size == strlen(doc2));
			So(memcmp(data, doc2, size) == 0);
			So(strcmp(ctype, "text/plain") == 0);
			nni_strfree(ctype);
			nni_free(data, size);
		});

		Convey("Missing index gives 404", {
			char     fullurl[256];
			void *   data;
			size_t   size;
			uint16_t stat;
			char *   ctype;

			snprintf(fullurl, sizeof(fullurl), "%s/docs/", urlstr);
			So(httpget(fullurl, &data, &size, &stat, &ctype) == 0);
			So(stat == NNI_HTTP_STATUS_NOT_FOUND);
			So(size == 0);
		});
	});
})
