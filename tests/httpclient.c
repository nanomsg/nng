//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Basic HTTP client tests.

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include <nng/nng.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/tls/tls.h>

#include "core/nng_impl.h"

#include "convey.h"
#include "trantest.h"

TestMain("HTTP Client", {
	Convey("Given a TCP connection to example.com", {
		nng_aio         *aio;
		nng_http_client *cli;
		nng_http_conn   *http;
		nng_url         *url;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);

		So(nng_url_parse(&url, "http://example.com/") == 0);

		nng_aio_set_timeout(aio, 10000);
		So(nng_http_client_alloc(&cli, url) == 0);
		nng_http_client_connect(cli, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		http = nng_aio_get_output(aio, 0);
		Reset({
			nng_http_client_free(cli);
			nng_http_conn_close(http);
			nng_aio_free(aio);
			nng_url_free(url);
		});

		Convey("We can initiate a message", {
			nng_http_req *req;
			nng_http_res *res;

			So(http != NULL);

			So(nng_http_req_alloc(&req, url) == 0);
			So(nng_http_res_alloc(&res) == 0);
			Reset({
				nng_http_req_free(req);
				nng_http_res_free(res);
			});
			nng_http_conn_write_req(http, req, aio);

			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			nng_http_conn_read_res(http, res, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_res_get_status(res) == 200);

			Convey("The message contents are correct", {
				void       *data;
				const char *cstr;
				size_t      sz;
				nng_iov     iov;

				cstr = nng_http_res_get_header(
				    res, "Content-Length");
				So(cstr != NULL);
				sz = atoi(cstr);
				So(sz > 0);

				data = nng_alloc(sz);
				So(data != NULL);
				Reset({ nng_free(data, sz); });

				iov.iov_buf = data;
				iov.iov_len = sz;
				So(nng_aio_set_iov(aio, 1, &iov) == 0);

				nng_aio_wait(aio);
				So(nng_aio_result(aio) == 0);

				nng_http_conn_read_all(http, aio);
				nng_aio_wait(aio);
				So(nng_aio_result(aio) == 0);
			});
		});
	});

	Convey("Given a client", {
		nng_aio         *aio;
		nng_http_client *cli;
		nng_url         *url;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);

		So(nng_url_parse(&url, "http://example.com/") == 0);

		So(nng_http_client_alloc(&cli, url) == 0);
		nng_aio_set_timeout(aio, 10000); // 10 sec timeout

		Reset({
			nng_http_client_free(cli);
			nng_url_free(url);
			nng_aio_free(aio);
		});

		Convey("One off exchange works", {
			nng_http_req *req;
			nng_http_res *res;
			void         *data;
			size_t        len;

			So(nng_http_req_alloc(&req, url) == 0);
			So(nng_http_res_alloc(&res) == 0);
			Reset({
				nng_http_req_free(req);
				nng_http_res_free(res);
			});

			nng_http_client_transact(cli, req, res, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_res_get_status(res) == 200);
			nng_http_res_get_data(res, &data, &len);
		});

		Convey("Connection reuse works", {
			nng_http_req  *req;
			nng_http_res  *res1;
			nng_http_res  *res2;
			void          *data;
			size_t         len;
			nng_http_conn *conn = NULL;

			So(nng_http_req_alloc(&req, url) == 0);
			So(nng_http_res_alloc(&res1) == 0);
			So(nng_http_res_alloc(&res2) == 0);
			Reset({
				nng_http_req_free(req);
				nng_http_res_free(res1);
				nng_http_res_free(res2);
				if (conn != NULL) {
					nng_http_conn_close(conn);
				}
			});

			nng_http_client_connect(cli, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			conn = nng_aio_get_output(aio, 0);

			nng_http_conn_transact(conn, req, res1, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_res_get_status(res1) == 200);
			nng_http_res_get_data(res1, &data, &len);

			nng_http_conn_transact(conn, req, res2, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_res_get_status(res2) == 200);
			nng_http_res_get_data(res2, &data, &len);
		});
	});

	// We are skipping this test for now, because it fails all the time
	// in the cloud -- it appears that there are caches and proxies that
	// are unavoidable in the infrastructure.  We will revisit when we
	// provide our own HTTP test server on localhost.
	SkipConvey("Client times out", {
		nng_aio         *aio;
		nng_http_client *cli;
		nng_url         *url;
		nng_http_req    *req;
		nng_http_res    *res;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);

		So(nng_url_parse(&url, "http://httpbin.org/delay/30") == 0);

		So(nng_http_client_alloc(&cli, url) == 0);
		So(nng_http_req_alloc(&req, url) == 0);
		So(nng_http_res_alloc(&res) == 0);

		Reset({
			nng_http_client_free(cli);
			nng_url_free(url);
			nng_aio_free(aio);
			nng_http_req_free(req);
			nng_http_res_free(res);
		});
		nng_aio_set_timeout(aio, 10); // 10 msec timeout

		So(nng_http_req_set_header(req, "Cache-Control", "no-cache") ==
		    0);
		nng_http_client_transact(cli, req, res, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == NNG_ETIMEDOUT);
	});

	Convey("Given a client (chunked)", {
		nng_aio         *aio;
		nng_http_client *cli;
		nng_url         *url;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);

		So(nng_url_parse(&url,
		       "http://anglesharp.azurewebsites.net/Chunked") == 0);
		//		       "https://jigsaw.w3.org/HTTP/ChunkedScript")
		//== 0);

		So(nng_http_client_alloc(&cli, url) == 0);
		nng_aio_set_timeout(aio, 10000); // 10 sec timeout

		Reset({
			nng_http_client_free(cli);
			nng_url_free(url);
			nng_aio_free(aio);
		});

		Convey("One off exchange works", {
			nng_http_req *req;
			nng_http_res *res;
			void         *data;
			size_t        len;

			So(nng_http_req_alloc(&req, url) == 0);
			So(nng_http_res_alloc(&res) == 0);
			Reset({
				nng_http_req_free(req);
				nng_http_res_free(res);
			});

			nng_http_client_transact(cli, req, res, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_res_get_status(res) == 200);
			nng_http_res_get_data(res, &data, &len);
		});
	});
})
