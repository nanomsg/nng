//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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

#include "supplemental/sha1/sha1.c"
#include "supplemental/sha1/sha1.h"

#include "convey.h"
#include "trantest.h"

const uint8_t example_sum[20] = { 0x0e, 0x97, 0x3b, 0x59, 0xf4, 0x76, 0x00,
	0x7f, 0xd1, 0x0f, 0x87, 0xf3, 0x47, 0xc3, 0x95, 0x60, 0x65, 0x51, 0x6f,
	0xc0 };

const uint8_t chunked_sum[20] = { 0x9b, 0x06, 0xfb, 0xee, 0x51, 0xc6, 0x42,
	0x69, 0x1c, 0xb3, 0xaa, 0x38, 0xce, 0xb8, 0x0b, 0x3a, 0xc8, 0x3b, 0x96,
	0x68 };

TestMain("HTTP Client", {
	atexit(nng_fini);

	Convey("Given a TCP connection to example.com", {
		nng_aio *        aio;
		nng_http_client *cli;
		nng_http_conn *  http;
		nng_url *        url;

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
				uint8_t     digest[20];
				void *      data;
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

				nni_sha1(data, sz, digest);
				So(memcmp(digest, example_sum, 20) == 0);
			});
		});
	});

	Convey("Given a client", {
		nng_aio *        aio;
		nng_http_client *cli;
		nng_url *        url;

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
			void *        data;
			size_t        len;
			uint8_t       digest[20];

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
			nni_sha1(data, len, digest);
			So(memcmp(digest, example_sum, 20) == 0);
		});

		Convey("Timeout works", {
			nng_http_req *req;
			nng_http_res *res;

			So(nng_http_req_alloc(&req, url) == 0);
			So(nng_http_res_alloc(&res) == 0);
			Reset({
				nng_http_req_free(req);
				nng_http_res_free(res);
			});

			nng_aio_set_timeout(aio, 1); // 1 ms, should timeout!
			nng_http_client_transact(cli, req, res, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == NNG_ETIMEDOUT);
		});

		Convey("Connection reuse works", {
			nng_http_req * req;
			nng_http_res * res1;
			nng_http_res * res2;
			void *         data;
			size_t         len;
			uint8_t        digest[20];
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
			nni_sha1(data, len, digest);
			So(memcmp(digest, example_sum, 20) == 0);

			nng_http_conn_transact(conn, req, res2, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_res_get_status(res2) == 200);
			nng_http_res_get_data(res2, &data, &len);
			nni_sha1(data, len, digest);
			So(memcmp(digest, example_sum, 20) == 0);
		});
	});

	Convey("Given a client (chunked)", {
		nng_aio *        aio;
		nng_http_client *cli;
		nng_url *        url;

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
			void *        data;
			size_t        len;
			uint8_t       digest[20];

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
			nni_sha1(data, len, digest);
			So(memcmp(digest, chunked_sum, 20) == 0);
		});
	});
})
