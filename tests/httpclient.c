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

// Basic HTTP client tests.
#include "core/nng_impl.h"
#include "supplemental/http/http.h"
#include "supplemental/sha1/sha1.h"

const uint8_t utf8_sha1sum[20] = { 0x54, 0xf3, 0xb8, 0xbb, 0xfe, 0xda, 0x6f,
	0xb4, 0x96, 0xdd, 0xc9, 0x8b, 0x8c, 0x41, 0xf4, 0xfe, 0xe5, 0xa9, 0x7d,
	0xa9 };

TestMain("HTTP Client", {

	nni_init();
	atexit(nng_fini);

	Convey("Given a TCP connection to httpbin.org", {
		nng_aio *        aio;
		nng_http_client *cli;
		nng_http_conn *  http;
		nng_url *        url;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);

		So(nng_url_parse(&url, "http://httpbin.org/encoding/utf8") ==
		    0);
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

				data = nni_alloc(sz);
				So(data != NULL);
				Reset({ nni_free(data, sz); });

				iov.iov_buf = data;
				iov.iov_len = sz;
				So(nng_aio_set_iov(aio, 1, &iov) == 0);

				nng_aio_wait(aio);
				So(nng_aio_result(aio) == 0);

				nng_http_conn_read_all(http, aio);
				nng_aio_wait(aio);
				So(nng_aio_result(aio) == 0);

				nni_sha1(data, sz, digest);
				So(memcmp(digest, utf8_sha1sum, 20) == 0);
			});
		});
	});
});
