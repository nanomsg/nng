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
		nni_aio *        iaio;
		nni_http_client *cli;
		nni_http *       http;
		nni_url *        url;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		iaio = (nni_aio *) aio;

		So(nni_url_parse(&url, "http://httpbin.org") == 0);
		So(nni_http_client_init(&cli, url) == 0);
		nni_http_client_connect(cli, iaio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		http = nni_aio_get_output(iaio, 0);
		Reset({
			nni_http_client_fini(cli);
			nni_http_fini(http);
			nng_aio_free(aio);
			nni_url_free(url);
		});

		Convey("We can initiate a message", {
			nni_http_req *req;
			nni_http_res *res;
			So(http != NULL);

			So(nni_http_req_init(&req) == 0);
			So(nni_http_res_init(&res) == 0);
			Reset({
				nni_http_close(http);
				nni_http_req_fini(req);
				nni_http_res_fini(res);
			});
			So(nni_http_req_set_method(req, "GET") == 0);
			So(nni_http_req_set_version(req, "HTTP/1.1") == 0);
			So(nni_http_req_set_uri(req, "/encoding/utf8") == 0);
			So(nni_http_req_set_header(
			       req, "Host", "httpbin.org") == 0);
			nni_http_write_req(http, req, iaio);

			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			nni_http_read_res(http, res, iaio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nni_http_res_get_status(res) == 200);

			Convey("The message contents are correct", {
				uint8_t     digest[20];
				void *      data;
				const char *cstr;
				size_t      sz;

				cstr = nni_http_res_get_header(
				    res, "Content-Length");
				So(cstr != NULL);
				sz = atoi(cstr);
				So(sz > 0);

				data = nni_alloc(sz);
				So(data != NULL);
				Reset({ nni_free(data, sz); });

				iaio->a_niov           = 1;
				iaio->a_iov[0].iov_len = sz;
				iaio->a_iov[0].iov_buf = data;

				nni_aio_wait(iaio);
				So(nng_aio_result(aio) == 0);

				nni_http_read_full(http, iaio);
				nni_aio_wait(iaio);
				So(nni_aio_result(iaio) == 0);

				nni_sha1(data, sz, digest);
				So(memcmp(digest, utf8_sha1sum, 20) == 0);
			});
		});
	});
});
