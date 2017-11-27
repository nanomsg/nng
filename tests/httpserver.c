//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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
#include "supplemental/sha1/sha1.h"

const uint8_t utf8_sha1sum[20] = { 0x54, 0xf3, 0xb8, 0xbb, 0xfe, 0xda, 0x6f,
	0xb4, 0x96, 0xdd, 0xc9, 0x8b, 0x8c, 0x41, 0xf4, 0xfe, 0xe5, 0xa9, 0x7d,
	0xa9 };

void
cleanup(void)
{
	nng_fini();
}

TestMain("HTTP Client", {

	nni_http_server *s;

	nni_init();
	atexit(cleanup);

	Convey("We can start an HTTP server", {
		nng_sockaddr sa;
		nni_aio *    aio;
		char         portbuf[16];
		char *doc = "<html><body>Someone <b>is</b> home!</body</html>";

		trantest_next_address(portbuf, "%u");

		So(nni_aio_init(&aio, NULL, NULL) == 0);
		aio->a_addr = &sa;
		nni_plat_tcp_resolv("127.0.0.1", portbuf, NNG_AF_INET, 0, aio);
		nni_aio_wait(aio);
		So(nni_aio_result(aio) == 0);

		So(nni_http_server_init(&s, &sa) == 0);

		Reset({
			nni_aio_fini(aio);
			nni_http_server_fini(s);
		});

		So(nni_http_server_add_static(s, NULL, "text/html",
		       "/home.html", doc, strlen(doc)) == 0);
		So(nni_http_server_start(s) == 0);

		Convey("We can connect a client to it", {
			nni_http_client *cli;
			nni_http *       h;
			nni_http_req *   req;
			nni_http_res *   res;

			So(nni_http_client_init(&cli, &sa) == 0);
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
				So(atoi(ptr) == strlen(doc));

				aio->a_niov           = 1;
				aio->a_iov[0].iov_len = strlen(doc);
				aio->a_iov[0].iov_buf = (void *) chunk;
				nni_http_read_full(h, aio);
				nni_aio_wait(aio);
				So(nni_aio_result(aio) == 0);
				So(nni_aio_count(aio) == strlen(doc));
				So(memcmp(chunk, doc, strlen(doc)) == 0);
			});

		});
	});
});
