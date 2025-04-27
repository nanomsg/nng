//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
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

#include <nng/http.h>
#include <nng/nng.h>

#include "core/nng_impl.h"

#include "convey.h"

TestMain("HTTP Client", {
	Convey("Given a TCP connection to example.com", {
		nng_aio         *aio;
		nng_http_client *cli;
		nng_http        *http;
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
			nng_http_close(http);
			nng_aio_free(aio);
			nng_url_free(url);
		});

		Convey("We can initiate a message", {
			So(http != NULL);

			So(nng_http_set_uri(http, nng_url_path(url), NULL) ==
			    0);
			nng_http_write_request(http, aio);

			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			nng_http_read_response(http, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_get_status(http) == 200);

			Convey("The message contents are correct", {
				void       *data;
				const char *cstr;
				size_t      sz;
				nng_iov     iov;

				cstr = nng_http_get_header(
				    http, "Content-Length");
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

				nng_http_read_all(http, aio);
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
			nng_http *conn;
			void     *data;
			size_t    len;

			nng_http_client_connect(cli, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			conn = nng_aio_get_output(aio, 0);
			Reset({ nng_http_close(conn); });

			So(nng_http_set_uri(conn, nng_url_path(url), NULL) ==
			    0);

			nng_http_transact(conn, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_get_status(conn) == 200);
			nng_http_get_body(conn, &data, &len);
		});

		Convey("Connection reuse works", {
			void     *data;
			size_t    len;
			nng_http *conn = NULL;

			Reset({
				if (conn != NULL) {
					nng_http_close(conn);
				}
			});

			nng_http_client_connect(cli, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			conn = nng_aio_get_output(aio, 0);

			So(nng_http_set_uri(conn, nng_url_path(url), NULL) ==
			    0);
			nng_http_transact(conn, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_get_status(conn) == 200);
			nng_http_get_body(conn, &data, &len);

			nng_http_reset(conn);
			So(nng_http_set_uri(conn, nng_url_path(url), NULL) ==
			    0);
			nng_http_transact(conn, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_get_status(conn) == 200);
			nng_http_get_body(conn, &data, &len);
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
		nng_http        *conn;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);

		So(nng_url_parse(&url, "http://httpbin.org/delay/30") == 0);

		So(nng_http_client_alloc(&cli, url) == 0);
		nng_http_client_connect(cli, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		conn = nng_aio_get_output(aio, 0);
		Reset({
			nng_http_client_free(cli);
			nng_url_free(url);
			nng_aio_free(aio);
		});
		nng_aio_set_timeout(aio, 10); // 10 msec timeout

		So(nng_http_set_header(conn, "Cache-Control", "no-cache") ==
		    0);
		nng_http_transact(conn, aio);
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
			void     *data;
			size_t    len;
			nng_http *conn;

			nng_http_client_connect(cli, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			conn = nng_aio_get_output(aio, 0);
			Reset({ nng_http_close(conn); });
			So(nng_http_set_uri(conn, nng_url_path(url), NULL) ==
			    0);
			nng_http_transact(conn, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			So(nng_http_get_status(conn) == 200);
			nng_http_get_body(conn, (void **) &data, &len);
		});
	});
})
