//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>

#include "convey.h"

TestMain("URLs", {
	nng_url *url;

	Convey("http://www.google.com", {
		So(nng_url_parse(&url, "http://www.google.com") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "www.google.com") == 0);
		So(strcmp(url->u_hostname, "www.google.com") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_path, "") == 0);
		So(strcmp(url->u_requri, "") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});

	Convey("http://www.google.com:1234", {
		So(nng_url_parse(&url, "http://www.google.com:1234") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "www.google.com:1234") == 0);
		So(strcmp(url->u_hostname, "www.google.com") == 0);
		So(strcmp(url->u_port, "1234") == 0);
		So(strcmp(url->u_path, "") == 0);
		So(strcmp(url->u_requri, "") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});

	Convey("http://www.google.com:1234/somewhere", {
		So(nng_url_parse(
		       &url, "http://www.google.com:1234/somewhere") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "www.google.com:1234") == 0);
		So(strcmp(url->u_hostname, "www.google.com") == 0);
		So(strcmp(url->u_port, "1234") == 0);
		So(strcmp(url->u_path, "/somewhere") == 0);
		So(strcmp(url->u_requri, "/somewhere") == 0);
		So(url->u_userinfo == NULL);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		nng_url_free(url);
	});
	Convey("http://garrett@www.google.com:1234/somewhere", {
		So(nng_url_parse(&url,
		       "http://garrett@www.google.com:1234/somewhere") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_userinfo, "garrett") == 0);
		So(strcmp(url->u_host, "www.google.com:1234") == 0);
		So(strcmp(url->u_hostname, "www.google.com") == 0);
		So(strcmp(url->u_port, "1234") == 0);
		So(strcmp(url->u_path, "/somewhere") == 0);
		So(strcmp(url->u_requri, "/somewhere") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		nng_url_free(url);
	});
	Convey("http://www.google.com/somewhere?result=yes", {
		So(nng_url_parse(&url,
		       "http://www.google.com/somewhere?result=yes") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "www.google.com") == 0);
		So(strcmp(url->u_hostname, "www.google.com") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_path, "/somewhere") == 0);
		So(strcmp(url->u_query, "result=yes") == 0);
		So(strcmp(url->u_requri, "/somewhere?result=yes") == 0);
		So(url->u_userinfo == NULL);
		So(url->u_fragment == NULL);
		nng_url_free(url);
	});
	Convey("http://www.google.com/somewhere?result=yes#chapter1", {
		So(nng_url_parse(&url,
		       "http://www.google.com/"
		       "somewhere?result=yes#chapter1") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "www.google.com") == 0);
		So(strcmp(url->u_hostname, "www.google.com") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_path, "/somewhere") == 0);
		So(strcmp(url->u_query, "result=yes") == 0);
		So(strcmp(url->u_fragment, "chapter1") == 0);
		So(strcmp(url->u_requri, "/somewhere?result=yes#chapter1") ==
		    0);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});
	Convey("http://www.google.com/somewhere#chapter2", {
		So(nng_url_parse(
		       &url, "http://www.google.com/somewhere#chapter2") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "www.google.com") == 0);
		So(strcmp(url->u_hostname, "www.google.com") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_path, "/somewhere") == 0);
		So(strcmp(url->u_fragment, "chapter2") == 0);
		So(strcmp(url->u_requri, "/somewhere#chapter2") == 0);
		So(url->u_query == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});
	Convey("http://www.google.com#chapter3", {
		So(nng_url_parse(&url, "http://www.google.com#chapter3") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "www.google.com") == 0);
		So(strcmp(url->u_hostname, "www.google.com") == 0);
		So(strcmp(url->u_path, "") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_fragment, "chapter3") == 0);
		So(strcmp(url->u_requri, "#chapter3") == 0);
		So(url->u_query == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});
	Convey("http://www.google.com?color=red", {
		So(nng_url_parse(&url, "http://www.google.com?color=red") ==
		    0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "www.google.com") == 0);
		So(strcmp(url->u_hostname, "www.google.com") == 0);
		So(strcmp(url->u_path, "") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_query, "color=red") == 0);
		So(strcmp(url->u_requri, "?color=red") == 0);
		So(url->u_fragment == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});

	Convey("http://[::1]", {
		So(nng_url_parse(&url, "http://[::1]") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "[::1]") == 0);
		So(strcmp(url->u_hostname, "::1") == 0);
		So(strcmp(url->u_path, "") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});

	Convey("http://[::1]:29", {
		So(nng_url_parse(&url, "http://[::1]:29") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "[::1]:29") == 0);
		So(strcmp(url->u_hostname, "::1") == 0);
		So(strcmp(url->u_path, "") == 0);
		So(strcmp(url->u_port, "29") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});
	Convey("http://[::1]:29/bottles", {
		So(nng_url_parse(&url, "http://[::1]:29/bottles") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_host, "[::1]:29") == 0);
		So(strcmp(url->u_hostname, "::1") == 0);
		So(strcmp(url->u_path, "/bottles") == 0);
		So(strcmp(url->u_port, "29") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});

	Convey("tcp://:9876/", {
		So(nng_url_parse(&url, "tcp://:9876/") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "tcp") == 0);
		So(strcmp(url->u_host, ":9876") == 0);
		So(strcmp(url->u_hostname, "") == 0);
		So(strcmp(url->u_path, "/") == 0);
		So(strcmp(url->u_port, "9876") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});

	Convey("ws://", {
		So(nng_url_parse(&url, "ws://") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "ws") == 0);
		So(strcmp(url->u_host, "") == 0);
		So(strcmp(url->u_hostname, "") == 0);
		So(strcmp(url->u_path, "") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});

	Convey("ws://*:12345/foobar", {
		So(nng_url_parse(&url, "ws://*:12345/foobar") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "ws") == 0);
		So(strcmp(url->u_host, ":12345") == 0);
		So(strcmp(url->u_hostname, "") == 0);
		So(strcmp(url->u_path, "/foobar") == 0);
		So(strcmp(url->u_port, "12345") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		So(url->u_userinfo == NULL);
		nng_url_free(url);
	});

	Convey("ssh://user@host.example.com", {
		So(nng_url_parse(&url, "ssh://user@host.example.com") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "ssh") == 0);
		So(strcmp(url->u_host, "host.example.com") == 0);
		So(strcmp(url->u_hostname, "host.example.com") == 0);
		So(strcmp(url->u_path, "") == 0);
		So(strcmp(url->u_port, "22") == 0);
		So(url->u_query == NULL);
		So(url->u_fragment == NULL);
		So(strcmp(url->u_userinfo, "user") == 0);
		nng_url_free(url);
	});

	Convey("Negative www.google.com", {
		url = NULL;
		So(nng_url_parse(&url, "www.google.com") == NNG_EINVAL);
		So(url == NULL);
	});

	Convey("Negative http:www.google.com", {
		url = NULL;
		So(nng_url_parse(&url, "http:www.google.com") == NNG_EINVAL);
		So(url == NULL);
	});

	Convey("Negative http://[::1", {
		url = NULL;
		So(nng_url_parse(&url, "http://[::1") == NNG_EINVAL);
		So(url == NULL);
	});

	Convey("Negative http://[::1]bogus", {
		url = NULL;
		So(nng_url_parse(&url, "http://[::1]bogus") == NNG_EINVAL);
		So(url == NULL);
	});

	Convey("Canonicalization works", {
		url = NULL;
		So(nng_url_parse(&url,
		       "hTTp://www.EXAMPLE.com/bogus/.%2e/%7egarrett") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_hostname, "www.example.com") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_path, "/~garrett") == 0);
		nng_url_free(url);
	});

	Convey("Path resolution works", {
		url = NULL;
		So(nng_url_parse(&url,
		       "http://www.x.com//abc/def/./x/..///./../y") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_hostname, "www.x.com") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_path, "/abc/y") == 0);
		nng_url_free(url);
	});

	Convey("Query info unmolested", {
		url = NULL;
		So(nng_url_parse(
		       &url, "http://www.x.com/?/abc/def/./x/.././../y") == 0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_hostname, "www.x.com") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_path, "/") == 0);
		So(strcmp(url->u_query, "/abc/def/./x/.././../y") == 0);
		nng_url_free(url);
	});

	Convey("Bad UTF-8 fails", {
		url = NULL;
		So(nng_url_parse(&url, "http://x.com/x%80x") == NNG_EINVAL);
		So(nng_url_parse(&url, "http://x.com/x%c0%81") == NNG_EINVAL);
	});

	Convey("Valid UTF-8 works", {
		url = NULL;
		So(nng_url_parse(&url, "http://www.x.com/%c2%a2_centsign") ==
		    0);
		So(url != NULL);
		So(strcmp(url->u_scheme, "http") == 0);
		So(strcmp(url->u_hostname, "www.x.com") == 0);
		So(strcmp(url->u_port, "80") == 0);
		So(strcmp(url->u_path, "/\xc2\xa2_centsign") == 0);
		nng_url_free(url);
	});
})
