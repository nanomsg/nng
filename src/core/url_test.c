//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//


#include "acutest.h"

#include <string.h>

#include <nng/nng.h>

#include "core/url.h"

#include "testutil.h"

void
test_url_host(void)
{
	nng_url *url;

	TEST_NNG_PASS(nng_url_parse(&url, "http://www.google.com"));
	TEST_ASSERT(url != NULL);
	TEST_CHECK(strcmp(url->u_scheme, "http") == 0);
	TEST_CHECK(strcmp(url->u_host, "www.google.com") == 0);
	TEST_CHECK(strcmp(url->u_hostname, "www.google.com") == 0);
	TEST_CHECK(strcmp(url->u_port, "80") == 0);
	TEST_CHECK(strcmp(url->u_path, "") == 0);
	TEST_CHECK(strcmp(url->u_requri, "") == 0);
	TEST_CHECK(url->u_query == NULL);
	TEST_CHECK(url->u_fragment == NULL);
	TEST_CHECK(url->u_userinfo == NULL);
	nng_url_free(url);
}

void
test_url_host_port(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url, "http://www.google.com:1234"));
	TEST_ASSERT(url != NULL);
	TEST_CHECK(strcmp(url->u_scheme, "http") == 0);
	TEST_CHECK(strcmp(url->u_host, "www.google.com:1234") == 0);
	TEST_CHECK(strcmp(url->u_hostname, "www.google.com") == 0);
	TEST_CHECK(strcmp(url->u_port, "1234") == 0);
	TEST_CHECK(strcmp(url->u_path, "") == 0);
	TEST_CHECK(strcmp(url->u_requri, "") == 0);
	TEST_CHECK(url->u_query == NULL);
	TEST_CHECK(url->u_fragment == NULL);
	TEST_CHECK(url->u_userinfo == NULL);
	nng_url_free(url);
}

void
test_url_host_port_path(void)
{
	nng_url *url;

	TEST_NNG_PASS(
	    nng_url_parse(&url, "http://www.google.com:1234/somewhere"));
	TEST_ASSERT(url != NULL);
	TEST_CHECK(strcmp(url->u_scheme, "http") == 0);
	TEST_CHECK(strcmp(url->u_host, "www.google.com:1234") == 0);
	TEST_CHECK(strcmp(url->u_hostname, "www.google.com") == 0);
	TEST_CHECK(strcmp(url->u_port, "1234") == 0);
	TEST_CHECK(strcmp(url->u_path, "/somewhere") == 0);
	TEST_CHECK(strcmp(url->u_requri, "/somewhere") == 0);
	TEST_CHECK(url->u_userinfo == NULL);
	TEST_CHECK(url->u_query == NULL);
	TEST_CHECK(url->u_fragment == NULL);
	nng_url_free(url);
}

void
test_url_user_info(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(
	    &url, "http://garrett@www.google.com:1234/somewhere"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_userinfo, "garrett");
	TEST_STREQUAL(url->u_host, "www.google.com:1234");
	TEST_STREQUAL(url->u_hostname, "www.google.com");
	TEST_STREQUAL(url->u_port, "1234");
	TEST_STREQUAL(url->u_path, "/somewhere");
	TEST_STREQUAL(url->u_requri, "/somewhere");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_fragment);
	nng_url_free(url);
}

void
test_url_path_query_param(void)
{
	nng_url *url;
	TEST_NNG_PASS(
	    nng_url_parse(&url, "http://www.google.com/somewhere?result=yes"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_host, "www.google.com");
	TEST_STREQUAL(url->u_hostname, "www.google.com");
	TEST_STREQUAL(url->u_port, "80");
	TEST_STREQUAL(url->u_path, "/somewhere");
	TEST_STREQUAL(url->u_query, "result=yes");
	TEST_STREQUAL(url->u_requri, "/somewhere?result=yes");
	TEST_NULL(url->u_userinfo);
	TEST_NULL(url->u_fragment);
	nng_url_free(url);
}

void
test_url_query_param_anchor(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url,
	    "http://www.google.com/"
	    "somewhere?result=yes#chapter1"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_host, "www.google.com");
	TEST_STREQUAL(url->u_hostname, "www.google.com");
	TEST_STREQUAL(url->u_port, "80");
	TEST_STREQUAL(url->u_path, "/somewhere");
	TEST_STREQUAL(url->u_query, "result=yes");
	TEST_STREQUAL(url->u_fragment, "chapter1");
	TEST_STREQUAL(url->u_requri, "/somewhere?result=yes#chapter1");
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_path_anchor(void)
{
	nng_url *url;
	TEST_NNG_PASS(
	    nng_url_parse(&url, "http://www.google.com/somewhere#chapter2"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_host, "www.google.com");
	TEST_STREQUAL(url->u_hostname, "www.google.com");
	TEST_STREQUAL(url->u_port, "80");
	TEST_STREQUAL(url->u_path, "/somewhere");
	TEST_STREQUAL(url->u_fragment, "chapter2");
	TEST_STREQUAL(url->u_requri, "/somewhere#chapter2");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_anchor(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url, "http://www.google.com#chapter3"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_host, "www.google.com");
	TEST_STREQUAL(url->u_hostname, "www.google.com");
	TEST_STREQUAL(url->u_path, "");
	TEST_STREQUAL(url->u_port, "80");
	TEST_STREQUAL(url->u_fragment, "chapter3");
	TEST_STREQUAL(url->u_requri, "#chapter3");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_query_param(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url, "http://www.google.com?color=red"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_host, "www.google.com");
	TEST_STREQUAL(url->u_hostname, "www.google.com");
	TEST_STREQUAL(url->u_path, "");
	TEST_STREQUAL(url->u_port, "80");
	TEST_STREQUAL(url->u_query, "color=red");
	TEST_STREQUAL(url->u_requri, "?color=red");
	TEST_ASSERT(url != NULL);
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_v6_host(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url, "http://[::1]"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_host, "[::1]");
	TEST_STREQUAL(url->u_hostname, "::1");
	TEST_STREQUAL(url->u_path, "");
	TEST_STREQUAL(url->u_port, "80");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_fragment);
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_v6_host_port(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url, "http://[::1]:29"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_host, "[::1]:29");
	TEST_STREQUAL(url->u_hostname, "::1");
	TEST_STREQUAL(url->u_path, "");
	TEST_STREQUAL(url->u_port, "29");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_fragment);
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_v6_host_port_path(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url, "http://[::1]:29/bottles"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_host, "[::1]:29");
	TEST_STREQUAL(url->u_hostname, "::1");
	TEST_STREQUAL(url->u_path, "/bottles");
	TEST_STREQUAL(url->u_port, "29");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_fragment);
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_tcp_port(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url, "tcp://:9876/"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "tcp");
	TEST_STREQUAL(url->u_host, ":9876");
	TEST_STREQUAL(url->u_hostname, "");
	TEST_STREQUAL(url->u_path, "/");
	TEST_STREQUAL(url->u_port, "9876");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_fragment);
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_bare_ws(void)
{
	nng_url *url;

	TEST_NNG_PASS(nng_url_parse(&url, "ws://"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "ws");
	TEST_STREQUAL(url->u_host, "");
	TEST_STREQUAL(url->u_hostname, "");
	TEST_STREQUAL(url->u_path, "");
	TEST_STREQUAL(url->u_port, "80");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_fragment);
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_ws_wildcard(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url, "ws://*:12345/foobar"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "ws");
	TEST_STREQUAL(url->u_host, ":12345");
	TEST_STREQUAL(url->u_hostname, "");
	TEST_STREQUAL(url->u_path, "/foobar");
	TEST_STREQUAL(url->u_port, "12345");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_fragment);
	TEST_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_ssh(void)
{
	nng_url *url;
	TEST_NNG_PASS(nng_url_parse(&url, "ssh://user@host.example.com"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "ssh");
	TEST_STREQUAL(url->u_host, "host.example.com");
	TEST_STREQUAL(url->u_hostname, "host.example.com");
	TEST_STREQUAL(url->u_path, "");
	TEST_STREQUAL(url->u_port, "22");
	TEST_NULL(url->u_query);
	TEST_NULL(url->u_fragment);
	TEST_STREQUAL(url->u_userinfo, "user");
	nng_url_free(url);
}

void
test_url_bad_scheme(void)
{
	nng_url *url = NULL;
	TEST_NNG_FAIL(nng_url_parse(&url, "www.google.com"), NNG_EINVAL);
	TEST_NULL(url);
	TEST_NNG_FAIL(nng_url_parse(&url, "http:www.google.com"), NNG_EINVAL);
	TEST_NULL(url);
}

void
test_url_bad_ipv6(void)
{
	nng_url *url = NULL;
	TEST_NNG_FAIL(nng_url_parse(&url, "http://[::1"), NNG_EINVAL);
	TEST_NULL(url);
	TEST_NNG_FAIL(nng_url_parse(&url, "http://[::1]bogus"), NNG_EINVAL);
	TEST_NULL(url);
}

void
test_url_canonify(void)
{
	nng_url *url = NULL;
	TEST_NNG_PASS(nng_url_parse(
	    &url, "hTTp://www.EXAMPLE.com/bogus/.%2e/%7egarrett"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_hostname, "www.example.com");
	TEST_STREQUAL(url->u_port, "80");
	TEST_STREQUAL(url->u_path, "/~garrett");
	nng_url_free(url);
}

void
test_url_path_resolve(void)
{
	nng_url *url = NULL;
	TEST_NNG_PASS(
	    nng_url_parse(&url, "http://www.x.com//abc/def/./x/..///./../y"));
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_hostname, "www.x.com");
	TEST_STREQUAL(url->u_port, "80");
	TEST_STREQUAL(url->u_path, "/abc/y");
	nng_url_free(url);
}

void
test_url_query_info_pass(void)
{
	nng_url *url = NULL;
	TEST_NNG_PASS(
	    nng_url_parse(&url, "http://www.x.com/?/abc/def/./x/.././../y"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_hostname, "www.x.com");
	TEST_STREQUAL(url->u_port, "80");
	TEST_STREQUAL(url->u_path, "/");
	TEST_STREQUAL(url->u_query, "/abc/def/./x/.././../y");
	nng_url_free(url);
}

void
test_url_bad_utf8(void)
{
	nng_url *url = NULL;
	TEST_NNG_FAIL(nng_url_parse(&url, "http://x.com/x%80x"), NNG_EINVAL);
	TEST_NULL(url);
	TEST_NNG_FAIL(nng_url_parse(&url, "http://x.com/x%c0%81"), NNG_EINVAL);
	TEST_NULL(url);
}

void
test_url_good_utf8(void)
{
	nng_url *url = NULL;
	TEST_NNG_PASS(nng_url_parse(&url, "http://www.x.com/%c2%a2_cents"));
	TEST_ASSERT(url != NULL);
	TEST_STREQUAL(url->u_scheme, "http");
	TEST_STREQUAL(url->u_hostname, "www.x.com");
	TEST_STREQUAL(url->u_port, "80");
	TEST_STREQUAL(url->u_path, "/\xc2\xa2_cents");
	nng_url_free(url);
}

void
test_url_decode(void)
{
	uint8_t out[16];
	size_t  len;

	out[3] = 'x';
	len    = nni_url_decode(out, "abc", 3);
	TEST_CHECK(len == 3);
	TEST_CHECK(memcmp(out, "abc", 3) == 0);
	TEST_CHECK(out[3] == 'x');

	len = nni_url_decode(out, "x%00y", 3); // embedded NULL
	TEST_CHECK(len == 3);
	TEST_CHECK(memcmp(out, "x\x00y", 3) == 0);
	TEST_CHECK(out[3] == 'x');

	len = nni_url_decode(out, "%3987", 3);
	TEST_CHECK(len == 3);
	TEST_CHECK(memcmp(out, "987", 3) == 0);
	TEST_CHECK(out[3] == 'x');

	len = nni_url_decode(out, "78%39", 3);
	TEST_CHECK(len == 3);
	TEST_CHECK(memcmp(out, "789", 3) == 0);
	TEST_CHECK(out[3] == 'x');

        len = nni_url_decode(out, "", 5);
        TEST_CHECK(len == 0);
        TEST_CHECK(memcmp(out, "789", 3) == 0);
        TEST_CHECK(out[3] == 'x');

        len = nni_url_decode(out, "be", 2);
        TEST_CHECK(len == 2);
        TEST_CHECK(memcmp(out, "be9", 3) == 0);
        TEST_CHECK(out[3] == 'x');

        len = nni_url_decode(out, "78%39", 2);
	TEST_CHECK(len == (size_t) -1);

        len = nni_url_decode(out, "", 2);
        TEST_CHECK(len == 0);

        len = nni_url_decode(out, "78%", 5);
        TEST_CHECK(len == (size_t) -1);

        len = nni_url_decode(out, "78%xy", 5);
        TEST_CHECK(len == (size_t) -1);

        len = nni_url_decode(out, "78%1$", 5);
        TEST_CHECK(len == (size_t) -1);

        len = nni_url_decode(out, "%%20", 5);
        TEST_CHECK(len == (size_t) -1);
}

TEST_LIST = {
	{ "url host", test_url_host },
	{ "url host port", test_url_host_port },
	{ "url host port path", test_url_host_port_path },
	{ "url user info", test_url_user_info },
	{ "url path query param", test_url_path_query_param },
	{ "url query param anchor", test_url_query_param_anchor },
	{ "url path anchor", test_url_path_anchor },
	{ "url anchor", test_url_anchor },
	{ "url query param", test_url_query_param },
	{ "url v6 host", test_url_v6_host },
	{ "url v6 host port", test_url_v6_host_port },
	{ "url v6 host port path", test_url_v6_host_port_path },
	{ "url tcp port", test_url_tcp_port },
	{ "url bare ws", test_url_bare_ws },
	{ "url ws wildcard", test_url_ws_wildcard },
	{ "url ssh", test_url_ssh },
	{ "url bad scheme", test_url_bad_scheme },
	{ "url bad v6", test_url_bad_ipv6 },
	{ "url canonify", test_url_canonify },
	{ "url path resolve", test_url_path_resolve },
	{ "url query info pass", test_url_query_info_pass },
	{ "url bad utf8", test_url_bad_utf8 },
	{ "url good utf8", test_url_good_utf8 },
	{ "url decode", test_url_decode },
	{ NULL, NULL },
};