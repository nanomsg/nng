//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng_impl.h"
#include <nuts.h>
#include <string.h>

void
test_url_host(void)
{
	nng_url *url;

	NUTS_PASS(nng_url_parse(&url, "http://www.google.com"));
	NUTS_ASSERT(url != NULL);
	NUTS_TRUE(strcmp(url->u_scheme, "http") == 0);
	NUTS_TRUE(strcmp(url->u_host, "www.google.com") == 0);
	NUTS_TRUE(strcmp(url->u_hostname, "www.google.com") == 0);
	NUTS_TRUE(strcmp(url->u_port, "80") == 0);
	NUTS_TRUE(strcmp(url->u_path, "") == 0);
	NUTS_TRUE(strcmp(url->u_requri, "") == 0);
	NUTS_TRUE(url->u_query == NULL);
	NUTS_TRUE(url->u_fragment == NULL);
	NUTS_TRUE(url->u_userinfo == NULL);
	nng_url_free(url);
}

void
test_url_host_port(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://www.google.com:1234"));
	NUTS_ASSERT(url != NULL);
	NUTS_TRUE(strcmp(url->u_scheme, "http") == 0);
	NUTS_TRUE(strcmp(url->u_host, "www.google.com:1234") == 0);
	NUTS_TRUE(strcmp(url->u_hostname, "www.google.com") == 0);
	NUTS_TRUE(strcmp(url->u_port, "1234") == 0);
	NUTS_TRUE(strcmp(url->u_path, "") == 0);
	NUTS_TRUE(strcmp(url->u_requri, "") == 0);
	NUTS_TRUE(url->u_query == NULL);
	NUTS_TRUE(url->u_fragment == NULL);
	NUTS_TRUE(url->u_userinfo == NULL);
	nng_url_free(url);
}

void
test_url_host_port_path(void)
{
	nng_url *url;

	NUTS_PASS(
	    nng_url_parse(&url, "http://www.google.com:1234/somewhere"));
	NUTS_ASSERT(url != NULL);
	NUTS_TRUE(strcmp(url->u_scheme, "http") == 0);
	NUTS_TRUE(strcmp(url->u_host, "www.google.com:1234") == 0);
	NUTS_TRUE(strcmp(url->u_hostname, "www.google.com") == 0);
	NUTS_TRUE(strcmp(url->u_port, "1234") == 0);
	NUTS_TRUE(strcmp(url->u_path, "/somewhere") == 0);
	NUTS_TRUE(strcmp(url->u_requri, "/somewhere") == 0);
	NUTS_TRUE(url->u_userinfo == NULL);
	NUTS_TRUE(url->u_query == NULL);
	NUTS_TRUE(url->u_fragment == NULL);
	nng_url_free(url);
}

void
test_url_user_info(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(
	    &url, "http://garrett@www.google.com:1234/somewhere"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_userinfo, "garrett");
	NUTS_MATCH(url->u_host, "www.google.com:1234");
	NUTS_MATCH(url->u_hostname, "www.google.com");
	NUTS_MATCH(url->u_port, "1234");
	NUTS_MATCH(url->u_path, "/somewhere");
	NUTS_MATCH(url->u_requri, "/somewhere");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_fragment);
	nng_url_free(url);
}

void
test_url_path_query_param(void)
{
	nng_url *url;
	NUTS_PASS(
	    nng_url_parse(&url, "http://www.google.com/somewhere?result=yes"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_host, "www.google.com");
	NUTS_MATCH(url->u_hostname, "www.google.com");
	NUTS_MATCH(url->u_port, "80");
	NUTS_MATCH(url->u_path, "/somewhere");
	NUTS_MATCH(url->u_query, "result=yes");
	NUTS_MATCH(url->u_requri, "/somewhere?result=yes");
	NUTS_NULL(url->u_userinfo);
	NUTS_NULL(url->u_fragment);
	nng_url_free(url);
}

void
test_url_query_param_anchor(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url,
	    "http://www.google.com/"
	    "somewhere?result=yes#chapter1"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_host, "www.google.com");
	NUTS_MATCH(url->u_hostname, "www.google.com");
	NUTS_MATCH(url->u_port, "80");
	NUTS_MATCH(url->u_path, "/somewhere");
	NUTS_MATCH(url->u_query, "result=yes");
	NUTS_MATCH(url->u_fragment, "chapter1");
	NUTS_MATCH(url->u_requri, "/somewhere?result=yes#chapter1");
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_path_anchor(void)
{
	nng_url *url;
	NUTS_PASS(
	    nng_url_parse(&url, "http://www.google.com/somewhere#chapter2"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_host, "www.google.com");
	NUTS_MATCH(url->u_hostname, "www.google.com");
	NUTS_MATCH(url->u_port, "80");
	NUTS_MATCH(url->u_path, "/somewhere");
	NUTS_MATCH(url->u_fragment, "chapter2");
	NUTS_MATCH(url->u_requri, "/somewhere#chapter2");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_anchor(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://www.google.com#chapter3"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_host, "www.google.com");
	NUTS_MATCH(url->u_hostname, "www.google.com");
	NUTS_MATCH(url->u_path, "");
	NUTS_MATCH(url->u_port, "80");
	NUTS_MATCH(url->u_fragment, "chapter3");
	NUTS_MATCH(url->u_requri, "#chapter3");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_query_param(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://www.google.com?color=red"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_host, "www.google.com");
	NUTS_MATCH(url->u_hostname, "www.google.com");
	NUTS_MATCH(url->u_path, "");
	NUTS_MATCH(url->u_port, "80");
	NUTS_MATCH(url->u_query, "color=red");
	NUTS_MATCH(url->u_requri, "?color=red");
	NUTS_ASSERT(url != NULL);
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_v6_host(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://[::1]"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_host, "[::1]");
	NUTS_MATCH(url->u_hostname, "::1");
	NUTS_MATCH(url->u_path, "");
	NUTS_MATCH(url->u_port, "80");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_fragment);
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_v6_host_port(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://[::1]:29"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_host, "[::1]:29");
	NUTS_MATCH(url->u_hostname, "::1");
	NUTS_MATCH(url->u_path, "");
	NUTS_MATCH(url->u_port, "29");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_fragment);
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_v6_host_port_path(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://[::1]:29/bottles"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_host, "[::1]:29");
	NUTS_MATCH(url->u_hostname, "::1");
	NUTS_MATCH(url->u_path, "/bottles");
	NUTS_MATCH(url->u_port, "29");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_fragment);
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_tcp_port(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "tcp://:9876/"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "tcp");
	NUTS_MATCH(url->u_host, ":9876");
	NUTS_MATCH(url->u_hostname, "");
	NUTS_MATCH(url->u_path, "/");
	NUTS_MATCH(url->u_port, "9876");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_fragment);
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_bare_ws(void)
{
	nng_url *url;

	NUTS_PASS(nng_url_parse(&url, "ws://"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "ws");
	NUTS_MATCH(url->u_host, "");
	NUTS_MATCH(url->u_hostname, "");
	NUTS_MATCH(url->u_path, "");
	NUTS_MATCH(url->u_port, "80");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_fragment);
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_ws_wildcard(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "ws://*:12345/foobar"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "ws");
	NUTS_MATCH(url->u_host, ":12345");
	NUTS_MATCH(url->u_hostname, "");
	NUTS_MATCH(url->u_path, "/foobar");
	NUTS_MATCH(url->u_port, "12345");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_fragment);
	NUTS_NULL(url->u_userinfo);
	nng_url_free(url);
}

void
test_url_ssh(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "ssh://user@host.example.com"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "ssh");
	NUTS_MATCH(url->u_host, "host.example.com");
	NUTS_MATCH(url->u_hostname, "host.example.com");
	NUTS_MATCH(url->u_path, "");
	NUTS_MATCH(url->u_port, "22");
	NUTS_NULL(url->u_query);
	NUTS_NULL(url->u_fragment);
	NUTS_MATCH(url->u_userinfo, "user");
	nng_url_free(url);
}

void
test_url_bad_scheme(void)
{
	nng_url *url = NULL;
	NUTS_FAIL(nng_url_parse(&url, "www.google.com"), NNG_EINVAL);
	NUTS_NULL(url);
	NUTS_FAIL(nng_url_parse(&url, "http:www.google.com"), NNG_EINVAL);
	NUTS_NULL(url);
}

void
test_url_bad_ipv6(void)
{
	nng_url *url = NULL;
	NUTS_FAIL(nng_url_parse(&url, "http://[::1"), NNG_EINVAL);
	NUTS_NULL(url);
	NUTS_FAIL(nng_url_parse(&url, "http://[::1]bogus"), NNG_EINVAL);
	NUTS_NULL(url);
}

void
test_url_canonify(void)
{
	nng_url *url = NULL;
	NUTS_PASS(nng_url_parse(
	    &url, "hTTp://www.EXAMPLE.com/bogus/.%2e/%7egarrett"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_hostname, "www.example.com");
	NUTS_MATCH(url->u_port, "80");
	NUTS_MATCH(url->u_path, "/~garrett");
	nng_url_free(url);
}

void
test_url_path_resolve(void)
{
	nng_url *url = NULL;
	NUTS_PASS(
	    nng_url_parse(&url, "http://www.x.com//abc/def/./x/..///./../y"));
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_hostname, "www.x.com");
	NUTS_MATCH(url->u_port, "80");
	NUTS_MATCH(url->u_path, "/abc/y");
	nng_url_free(url);
}

void
test_url_query_info_pass(void)
{
	nng_url *url = NULL;
	NUTS_PASS(
	    nng_url_parse(&url, "http://www.x.com/?/abc/def/./x/.././../y"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_hostname, "www.x.com");
	NUTS_MATCH(url->u_port, "80");
	NUTS_MATCH(url->u_path, "/");
	NUTS_MATCH(url->u_query, "/abc/def/./x/.././../y");
	nng_url_free(url);
}

void
test_url_bad_utf8(void)
{
	nng_url *url = NULL;
	NUTS_FAIL(nng_url_parse(&url, "http://x.com/x%80x"), NNG_EINVAL);
	NUTS_NULL(url);
	NUTS_FAIL(nng_url_parse(&url, "http://x.com/x%c0%81"), NNG_EINVAL);
	NUTS_NULL(url);
}

void
test_url_good_utf8(void)
{
	nng_url *url = NULL;
	NUTS_PASS(nng_url_parse(&url, "http://www.x.com/%c2%a2_cents"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(url->u_scheme, "http");
	NUTS_MATCH(url->u_hostname, "www.x.com");
	NUTS_MATCH(url->u_port, "80");
	NUTS_MATCH(url->u_path, "/\xc2\xa2_cents");
	nng_url_free(url);
}

void
test_url_decode(void)
{
	uint8_t out[16];
	size_t  len;

	out[3] = 'x';
	len    = nni_url_decode(out, "abc", 3);
	NUTS_TRUE(len == 3);
	NUTS_TRUE(memcmp(out, "abc", 3) == 0);
	NUTS_TRUE(out[3] == 'x');

	len = nni_url_decode(out, "x%00y", 3); // embedded NULL
	NUTS_TRUE(len == 3);
	NUTS_TRUE(memcmp(out, "x\x00y", 3) == 0);
	NUTS_TRUE(out[3] == 'x');

	len = nni_url_decode(out, "%3987", 3);
	NUTS_TRUE(len == 3);
	NUTS_TRUE(memcmp(out, "987", 3) == 0);
	NUTS_TRUE(out[3] == 'x');

	len = nni_url_decode(out, "78%39", 3);
	NUTS_TRUE(len == 3);
	NUTS_TRUE(memcmp(out, "789", 3) == 0);
	NUTS_TRUE(out[3] == 'x');

	len = nni_url_decode(out, "", 5);
	NUTS_TRUE(len == 0);
	NUTS_TRUE(memcmp(out, "789", 3) == 0);
	NUTS_TRUE(out[3] == 'x');

	len = nni_url_decode(out, "be", 2);
	NUTS_TRUE(len == 2);
	NUTS_TRUE(memcmp(out, "be9", 3) == 0);
	NUTS_TRUE(out[3] == 'x');

	len = nni_url_decode(out, "78%39", 2);
	NUTS_TRUE(len == (size_t) -1);

	len = nni_url_decode(out, "", 2);
	NUTS_TRUE(len == 0);

	len = nni_url_decode(out, "78%", 5);
	NUTS_TRUE(len == (size_t) -1);

	len = nni_url_decode(out, "78%xy", 5);
	NUTS_TRUE(len == (size_t) -1);

	len = nni_url_decode(out, "78%1$", 5);
	NUTS_TRUE(len == (size_t) -1);

	len = nni_url_decode(out, "%%20", 5);
	NUTS_TRUE(len == (size_t) -1);
}

NUTS_TESTS = {
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