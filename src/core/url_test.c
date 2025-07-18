//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#include "nng_impl.h"
#include <nuts.h>
#include <string.h>

void
test_url_host(void)
{
	nng_url *url;

	NUTS_PASS(nng_url_parse(&url, "http://www.google.com"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "");
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_host_too_long(void)
{
	nng_url *url;
	char     buffer[512]; //

	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer), "http://");
	for (size_t i = strlen(buffer); i < sizeof(buffer) - 1; i++) {
		buffer[i] = 'a';
	}
	NUTS_FAIL(nng_url_parse(&url, buffer), NNG_EINVAL);
}

void
test_url_host_port(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://www.google.com:1234"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_TRUE(nng_url_port(url) == 1234);
	NUTS_MATCH(nng_url_path(url), "");
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_host_port_path(void)
{
	nng_url *url;

	NUTS_PASS(nng_url_parse(&url, "http://www.google.com:1234/somewhere"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_TRUE(nng_url_port(url) == 1234);
	NUTS_MATCH(nng_url_path(url), "/somewhere");
	NUTS_NULL(nng_url_userinfo(url));
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	nng_url_free(url);
}

void
test_url_user_info(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(
	    &url, "http://garrett@www.google.com:1234/somewhere"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_userinfo(url), "garrett");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_TRUE(nng_url_port(url) == 1234);
	NUTS_MATCH(nng_url_path(url), "/somewhere");
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	nng_url_free(url);
}

void
test_url_path_query_param(void)
{
	nng_url *url;
	NUTS_PASS(
	    nng_url_parse(&url, "http://www.google.com/somewhere?result=yes"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "/somewhere");
	NUTS_MATCH(nng_url_query(url), "result=yes");
	NUTS_NULL(nng_url_userinfo(url));
	NUTS_NULL(nng_url_fragment(url));
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
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "/somewhere");
	NUTS_MATCH(nng_url_query(url), "result=yes");
	NUTS_MATCH(nng_url_fragment(url), "chapter1");
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_clone(void)
{
	nng_url *url;
	nng_url *src;
	NUTS_PASS(nng_url_parse(&src,
	    "http://www.google.com/"
	    "somewhere?result=yes#chapter1"));
	NUTS_ASSERT(src != NULL);
	NUTS_PASS(nng_url_clone(&url, src));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "/somewhere");
	NUTS_MATCH(nng_url_query(url), "result=yes");
	NUTS_MATCH(nng_url_fragment(url), "chapter1");
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
	nng_url_free(src);
}

void
test_url_path_anchor(void)
{
	nng_url *url;
	NUTS_PASS(
	    nng_url_parse(&url, "http://www.google.com/somewhere#chapter2"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "/somewhere");
	NUTS_MATCH(nng_url_fragment(url), "chapter2");
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_anchor(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://www.google.com#chapter3"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_MATCH(nng_url_path(url), "");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_fragment(url), "chapter3");
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_query_param(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://www.google.com?color=red"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.google.com");
	NUTS_MATCH(nng_url_path(url), "");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_query(url), "color=red");
	NUTS_ASSERT(url != NULL);
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_v6_host(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://[::1]"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "::1");
	NUTS_MATCH(nng_url_path(url), "");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_v6_host_port(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://[::1]:29"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "::1");
	NUTS_MATCH(nng_url_path(url), "");
	NUTS_TRUE(nng_url_port(url) == 29);
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_v6_host_port_path(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "http://[::1]:29/bottles"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "::1");
	NUTS_MATCH(nng_url_path(url), "/bottles");
	NUTS_TRUE(nng_url_port(url) == 29);
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_tcp_port(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "tcp://:9876/"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "tcp");
	NUTS_MATCH(nng_url_hostname(url), "");
	NUTS_MATCH(nng_url_path(url), "/");
	NUTS_TRUE(nng_url_port(url) == 9876);
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_bare_ws(void)
{
	nng_url *url;

	NUTS_PASS(nng_url_parse(&url, "ws://"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "ws");
	NUTS_MATCH(nng_url_hostname(url), "");
	NUTS_MATCH(nng_url_path(url), "");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	NUTS_NULL(nng_url_userinfo(url));
	nng_url_free(url);
}

void
test_url_ssh(void)
{
	nng_url *url;
	NUTS_PASS(nng_url_parse(&url, "ssh://user@host.example.com"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "ssh");
	NUTS_MATCH(nng_url_hostname(url), "host.example.com");
	NUTS_MATCH(nng_url_path(url), "");
	NUTS_TRUE(nng_url_port(url) == 22);
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	NUTS_MATCH(nng_url_userinfo(url), "user");
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
	NUTS_FAIL(nng_url_parse(&url, "nosuch://bogus"), NNG_ENOTSUP);
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
	    &url, "http://www.EXAMPLE.com/bogus/.%2e/%7egarrett"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.example.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "/~garrett");
	nng_url_free(url);
}

void
test_url_path_resolve(void)
{
	nng_url *url = NULL;
	NUTS_PASS(
	    nng_url_parse(&url, "http://www.x.com//abc/def/./x/..///./../y"));
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.x.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "/abc/y");
	nng_url_free(url);
}

void
test_url_query_info_pass(void)
{
	nng_url *url = NULL;
	NUTS_PASS(
	    nng_url_parse(&url, "http://www.x.com/?/abc/def/./x/.././../y"));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.x.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "/");
	NUTS_MATCH(nng_url_query(url), "/abc/def/./x/.././../y");
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
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "www.x.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "/\xc2\xa2_cents");
	nng_url_free(url);
}

void
test_url_missing_port(void)
{
	nng_url *url = NULL;
	NUTS_FAIL(
	    nng_url_parse(&url, "http://www.x.com:/something"), NNG_EINVAL);
}

void
test_url_unknown_service(void)
{
	nng_url *url = NULL;
	NUTS_FAIL(
	    nng_url_parse(&url, "http://www.x.com:nosuchservice"), NNG_EINVAL);
}

void
test_url_duplicate_userinfo(void)
{
	nng_url *url = NULL;
	NUTS_FAIL(
	    nng_url_parse(&url, "http://user@@user@www.x.com"), NNG_EINVAL);
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

void
test_url_huge(void)
{
	nng_url *url = NULL;
	char     huge1[8192];
	char     huge2[8192];
	char    *prefix = "http://example.com/";
	size_t   len;

	memset(huge1, 'a', sizeof huge1);
	huge1[sizeof(huge1) - 1] = '\0';       // terminate it
	memcpy(huge1, prefix, strlen(prefix)); // *NOT* including the \0

	NUTS_PASS(nng_url_parse(&url, huge1));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "example.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(
	    nng_url_path(url), huge1 + strlen(prefix) - 1); // -1 for '/'
	NUTS_NULL(nng_url_query(url));
	NUTS_NULL(nng_url_fragment(url));
	len = nng_url_sprintf(huge2, sizeof(huge2), url);
	NUTS_TRUE(len == strlen(huge1));
	NUTS_MATCH(huge2, huge1);
	nng_url_free(url);
}

void
test_url_huge_parts(void)
{
	nng_url *url = NULL;
	char     huge1[8800];
	char     huge2[8192];
	char    *prefix = "http://example.com/path";
	char    *frag   = "frag";
	size_t   len;

	memset(huge2, 'a', 4096);
	huge2[4096] = '\0';
	snprintf(huge1, sizeof(huge1), "%s?%s#%s", prefix, huge2, frag);

	NUTS_PASS(nng_url_parse(&url, huge1));
	NUTS_ASSERT(url != NULL);
	NUTS_MATCH(nng_url_scheme(url), "http");
	NUTS_MATCH(nng_url_hostname(url), "example.com");
	NUTS_TRUE(nng_url_port(url) == 80);
	NUTS_MATCH(nng_url_path(url), "/path");
	NUTS_MATCH(nng_url_query(url), huge2);
	NUTS_MATCH(nng_url_fragment(url), frag);
	len = nng_url_sprintf(huge2, sizeof(huge2), url);
	NUTS_TRUE(len == strlen(huge1));
	NUTS_MATCH(huge2, huge1);
	nng_url_free(url);
}

NUTS_TESTS = {
	{ "url host", test_url_host },
	{ "url host too long", test_url_host_too_long },
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
	{ "url clone", test_url_clone },
	{ "url ssh", test_url_ssh },
	{ "url bad scheme", test_url_bad_scheme },
	{ "url bad v6", test_url_bad_ipv6 },
	{ "url canonify", test_url_canonify },
	{ "url path resolve", test_url_path_resolve },
	{ "url query info pass", test_url_query_info_pass },
	{ "url missing port", test_url_missing_port },
	{ "url unknown service", test_url_unknown_service },
	{ "url duplicate userinfo", test_url_duplicate_userinfo },
	{ "url bad utf8", test_url_bad_utf8 },
	{ "url good utf8", test_url_good_utf8 },
	{ "url decode", test_url_decode },
	{ "url huge", test_url_huge },
	{ "url huge parts", test_url_huge_parts },
	{ NULL, NULL },
};
