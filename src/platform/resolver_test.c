//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <nuts.h>

uint8_t v6loop[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

void
test_google_dns(void)
{
	nng_aio *    aio;
	nng_sockaddr sa;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nni_resolv_ip("google-public-dns-a.google.com", "80", NNG_AF_INET,
	    true, &sa, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(sa.s_in.sa_family == NNG_AF_INET);
	NUTS_TRUE(sa.s_in.sa_port == nuts_be16(80));
	NUTS_TRUE(sa.s_in.sa_addr == 0x08080808); // aka 8.8.8.8
	nng_aio_free(aio);
}

void
test_numeric_addr(void)
{
	nng_aio *    aio;
	nng_sockaddr sa;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nni_resolv_ip("8.8.4.4", "69", NNG_AF_INET, true, &sa, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(sa.s_in.sa_family == NNG_AF_INET);
	NUTS_TRUE(sa.s_in.sa_port == nuts_be16(69));
	NUTS_TRUE(sa.s_in.sa_addr == nuts_be32(0x08080404)); // 8.8.4.4.
	nng_aio_free(aio);
}

void
test_numeric_v6(void)
{
	nng_aio *    aio;
	nng_sockaddr sa;

	// Travis CI has moved some of their services to host that
	// apparently don't support IPv6 at all.  This is very sad.
	// CircleCI 2.0 is in the same boat.  (Amazon to blame.)
	if ((getenv("TRAVIS") != NULL) || (getenv("CIRCLECI") != NULL)) {
		return; // skip this one.
	}

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nni_resolv_ip("::1", "80", NNG_AF_INET6, true, &sa, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(sa.s_in6.sa_family == NNG_AF_INET6);
	NUTS_TRUE(sa.s_in6.sa_port == nuts_be16(80));
	NUTS_TRUE(memcmp(sa.s_in6.sa_addr, v6loop, 16) == 0);
	nng_aio_free(aio);
}

void
test_service_names(void)
{
	nng_aio *    aio;
	nng_sockaddr sa;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nni_resolv_ip("8.8.4.4", "http", NNG_AF_INET, true, &sa, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(sa.s_in.sa_port == nuts_be16(80));
	NUTS_TRUE(sa.s_in.sa_addr = nuts_be32(0x08080404));
	nng_aio_free(aio);
}

void
test_localhost_v4(void)
{
	nng_aio *    aio;
	nng_sockaddr sa;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nni_resolv_ip("localhost", "80", NNG_AF_INET, true, &sa, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(sa.s_in.sa_family == NNG_AF_INET);
	NUTS_TRUE(sa.s_in.sa_port == nuts_be16(80));
	NUTS_TRUE(sa.s_in.sa_addr == nuts_be32(0x7f000001));
	nng_aio_free(aio);
}

void
test_localhost_unspecified(void)
{
	nng_aio *    aio;
	nng_sockaddr sa;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nni_resolv_ip("localhost", "80", NNG_AF_UNSPEC, true, &sa, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(
	    (sa.s_family == NNG_AF_INET) || (sa.s_family == NNG_AF_INET6));
	switch (sa.s_family) {
	case NNG_AF_INET:
		NUTS_TRUE(sa.s_in.sa_port == nuts_be16(80));
		NUTS_TRUE(sa.s_in.sa_addr == nuts_be32(0x7f000001));
		break;
	case NNG_AF_INET6:
		NUTS_TRUE(sa.s_in6.sa_port == nuts_be16(80));
		NUTS_TRUE(memcmp(sa.s_in6.sa_addr, v6loop, 16) == 0);
		break;
	}
	nng_aio_free(aio);
}

void
test_null_passive(void)
{
	nng_aio *    aio;
	nng_sockaddr sa;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nni_resolv_ip(NULL, "80", NNG_AF_INET, true, &sa, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(sa.s_in.sa_family == NNG_AF_INET);
	NUTS_TRUE(sa.s_in.sa_port == nuts_be16(80));
	NUTS_TRUE(sa.s_in.sa_addr == 0); // any local address
	nng_aio_free(aio);
}

void
test_null_not_passive(void)
{
	nng_aio *    aio;
	nng_sockaddr sa;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nni_resolv_ip(NULL, "80", NNG_AF_INET, false, &sa, aio);
	nng_aio_wait(aio);
	// We can either get invalid address, or a loopback address.
	// Most systems do the former, but Linux does the latter.
	if (nng_aio_result(aio) == 0) {
		NUTS_TRUE(sa.s_family == NNG_AF_INET);
		NUTS_TRUE(sa.s_in.sa_addr == nuts_be32(0x7f000001));
		NUTS_TRUE(sa.s_in.sa_port == nuts_be16(80));
	} else {
		NUTS_FAIL(nng_aio_result(aio), NNG_EADDRINVAL);
	}
	nng_aio_free(aio);
}

void
test_bad_port_number(void)
{
	nng_aio *    aio;
	nng_sockaddr sa;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nni_resolv_ip("1.1.1.1", "1000000", NNG_AF_INET, true, &sa, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_EADDRINVAL);
	nng_aio_free(aio);
}

NUTS_TESTS = {
	{ "resolve google dns", test_google_dns },
	{ "resolve numeric addr", test_numeric_addr },
	{ "resolve numeric v6", test_numeric_v6 },
	{ "resolve service names", test_service_names },
	{ "resolve localhost v4", test_localhost_v4 },
	{ "resolve localhost unspecified", test_localhost_unspecified },
	{ "resolve null passive", test_null_passive },
	{ "resolve null not passive", test_null_not_passive },
	{ "resolve bad port number", test_bad_port_number },
	{ NULL, NULL },
};
