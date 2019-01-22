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

#include "convey.h"
#include "core/nng_impl.h"
#include "stubs.h"

#ifndef _WIN32
#include <arpa/inet.h>
#endif

static const char *
ip4tostr(void *addr)
{
	static char buf[256];

#ifdef _WIN32
	return (InetNtop(AF_INET, addr, buf, sizeof(buf)));

#else
	return (inet_ntop(AF_INET, addr, buf, sizeof(buf)));

#endif
}

static const char *
ip6tostr(void *addr)
{
	static char buf[256];

#ifdef _WIN32
	return (InetNtop(AF_INET6, addr, buf, sizeof(buf)));

#else
	return (inet_ntop(AF_INET6, addr, buf, sizeof(buf)));

#endif
}

// These work on Darwin, and should work on illumos, but they may
// depend on the local resolver configuration.  We elect not to depend
// too much on them, since localhost can be configured weirdly.  Notably
// the normal assumptions on Linux do *not* hold true.
#if 0
	    Convey("Localhost IPv6 resolves", {
		    nng_aio *aio;
		    const char *str;
		    nng_sockaddr sa;
		    So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		    So(nng_aio_set_input(aio, 0, &sa) == 0);
		    nni_tcp_resolv("localhost", "80", NNG_AF_INET6, 1, aio);
		    nng_aio_wait(aio);
		    So(nng_aio_result(aio) == 0);
		    So(sa.s_in6.sa_family == NNG_AF_INET6);
		    So(sa.s_in6.sa_port == ntohs(80));
		    str = ip6tostr(&sa.s_in6.sa_addr);
		    So(strcmp(str, "::1") == 0);
		    nng_aio_free(aio);
	    }
#endif

TestMain("Resolver", {
	nni_init();

	Convey("Google DNS IPv4 resolves", {
		nng_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		nni_tcp_resolv("google-public-dns-a.google.com", "80",
		    NNG_AF_INET, 1, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		nni_aio_get_sockaddr(aio, &sa);
		So(sa.s_in.sa_family == NNG_AF_INET);
		So(sa.s_in.sa_port == ntohs(80));
		str = ip4tostr(&sa.s_in.sa_addr);
		So(strcmp(str, "8.8.8.8") == 0);
		nng_aio_free(aio);
	});
	Convey("Numeric UDP resolves", {
		nng_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		nni_udp_resolv("8.8.4.4", "69", NNG_AF_INET, 1, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		nni_aio_get_sockaddr(aio, &sa);
		So(sa.s_in.sa_family == NNG_AF_INET);
		So(sa.s_in.sa_port == ntohs(69));
		str = ip4tostr(&sa.s_in.sa_addr);
		So(strcmp(str, "8.8.4.4") == 0);
		nng_aio_free(aio);
	});
	Convey("Numeric v4 resolves", {
		nng_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		nni_tcp_resolv("8.8.4.4", "80", NNG_AF_INET, 1, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		nni_aio_get_sockaddr(aio, &sa);
		So(sa.s_in.sa_family == NNG_AF_INET);
		So(sa.s_in.sa_port == ntohs(80));
		str = ip4tostr(&sa.s_in.sa_addr);
		So(strcmp(str, "8.8.4.4") == 0);
		nng_aio_free(aio);
	});

	Convey("Numeric v6 resolves", {
		nng_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		// Travis CI has moved some of their services to host that
		// apparently don't support IPv6 at all.  This is very sad.
		// CircleCI 2.0 is in the same boat.  (Amazon to blame.)
		if ((getenv("TRAVIS") != NULL) ||
		    (getenv("CIRCLECI") != NULL)) {
			ConveySkip("IPv6 missing from CI provider");
		}

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		nni_tcp_resolv("::1", "80", NNG_AF_INET6, 1, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		nni_aio_get_sockaddr(aio, &sa);
		So(sa.s_in6.sa_family == NNG_AF_INET6);
		So(sa.s_in6.sa_port == ntohs(80));
		str = ip6tostr(&sa.s_in6.sa_addr);
		So(strcmp(str, "::1") == 0);
		nng_aio_free(aio);
	});

	Convey("Name service names not supported", {
		nng_aio *aio;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		nni_tcp_resolv("8.8.4.4", "http", NNG_AF_INET, 1, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == NNG_EADDRINVAL);
		nng_aio_free(aio);
	});

	Convey("Localhost IPv4 resolves", {
		nng_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		nni_tcp_resolv("localhost", "80", NNG_AF_INET, 1, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		nni_aio_get_sockaddr(aio, &sa);
		So(sa.s_in.sa_family == NNG_AF_INET);
		So(sa.s_in.sa_port == ntohs(80));
		So(sa.s_in.sa_addr == ntohl(0x7f000001));
		str = ip4tostr(&sa.s_in.sa_addr);
		So(strcmp(str, "127.0.0.1") == 0);
		nng_aio_free(aio);
	});

	Convey("Localhost UNSPEC resolves", {
		nng_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		nni_tcp_resolv("localhost", "80", NNG_AF_UNSPEC, 1, aio);
		nng_aio_wait(aio);
		So(nng_aio_result(aio) == 0);
		nni_aio_get_sockaddr(aio, &sa);
		So((sa.s_family == NNG_AF_INET) ||
		    (sa.s_family == NNG_AF_INET6));
		switch (sa.s_family) {
		case NNG_AF_INET:
			So(sa.s_in.sa_port == ntohs(80));
			So(sa.s_in.sa_addr == ntohl(0x7f000001));
			str = ip4tostr(&sa.s_in.sa_addr);
			So(strcmp(str, "127.0.0.1") == 0);
			break;
		case NNG_AF_INET6:
			So(sa.s_in6.sa_port == ntohs(80));
			str = ip6tostr(&sa.s_in6.sa_addr);
			So(strcmp(str, "::1") == 0);
			break;
		}
		nng_aio_free(aio);
	});

	nni_fini();
})
