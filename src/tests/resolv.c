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
#include "core/nng_impl.h"
#include "stubs.h"

#include <string.h>

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

	    Convey("Localhost IPv4 resolves", {
		    nni_aio aio;
		    const char *str;
		    memset(&aio, 0, sizeof (aio));
		    nni_aio_init(&aio, NULL, NULL);
		    nni_plat_tcp_resolv("localhost", "80", NNG_AF_INET, 1,
		    &aio);
		    nni_aio_wait(&aio);
		    So(nni_aio_result(&aio) == 0);
		    So(aio.a_naddrs == 1);
		    So(aio.a_addrs[0].s_un.s_in.sa_family == NNG_AF_INET);
		    So(aio.a_addrs[0].s_un.s_in.sa_port == ntohs(80));
		    So(aio.a_addrs[0].s_un.s_in.sa_addr == ntohl(0x7f000001));
		    str = ip4tostr(&aio.a_addrs[0].s_un.s_in.sa_addr);
		    So(strcmp(str, "127.0.0.1") == 0);
		    nni_aio_fini(&aio);
	    }
	    );

	    Convey("Localhost IPv6 resolves", {
		    nni_aio aio;
		    memset(&aio, 0, sizeof (aio));
		    const char *str;
		    nni_aio_init(&aio, NULL, NULL);
		    nni_plat_tcp_resolv("localhost", "80", NNG_AF_INET6, 1,
		    &aio);
		    nni_aio_wait(&aio);
		    So(nni_aio_result(&aio) == 0);
		    So(aio.a_naddrs == 1);
		    So(aio.a_addrs[0].s_un.s_in6.sa_family == NNG_AF_INET6);
		    So(aio.a_addrs[0].s_un.s_in6.sa_port == ntohs(80));
		    str = ip6tostr(&aio.a_addrs[0].s_un.s_in6.sa_addr);
		    So(strcmp(str, "::1") == 0);
		    nni_aio_fini(&aio);
	    }
	    );
	    Convey("Localhost UNSPEC resolves", {
		    nni_aio aio;
		    memset(&aio, 0, sizeof (aio));
		    const char *str;
		    int i;
		    nni_aio_init(&aio, NULL, NULL);
		    nni_plat_tcp_resolv("localhost", "80", NNG_AF_UNSPEC, 1,
		    &aio);
		    nni_aio_wait(&aio);
		    So(nni_aio_result(&aio) == 0);
		    So(aio.a_naddrs == 2);
		    for (i = 0; i < 2; i++) {
			    switch (aio.a_addrs[i].s_un.s_family) {
			    case NNG_AF_INET6:
				    So(aio.a_addrs[i].s_un.s_in6.sa_port ==
				    ntohs(80));
				    str =
				    ip6tostr(&aio.a_addrs[i].s_un.s_in6.sa_addr);
				    So(strcmp(str, "::1") == 0);
				    break;

			    case NNG_AF_INET:
				    So(aio.a_addrs[i].s_un.s_in.sa_port ==
				    ntohs(80));
				    str =
				    ip4tostr(&aio.a_addrs[i].s_un.s_in.sa_addr);
				    So(strcmp(str, "127.0.0.1") == 0);
				    break;
			    default:
				    So(1 == 0);
			    }
		    }
		    So(aio.a_addrs[0].s_un.s_family !=
		    aio.a_addrs[1].s_un.s_family);
		    nni_aio_fini(&aio);
	    }
	    );
#endif

TestMain("Resolver", {
	nni_init();

	Convey("Google DNS IPv4 resolves", {
		nni_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		nni_aio_init(&aio, NULL, NULL);
		aio->a_addr = &sa;
		nni_plat_tcp_resolv("google-public-dns-a.google.com", "80",
		    NNG_AF_INET, 1, aio);
		nni_aio_wait(aio);
		So(nni_aio_result(aio) == 0);
		So(sa.s_un.s_in.sa_family == NNG_AF_INET);
		So(sa.s_un.s_in.sa_port == ntohs(80));
		str = ip4tostr(&sa.s_un.s_in.sa_addr);
		So(strcmp(str, "8.8.8.8") == 0);
		nni_aio_fini(aio);
	});
	Convey("Numeric UDP resolves", {
		nni_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		nni_aio_init(&aio, NULL, NULL);
		aio->a_addr = &sa;
		nni_plat_udp_resolv("8.8.4.4", "69", NNG_AF_INET, 1, aio);
		nni_aio_wait(aio);
		So(nni_aio_result(aio) == 0);
		So(sa.s_un.s_in.sa_family == NNG_AF_INET);
		So(sa.s_un.s_in.sa_port == ntohs(69));
		str = ip4tostr(&sa.s_un.s_in.sa_addr);
		So(strcmp(str, "8.8.4.4") == 0);
		nni_aio_fini(aio);
	});
	Convey("Numeric v4 resolves", {
		nni_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		nni_aio_init(&aio, NULL, NULL);
		aio->a_addr = &sa;
		nni_plat_tcp_resolv("8.8.4.4", "80", NNG_AF_INET, 1, aio);
		nni_aio_wait(aio);
		So(nni_aio_result(aio) == 0);
		So(sa.s_un.s_in.sa_family == NNG_AF_INET);
		So(sa.s_un.s_in.sa_port == ntohs(80));
		str = ip4tostr(&sa.s_un.s_in.sa_addr);
		So(strcmp(str, "8.8.4.4") == 0);
		nni_aio_fini(aio);
	});
	Convey("Numeric v6 resolves", {
		nni_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		nni_aio_init(&aio, NULL, NULL);
		aio->a_addr = &sa;
		nni_plat_tcp_resolv("::1", "80", NNG_AF_INET6, 1, aio);
		nni_aio_wait(aio);
		So(nni_aio_result(aio) == 0);
		So(sa.s_un.s_in6.sa_family == NNG_AF_INET6);
		So(sa.s_un.s_in6.sa_port == ntohs(80));
		str = ip6tostr(&sa.s_un.s_in6.sa_addr);
		So(strcmp(str, "::1") == 0);
		nni_aio_fini(aio);
	});

	Convey("TCP Name service resolves", {
		nni_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		nni_aio_init(&aio, NULL, NULL);
		aio->a_addr = &sa;
		nni_plat_tcp_resolv("8.8.4.4", "http", NNG_AF_INET, 1, aio);
		nni_aio_wait(aio);
		So(nni_aio_result(aio) == 0);
		So(sa.s_un.s_in.sa_family == NNG_AF_INET);
		So(sa.s_un.s_in.sa_port == ntohs(80));
		str = ip4tostr(&sa.s_un.s_in.sa_addr);
		So(strcmp(str, "8.8.4.4") == 0);
		nni_aio_fini(aio);
	});

	Convey("UDP Name service resolves", {
		nni_aio *    aio;
		const char * str;
		nng_sockaddr sa;

		nni_aio_init(&aio, NULL, NULL);
		aio->a_addr = &sa;
		nni_plat_udp_resolv("8.8.4.4", "tftp", NNG_AF_INET, 1, aio);
		nni_aio_wait(aio);
		So(nni_aio_result(aio) == 0);
		So(sa.s_un.s_in.sa_family == NNG_AF_INET);
		So(sa.s_un.s_in.sa_port == ntohs(69));
		str = ip4tostr(&sa.s_un.s_in.sa_addr);
		So(strcmp(str, "8.8.4.4") == 0);
		nni_aio_fini(aio);
	});

	nni_fini();
})
