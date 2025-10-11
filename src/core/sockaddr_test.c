//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "../testing/nuts.h"

#ifndef _WIN32
#include <arpa/inet.h> // for endianness functions
#endif

void
test_sa_ipc(void)
{
	nng_sockaddr sa1;
	nng_sockaddr sa2;
	char         addr[NNG_MAXADDRSTRLEN];
	sa1.s_ipc.sa_family = NNG_AF_IPC;
	sa2.s_ipc.sa_family = NNG_AF_IPC;
	snprintf(sa1.s_ipc.sa_path, sizeof(sa1.s_ipc.sa_path), "/tmp/testing");
	snprintf(sa2.s_ipc.sa_path, sizeof(sa2.s_ipc.sa_path), "/tmp/nothing");
	NUTS_ASSERT(strcmp(nng_str_sockaddr(&sa1, addr, sizeof(addr)),
	                "/tmp/testing") == 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa1) != 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa2) != nng_sockaddr_hash(&sa1));
	NUTS_ASSERT(!nng_sockaddr_equal(&sa1, &sa2));
}

void
test_sa_abstract(void)
{
	nng_sockaddr sa1;
	nng_sockaddr sa2;
	char         addr[NNG_MAXADDRSTRLEN];
	sa1.s_abstract.sa_family = NNG_AF_ABSTRACT;
	sa2.s_abstract.sa_family = NNG_AF_ABSTRACT;
	snprintf((char *) sa1.s_abstract.sa_name,
	    sizeof(sa1.s_abstract.sa_name), "one");
	snprintf((char *) sa2.s_abstract.sa_name,
	    sizeof(sa2.s_abstract.sa_name), "two");
	NUTS_ASSERT(strcmp(nng_str_sockaddr(&sa1, addr, sizeof(addr)),
	                "abstract[one]") == 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa1) != 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa2) != nng_sockaddr_hash(&sa1));
	NUTS_ASSERT(!nng_sockaddr_equal(&sa1, &sa2));
}

void
test_sa_inproc(void)
{
	nng_sockaddr sa1;
	nng_sockaddr sa2;
	char         addr[NNG_MAXADDRSTRLEN];
	sa1.s_inproc.sa_family = NNG_AF_INPROC;
	sa2.s_inproc.sa_family = NNG_AF_INPROC;
	snprintf((char *) sa1.s_inproc.sa_name, sizeof(sa1.s_inproc.sa_name),
	    "one");
	snprintf((char *) sa2.s_inproc.sa_name, sizeof(sa2.s_inproc.sa_name),
	    "two");
	nng_str_sockaddr(&sa1, addr, sizeof(addr));
	NUTS_ASSERT(strcmp(addr, "inproc[one]") == 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa1) != 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa2) != nng_sockaddr_hash(&sa1));
	NUTS_ASSERT(!nng_sockaddr_equal(&sa1, &sa2));
}

void
test_sa_inet(void)
{
	nng_sockaddr sa1;
	nng_sockaddr sa2;
	char         addr[NNG_MAXADDRSTRLEN];
	sa1.s_in.sa_family = NNG_AF_INET;
	sa1.s_in.sa_addr   = htonl(0x7F000001);
	sa1.s_in.sa_port   = htons(80);
	sa2                = sa1;
	sa2.s_in.sa_port   = htons(25);
	NUTS_ASSERT(strcmp(nng_str_sockaddr(&sa1, addr, sizeof(addr)),
	                "127.0.0.1:80") == 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa1) != 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa2) != nng_sockaddr_hash(&sa1));
	NUTS_ASSERT(!nng_sockaddr_equal(&sa1, &sa2));
}

void
test_sa_inet6(void)
{
	nng_sockaddr sa1;
	nng_sockaddr sa2;
	char         addr[NNG_MAXADDRSTRLEN];
	sa1.s_in.sa_family = NNG_AF_INET6;
	memset(sa1.s_in6.sa_addr, 0, sizeof(sa1.s_in6.sa_addr));
	sa1.s_in6.sa_addr[15] = 1; // loopback
	sa1.s_in6.sa_scope    = 0;
	sa1.s_in6.sa_port     = htons(80);
	sa2                   = sa1;
	NUTS_ASSERT(nng_sockaddr_equal(&sa1, &sa2));
	sa2.s_in6.sa_port = htons(25);
	nng_str_sockaddr(&sa1, addr, sizeof(addr));
	NUTS_ASSERT(strcmp(addr, "[::1]:80") == 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa1) != 0);
	NUTS_ASSERT(nng_sockaddr_hash(&sa2) != nng_sockaddr_hash(&sa1));
	NUTS_ASSERT(!nng_sockaddr_equal(&sa1, &sa2));
}

void
test_sa_families_unequal(void)
{
	nng_sockaddr sa1;
	nng_sockaddr sa2;

	sa1.s_inproc.sa_family = NNG_AF_INPROC;
	memcpy(sa1.s_inproc.sa_name, "ABC", 3);
	sa2.s_ipc.sa_family = NNG_AF_IPC;
	memcpy(sa2.s_ipc.sa_path, "ABC", 3);
	NUTS_ASSERT(!nng_sockaddr_equal(&sa1, &sa2));
}

void
test_sa_inet6_v4_mapped(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_in.sa_family = NNG_AF_INET6;
	memset(sa.s_in6.sa_addr, 0, sizeof(sa.s_in6.sa_addr));
	sa.s_in6.sa_addr[10] = 0xff;
	sa.s_in6.sa_addr[11] = 0xff;
	sa.s_in6.sa_addr[12] = 192;
	sa.s_in6.sa_addr[13] = 168;
	sa.s_in6.sa_addr[14] = 1;
	sa.s_in6.sa_addr[15] = 100;
	sa.s_in6.sa_scope    = 0;
	sa.s_in6.sa_port     = htons(80);
	nng_str_sockaddr(&sa, addr, sizeof(addr));
	nng_log_debug(NULL, "address is %s", addr);
	NUTS_ASSERT(strcmp(addr, "[::ffff:192.168.1.100]:80") == 0);
}

void
test_sa_inet6_ll(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_in.sa_family = NNG_AF_INET6;
	memset(sa.s_in6.sa_addr, 0, sizeof(sa.s_in6.sa_addr));
	sa.s_in6.sa_addr[0]  = 0xfe;
	sa.s_in6.sa_addr[1]  = 0x80;
	sa.s_in6.sa_addr[15] = 4;
	sa.s_in6.sa_scope    = 0;
	sa.s_in6.sa_port     = htons(80);
	sa.s_in6.sa_scope    = 2; // link local addresses have a non-zero scope
	nng_str_sockaddr(&sa, addr, sizeof(addr));
	nng_log_debug(NULL, "address is %s", addr);
	NUTS_ASSERT(strcmp(addr, "[fe80::4%2]:80") == 0);
}

void
test_sa_inet6_zero(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_in6.sa_family = NNG_AF_INET6;
	memset(sa.s_in6.sa_addr, 0, sizeof(sa.s_in6.sa_addr));
	sa.s_in6.sa_port  = htons(80);
	sa.s_in6.sa_scope = 0;
	nng_str_sockaddr(&sa, addr, sizeof(addr));
	nng_log_debug(NULL, "address is %s", addr);
	NUTS_ASSERT(strcmp(addr, "[::]:80") == 0);
}

void
test_sa_inet6_net(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_in6.sa_family = NNG_AF_INET6;
	memset(sa.s_in6.sa_addr, 0, sizeof(sa.s_in6.sa_addr));
	sa.s_in6.sa_port    = htons(80);
	sa.s_in6.sa_addr[0] = 0xfc;
	sa.s_in6.sa_scope   = 0;
	nng_str_sockaddr(&sa, addr, sizeof(addr));
	nng_log_debug(NULL, "address is %s", addr);
	NUTS_ASSERT(strcmp(addr, "[fc00::]:80") == 0);
}

TEST_LIST = {
	{ "nng_sockaddr_ipc", test_sa_ipc },
	{ "nng_sockaddr_abstract", test_sa_abstract },
	{ "nng_sockaddr_inproc", test_sa_inproc },
	{ "nng_sockaddr_in", test_sa_inet },
	{ "nng_sockaddr_in6", test_sa_inet6 },
	{ "nng_sockaddr_in6 v4 mapped", test_sa_inet6_v4_mapped },
	{ "nng_sockaddr_in6 link local", test_sa_inet6_ll },
	{ "nng_sockaddr_in6 zero", test_sa_inet6_zero },
	{ "nng_sockaddr_in6 subnet", test_sa_inet6_net },
	{ "nng_sockaddr families unequal", test_sa_families_unequal },
	{ NULL, NULL },
};
