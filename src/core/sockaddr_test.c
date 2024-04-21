//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <string.h>

#include "nuts.h"
#include <nng/nng.h>

#ifndef _WIN32
#include <arpa/inet.h> // for endianness functions
#endif

void
test_sa_ipc(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_ipc.sa_family = NNG_AF_IPC;
	snprintf(sa.s_ipc.sa_path, sizeof(sa.s_ipc.sa_path), "/tmp/something");
	NUTS_ASSERT(strcmp(nng_str_sockaddr(&sa, addr, sizeof(addr)),
	                "/tmp/something") == 0);
}

void
test_sa_abstract(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_abstract.sa_family = NNG_AF_ABSTRACT;
	snprintf((char *) sa.s_abstract.sa_name, sizeof(sa.s_abstract.sa_name),
	    "something");
	NUTS_ASSERT(strcmp(nng_str_sockaddr(&sa, addr, sizeof(addr)),
	                "abstract[something]") == 0);
}

void
test_sa_inproc(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_inproc.sa_family = NNG_AF_INPROC;
	snprintf((char *) sa.s_inproc.sa_name, sizeof(sa.s_inproc.sa_name),
	    "something");
	nng_str_sockaddr(&sa, addr, sizeof(addr));
	nng_log_debug(NULL, "address is %s", addr);
	NUTS_ASSERT(strcmp(addr, "inproc[something]") == 0);
}

void
test_sa_inet(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_in.sa_family = NNG_AF_INET;
	sa.s_in.sa_addr   = htonl(0x7F000001);
	sa.s_in.sa_port   = htons(80);
	NUTS_ASSERT(strcmp(nng_str_sockaddr(&sa, addr, sizeof(addr)),
	                "127.0.0.1:80") == 0);
}

void
test_sa_inet6(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_in.sa_family = NNG_AF_INET6;
	memset(sa.s_in6.sa_addr, 0, sizeof(sa.s_in6.sa_addr));
	sa.s_in6.sa_addr[15] = 1; // loopback
	sa.s_in6.sa_scope    = 0;
	sa.s_in6.sa_port     = htons(80);
	nng_str_sockaddr(&sa, addr, sizeof(addr));
	nng_log_debug(NULL, "address is %s", addr);
	NUTS_ASSERT(strcmp(addr, "[::1]:80") == 0);
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

void
test_sa_zt(void)
{
	nng_sockaddr sa;
	char         addr[NNG_MAXADDRSTRLEN];
	sa.s_zt.sa_family = NNG_AF_ZT;
	sa.s_zt.sa_nodeid = 0xa;
	sa.s_zt.sa_nwid   = 0xb;
	sa.s_zt.sa_port   = 1 << 20;
	nng_str_sockaddr(&sa, addr, sizeof(addr));
	nng_log_debug(NULL, "address is %s", addr);
	NUTS_ASSERT(strcmp(addr, "ZT[a:b:1048576]") == 0);
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
	{ "nng_sockaddr_zt", test_sa_zt },
	{ NULL, NULL },
};
