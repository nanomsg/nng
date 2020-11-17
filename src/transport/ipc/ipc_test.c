//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Cody Piersall <cody.piersall@gmail.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/nng.h>
#include <nng/protocol/pair0/pair.h>
#include <nng/supplemental/util/platform.h>

#include <testutil.h>

#include <acutest.h>

#ifdef NNG_PLATFORM_POSIX
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

void
test_path_too_long(void)
{
	nng_socket s1;
	char       addr[256];

	// All our names have to be less than 128 bytes.
	memset(addr, 'a', 255);
	addr[255] = 0;
	memcpy(addr, "ipc://", strlen("ipc://"));

	TEST_ASSERT(strlen(addr) == 255);
	TEST_NNG_PASS(nng_pair0_open(&s1));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_FAIL(nng_listen(s1, addr, NULL, 0), NNG_EADDRINVAL);
	TEST_NNG_FAIL(
	    nng_dial(s1, addr, NULL, NNG_FLAG_NONBLOCK), NNG_EADDRINVAL);

	TEST_NNG_PASS(nng_close(s1));
}

void
test_ipc_dialer_perms(void)
{
	nng_socket s;
	nng_dialer d;
	char       addr[64];

	testutil_scratch_addr("ipc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_pair0_open(&s));
	TEST_NNG_PASS(nng_dialer_create(&d, s, addr));
	TEST_NNG_FAIL(
	    nng_dialer_set_int(d, NNG_OPT_IPC_PERMISSIONS, 0444), NNG_ENOTSUP);

	TEST_NNG_PASS(nng_close(s));
}

void
test_ipc_dialer_properties(void)
{
	nng_socket   s;
	nng_dialer   d;
	nng_sockaddr sa;
	size_t       z;
	char         addr[64];

	testutil_scratch_addr("ipc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_pair0_open(&s));
	TEST_NNG_PASS(nng_dial(s, addr, &d, NNG_FLAG_NONBLOCK));
	// Dialers don't have local addresses.
	TEST_NNG_FAIL(
	    nng_dialer_get_addr(d, NNG_OPT_LOCADDR, &sa), NNG_ENOTSUP);

	TEST_NNG_FAIL(
	    nng_dialer_set(d, NNG_OPT_LOCADDR, &sa, sizeof(sa)), NNG_ENOTSUP);

	z = 8192;
	TEST_NNG_PASS(nng_dialer_set_size(d, NNG_OPT_RECVMAXSZ, z));
	z = 0;
	TEST_NNG_PASS(nng_dialer_get_size(d, NNG_OPT_RECVMAXSZ, &z));
	TEST_CHECK(z == 8192);
	TEST_NNG_FAIL(nng_dialer_set_bool(d, NNG_OPT_RAW, true), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(s));
}

void
test_ipc_listener_perms(void)
{
	nng_socket   s;
	nng_listener l;
	char         addr[64];

#ifndef _WIN32
	char *      path;
	struct stat st;
#endif

	testutil_scratch_addr("ipc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_pair0_open(&s));
	TEST_NNG_PASS(nng_listener_create(&l, s, addr));

#ifdef _WIN32
	TEST_NNG_FAIL(nng_listener_set_int(l, NNG_OPT_IPC_PERMISSIONS, 0444),
	    NNG_ENOTSUP);
#else
	path = &addr[strlen("ipc://")];

	// Attempt to set invalid permissions fails.
	TEST_NNG_FAIL(
	    nng_listener_set_int(l, NNG_OPT_IPC_PERMISSIONS, S_IFREG),
	    NNG_EINVAL);

	TEST_NNG_PASS(nng_listener_set_int(l, NNG_OPT_IPC_PERMISSIONS, 0444));
	TEST_NNG_PASS(nng_listener_start(l, 0));
	TEST_CHECK(stat(path, &st) == 0);
	TEST_CHECK((st.st_mode & 0777) == 0444);

	// Now that it's running, we cannot set it.
	TEST_NNG_FAIL(
	    nng_listener_set_int(l, NNG_OPT_IPC_PERMISSIONS, 0644), NNG_EBUSY);
#endif

	TEST_NNG_PASS(nng_close(s));
}

void
test_ipc_listener_properties(void)
{
	nng_socket   s;
	nng_listener l;
	nng_sockaddr sa;
	size_t       z;
	char         addr[64];

	testutil_scratch_addr("ipc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_pair0_open(&s));
	TEST_NNG_PASS(nng_listen(s, addr, &l, 0));
	TEST_NNG_PASS(nng_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	TEST_CHECK(sa.s_ipc.sa_family == NNG_AF_IPC);
	TEST_STREQUAL(sa.s_ipc.sa_path, addr + strlen("ipc://"));

	TEST_NNG_FAIL(nng_listener_set(l, NNG_OPT_LOCADDR, &sa, sizeof(sa)),
	    NNG_EREADONLY);
	z = 8192;
	TEST_NNG_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, z));
	z = 0;
	TEST_NNG_PASS(nng_listener_get_size(l, NNG_OPT_RECVMAXSZ, &z));
	TEST_CHECK(z == 8192);
	TEST_NNG_FAIL(
	    nng_listener_set_bool(l, NNG_OPT_RAW, true), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(s));
}

void
test_ipc_recv_max(void)
{
	char         msg[256];
	char         rcvbuf[256];
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l;
	size_t       sz;
	char         addr[64];

	testutil_scratch_addr("ipc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_pair0_open(&s0));
	TEST_NNG_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 200));
	TEST_NNG_PASS(nng_listener_create(&l, s0, addr));
	TEST_NNG_PASS(nng_socket_get_size(s0, NNG_OPT_RECVMAXSZ, &sz));
	TEST_CHECK(sz == 200);
	TEST_NNG_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 100));
	TEST_NNG_PASS(nng_listener_start(l, 0));

	TEST_NNG_PASS(nng_pair0_open(&s1));
	TEST_NNG_PASS(nng_dial(s1, addr, NULL, 0));
	TEST_NNG_PASS(nng_send(s1, msg, 95, 0));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	TEST_NNG_PASS(nng_recv(s0, rcvbuf, &sz, 0));
	TEST_CHECK(sz == 95);
	TEST_NNG_PASS(nng_send(s1, msg, 150, 0));
	TEST_NNG_FAIL(nng_recv(s0, rcvbuf, &sz, 0), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(s0));
	TEST_NNG_PASS(nng_close(s1));
}

void
test_abstract_sockets(void)
{
#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	nng_socket   s1;
	nng_socket   s2;
	char         addr[64];
	nng_pipe     p1;
	nng_pipe     p2;
	nng_sockaddr sa1;
	nng_sockaddr sa2;
	char *       prefix = "abstract://";
	testutil_scratch_addr("abstract", sizeof(addr), addr);

	TEST_NNG_PASS(nng_pair0_open(&s1));
	TEST_NNG_PASS(nng_pair0_open(&s2));
	TEST_NNG_PASS(testutil_marry_ex(s1, s2, addr, &p1, &p2));
	TEST_NNG_PASS(nng_pipe_get_addr(p1, NNG_OPT_REMADDR, &sa1));
	TEST_NNG_PASS(nng_pipe_get_addr(p2, NNG_OPT_LOCADDR, &sa2));
	TEST_CHECK(sa1.s_family == sa2.s_family);
	TEST_CHECK(sa1.s_family == NNG_AF_ABSTRACT);
	TEST_CHECK(sa1.s_abstract.sa_len == strlen(addr) - strlen(prefix));
	TEST_CHECK(sa2.s_abstract.sa_len == strlen(addr) - strlen(prefix));
	TEST_NNG_SEND_STR(s1, "ping");
	TEST_NNG_RECV_STR(s2, "ping");
	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(s2));
#endif
}

void
test_abstract_auto_bind(void)
{
#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	nng_socket   s1;
	nng_socket   s2;
	char         addr[40];
	char         name[12];
	nng_sockaddr sa;
	nng_listener l;
	size_t       len;

	snprintf(addr, sizeof(addr), "abstract://");

	TEST_NNG_PASS(nng_pair0_open(&s1));
	TEST_NNG_PASS(nng_pair0_open(&s2));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_listen(s1, addr, &l, 0));

	TEST_NNG_PASS(nng_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	// Under linux there are either 8 or 5 hex characters.
	TEST_CHECK(sa.s_family == NNG_AF_ABSTRACT);
	TEST_CHECK(sa.s_abstract.sa_len < 10);

	len = sa.s_abstract.sa_len;
	memcpy(name, sa.s_abstract.sa_name, len);
	name[len] = '\0';
	TEST_CHECK(strlen(name) == len);

	(void) snprintf(addr, sizeof(addr), "abstract://%s", name);
	TEST_NNG_PASS(nng_dial(s2, addr, NULL, 0));

	// first send the ping
	TEST_NNG_SEND_STR(s1, "ping");
	TEST_NNG_RECV_STR(s2, "ping");

	TEST_NNG_SEND_STR(s2, "pong");
	TEST_NNG_RECV_STR(s1, "pong");

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(s2));
#endif
}

void
test_abstract_too_long(void)
{
#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	nng_socket s1;
	char       addr[256];

	// All our names have to be less than 128 bytes.
	memset(addr, 'a', 255);
	addr[255] = 0;
	memcpy(addr, "abstract://", strlen("abstract://"));

	TEST_ASSERT(strlen(addr) == 255);
	TEST_NNG_PASS(nng_pair0_open(&s1));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_FAIL(nng_listen(s1, addr, NULL, 0), NNG_EADDRINVAL);
	TEST_NNG_FAIL(
	    nng_dial(s1, addr, NULL, NNG_FLAG_NONBLOCK), NNG_EADDRINVAL);

	TEST_NNG_PASS(nng_close(s1));
#endif
}

void
test_abstract_null(void)
{
#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	nng_socket s1;
	nng_socket s2;
	char       addr[64];
	char       name[40];
	char       rng[20];

	nng_sockaddr sa;
	nng_listener l;
	size_t       len;

	snprintf(rng, sizeof(rng), "%08x%08x", nng_random(), nng_random());
	snprintf(name, sizeof(name), "a%%00b_%s", rng);
	snprintf(addr, sizeof(addr), "abstract://%s", name);

	TEST_NNG_PASS(nng_pair0_open(&s1));
	TEST_NNG_PASS(nng_pair0_open(&s2));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_listen(s1, addr, &l, 0));

	TEST_NNG_PASS(nng_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	// Under linux there are either 8 or 5 hex characters.
	TEST_CHECK(sa.s_family == NNG_AF_ABSTRACT);
	TEST_CHECK(sa.s_abstract.sa_len < 32);
	len = sa.s_abstract.sa_len;
	TEST_CHECK(len == 20);
	TEST_CHECK(sa.s_abstract.sa_name[0] == 'a');
	TEST_CHECK(sa.s_abstract.sa_name[1] == '\0');
	TEST_CHECK(sa.s_abstract.sa_name[2] == 'b');
	TEST_CHECK(sa.s_abstract.sa_name[3] == '_');
	TEST_CHECK(memcmp(&sa.s_abstract.sa_name[4], rng, 16) == 0);

	TEST_NNG_PASS(nng_dial(s2, addr, NULL, 0));

	// first send the ping
	TEST_NNG_SEND_STR(s1, "1234");
	TEST_NNG_RECV_STR(s2, "1234");

	TEST_NNG_SEND_STR(s2, "5678");
	TEST_NNG_RECV_STR(s1, "5678");

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(s2));
#endif
}

void
test_unix_alias(void)
{
#ifdef NNG_PLATFORM_POSIX
	nng_socket   s1;
	nng_socket   s2;
	char         addr1[32];
	char         addr2[32];
	char         rng[20];
	nng_sockaddr sa1;
	nng_sockaddr sa2;
	nng_msg *    msg;
	nng_pipe     p;

	// Presumes /tmp.

	(void) snprintf(
	    rng, sizeof(rng), "%08x%08x", nng_random(), nng_random());
	snprintf(addr1, sizeof(addr1), "ipc:///tmp/%s", rng);
	snprintf(addr2, sizeof(addr2), "unix:///tmp/%s", rng);

	TEST_NNG_PASS(nng_pair0_open(&s1));
	TEST_NNG_PASS(nng_pair0_open(&s2));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_listen(s1, addr1, NULL, 0));
	TEST_NNG_PASS(nng_dial(s2, addr2, NULL, 0));

	// first send the ping
	TEST_NNG_SEND_STR(s1, "ping");
	TEST_NNG_PASS(nng_recvmsg(s2, &msg, 0));
	TEST_ASSERT(msg != NULL);
	TEST_CHECK(nng_msg_len(msg) == 5);
	TEST_STREQUAL(nng_msg_body(msg), "ping");
	p = nng_msg_get_pipe(msg);
	TEST_NNG_PASS(nng_pipe_get_addr(p, NNG_OPT_REMADDR, &sa1));
	TEST_NNG_PASS(nng_pipe_get_addr(p, NNG_OPT_REMADDR, &sa2));
	TEST_CHECK(sa1.s_family == sa2.s_family);
	TEST_CHECK(sa1.s_family == NNG_AF_IPC);
	TEST_STREQUAL(sa1.s_ipc.sa_path, sa2.s_ipc.sa_path);
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(s2));
#endif
}

TEST_LIST = {
	{ "ipc path too long", test_path_too_long },
	{ "ipc dialer perms", test_ipc_dialer_perms },
	{ "ipc dialer props", test_ipc_dialer_properties },
	{ "ipc listener perms", test_ipc_listener_perms },
	{ "ipc listener props", test_ipc_listener_properties },
	{ "ipc recv max", test_ipc_recv_max },
	{ "ipc abstract sockets", test_abstract_sockets },
	{ "ipc abstract auto bind", test_abstract_auto_bind },
	{ "ipc abstract name too long", test_abstract_too_long },
	{ "ipc abstract embedded null", test_abstract_null },
	{ "ipc unix alias", test_unix_alias },
	{ NULL, NULL },
};