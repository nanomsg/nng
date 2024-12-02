//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Cody Piersall <cody.piersall@gmail.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/nng.h>
#include <nuts.h>

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

	NUTS_ASSERT(strlen(addr) == 255);
	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_FAIL(nng_listen(s1, addr, NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(nng_dial(s1, addr, NULL, NNG_FLAG_NONBLOCK), NNG_EADDRINVAL);

	NUTS_CLOSE(s1);
}

void
test_ipc_dialer_perms(void)
{
	nng_socket s;
	nng_dialer d;
	char      *addr;

	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));
	NUTS_FAIL(
	    nng_dialer_set_int(d, NNG_OPT_IPC_PERMISSIONS, 0444), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

void
test_ipc_dialer_properties(void)
{
	nng_socket   s;
	nng_dialer   d;
	nng_sockaddr sa;
	size_t       z;
	char        *addr;

	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s);
	NUTS_PASS(nng_dial(s, addr, &d, NNG_FLAG_NONBLOCK));
	// Dialers don't have local addresses.
	NUTS_FAIL(nng_dialer_get_addr(d, NNG_OPT_LOCADDR, &sa), NNG_ENOTSUP);

	NUTS_FAIL(nng_dialer_set_addr(d, NNG_OPT_LOCADDR, &sa), NNG_ENOTSUP);
	NUTS_PASS(nng_dialer_get_addr(d, NNG_OPT_REMADDR, &sa));
	NUTS_TRUE(sa.s_family == NNG_AF_IPC);

	z = 8192;
	NUTS_PASS(nng_dialer_set_size(d, NNG_OPT_RECVMAXSZ, z));
	z = 0;
	NUTS_PASS(nng_dialer_get_size(d, NNG_OPT_RECVMAXSZ, &z));
	NUTS_TRUE(z == 8192);
	NUTS_CLOSE(s);
}

void
test_ipc_listener_perms(void)
{
	nng_socket   s;
	nng_listener l;
	char        *addr;

#ifndef _WIN32
	char       *path;
	struct stat st;
#endif

	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s);
	NUTS_PASS(nng_listener_create(&l, s, addr));

#ifdef _WIN32
	NUTS_FAIL(nng_listener_set_int(l, NNG_OPT_IPC_PERMISSIONS, 0444),
	    NNG_ENOTSUP);
#else
	path = &addr[strlen("ipc://")];

	// Attempt to set invalid permissions fails.
	NUTS_FAIL(nng_listener_set_int(l, NNG_OPT_IPC_PERMISSIONS, S_IFREG),
	    NNG_EINVAL);

	NUTS_PASS(nng_listener_set_int(l, NNG_OPT_IPC_PERMISSIONS, 0444));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_TRUE(stat(path, &st) == 0);
	NUTS_TRUE((st.st_mode & 0777) == 0444);

	// Now that it's running, we cannot set it.
	NUTS_FAIL(
	    nng_listener_set_int(l, NNG_OPT_IPC_PERMISSIONS, 0644), NNG_EBUSY);
#endif

	NUTS_CLOSE(s);
}

void
test_ipc_listener_properties(void)
{
	nng_socket   s;
	nng_listener l;
	nng_sockaddr sa;
	size_t       z;
	char        *addr;

	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s);
	NUTS_PASS(nng_listen(s, addr, &l, 0));
	NUTS_PASS(nng_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	NUTS_TRUE(sa.s_ipc.sa_family == NNG_AF_IPC);
	NUTS_MATCH(sa.s_ipc.sa_path, addr + strlen("ipc://"));

	NUTS_FAIL(
	    nng_listener_set_addr(l, NNG_OPT_LOCADDR, &sa), NNG_EREADONLY);
	z = 8192;
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, z));
	z = 0;
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_RECVMAXSZ, &z));
	NUTS_TRUE(z == 8192);
	NUTS_CLOSE(s);
}

void
test_ipc_ping_pong(void)
{
	nng_socket s0;
	nng_socket s1;
	char      *addr;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s0);
	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));

	NUTS_MARRY_EX(s0, s1, addr, NULL, NULL);

	NUTS_SEND(s0, "ping");
	NUTS_RECV(s1, "ping");
	NUTS_SEND(s1, "pong");
	NUTS_RECV(s0, "pong");
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
}

void
test_ipc_ping_pong_many(void)
{
	nng_socket s0;
	nng_socket s1;
	char      *addr;

	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s0);
	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));

	NUTS_MARRY_EX(s0, s1, addr, NULL, NULL);

	for (int i = 0; i < 100; i++) {
		NUTS_SEND(s0, "ping");
		NUTS_RECV(s1, "ping");
		NUTS_SEND(s1, "pong");
		NUTS_RECV(s0, "pong");
	}
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
}

void
test_ipc_huge_msg(void)
{
	nng_socket s0;
	nng_socket s1;
	char      *addr;
	nng_msg   *m;

	NUTS_ADDR(addr, "ipc");
	NUTS_PASS(nng_msg_alloc(&m, 1 << 20));
	memset(nng_msg_body(m), 'a', 1 << 20);
	NUTS_OPEN(s0);
	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));

	NUTS_MARRY_EX(s0, s1, addr, NULL, NULL);

	NUTS_PASS(nng_sendmsg(s0, m, 0));
	NUTS_PASS(nng_recvmsg(s1, &m, 0));

	NUTS_TRUE(nng_msg_len(m) == 1 << 20);
	char *body = nng_msg_body(m);
	for (int i = 0; i < 1 << 20; i++) {
		if (body[i] != 'a') {
			NUTS_TRUE(body[i] == 'a');
			break;
		}
	}
	nng_msg_free(m);
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
}

void
test_ipc_recv_max(void)
{
	char         msg[256]    = { 0 };
	char         rcvbuf[256] = { 0 };
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l;
	size_t       sz;
	char        *addr;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 200));
	NUTS_PASS(nng_listener_create(&l, s0, addr));
	NUTS_PASS(nng_socket_get_size(s0, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 200);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 100));
	NUTS_PASS(nng_listener_start(l, 0));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_dial(s1, addr, NULL, 0));
	NUTS_PASS(nng_send(s1, msg, 95, 0));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_recv(s0, rcvbuf, &sz, 0));
	NUTS_TRUE(sz == 95);
	NUTS_PASS(nng_send(s1, msg, 150, 0));
	NUTS_FAIL(nng_recv(s0, rcvbuf, &sz, 0), NNG_ETIMEDOUT);
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
}

void
test_ipc_connect_refused(void)
{
	nng_socket s0;
	nng_dialer d;
	char      *addr;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 200));
	NUTS_PASS(nng_dialer_create(&d, s0, addr));
	NUTS_FAIL(nng_dialer_start(d, 0), NNG_ECONNREFUSED);
	NUTS_CLOSE(s0);
}

void
test_ipc_connect_blocking(void)
{
	nng_socket           s0;
	nng_stream_listener *l;
	char                *addr;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s0);

	// start a listening stream listener but do not call accept
	NUTS_PASS(nng_stream_listener_alloc(&l, addr));
	NUTS_PASS(nng_stream_listener_listen(l));

	NUTS_PASS(nng_dial(s0, addr, NULL, NNG_FLAG_NONBLOCK));
	nng_msleep(100);
	NUTS_CLOSE(s0);
	nng_stream_listener_close(l);
	nng_stream_listener_free(l);
}

void
test_ipc_connect_blocking_accept(void)
{
	nng_socket           s0;
	nng_stream_listener *l;
	char                *addr;
	nng_aio             *aio;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s0);

	// start a listening stream listener but do not call accept
	NUTS_PASS(nng_stream_listener_alloc(&l, addr));
	NUTS_PASS(nng_stream_listener_listen(l));

	NUTS_PASS(nng_dial(s0, addr, NULL, NNG_FLAG_NONBLOCK));
	nng_msleep(100);
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_stream_listener_accept(l, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	nng_stream_close(nng_aio_get_output(aio, 0));
	nng_stream_free(nng_aio_get_output(aio, 0));
	nng_aio_free(aio);
	NUTS_CLOSE(s0);
	nng_stream_listener_close(l);
	nng_stream_listener_free(l);
}

void
test_ipc_listen_accept_cancel(void)
{
	nng_stream_listener *l;
	char                *addr;
	nng_aio             *aio;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_ADDR(addr, "ipc");
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	// start a listening stream listener but do not call accept
	NUTS_PASS(nng_stream_listener_alloc(&l, addr));
	NUTS_PASS(nng_stream_listener_listen(l));
	nng_stream_listener_accept(l, aio);
	nng_msleep(100);
	nng_aio_free(aio);
	nng_stream_listener_close(l);
	nng_stream_listener_free(l);
}

void
test_ipc_listen_duplicate(void)
{
	nng_socket s0;
	char      *addr;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s0);

	// start a listening stream listener but do not call accept
	NUTS_PASS(nng_listen(s0, addr, NULL, 0));
	NUTS_FAIL(nng_listen(s0, addr, NULL, 0), NNG_EADDRINUSE);
	NUTS_CLOSE(s0);
}

void
test_ipc_listener_clean_stale(void)
{
#ifdef NNG_PLATFORM_POSIX
	nng_socket           s0;
	nng_stream_listener *l;
	char                *addr;
	char                *path;
	char                 renamed[256];

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s0);

	// start a listening stream listener but do not call accept
	NUTS_PASS(nng_stream_listener_alloc(&l, addr));
	NUTS_PASS(nng_stream_listener_listen(l));
	path = addr + strlen("ipc://");
	snprintf(renamed, sizeof(renamed), "%s.renamed", path);
	NUTS_ASSERT(rename(path, renamed) == 0);
	nng_stream_listener_close(l);
	nng_stream_listener_free(l);
	nng_msleep(100);
	// put it back
	NUTS_ASSERT(rename(renamed, path) == 0);

	NUTS_PASS(nng_listen(s0, addr, NULL, 0));
	nng_msleep(50);
	NUTS_CLOSE(s0);
#else
	NUTS_SKIP("Not POSIX.");
#endif
}

void
test_abstract_sockets(void)
{
#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	nng_socket   s1;
	nng_socket   s2;
	char        *addr;
	nng_pipe     p1;
	nng_pipe     p2;
	nng_sockaddr sa1;
	nng_sockaddr sa2;
	char        *prefix = "abstract://";

	NUTS_ADDR(addr, "abstract");
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_MARRY_EX(s1, s2, addr, &p1, &p2);
	NUTS_PASS(nng_pipe_get_addr(p1, NNG_OPT_REMADDR, &sa1));
	NUTS_PASS(nng_pipe_get_addr(p2, NNG_OPT_LOCADDR, &sa2));
	NUTS_TRUE(sa1.s_family == sa2.s_family);
	NUTS_TRUE(sa1.s_family == NNG_AF_ABSTRACT);
	NUTS_TRUE(sa1.s_abstract.sa_len == strlen(addr) - strlen(prefix));
	NUTS_TRUE(sa2.s_abstract.sa_len == strlen(addr) - strlen(prefix));
	NUTS_SEND(s1, "ping");
	NUTS_RECV(s2, "ping");
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
#else
	NUTS_SKIP("No abstract sockets.");
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

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_listen(s1, addr, &l, 0));

	NUTS_PASS(nng_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	// Under linux there are either 8 or 5 hex characters.
	NUTS_TRUE(sa.s_family == NNG_AF_ABSTRACT);
	NUTS_TRUE(sa.s_abstract.sa_len < 10);

	len = sa.s_abstract.sa_len;
	memcpy(name, sa.s_abstract.sa_name, len);
	name[len] = '\0';
	NUTS_TRUE(strlen(name) == len);

	(void) snprintf(addr, sizeof(addr), "abstract://%s", name);
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));

	// first send the ping
	NUTS_SEND(s1, "ping");
	NUTS_RECV(s2, "ping");

	NUTS_SEND(s2, "pong");
	NUTS_RECV(s1, "pong");

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
#else
	NUTS_SKIP("No abstract sockets.");
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

	NUTS_ASSERT(strlen(addr) == 255);
	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_FAIL(nng_listen(s1, addr, NULL, 0), NNG_EADDRINVAL);
	NUTS_FAIL(nng_dial(s1, addr, NULL, NNG_FLAG_NONBLOCK), NNG_EADDRINVAL);

	NUTS_CLOSE(s1);
#else
	NUTS_SKIP("No abstract sockets.");
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

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_listen(s1, addr, &l, 0));

	NUTS_PASS(nng_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	// Under linux there are either 8 or 5 hex characters.
	NUTS_TRUE(sa.s_family == NNG_AF_ABSTRACT);
	NUTS_TRUE(sa.s_abstract.sa_len < 32);
	len = sa.s_abstract.sa_len;
	NUTS_TRUE(len == 20);
	NUTS_TRUE(sa.s_abstract.sa_name[0] == 'a');
	NUTS_TRUE(sa.s_abstract.sa_name[1] == '\0');
	NUTS_TRUE(sa.s_abstract.sa_name[2] == 'b');
	NUTS_TRUE(sa.s_abstract.sa_name[3] == '_');
	NUTS_TRUE(memcmp(&sa.s_abstract.sa_name[4], rng, 16) == 0);

	NUTS_PASS(nng_dial(s2, addr, NULL, 0));

	// first send the ping
	NUTS_SEND(s1, "1234");
	NUTS_RECV(s2, "1234");

	NUTS_SEND(s2, "5678");
	NUTS_RECV(s1, "5678");

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
#else
	NUTS_SKIP("No abstract sockets.");
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
	nng_msg     *msg;
	nng_pipe     p;

	// Presumes /tmp.

	(void) snprintf(
	    rng, sizeof(rng), "%08x%08x", nng_random(), nng_random());
	snprintf(addr1, sizeof(addr1), "ipc:///tmp/%s", rng);
	snprintf(addr2, sizeof(addr2), "unix:///tmp/%s", rng);

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_listen(s1, addr1, NULL, 0));
	NUTS_PASS(nng_dial(s2, addr2, NULL, 0));

	// first send the ping
	NUTS_SEND(s1, "ping");
	NUTS_PASS(nng_recvmsg(s2, &msg, 0));
	NUTS_ASSERT(msg != NULL);
	NUTS_TRUE(nng_msg_len(msg) == 5);
	NUTS_MATCH(nng_msg_body(msg), "ping");
	p = nng_msg_get_pipe(msg);
	NUTS_PASS(nng_pipe_get_addr(p, NNG_OPT_REMADDR, &sa1));
	NUTS_PASS(nng_pipe_get_addr(p, NNG_OPT_REMADDR, &sa2));
	NUTS_TRUE(sa1.s_family == sa2.s_family);
	NUTS_TRUE(sa1.s_family == NNG_AF_IPC);
	NUTS_MATCH(sa1.s_ipc.sa_path, sa2.s_ipc.sa_path);
	nng_msg_free(msg);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
#else
	NUTS_SKIP("Not POSIX.");
#endif
}

void
test_ipc_pipe_peer(void)
{
#ifdef NNG_PLATFORM_POSIX
	// this test verifies that closing a socket peer
	// during negotiation is ok.
	nng_socket s0, s1;
	nng_msg   *msg;
	nng_pipe   p;
	uint64_t   id;
	char      *addr;

	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s0);
	NUTS_PASS(nng_listen(s0, addr, NULL, 0));
	NUTS_OPEN(s1);
	NUTS_PASS(nng_dial(s1, addr, NULL, 0));

	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));

	NUTS_SEND(s0, "something");
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	p = nng_msg_get_pipe(msg);
	NUTS_ASSERT(nng_pipe_id(p) != -1);
#if defined(NNG_PLATFORM_DARWIN) || defined(NNG_PLATFORM_LINUX)
	NUTS_PASS(nng_pipe_get_uint64(p, NNG_OPT_PEER_PID, &id));
	NUTS_ASSERT(id == (uint64_t) getpid());
#endif
#if defined(NNG_PLATFORM_DARWIN) || defined(NNG_PLATFORM_LINUX)
	NUTS_PASS(nng_pipe_get_uint64(p, NNG_OPT_PEER_UID, &id));
	NUTS_ASSERT(id == (uint64_t) getuid());
#endif
#if defined(NNG_PLATFORM_DARWIN) || defined(NNG_PLATFORM_LINUX)
	NUTS_PASS(nng_pipe_get_uint64(p, NNG_OPT_PEER_GID, &id));
	NUTS_ASSERT(id == (uint64_t) getgid());
#endif
#if defined(NNG_PLATFORM_SUNOS)
	NUTS_PASS(nng_pipe_get_uint64(p, NNG_OPT_PEER_ZONEID, &id));
	NUTS_ASSERT(id == (uint64_t) getzoneid());
#else
	NUTS_FAIL(
	    nng_pipe_get_uint64(p, NNG_OPT_PEER_ZONEID, &id), NNG_ENOTSUP);
#endif

	nng_msg_free(msg);
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
#else
	NUTS_SKIP("Not POSIX.");
#endif // NNG_PLATFORM_POSIX
}

void
test_ipc_security_descriptor(void)
{
	nng_socket   s;
	nng_listener l;
	char        *addr;

	NUTS_ADDR(addr, "ipc");
	NUTS_OPEN(s);
	NUTS_PASS(nng_listener_create(&l, s, addr));
#ifdef NNG_PLATFORM_WINDOWS
	// not a security descriptor
	NUTS_FAIL(nng_listener_set_security_descriptor(l, addr), NNG_EINVAL);
#else
	// not appropriate
	NUTS_FAIL(nng_listener_set_security_descriptor(l, addr), NNG_ENOTSUP);
#endif
	NUTS_CLOSE(s);
}

TEST_LIST = {
	{ "ipc path too long", test_path_too_long },
	{ "ipc dialer perms", test_ipc_dialer_perms },
	{ "ipc dialer props", test_ipc_dialer_properties },
	{ "ipc listener perms", test_ipc_listener_perms },
	{ "ipc listener props", test_ipc_listener_properties },
	{ "ipc ping pong", test_ipc_ping_pong },
	{ "ipc ping pong many", test_ipc_ping_pong_many },
	{ "ipc huge msg", test_ipc_huge_msg },
	{ "ipc recv max", test_ipc_recv_max },
	{ "ipc connect refused", test_ipc_connect_refused },
	{ "ipc connect blocking", test_ipc_connect_blocking },
	{ "ipc connect blocking accept", test_ipc_connect_blocking_accept },
	{ "ipc listen cleanup stale", test_ipc_listener_clean_stale },
	{ "ipc listen duplicate", test_ipc_listen_duplicate },
	{ "ipc listen accept cancel", test_ipc_listen_accept_cancel },
	{ "ipc abstract sockets", test_abstract_sockets },
	{ "ipc abstract auto bind", test_abstract_auto_bind },
	{ "ipc abstract name too long", test_abstract_too_long },
	{ "ipc abstract embedded null", test_abstract_null },
	{ "ipc unix alias", test_unix_alias },
	{ "ipc peer id", test_ipc_pipe_peer },
	{ "ipc security descriptor", test_ipc_security_descriptor },
	{ NULL, NULL },
};
