//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
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
#include <fcntl.h>
#include <unistd.h>
#ifdef NNG_PLATFORM_SUNOS
#include <zone.h>
#endif
#endif

// Windows complains if we use the POSIX API.
#ifdef NNG_PLATFORM_WINDOWS
#include <io.h>
#define close(fd) _close(fd)
#endif

// FDC tests.
static void
test_sfd_connect_fail(void)
{
	nng_socket s;

	NUTS_OPEN(s);
	NUTS_FAIL(nng_dial(s, "socket://", NULL, 0), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

void
test_sfd_malformed_address(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_listen(s1, "socket://junk", NULL, 0), NNG_EADDRINVAL);
	NUTS_CLOSE(s1);
}

void
test_sfd_listen(void)
{
	nng_socket     s1;
	nng_listener   l;
	const nng_url *u;

	NUTS_OPEN(s1);
	NUTS_PASS(nng_listen(s1, "socket://", &l, 0));
	NUTS_PASS(nng_listener_get_url(l, &u));
	NUTS_MATCH(nng_url_scheme(u), "socket");
	NUTS_MATCH(nng_url_path(u), "");
	NUTS_NULL(nng_url_userinfo(u));
	NUTS_NULL(nng_url_hostname(u));
	NUTS_NULL(nng_url_query(u));
	NUTS_NULL(nng_url_fragment(u));

	NUTS_CLOSE(s1);
}

void
test_sfd_accept(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	nng_socket   s1, s2;
	nng_listener l;
	int          fds[2];

	NUTS_PASS(nng_socket_pair(fds));
	// make sure we won't have to deal with SIGPIPE - EPIPE is better
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_listener_create(&l, s1, "socket://"));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fds[0]));
	NUTS_SLEEP(10);
	NUTS_CLOSE(s1);
	close(fds[1]);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sfd_exchange(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	nng_socket   s1, s2;
	nng_listener l1, l2;
	int          fds[2];

	NUTS_PASS(nng_socket_pair(fds));
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_listener_create(&l1, s1, "socket://"));
	NUTS_PASS(nng_listener_start(l1, 0));
	NUTS_PASS(nng_listener_set_int(l1, NNG_OPT_SOCKET_FD, fds[0]));
	NUTS_PASS(nng_listener_create(&l2, s2, "socket://"));
	NUTS_PASS(nng_listener_start(l2, 0));
	NUTS_PASS(nng_listener_set_int(l2, NNG_OPT_SOCKET_FD, fds[1]));
	NUTS_SLEEP(10);
	NUTS_SEND(s1, "hello");
	NUTS_RECV(s2, "hello");
	NUTS_SEND(s2, "there");
	NUTS_RECV(s1, "there");

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	close(fds[1]);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sfd_exchange_late(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	nng_socket   s1, s2;
	nng_listener l1, l2;
	int          fds[2];

	NUTS_PASS(nng_socket_pair(fds));
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_listener_create(&l1, s1, "socket://"));
	NUTS_PASS(nng_listener_set_int(l1, NNG_OPT_SOCKET_FD, fds[0]));
	NUTS_PASS(nng_listener_start(l1, 0));
	NUTS_PASS(nng_listener_create(&l2, s2, "socket://"));
	NUTS_PASS(nng_listener_set_int(l2, NNG_OPT_SOCKET_FD, fds[1]));
	NUTS_PASS(nng_listener_start(l2, 0));
	NUTS_SLEEP(10);
	NUTS_SEND(s1, "hello");
	NUTS_RECV(s2, "hello");
	NUTS_SEND(s2, "there");
	NUTS_RECV(s1, "there");

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	close(fds[1]);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sfd_recv_max(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	char         msg[256] = { 0 };
	char         buf[256] = { 0 };
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l0;
	nng_listener l1;
	size_t       sz;
	size_t       scratch;
	int          fds[2];

	NUTS_PASS(nng_socket_pair(fds));

	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 200));
	NUTS_PASS(nng_listener_create(&l0, s0, "socket://"));
	NUTS_PASS(nng_socket_get_size(s0, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 200);
	NUTS_PASS(nng_listener_set_size(l0, NNG_OPT_RECVMAXSZ, 100));
	NUTS_PASS(nng_listener_get_size(l0, NNG_OPT_RECVMAXSZ, &scratch));
	NUTS_ASSERT(scratch == 100);
	NUTS_PASS(nng_listener_start(l0, 0));
	NUTS_PASS(nng_listener_set_int(l0, NNG_OPT_SOCKET_FD, fds[0]));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_listener_create(&l1, s1, "socket://"));
	NUTS_PASS(nng_listener_start(l1, 0));
	NUTS_PASS(nng_listener_set_int(l1, NNG_OPT_SOCKET_FD, fds[1]));
	NUTS_PASS(nng_send(s1, msg, 95, 0));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_recv(s0, buf, &sz, 0));
	NUTS_TRUE(sz == 95);
	NUTS_PASS(nng_send(s1, msg, 150, 0));
	NUTS_FAIL(nng_recv(s0, buf, &sz, 0), NNG_ETIMEDOUT);
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sfd_large(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	char        *buf;
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l0;
	nng_listener l1;
	size_t       sz;
	nng_msg     *msg;
	int          fds[2];

	sz          = 1U << 20;
	buf         = nng_alloc(sz); // a MB
	buf[sz - 1] = 0;
	memset(buf, 'A', sz - 1);
	NUTS_PASS(nng_socket_pair(fds));
	NUTS_PASS(nng_msg_alloc(&msg, sz));

	NUTS_OPEN(s0);
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_size(s0, NNG_OPT_RECVMAXSZ, 2U << 20));
	NUTS_PASS(nng_listener_create(&l0, s0, "socket://"));
	NUTS_PASS(nng_listener_start(l0, 0));
	NUTS_PASS(nng_listener_set_int(l0, NNG_OPT_SOCKET_FD, fds[0]));

	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_size(s1, NNG_OPT_RECVMAXSZ, 2U << 20));
	NUTS_PASS(nng_listener_create(&l1, s1, "socket://"));
	NUTS_PASS(nng_listener_start(l1, 0));
	NUTS_PASS(nng_listener_set_int(l1, NNG_OPT_SOCKET_FD, fds[1]));
	nng_msleep(100);

	nng_msg_clear(msg);
	NUTS_PASS(nng_msg_append(msg, buf, sz));
	NUTS_PASS(nng_sendmsg(s0, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	NUTS_ASSERT(strcmp(nng_msg_body(msg), buf) == 0);

	memset(nng_msg_body(msg), 'B', sz - 1);
	memset(buf, 'B', sz - 1);

	NUTS_PASS(nng_sendmsg(s1, msg, 0));
	NUTS_PASS(nng_recvmsg(s0, &msg, 0));
	NUTS_ASSERT(strcmp(nng_msg_body(msg), buf) == 0);

	nng_msg_clear(msg);
	NUTS_PASS(nng_msg_append(msg, buf, sz));
	NUTS_PASS(nng_sendmsg(s0, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	NUTS_ASSERT(strcmp(nng_msg_body(msg), buf) == 0);

	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
	nng_msg_free(msg);
	nng_free(buf, sz);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sockfd_close_pending(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	// this test verifies that closing a socket pair that has not
	// started negotiation with the other side still works.
	int          fds[2];
	nng_socket   s0;
	nng_listener l;

	NUTS_PASS(nng_socket_pair(fds));
	NUTS_OPEN(s0);
	nng_listen(s0, "socket://", &l, 0);
	nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fds[0]);
	nng_msleep(10);
	NUTS_CLOSE(s0);
	close(fds[1]);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sockfd_close_peer(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	// this test verifies that closing a socket peer
	// during negotiation is ok.
	int          fds[2];
	nng_socket   s0;
	nng_listener l;

	NUTS_PASS(nng_socket_pair(fds));
	NUTS_OPEN(s0);
	NUTS_PASS(nng_listen(s0, "socket://", &l, 0));
	NUTS_PASS(nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fds[0]));
	close(fds[1]);
	nng_msleep(100);
	NUTS_CLOSE(s0);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sockfd_listener_sockaddr(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	// this test verifies that closing a socket peer
	// during negotiation is ok.
	int          fds[2];
	nng_socket   s0;
	nng_listener l;
	nng_sockaddr sa;

	NUTS_PASS(nng_socket_pair(fds));
	NUTS_OPEN(s0);
	NUTS_PASS(nng_listen(s0, "socket://", &l, 0));
	NUTS_PASS(nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fds[0]));
	NUTS_PASS(nng_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	NUTS_ASSERT(sa.s_family == NNG_AF_UNSPEC);
	close(fds[1]);
	NUTS_CLOSE(s0);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sockfd_pipe_sockaddr(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	// this test verifies that closing a socket peer
	// during negotiation is ok.
	int          fds[2];
	nng_socket   s0, s1;
	nng_listener l;
	nng_sockaddr sa;
	nng_msg     *msg;
	nng_pipe     p;

	NUTS_PASS(nng_socket_pair(fds));
	NUTS_OPEN(s0);
	NUTS_OPEN(s1);
	NUTS_PASS(nng_listen(s0, "socket://", &l, 0));
	NUTS_PASS(nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fds[0]));
	NUTS_PASS(nng_listen(s1, "socket://", &l, 0));
	NUTS_PASS(nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fds[1]));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s0, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));

	NUTS_SEND(s0, "something");
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	p = nng_msg_get_pipe(msg);
	NUTS_PASS(nng_pipe_get_addr(p, NNG_OPT_LOCADDR, &sa));
	NUTS_ASSERT(sa.s_family == NNG_AF_UNSPEC);
	NUTS_PASS(nng_pipe_get_addr(p, NNG_OPT_REMADDR, &sa));
	NUTS_ASSERT(sa.s_family == NNG_AF_UNSPEC);
	NUTS_CLOSE(s0);
	NUTS_CLOSE(s1);
	nng_msg_free(msg);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sockfd_pipe_peer(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	// this test verifies that closing a socket peer
	// during negotiation is ok.
	int          fds[2];
	nng_socket   s0, s1;
	nng_listener l;
	nng_msg     *msg;
	nng_pipe     p;
	uint64_t     id;

	NUTS_PASS(nng_socket_pair(fds));
	NUTS_OPEN(s0);
	NUTS_OPEN(s1);
	NUTS_PASS(nng_listen(s0, "socket://", &l, 0));
	NUTS_PASS(nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fds[0]));
	NUTS_PASS(nng_listen(s1, "socket://", &l, 0));
	NUTS_PASS(nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fds[1]));
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
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sfd_listen_full(void)
{
#ifndef NNG_SFD_LISTEN_QUEUE
#define NNG_SFD_LISTEN_QUEUE 16
#endif

#ifdef NNG_HAVE_SOCKETPAIR
	int          fds[NNG_SFD_LISTEN_QUEUE * 2];
	nng_socket   s;
	int          i;
	nng_listener l;
	for (i = 0; i < NNG_SFD_LISTEN_QUEUE * 2; i += 2) {
		int pair[2];
		NUTS_PASS(nng_socket_pair(pair));
		fds[i]     = pair[0];
		fds[i + 1] = pair[1];
	}
	NUTS_OPEN(s);
	NUTS_PASS(nng_listener_create(&l, s, "socket://"));
	for (i = 0; i < NNG_SFD_LISTEN_QUEUE * 2; i++) {
		if (i < NNG_SFD_LISTEN_QUEUE) {
			NUTS_PASS(nng_listener_set_int(
			    l, NNG_OPT_SOCKET_FD, fds[i]));
		} else {
			NUTS_FAIL(
			    nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fds[i]),
			    NNG_ENOSPC);
		}
	}
	for (i = 0; i < NNG_SFD_LISTEN_QUEUE * 2; i++) {
		close(fds[i]);
	}
	NUTS_CLOSE(s);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sfd_fd_option_type(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	nng_socket   s;
	nng_listener l;

	NUTS_OPEN(s);
	NUTS_PASS(nng_listener_create(&l, s, "socket://"));
	NUTS_FAIL(
	    nng_listener_set_bool(l, NNG_OPT_SOCKET_FD, false), NNG_EBADTYPE);
	NUTS_CLOSE(s);
#else
	NUTS_SKIP("no socketpair");
#endif
}

void
test_sfd_fd_invalid_fd(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	nng_socket   s;
	nng_listener l;

	NUTS_OPEN(s);
	NUTS_PASS(nng_listener_create(&l, s, "socket://"));
	NUTS_FAIL(
	    nng_listener_set_int(l, NNG_OPT_SOCKET_FD, -100), NNG_EINVAL);
	NUTS_CLOSE(s);
#else
	NUTS_SKIP("no socketpair");
#endif
}
void
test_sfd_fd_dev_zero(void)
{
#ifdef NNG_HAVE_SOCKETPAIR
	nng_socket   s;
	nng_listener l;
	int          fd;

	// dev/zero produces a stream of zero bytes leading to protocol error
	NUTS_ASSERT((fd = open("/dev/zero", O_RDONLY, 0777)) >= 0);

	NUTS_OPEN(s);
	NUTS_PASS(nng_listener_create(&l, s, "socket://"));
	NUTS_PASS(nng_listener_set_int(l, NNG_OPT_SOCKET_FD, fd));
	nng_msleep(100);
	NUTS_CLOSE(s);
#else
	NUTS_SKIP("no socketpair");
#endif
}

NUTS_TESTS = {
	{ "socket connect fail", test_sfd_connect_fail },
	{ "socket malformed address", test_sfd_malformed_address },
	{ "socket listen", test_sfd_listen },
	{ "socket accept", test_sfd_accept },
	{ "socket exchange", test_sfd_exchange },
	{ "socket exchange late", test_sfd_exchange_late },
	{ "socket recv max", test_sfd_recv_max },
	{ "socket exchange large", test_sfd_large },
	{ "socket close pending", test_sockfd_close_pending },
	{ "socket close peer", test_sockfd_close_peer },
	{ "socket listener address", test_sockfd_listener_sockaddr },
	{ "socket pipe address", test_sockfd_pipe_sockaddr },
	{ "socket pipe peer id", test_sockfd_pipe_peer },
	{ "socket listen full", test_sfd_listen_full },
	{ "socket bad fd type", test_sfd_fd_option_type },
	{ "socket invalid fd", test_sfd_fd_invalid_fd },
	{ "socket dev zero", test_sfd_fd_dev_zero },
	{ NULL, NULL },
};
