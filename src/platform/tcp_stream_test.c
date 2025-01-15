//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <string.h>

#include <nng/nng.h>

#include <nuts.h>

void
test_tcp_stream(void)
{
	nng_stream_dialer   *d = NULL;
	nng_stream_listener *l = NULL;
	nng_sockaddr         sa;
	uint8_t              ip[4];
	nng_aio             *daio = NULL;
	nng_aio             *laio = NULL;
	nng_aio             *maio = NULL;
	nng_stream          *c1   = NULL;
	nng_stream          *c2   = NULL;
	nng_aio             *aio1;
	nng_aio             *aio2;
	nng_iov              iov;
	nng_sockaddr         sa2;
	char                 buf1[5];
	char                 buf2[5];
	bool                 on;

	NUTS_PASS(nng_aio_alloc(&daio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&laio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&maio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	NUTS_PASS(nng_stream_listener_alloc(&l, "tcp://127.0.0.1"));
	NUTS_PASS(nng_stream_listener_listen(l));

	ip[0] = 127;
	ip[1] = 0;
	ip[2] = 0;
	ip[3] = 1;
	NUTS_PASS(nng_stream_listener_get_addr(l, NNG_OPT_LOCADDR, &sa));
	NUTS_TRUE(sa.s_in.sa_port != 0);
	NUTS_TRUE(memcmp(&sa.s_in.sa_addr, ip, 4) == 0);

	char uri[64];
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%d",
	    nuts_be16(sa.s_in.sa_port));

	NUTS_PASS(nng_stream_dialer_alloc(&d, uri));
	nng_stream_dialer_dial(d, daio);
	nng_stream_listener_accept(l, laio);

	nng_aio_wait(daio);
	NUTS_PASS(nng_aio_result(daio));
	nng_aio_wait(laio);
	NUTS_PASS(nng_aio_result(laio));

	c1 = nng_aio_get_output(daio, 0);
	c2 = nng_aio_get_output(laio, 0);
	NUTS_TRUE(c1 != NULL);
	NUTS_TRUE(c2 != NULL);

	on = false;
	NUTS_PASS(nng_stream_get_bool(c1, NNG_OPT_TCP_NODELAY, &on));
	NUTS_TRUE(on);

	on = false;
	NUTS_PASS(nng_stream_get_bool(c1, NNG_OPT_TCP_KEEPALIVE, &on));

	// This relies on send completing for
	// for just 5 bytes, and on recv doing
	// the same.  Technically this isn't
	// guaranteed, but it would be weird
	// to split such a small payload.
	memcpy(buf1, "TEST", 5);
	memset(buf2, 0, 5);
	iov.iov_buf = buf1;
	iov.iov_len = 5;

	nng_aio_set_iov(aio1, 1, &iov);

	iov.iov_buf = buf2;
	iov.iov_len = 5;
	nng_aio_set_iov(aio2, 1, &iov);
	nng_stream_send(c1, aio1);
	nng_stream_recv(c2, aio2);
	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_TRUE(nng_aio_count(aio1) == 5);

	NUTS_PASS(nng_aio_result(aio2));
	NUTS_TRUE(nng_aio_count(aio2) == 5);

	NUTS_TRUE(memcmp(buf1, buf2, 5) == 0);

	NUTS_PASS(nng_stream_get_addr(c2, NNG_OPT_LOCADDR, &sa2));
	NUTS_TRUE(sa2.s_in.sa_family == NNG_AF_INET);

	NUTS_TRUE(sa2.s_in.sa_addr == sa.s_in.sa_addr);
	NUTS_TRUE(sa2.s_in.sa_port == sa.s_in.sa_port);

	NUTS_PASS(nng_stream_get_addr(c1, NNG_OPT_REMADDR, &sa2));
	NUTS_TRUE(sa2.s_in.sa_family == NNG_AF_INET);
	NUTS_TRUE(sa2.s_in.sa_addr == sa.s_in.sa_addr);
	NUTS_TRUE(sa2.s_in.sa_port == sa.s_in.sa_port);

	nng_stream_listener_free(l);
	nng_stream_dialer_free(d);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_aio_free(daio);
	nng_aio_free(laio);
	nng_aio_free(maio);
	nng_stream_close(c1);
	nng_stream_close(c2);
	nng_stream_stop(c1);
	nng_stream_stop(c2);
	nng_stream_free(c1);
	nng_stream_free(c2);
}

void
test_tcp_listen_accept_cancel(void)
{
	nng_stream_listener *l;
	char                *addr;
	nng_aio             *aio;

	nng_log_set_logger(nng_stderr_logger);
	NUTS_ADDR(addr, "tcp");
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
test_tcp_listen_port_zero_not_bound(void)
{
	nng_stream_listener *l;
	char                *addr;
	int                  p;

	nng_log_set_logger(nng_stderr_logger);
	NUTS_ADDR_ZERO(addr, "tcp");

	// start a listening stream listener but do not call accept
	NUTS_PASS(nng_stream_listener_alloc(&l, addr));
	NUTS_FAIL(nng_stream_listener_get_int(l, NNG_OPT_TCP_BOUND_PORT, &p),
	    NNG_ESTATE);
	nng_stream_listener_free(l);
}

void
test_tcp_listen_empty_address(void)
{
	nng_stream_listener *l;

	// start a listening stream listener but do not call accept
	NUTS_PASS(nng_stream_listener_alloc(&l, "tcp4://"));
	NUTS_PASS(nng_stream_listener_listen(l));
	nng_stream_listener_free(l);
}

void
test_tcp_listen_activation(void)
{
#if defined(NNG_PLATFORM_POSIX)
	nng_stream_listener *l1;
	nng_stream_listener *l2;
	char                *addr;
	int                  fd;
	int                  port;
	nng_aio             *aio1;
	nng_aio             *aio2;
	nng_stream_dialer   *d;
	nng_stream          *c1, *c2;
	char                 url[32];

	NUTS_ADDR_ZERO(addr, "tcp4");
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	nng_aio_set_timeout(aio1, 2000);
	nng_aio_set_timeout(aio2, 2000);

	NUTS_PASS(nng_stream_listener_alloc(&l1, addr));
	NUTS_PASS(nng_stream_listener_listen(l1));
	NUTS_PASS(
	    nng_stream_listener_get_int(l1, NNG_OPT_TCP_BOUND_PORT, &port));

	snprintf(url, sizeof(url), "tcp4://127.0.0.1:%u", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, url));

	NUTS_PASS(nng_stream_listener_get_int(l1, NNG_OPT_LISTEN_FD, &fd));
	fd = dup(fd);
	// dupe this because we need to separate the file descriptors to
	// prevent confusion when we clean up (only one FD can be registered at
	// a time!)
	NUTS_ASSERT(fd >= -1);

	NUTS_PASS(nng_stream_listener_alloc(&l2, "tcp4://"));
	NUTS_PASS(nng_stream_listener_set_int(l2, NNG_OPT_LISTEN_FD, fd));
	nng_stream_dialer_dial(d, aio2);
	nng_stream_listener_accept(l2, aio1);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	c1 = nng_aio_get_output(aio1, 0);
	c2 = nng_aio_get_output(aio2, 0);

	char    buf1[4];
	char    buf2[4];
	nng_iov iov1;
	nng_iov iov2;

	iov1.iov_buf = buf1;
	iov1.iov_len = sizeof(buf1);

	iov2.iov_buf = buf2;
	iov2.iov_len = sizeof(buf2);

	nng_aio_set_iov(aio1, 1, &iov1);
	nng_aio_set_iov(aio2, 1, &iov2);

	snprintf(buf1, sizeof(buf1), "abc");

	nng_stream_send(c1, aio1);
	nng_stream_recv(c2, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_MATCH(buf1, buf2);

	nng_stream_listener_free(l1);
	nng_stream_listener_free(l2);
	nng_stream_dialer_free(d);
	nng_stream_free(c1);
	nng_stream_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
#elif defined(NNG_PLATFORM_WINDOWS)
	// Windows requires that we not have created an I/O completion port yet
	// on the incoming FD.
	nng_stream_listener *l2;
	SOCKET               s;
	char                *addr;
	int                  port;
	nng_aio             *aio1;
	nng_aio             *aio2;
	nng_stream_dialer   *d;
	nng_stream          *c1, *c2;
	char                 url[32];
	SOCKADDR_IN          sin;

	NUTS_ADDR_ZERO(addr, "tcp4");
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	nng_aio_set_timeout(aio1, 20000);
	nng_aio_set_timeout(aio2, 20000);

	s                   = socket(AF_INET, SOCK_STREAM, 0);
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port        = 0;
	int len             = sizeof(sin);
	NUTS_ASSERT(bind(s, (SOCKADDR *) &sin, sizeof(sin)) == 0);
	NUTS_ASSERT(getsockname(s, (SOCKADDR *) &sin, &len) == 0);
	port = ntohs(sin.sin_port);
	NUTS_ASSERT(listen(s, SOMAXCONN) == 0);

	NUTS_PASS(nng_stream_listener_alloc(&l2, "tcp4://"));
	NUTS_PASS(nng_stream_listener_set_int(l2, NNG_OPT_LISTEN_FD, (int) s));
	snprintf(url, sizeof(url), "tcp://127.0.0.1:%u", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, url));
	nng_stream_listener_accept(l2, aio1);

	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	NUTS_PASS(nng_aio_result(aio1));

	nng_aio_wait(aio2);
	NUTS_PASS(nng_aio_result(aio2));

	c1 = nng_aio_get_output(aio1, 0);
	c2 = nng_aio_get_output(aio2, 0);

	char    buf1[4];
	char    buf2[4];
	nng_iov iov1;
	nng_iov iov2;

	iov1.iov_buf = buf1;
	iov1.iov_len = sizeof(buf1);

	iov2.iov_buf = buf2;
	iov2.iov_len = sizeof(buf2);

	nng_aio_set_iov(aio1, 1, &iov1);
	nng_aio_set_iov(aio2, 1, &iov2);

	snprintf(buf1, sizeof(buf1), "abc");

	nng_stream_send(c1, aio1);
	nng_stream_recv(c2, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_MATCH(buf1, buf2);

	nng_stream_listener_free(l2);
	nng_stream_dialer_free(d);
	nng_stream_free(c1);
	nng_stream_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
#else
	NUTS_SKIP("Not Windows or POSIX");
#endif
}

void
test_tcp_listen_activation_busy(void)
{
	nng_stream_listener *l1;
	int                  fd;

	NUTS_PASS(nng_stream_listener_alloc(&l1, "tcp://"));
	NUTS_PASS(nng_stream_listener_listen(l1));
	NUTS_PASS(nng_stream_listener_get_int(l1, NNG_OPT_LISTEN_FD, &fd));
	NUTS_FAIL(
	    nng_stream_listener_set_int(l1, NNG_OPT_LISTEN_FD, fd), NNG_EBUSY);
	nng_stream_listener_free(l1);
}

void
test_tcp_listen_activation_closed(void)
{
	nng_stream_listener *l1;
	nng_stream_listener *l2;
	int                  fd;

	NUTS_PASS(nng_stream_listener_alloc(&l1, "tcp://"));
	NUTS_PASS(nng_stream_listener_alloc(&l2, "tcp://"));
	NUTS_PASS(nng_stream_listener_listen(l2));
	NUTS_PASS(nng_stream_listener_get_int(l2, NNG_OPT_LISTEN_FD, &fd));
	nng_stream_listener_close(l1);
	NUTS_FAIL(nng_stream_listener_set_int(l1, NNG_OPT_LISTEN_FD, fd),
	    NNG_ECLOSED);
	nng_stream_listener_free(l1);
	nng_stream_listener_free(l2);
}

void
test_tcp_listen_activation_wrong_family(void)
{

#if !defined(NNG_PLATFORM_POSIX) || !defined(NNG_TRANSPORT_IPC)
	NUTS_SKIP("Not posix or no IPC");
#else
	nng_stream_listener *l1;
	nng_stream_listener *l2;
	int                  fd;
	char                *addr;

	NUTS_ADDR(addr, "ipc");
	NUTS_PASS(nng_stream_listener_alloc(&l1, "tcp://"));
	NUTS_PASS(nng_stream_listener_alloc(&l2, addr));
	NUTS_PASS(nng_stream_listener_listen(l2));
	NUTS_PASS(nng_stream_listener_get_int(l2, NNG_OPT_LISTEN_FD, &fd));
	NUTS_FAIL(nng_stream_listener_set_int(l1, NNG_OPT_LISTEN_FD, fd),
	    NNG_EADDRINVAL);
	nng_stream_listener_free(l1);
	nng_stream_listener_free(l2);
#endif
}

void
test_tcp_listen_activation_bogus_fd(void)
{
	nng_stream_listener *l1;

	NUTS_PASS(nng_stream_listener_alloc(&l1, "tcp://"));
	NUTS_FAIL(nng_stream_listener_set_int(l1, NNG_OPT_LISTEN_FD, 12345),
	    NNG_ECLOSED);
	nng_stream_listener_free(l1);
}

void
test_tcp_listen_activation_bad_arg(void)
{
	nng_stream_listener *l1;

	NUTS_PASS(nng_stream_listener_alloc(&l1, "tcp://"));
	NUTS_FAIL(nng_stream_listener_set_bool(l1, NNG_OPT_LISTEN_FD, false),
	    NNG_EBADTYPE);
	nng_stream_listener_free(l1);
}

void
test_tcp_dialer_loc_addr(void)
{
	nng_stream_dialer *d;
	nng_sockaddr       sa;
	NUTS_PASS(nng_stream_dialer_alloc(&d, "tcp://127.0.0.1:80"));
	NUTS_PASS(nng_stream_dialer_get_addr(d, NNG_OPT_LOCADDR, &sa));
	NUTS_TRUE(sa.s_family == NNG_AF_UNSPEC);

	// cannot set a local port
	sa.s_in.sa_family = NNG_AF_INET;
	sa.s_in.sa_port   = 8080;
	NUTS_FAIL(nng_stream_dialer_set_addr(d, NNG_OPT_LOCADDR, &sa),
	    NNG_EADDRINVAL);

#ifdef NNG_HAVE_INET6
	// cannot set a local port
	sa.s_in6.sa_family = NNG_AF_INET6;
	sa.s_in6.sa_port   = 8080;
	NUTS_FAIL(nng_stream_dialer_set_addr(d, NNG_OPT_LOCADDR, &sa),
	    NNG_EADDRINVAL);
#endif

	// cannot set it to a bogus family
	sa.s_inproc.sa_family = NNG_AF_INPROC;
	snprintf(sa.s_inproc.sa_name, sizeof(sa.s_inproc.sa_name), "junk");
	NUTS_FAIL(nng_stream_dialer_set_addr(d, NNG_OPT_LOCADDR, &sa),
	    NNG_EADDRINVAL);

	// bad type test
	NUTS_FAIL(
	    nng_stream_dialer_set_int(d, NNG_OPT_LOCADDR, 42), NNG_EBADTYPE);

	// but we can set it to a legal value
	sa.s_in.sa_family = NNG_AF_INET;
	sa.s_in.sa_port   = 0;
	sa.s_in.sa_addr   = nuts_be32(0x7F000001);
	NUTS_PASS(nng_stream_dialer_set_addr(d, NNG_OPT_LOCADDR, &sa));

	nng_stream_dialer_free(d);
}

NUTS_TESTS = {
	{ "tcp stream", test_tcp_stream },
	{ "tcp listen accept cancel", test_tcp_listen_accept_cancel },
	{ "tcp listen port zero not bound",
	    test_tcp_listen_port_zero_not_bound },
	{ "tcp listen empty address", test_tcp_listen_empty_address },
	{ "tcp socket activation", test_tcp_listen_activation },
	{ "tcp socket activation busy", test_tcp_listen_activation_busy },
	{ "tcp socket activation closed", test_tcp_listen_activation_closed },
	{ "tcp socket activation wrong family",
	    test_tcp_listen_activation_wrong_family },
	{ "tcp socket activation bogus fd",
	    test_tcp_listen_activation_bogus_fd },
	{ "tcp socket activation bad arg",
	    test_tcp_listen_activation_bad_arg },
	{ "tcp dialer local address", test_tcp_dialer_loc_addr },
	{ NULL, NULL },
};
