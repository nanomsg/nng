//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>

#include <nuts.h>

void
test_ipc_stream(void)
{
	nng_stream_dialer   *d = NULL;
	nng_stream_listener *l = NULL;
	char                *url;
	nng_aio             *daio = NULL;
	nng_aio             *laio = NULL;
	nng_aio             *maio = NULL;
	nng_stream          *c1   = NULL;
	nng_stream          *c2   = NULL;
	nng_aio             *aio1;
	nng_aio             *aio2;
	nng_iov              iov;
	char                 buf1[5];
	char                 buf2[5];
	const nng_sockaddr  *sap;

	NUTS_ADDR(url, "ipc");
	NUTS_PASS(nng_aio_alloc(&daio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&laio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&maio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	NUTS_PASS(nng_stream_listener_alloc(&l, url));
	NUTS_PASS(nng_stream_listener_listen(l));

	NUTS_PASS(nng_stream_dialer_alloc(&d, url));
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

	sap = nng_stream_self_addr(c2);
	NUTS_TRUE(sap->s_ipc.sa_family == NNG_AF_IPC);
	NUTS_MATCH(sap->s_ipc.sa_path, url + strlen("ipc://"));

	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_aio_free(daio);
	nng_aio_free(laio);
	nng_aio_free(maio);

	nng_stream_listener_close(l);
	nng_stream_dialer_close(d);
	nng_stream_listener_stop(l);
	nng_stream_dialer_stop(d);
	nng_stream_listener_free(l);
	nng_stream_dialer_free(d);
	nng_stream_close(c1);
	nng_stream_free(c1);
	nng_stream_close(c2);
	nng_stream_free(c2);
}

void
test_ipc_no_connect(void)
{
#ifdef NNG_PLATFORM_POSIX
	nng_stream_dialer   *d = NULL;
	nng_stream_listener *l = NULL;
	char                *url;
	nng_aio             *daio = NULL;

	NUTS_ADDR(url, "ipc");
	NUTS_PASS(nng_aio_alloc(&daio, NULL, NULL));

	NUTS_PASS(nng_stream_listener_alloc(&l, url));
	NUTS_PASS(nng_stream_listener_listen(l));
	nng_aio_set_timeout(daio, 100);

	NUTS_PASS(nng_stream_dialer_alloc(&d, url));
	NUTS_PASS(nng_stream_dialer_set_bool(d, "test-no-connect", true));
	nng_stream_dialer_dial(d, daio);

	nng_aio_wait(daio);
	NUTS_FAIL(nng_aio_result(daio), NNG_ETIMEDOUT);

	nng_aio_free(daio);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
#else
	NUTS_SKIP("Not POSIX");
#endif
}

void
test_ipc_listen_activation(void)
{
#if defined(NNG_PLATFORM_POSIX)
	nng_stream_listener *l1;
	nng_stream_listener *l2;
	char                *addr;
	int                  fd;
	nng_aio             *aio1;
	nng_aio             *aio2;
	nng_stream_dialer   *d;
	nng_stream          *c1, *c2;

	NUTS_ADDR(addr, "ipc");
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	nng_aio_set_timeout(aio1, 20000);
	nng_aio_set_timeout(aio2, 20000);

	NUTS_PASS(nng_stream_listener_alloc(&l1, addr));
	NUTS_PASS(nng_stream_listener_listen(l1));

	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));

	NUTS_PASS(nng_stream_listener_get_int(l1, NNG_OPT_LISTEN_FD, &fd));
	fd = dup(fd);
	// dupe this because we need to separate the file descriptors to
	// prevent confusion when we clean up (only one FD can be registered at
	// a time!)
	NUTS_ASSERT(fd >= -1);
	NUTS_PASS(nng_stream_listener_alloc(&l2, addr));
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
#else
	NUTS_SKIP("Not POSIX");
#endif
}

void
test_ipc_listen_activation_busy(void)
{
#if defined(NNG_PLATFORM_POSIX)
	nng_stream_listener *l1;
	int                  fd;
	char                *addr;

	NUTS_ADDR(addr, "ipc");
	NUTS_PASS(nng_stream_listener_alloc(&l1, addr));
	NUTS_PASS(nng_stream_listener_listen(l1));
	NUTS_PASS(nng_stream_listener_get_int(l1, NNG_OPT_LISTEN_FD, &fd));
	NUTS_FAIL(
	    nng_stream_listener_set_int(l1, NNG_OPT_LISTEN_FD, fd), NNG_EBUSY);
	nng_stream_listener_free(l1);
#else
	NUTS_SKIP("Not POSIX");
#endif
}

void
test_ipc_listen_activation_closed(void)
{
#if defined(NNG_PLATFORM_POSIX)
	nng_stream_listener *l1;
	nng_stream_listener *l2;
	int                  fd;
	char                *addr;

	NUTS_ADDR(addr, "ipc");
	NUTS_PASS(nng_stream_listener_alloc(&l1, "ipc:///"));
	NUTS_PASS(nng_stream_listener_alloc(&l2, addr));
	NUTS_PASS(nng_stream_listener_listen(l2));
	NUTS_PASS(nng_stream_listener_get_int(l2, NNG_OPT_LISTEN_FD, &fd));
	nng_stream_listener_close(l1);
	NUTS_FAIL(nng_stream_listener_set_int(l1, NNG_OPT_LISTEN_FD, fd),
	    NNG_ECLOSED);
	nng_stream_listener_free(l1);
	nng_stream_listener_free(l2);
#else
	NUTS_SKIP("Not POSIX");
#endif
}

void
test_ipc_listen_activation_wrong_family(void)
{
#if !defined(NNG_PLATFORM_POSIX) || !defined(NNG_TRANSPORT_TCP)
	NUTS_SKIP("Not POSIX or no TCP");
#else
	nng_stream_listener *l1;
	nng_stream_listener *l2;
	int                  fd;
	char                *addr;

	NUTS_ADDR(addr, "tcp");
	NUTS_PASS(nng_stream_listener_alloc(&l1, "ipc:///"));
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
test_ipc_listen_activation_bogus_fd(void)
{
#if defined(NNG_PLATFORM_POSIX)
	nng_stream_listener *l1;

	NUTS_PASS(nng_stream_listener_alloc(&l1, "ipc:///"));
	NUTS_FAIL(nng_stream_listener_set_int(l1, NNG_OPT_LISTEN_FD, 12345),
	    NNG_ECLOSED);
	nng_stream_listener_free(l1);
#else
	NUTS_SKIP("Not POSIX");
#endif
}

void
test_ipc_listen_activation_bad_arg(void)
{
#if defined(NNG_PLATFORM_POSIX)
	nng_stream_listener *l1;

	NUTS_PASS(nng_stream_listener_alloc(&l1, "ipc:///"));
	NUTS_FAIL(nng_stream_listener_set_bool(l1, NNG_OPT_LISTEN_FD, false),
	    NNG_EBADTYPE);
	nng_stream_listener_free(l1);
#else
	NUTS_SKIP("Not POSIX");
#endif
}

NUTS_TESTS = {
	{ "ipc stream", test_ipc_stream },
	{ "ipc no connect", test_ipc_no_connect },
	{ "ipc socket activation", test_ipc_listen_activation },
	{ "ipc socket activation busy", test_ipc_listen_activation_busy },
	{ "ipc socket activation closed", test_ipc_listen_activation_closed },
	{ "ipc socket activation wrong family",
	    test_ipc_listen_activation_wrong_family },
	{ "ipc socket activation bogus fd",
	    test_ipc_listen_activation_bogus_fd },
	{ "ipc socket activation bad arg",
	    test_ipc_listen_activation_bad_arg },
	{ NULL, NULL },
};
