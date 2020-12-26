//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

static void
test_pull_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	NUTS_PASS(nng_pull0_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NUTS_PROTO(5u, 1u)); // 81
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p));
	NUTS_TRUE(p == NUTS_PROTO(5u, 0u)); // 80
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n));
	NUTS_MATCH(n, "pull");
	nng_strfree(n);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n));
	NUTS_MATCH(n, "push");
	nng_strfree(n);
	NUTS_CLOSE(s);
}

static void
test_pull_cannot_send(void)
{
	nng_socket s;

	NUTS_PASS(nng_pull0_open(&s));
	NUTS_FAIL(nng_send(s, "", 0, 0), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_pull_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	NUTS_PASS(nng_pull0_open(&s));
	NUTS_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_pull_not_writeable(void)
{
	int        fd;
	nng_socket s;

	NUTS_PASS(nng_pull0_open(&s));
	NUTS_FAIL(nng_socket_get_int(s, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_pull_poll_readable(void)
{
	int        fd;
	nng_socket pull;
	nng_socket push;

	NUTS_PASS(nng_pull0_open(&pull));
	NUTS_PASS(nng_push0_open(&push));
	NUTS_PASS(nng_socket_set_ms(pull, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(push, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_get_int(pull, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(pull, push);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_SEND(push, "abc");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));

	// and receiving makes it no longer ready
	NUTS_RECV(pull, "abc");
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(pull);
	NUTS_CLOSE(push);
}

static void
test_pull_close_pending(void)
{
	int        fd;
	nng_socket pull;
	nng_socket push;
	nng_pipe   p1, p2;
	char *     addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_pull0_open(&pull));
	NUTS_PASS(nng_push0_open(&push));
	NUTS_PASS(nng_socket_get_int(pull, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);
	NUTS_MARRY_EX(pull, push, addr, &p1, &p2);

	// Send a message -- it's ready for reading.
	NUTS_SEND(push, "abc");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));

	// NB: We have to close the pipe instead of the socket.
	// This is because the socket won't notice the remote pipe
	// disconnect until we collect the message and start another
	// receive operation.
	nng_pipe_close(p1);
	nng_pipe_close(p2);

	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(pull);
	NUTS_CLOSE(push);
}

void
test_pull_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char *     addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_pull0_open(&s1));
	NUTS_PASS(nng_pull0_open(&s2));

	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	NUTS_PASS(nng_dial(s2, addr, NULL, NNG_FLAG_NONBLOCK));

	NUTS_SLEEP(100);
	NUTS_PASS(nng_stats_get(&stats));

	NUTS_TRUE(stats != NULL);
	NUTS_TRUE((reject = nng_stat_find_socket(stats, s1)) != NULL);
	NUTS_TRUE((reject = nng_stat_find(reject, "reject")) != NULL);

	NUTS_TRUE(nng_stat_type(reject) == NNG_STAT_COUNTER);
	NUTS_TRUE(nng_stat_value(reject) > 0);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	nng_stats_free(stats);
}

static void
test_pull_recv_aio_stopped(void)
{
	nng_socket s;
	nng_aio *  aio;

	NUTS_PASS(nng_pull0_open(&s));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_stop(aio);
	nng_recv_aio(s, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(s);
	nng_aio_free(aio);
}

static void
test_pull_close_recv(void)
{
	nng_socket s;
	nng_aio *  aio;

	NUTS_PASS(nng_pull0_open(&s));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, 1000);
	nng_recv_aio(s, aio);
	NUTS_PASS(nng_close(s));
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);

	nng_aio_free(aio);
}

static void
test_pull_recv_nonblock(void)
{
	nng_socket s;
	nng_aio *  aio;

	NUTS_PASS(nng_pull0_open(&s));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_recv_aio(s, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(s);
	nng_aio_free(aio);
}

static void
test_pull_recv_cancel(void)
{
	nng_socket s;
	nng_aio *  aio;

	NUTS_PASS(nng_pull0_open(&s));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 1000);
	nng_recv_aio(s, aio);
	nng_aio_abort(aio, NNG_ECANCELED);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(s);
	nng_aio_free(aio);
}

static void
test_pull_cooked(void)
{
	nng_socket s;
	bool       b;

	NUTS_PASS(nng_pull0_open(&s));
	NUTS_PASS(nng_socket_get_bool(s, NNG_OPT_RAW, &b));
	NUTS_TRUE(!b);
	NUTS_CLOSE(s);
}

TEST_LIST = {
	{ "pull identity", test_pull_identity },
	{ "pull cannot send", test_pull_cannot_send },
	{ "pull no context", test_pull_no_context },
	{ "pull not writeable", test_pull_not_writeable },
	{ "pull poll readable", test_pull_poll_readable },
	{ "pull close pending", test_pull_close_pending },
	{ "pull validate peer", test_pull_validate_peer },
	{ "pull recv aio stopped", test_pull_recv_aio_stopped },
	{ "pull close recv", test_pull_close_recv },
	{ "pull recv nonblock", test_pull_recv_nonblock },
	{ "pull recv cancel", test_pull_recv_cancel },
	{ "pull cooked", test_pull_cooked },
	{ NULL, NULL },
};
