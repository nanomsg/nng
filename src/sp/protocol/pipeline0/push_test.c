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
test_push_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NUTS_PROTO(5u, 0u)); // 80
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p));
	NUTS_TRUE(p == NUTS_PROTO(5u, 1u)); // 81
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n));
	NUTS_MATCH(n, "push");
	nng_strfree(n);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n));
	NUTS_MATCH(n, "pull");
	nng_strfree(n);
	NUTS_CLOSE(s);
}

static void
test_push_cannot_recv(void)
{
	nng_socket s;
	nng_msg *  m = NULL;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_FAIL(nng_recvmsg(s, &m, 0), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_push_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_push_not_readable(void)
{
	int        fd;
	nng_socket s;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_FAIL(nng_socket_get_int(s, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_push_poll_writable(void)
{
	int        fd;
	nng_socket pull;
	nng_socket push;

	NUTS_PASS(nng_pull0_open(&pull));
	NUTS_PASS(nng_push0_open(&push));
	NUTS_PASS(nng_socket_set_ms(pull, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(push, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_get_int(push, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// This tests unbuffered sockets for now.
	// Note that for this we are using unbuffered inproc.
	// If using TCP or similar, then transport buffering will
	// break assumptions in this test.

	// Not writable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// After connect we can write.
	NUTS_MARRY(pull, push);
	NUTS_TRUE(nuts_poll_fd(fd) == true);

	// But once we send a message, it is not anymore.
	NUTS_SEND(push, "abc");
	// Have to send a second message, because the remote socket
	// will have consumed the first one.
	NUTS_SEND(push, "def");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// and receiving receiving the message makes it possible again.
	NUTS_RECV(pull, "abc");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));

	NUTS_CLOSE(pull);
	NUTS_CLOSE(push);
}

static void
test_push_poll_buffered(void)
{
	int        fd;
	nng_socket pull;
	nng_socket push;

	NUTS_PASS(nng_pull0_open(&pull));
	NUTS_PASS(nng_push0_open(&push));
	NUTS_PASS(nng_socket_set_ms(pull, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(push, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(push, NNG_OPT_SENDBUF, 2));
	NUTS_PASS(nng_socket_get_int(push, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// We can write two message while unbuffered.
	NUTS_TRUE(nuts_poll_fd(fd));
	NUTS_SEND(push, "abc");
	NUTS_TRUE(nuts_poll_fd(fd));
	NUTS_SEND(push, "def");
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// After connect we remote end will pick up one of them.
	// Also, the local pipe itself will pick up one.  So we
	// have two.
	NUTS_MARRY(pull, push);
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));
	NUTS_SEND(push, "ghi");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));
	NUTS_SEND(push, "jkl");
	// Now it should be full.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// and receiving receiving the message makes it possible again.
	NUTS_RECV(pull, "abc");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));
	NUTS_RECV(pull, "def");
	NUTS_RECV(pull, "ghi");
	NUTS_RECV(pull, "jkl");

	NUTS_CLOSE(pull);
	NUTS_CLOSE(push);
}

static void
test_push_poll_truncate(void)
{
	int        fd;
	nng_socket pull;
	nng_socket push;

	// This test starts with a buffer and then truncates it to see
	// that shortening the buffer has an impact.

	NUTS_PASS(nng_pull0_open(&pull));
	NUTS_PASS(nng_push0_open(&push));
	NUTS_PASS(nng_socket_set_ms(pull, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(push, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(push, NNG_OPT_SENDBUF, 3));
	NUTS_PASS(nng_socket_get_int(push, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// We can write two message while unbuffered.
	NUTS_TRUE(nuts_poll_fd(fd));
	NUTS_SEND(push, "abc");
	NUTS_TRUE(nuts_poll_fd(fd));
	NUTS_SEND(push, "def");
	NUTS_TRUE(nuts_poll_fd(fd));

	NUTS_PASS(nng_socket_set_int(push, NNG_OPT_SENDBUF, 1));
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_MARRY(pull, push);
	NUTS_RECV(pull, "abc");
	// def got dropped
	NUTS_SEND(push, "ghi");
	NUTS_RECV(pull, "ghi");

	NUTS_CLOSE(pull);
	NUTS_SLEEP(100);

	// We have a buffer of one.
	NUTS_SEND(push, "jkl");
	// Resize to 0 (unbuffered)
	NUTS_PASS(nng_socket_set_int(push, NNG_OPT_SENDBUF, 0));

	// reopen the pull socket and connect it
	NUTS_PASS(nng_pull0_open(&pull));
	NUTS_MARRY(push, pull);

	// jkl got dropped.
	NUTS_SEND(push, "mno");
	NUTS_RECV(pull, "mno");

	NUTS_CLOSE(pull);
	NUTS_CLOSE(push);
}

void
test_push_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char *     addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_push0_open(&s1));
	NUTS_PASS(nng_push0_open(&s2));

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
test_push_send_aio_stopped(void)
{
	nng_socket s;
	nng_aio *  aio;
	nng_msg *  m;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&m, 0));

	nng_aio_set_msg(aio, m);
	nng_aio_stop(aio);
	nng_send_aio(s, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(s);
	nng_aio_free(aio);
	nng_msg_free(m);
}

static void
test_push_close_send(void)
{
	nng_socket s;
	nng_aio *  aio;
	nng_msg *  m;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&m, 0));
	nng_aio_set_timeout(aio, 1000);
	nng_aio_set_msg(aio, m);
	nng_send_aio(s, aio);
	NUTS_PASS(nng_close(s));
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);

	nng_aio_free(aio);
	nng_msg_free(m);
}

static void
test_push_send_nonblock(void)
{
	nng_socket s;
	nng_aio *  aio;
	nng_msg *  m;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&m, 0));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_aio_set_msg(aio, m);
	nng_send_aio(s, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(s);
	nng_aio_free(aio);
	nng_msg_free(m);
}

static void
test_push_send_timeout(void)
{
	nng_socket s;
	nng_aio *  aio;
	nng_msg *  m;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&m, 0));

	nng_aio_set_timeout(aio, 10);
	nng_aio_set_msg(aio, m);
	nng_send_aio(s, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(s);
	nng_aio_free(aio);
	nng_msg_free(m);
}

static void
test_push_send_cancel(void)
{
	nng_socket s;
	nng_aio *  aio;
	nng_msg *  m;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&m, 0));

	nng_aio_set_timeout(aio, 1000);
	nng_aio_set_msg(aio, m);
	nng_send_aio(s, aio);
	nng_aio_abort(aio, NNG_ECANCELED);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(s);
	nng_aio_free(aio);
	nng_msg_free(m);
}

static void
test_push_send_late_unbuffered(void)
{
	nng_socket s;
	nng_socket pull;
	nng_aio *  aio;
	nng_msg *  m;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_pull0_open(&pull));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append(m, "123\0", 4));

	nng_aio_set_timeout(aio, 1000);
	nng_aio_set_msg(aio, m);
	nng_send_aio(s, aio);

	NUTS_MARRY(s, pull);

	NUTS_RECV(pull, "123");

	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_CLOSE(s);
	nng_aio_free(aio);
}


static void
test_push_send_late_buffered(void)
{
	nng_socket s;
	nng_socket pull;
	nng_aio *  aio;
	nng_msg *  m;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_pull0_open(&pull));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_socket_set_int(s, NNG_OPT_SENDBUF, 2));
	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append(m, "123\0", 4));

	nng_aio_set_timeout(aio, 1000);
	nng_aio_set_msg(aio, m);
	nng_send_aio(s, aio);

	NUTS_MARRY(s, pull);

	NUTS_RECV(pull, "123");

	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_CLOSE(s);
	nng_aio_free(aio);
}

static void
test_push_cooked(void)
{
	nng_socket s;
	bool       b;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_socket_get_bool(s, NNG_OPT_RAW, &b));
	NUTS_TRUE(!b);
	NUTS_CLOSE(s);
}

static void
test_push_load_balance_buffered(void)
{
	nng_socket s;
	nng_socket pull1;
	nng_socket pull2;
	nng_socket pull3;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_pull0_open(&pull1));
	NUTS_PASS(nng_pull0_open(&pull2));
	NUTS_PASS(nng_pull0_open(&pull3));
	NUTS_PASS(nng_socket_set_int(s, NNG_OPT_SENDBUF, 4));
	NUTS_MARRY(s, pull1);
	NUTS_MARRY(s, pull2);
	NUTS_MARRY(s, pull3);
	NUTS_SLEEP(100);
	NUTS_SEND(s, "one");
	NUTS_SEND(s, "two");
	NUTS_SEND(s, "three");
	NUTS_RECV(pull1, "one");
	NUTS_RECV(pull2, "two");
	NUTS_RECV(pull3, "three");
	NUTS_CLOSE(s);
	NUTS_CLOSE(pull1);
	NUTS_CLOSE(pull2);
	NUTS_CLOSE(pull3);
}

static void
test_push_load_balance_unbuffered(void)
{
	nng_socket s;
	nng_socket pull1;
	nng_socket pull2;
	nng_socket pull3;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_pull0_open(&pull1));
	NUTS_PASS(nng_pull0_open(&pull2));
	NUTS_PASS(nng_pull0_open(&pull3));
	NUTS_MARRY(s, pull1);
	NUTS_MARRY(s, pull2);
	NUTS_MARRY(s, pull3);
	NUTS_SLEEP(100);
	NUTS_SEND(s, "one");
	NUTS_SEND(s, "two");
	NUTS_SEND(s, "three");
	NUTS_RECV(pull1, "one");
	NUTS_RECV(pull2, "two");
	NUTS_RECV(pull3, "three");
	// Loop around is unpredictable somewhat, because the the
	// pull sockets can take different periods of time to return
	// back to readiness.
	NUTS_CLOSE(s);
	NUTS_CLOSE(pull1);
	NUTS_CLOSE(pull2);
	NUTS_CLOSE(pull3);
}

static void
test_push_send_buffer(void)
{
	nng_socket s;
	int        v;
	bool       b;
	size_t     sz;

	NUTS_PASS(nng_push0_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_SENDBUF, &v));
	NUTS_TRUE(v == 0);
	NUTS_FAIL(nng_socket_get_bool(s, NNG_OPT_SENDBUF, &b), NNG_EBADTYPE);
	sz = 1;
	NUTS_FAIL(nng_socket_get(s, NNG_OPT_SENDBUF, &b, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, NNG_OPT_SENDBUF, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, NNG_OPT_SENDBUF, 100000), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(s, NNG_OPT_SENDBUF, false), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_set(s, NNG_OPT_SENDBUF, &b, 1), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(s, NNG_OPT_SENDBUF, 100));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_SENDBUF, &v));
	NUTS_TRUE(v == 100);
	NUTS_CLOSE(s);
}

TEST_LIST = {
	{ "push identity", test_push_identity },
	{ "push cannot recv", test_push_cannot_recv },
	{ "push no context", test_push_no_context },
	{ "push not readable", test_push_not_readable },
	{ "push poll writable", test_push_poll_writable },
	{ "push poll buffered", test_push_poll_buffered },
	{ "push poll truncate", test_push_poll_truncate },
	{ "push validate peer", test_push_validate_peer },
	{ "push send aio stopped", test_push_send_aio_stopped },
	{ "push close send", test_push_close_send },
	{ "push send nonblock", test_push_send_nonblock },
	{ "push send timeout", test_push_send_timeout },
	{ "push send cancel", test_push_send_cancel },
	{ "push send late buffered", test_push_send_late_buffered },
	{ "push send late unbuffered", test_push_send_late_unbuffered },
	{ "push cooked", test_push_cooked },
	{ "push load balance buffered", test_push_load_balance_buffered },
	{ "push load balance unbuffered", test_push_load_balance_unbuffered },
	{ "push send buffer", test_push_send_buffer },
	{ NULL, NULL },
};
