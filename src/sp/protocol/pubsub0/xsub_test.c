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
test_xsub_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	NUTS_PASS(nng_sub0_open_raw(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NUTS_PROTO(2u, 1u)); // 33
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p));
	NUTS_TRUE(p == NUTS_PROTO(2u, 0u)); // 32
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n));
	NUTS_MATCH(n, "sub");
	nng_strfree(n);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n));
	NUTS_MATCH(n, "pub");
	nng_strfree(n);
	NUTS_CLOSE(s);
}

static void
test_xsub_cannot_send(void)
{
	nng_socket sub;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_FAIL(nng_send(sub, "", 0, 0), NNG_ENOTSUP);
	NUTS_CLOSE(sub);
}

static void
test_xsub_not_writeable(void)
{
	int        fd;
	nng_socket sub;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_FAIL(nng_socket_get_int(sub, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	NUTS_CLOSE(sub);
}

static void
test_xsub_poll_readable(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_socket_set_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_get_int(sub, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(pub, sub);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_SEND(pub, "abc");
	NUTS_SLEEP(200);

	NUTS_TRUE(nuts_poll_fd(fd));

	// and receiving makes it no longer ready
	NUTS_RECV(sub, "abc");
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(pub);
	NUTS_CLOSE(sub);
}

static void
test_xsub_recv_late(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;
	nng_aio *  aio;
	nng_msg *  msg;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_socket_set_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_get_int(sub, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(pub, sub);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	nng_recv_aio(sub, aio);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_SEND(pub, "abc");
	NUTS_SLEEP(200);

	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	msg = nng_aio_get_msg(aio);
	nng_aio_set_msg(aio, NULL);
	NUTS_TRUE(nng_msg_len(msg) == 4);
	NUTS_TRUE(strcmp(nng_msg_body(msg), "abc") == 0);

	nng_msg_free(msg);
	nng_aio_free(aio);

	NUTS_CLOSE(pub);
	NUTS_CLOSE(sub);
}

void
test_xsub_no_context(void)
{
	nng_socket sub;
	nng_ctx    ctx;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_FAIL(nng_ctx_open(&ctx, sub), NNG_ENOTSUP);
	NUTS_CLOSE(sub);
}

void
test_xsub_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char *     addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_sub0_open_raw(&s1));
	NUTS_PASS(nng_sub0_open_raw(&s2));

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
test_xsub_recv_closed(void)
{
	nng_socket sub;
	nng_aio *  aio;
	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_CLOSE(sub);
	nng_recv_aio(sub, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
}

static void
test_xsub_close_recv(void)
{
	nng_socket sub;
	nng_aio *  aio;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, 1000);
	nng_recv_aio(sub, aio);
	NUTS_CLOSE(sub);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);

	nng_aio_free(aio);
}

static void
test_xsub_recv_nonblock(void)
{
	nng_socket sub;
	nng_aio *  aio;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_recv_aio(sub, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(sub);
	nng_aio_free(aio);
}

static void
test_xsub_recv_buf_option(void)
{
	nng_socket  sub;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_RECVBUF;

	NUTS_PASS(nng_sub0_open_raw(&sub));

	NUTS_PASS(nng_socket_set_int(sub, opt, 1));
	NUTS_FAIL(nng_socket_set_int(sub, opt, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(sub, opt, 1000000), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(sub, opt, 3));
	NUTS_PASS(nng_socket_get_int(sub, opt, &v));
	NUTS_TRUE(v == 3);
	v  = 0;
	sz = sizeof(v);
	NUTS_PASS(nng_socket_get(sub, opt, &v, &sz));
	NUTS_TRUE(v == 3);
	NUTS_TRUE(sz == sizeof(v));

	NUTS_FAIL(nng_socket_set(sub, opt, "", 1), NNG_EINVAL);
	sz = 1;
	NUTS_FAIL(nng_socket_get(sub, opt, &v, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(sub, opt, true), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(sub, opt, &b), NNG_EBADTYPE);

	NUTS_CLOSE(sub);
}

static void
test_xsub_subscribe_option(void)
{
	nng_socket  sub;
	const char *opt = NNG_OPT_SUB_SUBSCRIBE;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_FAIL(nng_socket_set(sub, opt, "abc", 3), NNG_ENOTSUP);
	NUTS_CLOSE(sub);
}

static void
test_xsub_unsubscribe_option(void)
{
	nng_socket  sub;
	const char *opt = NNG_OPT_SUB_UNSUBSCRIBE;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_FAIL(nng_socket_set(sub, opt, "abc", 3), NNG_ENOTSUP);
	NUTS_CLOSE(sub);
}

static void
test_xsub_raw(void)
{
	nng_socket s;
	bool       b;

	NUTS_PASS(nng_sub0_open_raw(&s));
	NUTS_PASS(nng_socket_get_bool(s, NNG_OPT_RAW, &b));
	NUTS_TRUE(b);
	NUTS_CLOSE(s);
}

static void
test_xsub_close_during_recv(void)
{
	nng_socket sub;
	nng_socket pub;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_socket_set_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(pub, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_int(sub, NNG_OPT_RECVBUF, 5));
	NUTS_PASS(nng_socket_set_int(pub, NNG_OPT_SENDBUF, 20));

	NUTS_MARRY(pub, sub);

	for (unsigned i = 0; i < 100; i++) {
		NUTS_PASS(nng_send(pub, "abc", 3, 0));
	}
	NUTS_CLOSE(pub);
	NUTS_CLOSE(sub);
}

static void
test_xsub_close_during_pipe_recv(void)
{
	nng_socket sub;
	nng_socket pub;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_socket_set_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(pub, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_int(sub, NNG_OPT_RECVBUF, 5));
	NUTS_PASS(nng_socket_set_int(pub, NNG_OPT_SENDBUF, 20));

	NUTS_MARRY(pub, sub);

	for (unsigned i = 0; i < 100; i++) {
		int rv;
		rv = nng_send(pub, "abc", 3, 0);
		if (rv == NNG_ETIMEDOUT) {
			break;
		}
		NUTS_SLEEP(1);
	}
	NUTS_CLOSE(sub);
}

static void
test_xsub_recv_aio_stopped(void)
{
	nng_socket sub;
	nng_aio *  aio;

	NUTS_PASS(nng_sub0_open_raw(&sub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_stop(aio);
	nng_recv_aio(sub, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(sub);
	nng_aio_free(aio);
}

TEST_LIST = {
	{ "xsub identity", test_xsub_identity },
	{ "xsub cannot send", test_xsub_cannot_send },
	{ "xsub not writeable", test_xsub_not_writeable },
	{ "xsub poll readable", test_xsub_poll_readable },
	{ "xsub validate peer", test_xsub_validate_peer },
	{ "xsub recv late", test_xsub_recv_late },
	{ "xsub recv closed", test_xsub_recv_closed },
	{ "xsub close recv", test_xsub_close_recv },
	{ "xsub recv nonblock", test_xsub_recv_nonblock },
	{ "xsub recv buf option", test_xsub_recv_buf_option },
	{ "xsub subscribe option", test_xsub_subscribe_option },
	{ "xsub unsubscribe option", test_xsub_unsubscribe_option },
	{ "xsub no context", test_xsub_no_context },
	{ "xsub raw", test_xsub_raw },
	{ "xsub recv aio stopped", test_xsub_recv_aio_stopped },
	{ "xsub close during recv ", test_xsub_close_during_recv },
	{ "xsub close during pipe recv", test_xsub_close_during_pipe_recv },
	{ NULL, NULL },
};
