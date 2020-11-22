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
test_pub_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	NUTS_PASS(nng_pub0_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NUTS_PROTO(2u, 0u)); // 32
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p));
	NUTS_TRUE(p == NUTS_PROTO(2u, 1u)); // 33
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n));
	NUTS_MATCH(n, "pub");
	nng_strfree(n);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n));
	NUTS_MATCH(n, "sub");
	nng_strfree(n);
	NUTS_CLOSE(s);
}

static void
test_pub_cannot_recv(void)
{
	nng_socket pub;

	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_FAIL(nng_recv(pub, "", 0, 0), NNG_ENOTSUP);
	NUTS_CLOSE(pub);
}

static void
test_pub_no_context(void)
{
	nng_socket pub;
	nng_ctx    ctx;

	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_FAIL(nng_ctx_open(&ctx, pub), NNG_ENOTSUP);
	NUTS_CLOSE(pub);
}

static void
test_pub_not_readable(void)
{
	int        fd;
	nng_socket pub;

	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_FAIL(nng_socket_get_int(pub, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	NUTS_CLOSE(pub);
}

static void
test_pub_poll_writeable(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_socket_get_int(pub, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Pub is *always* writeable
	NUTS_TRUE(nuts_poll_fd(fd));

	// Even after connect (no message yet)
	NUTS_MARRY(pub, sub);
	NUTS_TRUE(nuts_poll_fd(fd));

	// Even if we send messages.
	NUTS_SEND(pub, "abc");
	NUTS_TRUE(nuts_poll_fd(fd));

	NUTS_CLOSE(pub);
	NUTS_CLOSE(sub);
}

static void
test_pub_send_no_pipes(void)
{
	nng_socket pub;

	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_SEND(pub, "DROP1");
	NUTS_SEND(pub, "DROP2");
	NUTS_CLOSE(pub);
}

void
test_pub_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       *addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_pub0_open(&s1));
	NUTS_PASS(nng_pub0_open(&s2));

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
test_pub_send_queued(void)
{
	nng_socket pub;
	nng_socket sub;

	// MB: What we really need is a mock so that we can send harder
	// than we receive -- we need a way to apply back-pressure for this
	// test to be really meaningful.
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_SUBSCRIBE, "", 0));
	NUTS_PASS(nng_socket_set_int(pub, NNG_OPT_SENDBUF, 10));
	NUTS_PASS(nng_socket_set_int(sub, NNG_OPT_RECVBUF, 10));
	NUTS_PASS(nng_socket_set_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	NUTS_MARRY(pub, sub);
	NUTS_SEND(pub, "first");
	NUTS_SEND(pub, "second");
	NUTS_SEND(pub, "three musketeers");
	NUTS_SEND(pub, "four");
	NUTS_SLEEP(50);
	NUTS_RECV(sub, "first");
	NUTS_RECV(sub, "second");
	NUTS_RECV(sub, "three musketeers");
	NUTS_RECV(sub, "four");

	NUTS_CLOSE(pub);
	NUTS_CLOSE(sub);
}
static void
test_sub_recv_ctx_closed(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;
	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_ctx_open(&ctx, sub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_ctx_close(ctx);
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
	NUTS_CLOSE(sub);
}

static void
test_sub_ctx_recv_aio_stopped(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_ctx_open(&ctx, sub));

	nng_aio_stop(aio);
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_PASS(nng_ctx_close(ctx));
	NUTS_CLOSE(sub);
	nng_aio_free(aio);
}

static void
test_sub_close_context_recv(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_ctx_open(&ctx, sub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, 1000);
	nng_ctx_recv(ctx, aio);
	NUTS_PASS(nng_ctx_close(ctx));
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);

	NUTS_CLOSE(sub);
	nng_aio_free(aio);
}

static void
test_sub_ctx_recv_nonblock(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_ctx_open(&ctx, sub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(sub);
	nng_aio_free(aio);
}

static void
test_sub_ctx_recv_cancel(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_ctx_open(&ctx, sub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 1000);
	nng_ctx_recv(ctx, aio);
	nng_aio_abort(aio, NNG_ECANCELED);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(sub);
	nng_aio_free(aio);
}

static void
test_pub_send_buf_option(void)
{
	nng_socket  pub;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_SENDBUF;

	NUTS_PASS(nng_pub0_open(&pub));

	NUTS_PASS(nng_socket_set_int(pub, opt, 1));
	NUTS_FAIL(nng_socket_set_int(pub, opt, 0), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(pub, opt, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(pub, opt, 1000000), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(pub, opt, 3));
	NUTS_PASS(nng_socket_get_int(pub, opt, &v));
	NUTS_TRUE(v == 3);
	v  = 0;
	sz = sizeof(v);
	NUTS_PASS(nng_socket_get(pub, opt, &v, &sz));
	NUTS_TRUE(v == 3);
	NUTS_TRUE(sz == sizeof(v));

	NUTS_FAIL(nng_socket_set(pub, opt, "", 1), NNG_EINVAL);
	sz = 1;
	NUTS_FAIL(nng_socket_get(pub, opt, &v, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(pub, opt, true), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(pub, opt, &b), NNG_EBADTYPE);

	NUTS_CLOSE(pub);
}

static void
test_pub_cooked(void)
{
	nng_socket s;
	bool       b;

	NUTS_PASS(nng_pub0_open(&s));
	NUTS_PASS(nng_socket_get_bool(s, NNG_OPT_RAW, &b));
	NUTS_TRUE(!b);
	NUTS_FAIL(nng_socket_set_bool(s, NNG_OPT_RAW, true), NNG_EREADONLY);
	NUTS_PASS(nng_close(s));

	// raw pub only differs in the option setting
	NUTS_PASS(nng_pub0_open_raw(&s));
	NUTS_PASS(nng_socket_get_bool(s, NNG_OPT_RAW, &b));
	NUTS_TRUE(b);
	NUTS_CLOSE(s);
}

NUTS_TESTS = {
	{ "pub identity", test_pub_identity },
	{ "pub cannot recv", test_pub_cannot_recv },
	{ "put no context", test_pub_no_context },
	{ "pub not readable", test_pub_not_readable },
	{ "pub poll writeable", test_pub_poll_writeable },
	{ "pub validate peer", test_pub_validate_peer },
	{ "pub send queued", test_pub_send_queued },
	{ "pub send no pipes", test_pub_send_no_pipes },
	{ "sub recv ctx closed", test_sub_recv_ctx_closed },
	{ "sub recv aio ctx stopped", test_sub_ctx_recv_aio_stopped },
	{ "sub close context recv", test_sub_close_context_recv },
	{ "sub context recv nonblock", test_sub_ctx_recv_nonblock },
	{ "sub context recv cancel", test_sub_ctx_recv_cancel },
	{ "pub send buf option", test_pub_send_buf_option },
	{ "pub cooked", test_pub_cooked },
	{ NULL, NULL },
};
