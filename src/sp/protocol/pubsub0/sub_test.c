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
test_sub_identity(void)
{
	nng_socket s;
	int        p;
	char      *n;

	NUTS_PASS(nng_sub0_open(&s));
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
test_sub_cannot_send(void)
{
	nng_socket sub;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_FAIL(nng_send(sub, "", 0, 0), NNG_ENOTSUP);
	NUTS_CLOSE(sub);
}

static void
test_sub_context_cannot_send(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_msg   *m;
	nng_aio   *aio;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_ctx_open(&ctx, sub));
	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_msg(aio, m);
	nng_aio_set_timeout(aio, 1000);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ENOTSUP);
	NUTS_PASS(nng_ctx_close(ctx));
	NUTS_CLOSE(sub);
	nng_aio_free(aio);
	nng_msg_free(m);
}

static void
test_sub_not_writeable(void)
{
	int        fd;
	nng_socket sub;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_FAIL(nng_socket_get_int(sub, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	NUTS_CLOSE(sub);
}

static void
test_sub_poll_readable(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_SUBSCRIBE, "a", 1));
	NUTS_PASS(nng_socket_set_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_get_int(sub, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(pub, sub);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// If we send a message we didn't subscribe to, that doesn't matter.
	NUTS_SEND(pub, "def");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_SEND(pub, "abc");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));

	// and receiving makes it no longer ready
	NUTS_RECV(sub, "abc");
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(pub);
	NUTS_CLOSE(sub);
}

static void
test_sub_recv_late(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;
	nng_aio   *aio;
	nng_msg   *msg;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_SUBSCRIBE, "", 0));
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
	NUTS_MATCH(nng_msg_body(msg), "abc");

	nng_msg_free(msg);
	nng_aio_free(aio);

	NUTS_CLOSE(pub);
	NUTS_CLOSE(sub);
}

void
test_sub_context_no_poll(void)
{
	int        fd;
	nng_socket sub;
	nng_ctx    ctx;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_ctx_open(&ctx, sub));
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	NUTS_PASS(nng_ctx_close(ctx));
	NUTS_CLOSE(sub);
}

void
test_sub_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat  *stats;
	nng_stat  *reject;
	char      *addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_sub0_open(&s1));
	NUTS_PASS(nng_sub0_open(&s2));

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
test_sub_recv_ctx_closed(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio   *aio;
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
	nng_aio   *aio;

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
	nng_aio   *aio;

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
	nng_aio   *aio;

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
	nng_aio   *aio;

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
test_sub_recv_buf_option(void)
{
	nng_socket  sub;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_RECVBUF;

	NUTS_PASS(nng_sub0_open(&sub));

	NUTS_PASS(nng_socket_set_int(sub, opt, 1));
	NUTS_FAIL(nng_socket_set_int(sub, opt, 0), NNG_EINVAL);
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
test_sub_subscribe_option(void)
{
	nng_socket  sub;
	size_t      sz;
	int         v;
	const char *opt = NNG_OPT_SUB_SUBSCRIBE;

	NUTS_PASS(nng_sub0_open(&sub));

	NUTS_PASS(nng_socket_set(sub, opt, "abc", 3));
	NUTS_PASS(nng_socket_set(sub, opt, "abc", 3)); // duplicate
	NUTS_PASS(nng_socket_set_bool(sub, opt, false));
	NUTS_PASS(nng_socket_set_int(sub, opt, 32));
	sz = sizeof(v);
	NUTS_FAIL(nng_socket_get(sub, opt, &v, &sz), NNG_EWRITEONLY);
	NUTS_PASS(nng_sub0_socket_subscribe(sub, "abc", 3));
	NUTS_PASS(nng_sub0_socket_subscribe(sub, "abc", 3));
	NUTS_PASS(nng_sub0_socket_unsubscribe(sub, "abc", 3));

	NUTS_CLOSE(sub);
}

static void
test_sub_unsubscribe_option(void)
{
	nng_socket  sub;
	size_t      sz;
	int         v;
	const char *opt1 = NNG_OPT_SUB_SUBSCRIBE;
	const char *opt2 = NNG_OPT_SUB_UNSUBSCRIBE;

	NUTS_PASS(nng_sub0_open(&sub));

	NUTS_PASS(nng_socket_set(sub, opt1, "abc", 3));
	NUTS_FAIL(nng_socket_set(sub, opt2, "abc123", 6), NNG_ENOENT);
	NUTS_PASS(nng_socket_set(sub, opt2, "abc", 3));
	NUTS_FAIL(nng_socket_set(sub, opt2, "abc", 3), NNG_ENOENT);
	NUTS_PASS(nng_socket_set_int(sub, opt1, 32));
	NUTS_FAIL(nng_socket_set_int(sub, opt2, 23), NNG_ENOENT);
	NUTS_PASS(nng_socket_set_int(sub, opt2, 32));
	sz = sizeof(v);
	NUTS_FAIL(nng_socket_get(sub, opt2, &v, &sz), NNG_EWRITEONLY);

	NUTS_CLOSE(sub);
}

static void
test_sub_prefer_new_option(void)
{
	nng_socket  sub;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_SUB_PREFNEW;

	NUTS_PASS(nng_sub0_open(&sub));

	NUTS_PASS(nng_socket_set_bool(sub, opt, true));
	NUTS_PASS(nng_socket_set_bool(sub, opt, false));
	NUTS_PASS(nng_socket_get_bool(sub, opt, &b));
	NUTS_TRUE(b == false);
	sz = sizeof(b);
	b  = true;
	NUTS_PASS(nng_socket_get(sub, opt, &b, &sz));
	NUTS_TRUE(b == false);
	NUTS_TRUE(sz == sizeof(bool));

	NUTS_FAIL(nng_socket_set(sub, opt, "abc", 3), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(sub, opt, 1), NNG_EBADTYPE);

	NUTS_CLOSE(sub);
}

void
test_sub_drop_new(void)
{
	nng_socket sub;
	nng_socket pub;
	nng_msg   *msg;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_socket_set_int(sub, NNG_OPT_RECVBUF, 2));
	NUTS_PASS(nng_socket_set_bool(sub, NNG_OPT_SUB_PREFNEW, false));
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_SUBSCRIBE, NULL, 0));
	NUTS_PASS(nng_socket_set_ms(sub, NNG_OPT_RECVTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	NUTS_MARRY(pub, sub);
	NUTS_SEND(pub, "one");
	NUTS_SEND(pub, "two");
	NUTS_SEND(pub, "three");
	NUTS_SLEEP(100);
	NUTS_RECV(sub, "one");
	NUTS_RECV(sub, "two");
	NUTS_FAIL(nng_recvmsg(sub, &msg, 0), NNG_ETIMEDOUT);
	NUTS_CLOSE(pub);
	NUTS_CLOSE(sub);
}

void
test_sub_drop_old(void)
{
	nng_socket sub;
	nng_socket pub;
	nng_msg   *msg;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_socket_set_int(sub, NNG_OPT_RECVBUF, 2));
	NUTS_PASS(nng_socket_set_bool(sub, NNG_OPT_SUB_PREFNEW, true));
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_SUBSCRIBE, NULL, 0));
	NUTS_PASS(nng_socket_set_ms(sub, NNG_OPT_RECVTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	NUTS_MARRY(pub, sub);
	NUTS_SEND(pub, "one");
	NUTS_SEND(pub, "two");
	NUTS_SEND(pub, "three");
	NUTS_SLEEP(100);
	NUTS_RECV(sub, "two");
	NUTS_RECV(sub, "three");
	NUTS_FAIL(nng_recvmsg(sub, &msg, 0), NNG_ETIMEDOUT);
	NUTS_CLOSE(pub);
	NUTS_CLOSE(sub);
}

static void
test_sub_filter(void)
{
	nng_socket sub;
	nng_socket pub;
	char       buf[32];
	size_t     sz;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_socket_set_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(sub, NNG_OPT_RECVBUF, 10));

	// Set up some default filters
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_SUBSCRIBE, "abc", 3));
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_SUBSCRIBE, "def", 3));
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_SUBSCRIBE, "ghi", 3));
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_SUBSCRIBE, "jkl", 3));

	NUTS_MARRY(pub, sub);

	NUTS_PASS(nng_send(pub, "def", 3, 0));
	NUTS_PASS(nng_send(pub, "de", 2, 0)); // will not go through
	NUTS_PASS(nng_send(pub, "abc123", 6, 0));
	NUTS_PASS(nng_send(pub, "xzy", 3, 0));      // does not match
	NUTS_PASS(nng_send(pub, "ghi-drop", 7, 0)); // dropped by unsub
	NUTS_PASS(nng_send(pub, "jkl-mno", 6, 0));

	NUTS_SLEEP(100);
	NUTS_PASS(nng_socket_set(sub, NNG_OPT_SUB_UNSUBSCRIBE, "ghi", 3));
	sz = sizeof(buf);
	NUTS_PASS(nng_recv(sub, buf, &sz, 0));
	NUTS_TRUE(sz == 3);
	NUTS_TRUE(memcmp(buf, "def", 3) == 0);

	sz = sizeof(buf);
	NUTS_PASS(nng_recv(sub, buf, &sz, 0));
	NUTS_TRUE(sz == 6);
	NUTS_TRUE(memcmp(buf, "abc123", 6) == 0);

	sz = sizeof(buf);
	NUTS_PASS(nng_recv(sub, buf, &sz, 0));
	NUTS_TRUE(sz == 6);
	NUTS_TRUE(memcmp(buf, "jkl-mno", 6) == 0);

	NUTS_CLOSE(sub);
	NUTS_CLOSE(pub);
}

static void
test_sub_multi_context(void)
{
	nng_socket sub;
	nng_socket pub;
	nng_ctx    c1;
	nng_ctx    c2;
	nng_aio   *aio1;
	nng_aio   *aio2;
	nng_msg   *m;

	NUTS_PASS(nng_sub0_open(&sub));
	NUTS_PASS(nng_pub0_open(&pub));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	NUTS_PASS(nng_ctx_open(&c1, sub));
	NUTS_PASS(nng_ctx_open(&c2, sub));

	NUTS_PASS(nng_ctx_set(c1, NNG_OPT_SUB_SUBSCRIBE, "one", 3));
	NUTS_PASS(nng_ctx_set(c1, NNG_OPT_SUB_SUBSCRIBE, "all", 3));

	NUTS_PASS(nng_ctx_set(c2, NNG_OPT_SUB_SUBSCRIBE, "two", 3));
	NUTS_PASS(nng_sub0_ctx_subscribe(c2, "all", 3));
	NUTS_PASS(nng_sub0_ctx_subscribe(c2, "junk", 4));
	NUTS_PASS(nng_sub0_ctx_unsubscribe(c2, "junk", 4));

	nng_aio_set_timeout(aio1, 100);
	nng_aio_set_timeout(aio2, 100);

	NUTS_MARRY(pub, sub);

	NUTS_SEND(pub, "one for the money");
	NUTS_SEND(pub, "all dogs go to heaven");
	NUTS_SEND(pub, "nobody likes a snitch");
	NUTS_SEND(pub, "two for the show");

	nng_ctx_recv(c1, aio1);
	nng_aio_wait(aio1);
	NUTS_PASS(nng_aio_result(aio1));
	m = nng_aio_get_msg(aio1);
	NUTS_MATCH(nng_msg_body(m), "one for the money");
	nng_msg_free(m);

	nng_ctx_recv(c1, aio1);
	nng_aio_wait(aio1);
	NUTS_PASS(nng_aio_result(aio1));
	m = nng_aio_get_msg(aio1);
	NUTS_MATCH(nng_msg_body(m), "all dogs go to heaven");
	nng_msg_free(m);

	nng_ctx_recv(c2, aio1);
	nng_aio_wait(aio1);
	NUTS_PASS(nng_aio_result(aio1));
	m = nng_aio_get_msg(aio1);
	NUTS_MATCH(nng_msg_body(m), "all dogs go to heaven");
	nng_msg_free(m);

	nng_ctx_recv(c2, aio1);
	nng_aio_wait(aio1);
	NUTS_PASS(nng_aio_result(aio1));
	m = nng_aio_get_msg(aio1);
	NUTS_MATCH(nng_msg_body(m), "two for the show");
	nng_msg_free(m);

	nng_ctx_recv(c1, aio1);
	nng_ctx_recv(c2, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);
	NUTS_FAIL(nng_aio_result(aio1), NNG_ETIMEDOUT);
	NUTS_FAIL(nng_aio_result(aio2), NNG_ETIMEDOUT);
	NUTS_CLOSE(sub);
	NUTS_CLOSE(pub);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
}

static void
test_sub_cooked(void)
{
	nng_socket s;
	bool       b;

	NUTS_PASS(nng_sub0_open(&s));
	NUTS_PASS(nng_socket_get_bool(s, NNG_OPT_RAW, &b));
	NUTS_TRUE(!b);
	NUTS_CLOSE(s);
}

TEST_LIST = {
	{ "sub identity", test_sub_identity },
	{ "sub cannot send", test_sub_cannot_send },
	{ "sub context cannot send", test_sub_context_cannot_send },
	{ "sub not writeable", test_sub_not_writeable },
	{ "sub poll readable", test_sub_poll_readable },
	{ "sub context does not poll", test_sub_context_no_poll },
	{ "sub validate peer", test_sub_validate_peer },
	{ "sub recv late", test_sub_recv_late },
	{ "sub recv ctx closed", test_sub_recv_ctx_closed },
	{ "sub recv aio ctx stopped", test_sub_ctx_recv_aio_stopped },
	{ "sub close context recv", test_sub_close_context_recv },
	{ "sub context recv nonblock", test_sub_ctx_recv_nonblock },
	{ "sub context recv cancel", test_sub_ctx_recv_cancel },
	{ "sub recv buf option", test_sub_recv_buf_option },
	{ "sub subscribe option", test_sub_subscribe_option },
	{ "sub unsubscribe option", test_sub_unsubscribe_option },
	{ "sub prefer new option", test_sub_prefer_new_option },
	{ "sub drop new", test_sub_drop_new },
	{ "sub drop old", test_sub_drop_old },
	{ "sub filter", test_sub_filter },
	{ "sub multi context", test_sub_multi_context },
	{ "sub cooked", test_sub_cooked },
	{ NULL, NULL },
};
