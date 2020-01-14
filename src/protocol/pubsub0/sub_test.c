//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/pubsub0/sub.h>

#include <acutest.h>
#include <testutil.h>

#ifndef NNI_PROTO
#define NNI_PROTO(x, y) (((x) << 4u) | (y))
#endif

static void
test_sub_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	TEST_NNG_PASS(nng_sub0_open(&s));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PROTO, &p));
	TEST_CHECK(p == NNI_PROTO(2u, 1u)); // 33
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PEER, &p));
	TEST_CHECK(p == NNI_PROTO(2u, 0u)); // 32
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PROTONAME, &n));
	TEST_CHECK(strcmp(n, "sub") == 0);
	nng_strfree(n);
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PEERNAME, &n));
	TEST_CHECK(strcmp(n, "pub") == 0);
	nng_strfree(n);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_sub_cannot_send(void)
{
	nng_socket sub;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_FAIL(nng_send(sub, "", 0, 0), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_sub_context_cannot_send(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_msg *  m;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_ctx_open(&ctx, sub));
	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_msg(aio, m);
	nng_aio_set_timeout(aio, 1000);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	TEST_NNG_PASS(nng_close(sub));
	nng_aio_free(aio);
	nng_msg_free(m);
}

static void
test_sub_not_writeable(void)
{
	int        fd;
	nng_socket sub;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_FAIL(nng_getopt_int(sub, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_sub_poll_readable(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_SUBSCRIBE, "a", 1));
	TEST_NNG_PASS(nng_setopt_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_getopt_int(sub, NNG_OPT_RECVFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not readable if not connected!
	TEST_CHECK(testutil_pollfd(fd) == false);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(pub, sub));
	TEST_CHECK(testutil_pollfd(fd) == false);

	// If we send a message we didn't subscribe to, that doesn't matter.
	TEST_NNG_SEND_STR(pub, "def");
	testutil_sleep(100);
	TEST_CHECK(testutil_pollfd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	TEST_NNG_SEND_STR(pub, "abc");
	testutil_sleep(100);
	TEST_CHECK(testutil_pollfd(fd) == true);

	// and receiving makes it no longer ready
	TEST_NNG_RECV_STR(sub, "abc");
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(nng_close(pub));
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_sub_recv_late(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;
	nng_aio *  aio;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_SUBSCRIBE, "", 0));
	TEST_NNG_PASS(nng_setopt_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_getopt_int(sub, NNG_OPT_RECVFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not readable if not connected!
	TEST_CHECK(testutil_pollfd(fd) == false);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(pub, sub));
	TEST_CHECK(testutil_pollfd(fd) == false);

	nng_recv_aio(sub, aio);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	TEST_NNG_SEND_STR(pub, "abc");
	testutil_sleep(200);

	nng_aio_wait(aio);
	TEST_NNG_PASS(nng_aio_result(aio));
	msg = nng_aio_get_msg(aio);
	nng_aio_set_msg(aio, NULL);
	TEST_CHECK(nng_msg_len(msg) == 4);
	TEST_CHECK(strcmp(nng_msg_body(msg), "abc") == 0);

	nng_msg_free(msg);
	nng_aio_free(aio);

	TEST_NNG_PASS(nng_close(pub));
	TEST_NNG_PASS(nng_close(sub));
}

void
test_sub_context_no_poll(void)
{
	int        fd;
	nng_socket sub;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_ctx_open(&ctx, sub));
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	TEST_NNG_PASS(nng_close(sub));
}

void
test_sub_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_sub0_open(&s1));
	TEST_NNG_PASS(nng_sub0_open(&s2));

	TEST_NNG_PASS(nng_listen(s1, addr, NULL, 0));
	TEST_NNG_PASS(nng_dial(s2, addr, NULL, NNG_FLAG_NONBLOCK));

	testutil_sleep(100);
	TEST_NNG_PASS(nng_stats_get(&stats));

	TEST_CHECK(stats != NULL);
	TEST_CHECK((reject = nng_stat_find_socket(stats, s1)) != NULL);
	TEST_CHECK((reject = nng_stat_find(reject, "reject")) != NULL);

	TEST_CHECK(nng_stat_type(reject) == NNG_STAT_COUNTER);
	TEST_CHECK(nng_stat_value(reject) > 0);

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(s2));
	nng_stats_free(stats);
}

static void
test_sub_recv_ctx_closed(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;
	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_ctx_open(&ctx, sub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_ctx_close(ctx);
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_sub_ctx_recv_aio_stopped(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(nng_ctx_open(&ctx, sub));

	nng_aio_stop(aio);
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	TEST_NNG_PASS(nng_close(sub));
	nng_aio_free(aio);
}

static void
test_sub_close_context_recv(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_ctx_open(&ctx, sub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, 1000);
	nng_ctx_recv(ctx, aio);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECLOSED);

	TEST_NNG_PASS(nng_close(sub));
	nng_aio_free(aio);
}

static void
test_sub_ctx_recv_nonblock(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_ctx_open(&ctx, sub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(sub));
	nng_aio_free(aio);
}

static void
test_sub_ctx_recv_cancel(void)
{
	nng_socket sub;
	nng_ctx    ctx;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_ctx_open(&ctx, sub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 1000);
	nng_ctx_recv(ctx, aio);
	nng_aio_abort(aio, NNG_ECANCELED);

	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	TEST_NNG_PASS(nng_close(sub));
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

	TEST_NNG_PASS(nng_sub0_open(&sub));

	TEST_NNG_PASS(nng_setopt_int(sub, opt, 1));
	TEST_NNG_FAIL(nng_setopt_int(sub, opt, 0), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(sub, opt, -1), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(sub, opt, 1000000), NNG_EINVAL);
	TEST_NNG_PASS(nng_setopt_int(sub, opt, 3));
	TEST_NNG_PASS(nng_getopt_int(sub, opt, &v));
	TEST_CHECK(v == 3);
	v  = 0;
	sz = sizeof(v);
	TEST_NNG_PASS(nng_getopt(sub, opt, &v, &sz));
	TEST_CHECK(v == 3);
	TEST_CHECK(sz == sizeof(v));

	TEST_NNG_FAIL(nng_setopt(sub, opt, "", 1), NNG_EINVAL);
	sz = 1;
	TEST_NNG_FAIL(nng_getopt(sub, opt, &v, &sz), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_bool(sub, opt, true), NNG_EBADTYPE);
	TEST_NNG_FAIL(nng_getopt_bool(sub, opt, &b), NNG_EBADTYPE);

	TEST_NNG_PASS(nng_close(sub));
}

static void
test_sub_subscribe_option(void)
{
	nng_socket  sub;
	size_t      sz;
	int         v;
	const char *opt = NNG_OPT_SUB_SUBSCRIBE;

	TEST_NNG_PASS(nng_sub0_open(&sub));

	TEST_NNG_PASS(nng_setopt(sub, opt, "abc", 3));
	TEST_NNG_PASS(nng_setopt(sub, opt, "abc", 3)); // duplicate
	TEST_NNG_PASS(nng_setopt_bool(sub, opt, false));
	TEST_NNG_PASS(nng_setopt_int(sub, opt, 32));
	sz = sizeof(v);
	TEST_NNG_FAIL(nng_getopt(sub, opt, &v, &sz), NNG_EWRITEONLY);

	TEST_NNG_PASS(nng_close(sub));
}

static void
test_sub_unsubscribe_option(void)
{
	nng_socket  sub;
	size_t      sz;
	int         v;
	const char *opt1 = NNG_OPT_SUB_SUBSCRIBE;
	const char *opt2 = NNG_OPT_SUB_UNSUBSCRIBE;

	TEST_NNG_PASS(nng_sub0_open(&sub));

	TEST_NNG_PASS(nng_setopt(sub, opt1, "abc", 3));
	TEST_NNG_FAIL(nng_setopt(sub, opt2, "abcdef", 6), NNG_ENOENT);
	TEST_NNG_PASS(nng_setopt(sub, opt2, "abc", 3));
	TEST_NNG_FAIL(nng_setopt(sub, opt2, "abc", 3), NNG_ENOENT);
	TEST_NNG_PASS(nng_setopt_int(sub, opt1, 32));
	TEST_NNG_FAIL(nng_setopt_int(sub, opt2, 23), NNG_ENOENT);
	TEST_NNG_PASS(nng_setopt_int(sub, opt2, 32));
	sz = sizeof(v);
	TEST_NNG_FAIL(nng_getopt(sub, opt2, &v, &sz), NNG_EWRITEONLY);

	TEST_NNG_PASS(nng_close(sub));
}

static void
test_sub_prefer_new_option(void)
{
	nng_socket  sub;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_SUB_PREFNEW;

	TEST_NNG_PASS(nng_sub0_open(&sub));

	TEST_NNG_PASS(nng_setopt_bool(sub, opt, true));
	TEST_NNG_PASS(nng_setopt_bool(sub, opt, false));
	TEST_NNG_PASS(nng_getopt_bool(sub, opt, &b));
	TEST_CHECK(b == false);
	sz = sizeof(b);
	b  = true;
	TEST_NNG_PASS(nng_getopt(sub, opt, &b, &sz));
	TEST_CHECK(b == false);
	TEST_CHECK(sz == sizeof(bool));

	TEST_NNG_FAIL(nng_setopt(sub, opt, "abc", 3), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(sub, opt, 1), NNG_EBADTYPE);

	TEST_NNG_PASS(nng_close(sub));
}

void
test_sub_drop_new(void)
{
	nng_socket sub;
	nng_socket pub;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_setopt_int(sub, NNG_OPT_RECVBUF, 2));
	TEST_NNG_PASS(nng_setopt_bool(sub, NNG_OPT_SUB_PREFNEW, false));
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_SUBSCRIBE, NULL, 0));
	TEST_NNG_PASS(nng_setopt_ms(sub, NNG_OPT_RECVTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(testutil_marry(pub, sub));
	TEST_NNG_SEND_STR(pub, "one");
	TEST_NNG_SEND_STR(pub, "two");
	TEST_NNG_SEND_STR(pub, "three");
	testutil_sleep(100);
	TEST_NNG_RECV_STR(sub, "one");
	TEST_NNG_RECV_STR(sub, "two");
	TEST_NNG_FAIL(nng_recvmsg(sub, &msg, 0), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(pub));
	TEST_NNG_PASS(nng_close(sub));
}

void
test_sub_drop_old(void)
{
	nng_socket sub;
	nng_socket pub;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_setopt_int(sub, NNG_OPT_RECVBUF, 2));
	TEST_NNG_PASS(nng_setopt_bool(sub, NNG_OPT_SUB_PREFNEW, true));
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_SUBSCRIBE, NULL, 0));
	TEST_NNG_PASS(nng_setopt_ms(sub, NNG_OPT_RECVTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(testutil_marry(pub, sub));
	TEST_NNG_SEND_STR(pub, "one");
	TEST_NNG_SEND_STR(pub, "two");
	TEST_NNG_SEND_STR(pub, "three");
	testutil_sleep(100);
	TEST_NNG_RECV_STR(sub, "two");
	TEST_NNG_RECV_STR(sub, "three");
	TEST_NNG_FAIL(nng_recvmsg(sub, &msg, 0), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(pub));
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_sub_filter(void)
{
	nng_socket sub;
	nng_socket pub;
	char       buf[32];
	size_t     sz;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_setopt_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_int(sub, NNG_OPT_RECVBUF, 10));

	// Set up some default filters
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_SUBSCRIBE, "abc", 3));
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_SUBSCRIBE, "def", 3));
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_SUBSCRIBE, "ghi", 3));
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_SUBSCRIBE, "jkl", 3));

	TEST_NNG_PASS(testutil_marry(pub, sub));

	TEST_NNG_PASS(nng_send(pub, "def", 3, 0));
	TEST_NNG_PASS(nng_send(pub, "de", 2, 0)); // will not go through
	TEST_NNG_PASS(nng_send(pub, "abc123", 6, 0));
	TEST_NNG_PASS(nng_send(pub, "xzy", 3, 0));     // does not match
	TEST_NNG_PASS(nng_send(pub, "ghidrop", 7, 0)); // dropped by unsub
	TEST_NNG_PASS(nng_send(pub, "jklmno", 6, 0));

	testutil_sleep(100);
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_UNSUBSCRIBE, "ghi", 3));
	sz = sizeof(buf);
	TEST_NNG_PASS(nng_recv(sub, buf, &sz, 0));
	TEST_CHECK(sz == 3);
	TEST_CHECK(memcmp(buf, "def", 3) == 0);

	sz = sizeof(buf);
	TEST_NNG_PASS(nng_recv(sub, buf, &sz, 0));
	TEST_CHECK(sz == 6);
	TEST_CHECK(memcmp(buf, "abc123", 6) == 0);

	sz = sizeof(buf);
	TEST_NNG_PASS(nng_recv(sub, buf, &sz, 0));
	TEST_CHECK(sz == 6);
	TEST_CHECK(memcmp(buf, "jklmno", 6) == 0);

	TEST_NNG_PASS(nng_close(sub));
	TEST_NNG_PASS(nng_close(pub));
}

static void
test_sub_multi_context(void)
{
	nng_socket sub;
	nng_socket pub;
	nng_ctx    c1;
	nng_ctx    c2;
	nng_aio *  aio1;
	nng_aio *  aio2;
	nng_msg *  m;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	TEST_NNG_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	TEST_NNG_PASS(nng_ctx_open(&c1, sub));
	TEST_NNG_PASS(nng_ctx_open(&c2, sub));

	TEST_NNG_PASS(nng_ctx_setopt(c1, NNG_OPT_SUB_SUBSCRIBE, "one", 3));
	TEST_NNG_PASS(nng_ctx_setopt(c1, NNG_OPT_SUB_SUBSCRIBE, "all", 3));

	TEST_NNG_PASS(nng_ctx_setopt(c2, NNG_OPT_SUB_SUBSCRIBE, "two", 3));
	TEST_NNG_PASS(nng_ctx_setopt(c2, NNG_OPT_SUB_SUBSCRIBE, "all", 3));

	nng_aio_set_timeout(aio1, 100);
	nng_aio_set_timeout(aio2, 100);

	TEST_NNG_PASS(testutil_marry(pub, sub));

	TEST_NNG_SEND_STR(pub, "one for the money");
	TEST_NNG_SEND_STR(pub, "all dogs go to heaven");
	TEST_NNG_SEND_STR(pub, "nobody likes a snitch");
	TEST_NNG_SEND_STR(pub, "two for the show");

	nng_ctx_recv(c1, aio1);
	nng_aio_wait(aio1);
	TEST_NNG_PASS(nng_aio_result(aio1));
	m = nng_aio_get_msg(aio1);
	TEST_CHECK(strcmp(nng_msg_body(m), "one for the money") == 0);
	nng_msg_free(m);

	nng_ctx_recv(c1, aio1);
	nng_aio_wait(aio1);
	TEST_NNG_PASS(nng_aio_result(aio1));
	m = nng_aio_get_msg(aio1);
	TEST_CHECK(strcmp(nng_msg_body(m), "all dogs go to heaven") == 0);
	nng_msg_free(m);

	nng_ctx_recv(c2, aio1);
	nng_aio_wait(aio1);
	TEST_NNG_PASS(nng_aio_result(aio1));
	m = nng_aio_get_msg(aio1);
	TEST_CHECK(strcmp(nng_msg_body(m), "all dogs go to heaven") == 0);
	nng_msg_free(m);

	nng_ctx_recv(c2, aio1);
	nng_aio_wait(aio1);
	TEST_NNG_PASS(nng_aio_result(aio1));
	m = nng_aio_get_msg(aio1);
	TEST_CHECK(strcmp(nng_msg_body(m), "two for the show") == 0);
	nng_msg_free(m);

	nng_ctx_recv(c1, aio1);
	nng_ctx_recv(c2, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);
	TEST_NNG_FAIL(nng_aio_result(aio1), NNG_ETIMEDOUT);
	TEST_NNG_FAIL(nng_aio_result(aio2), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(sub));
	TEST_NNG_PASS(nng_close(pub));
	nng_aio_free(aio1);
	nng_aio_free(aio2);
}

static void
test_sub_cooked(void)
{
	nng_socket s;
	bool       b;

	TEST_NNG_PASS(nng_sub0_open(&s));
	TEST_NNG_PASS(nng_getopt_bool(s, NNG_OPT_RAW, &b));
	TEST_CHECK(!b);
	TEST_NNG_PASS(nng_close(s));
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
