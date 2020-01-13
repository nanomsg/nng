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
test_pub_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	TEST_NNG_PASS(nng_pub0_open(&s));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PROTO, &p));
	TEST_CHECK(p == NNI_PROTO(2u, 0u)); // 32
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PEER, &p));
	TEST_CHECK(p == NNI_PROTO(2u, 1u)); // 33
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PROTONAME, &n));
	TEST_CHECK(strcmp(n, "pub") == 0);
	nng_strfree(n);
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PEERNAME, &n));
	TEST_CHECK(strcmp(n, "sub") == 0);
	nng_strfree(n);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_pub_cannot_recv(void)
{
	nng_socket pub;

	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_FAIL(nng_recv(pub, "", 0, 0), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(pub));
}

static void
test_pub_no_context(void)
{
	nng_socket pub;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_FAIL(nng_ctx_open(&ctx, pub), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(pub));
}

static void
test_pub_not_readable(void)
{
	int        fd;
	nng_socket pub;

	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_FAIL(nng_getopt_int(pub, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(pub));
}

static void
test_pub_poll_writeable(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;

	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_getopt_int(pub, NNG_OPT_SENDFD, &fd));
	TEST_CHECK(fd >= 0);

	// Pub is *always* writeable
	TEST_CHECK(testutil_pollfd(fd) == true);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(pub, sub));
	TEST_CHECK(testutil_pollfd(fd) == true);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	TEST_NNG_SEND_STR(pub, "abc");
	TEST_CHECK(testutil_pollfd(fd) == true);

	TEST_NNG_PASS(nng_close(pub));
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_pub_send_no_pipes(void)
{
	nng_socket pub;

	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_SEND_STR(pub, "DROP1");
	TEST_NNG_SEND_STR(pub, "DROP2");
	TEST_NNG_PASS(nng_close(pub));
}

void
test_pub_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_pub0_open(&s1));
	TEST_NNG_PASS(nng_pub0_open(&s2));

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
test_pub_send_queued(void)
{
	nng_socket pub;
	nng_socket sub;

	// MB: What we really need is a mock so that we can send harder
	// than we receive -- we need a way to apply back-pressure for this
	// test to be really meaningful.
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_sub0_open(&sub));
	TEST_NNG_PASS(nng_setopt(sub, NNG_OPT_SUB_SUBSCRIBE, "", 0));
	TEST_NNG_PASS(nng_setopt_int(pub, NNG_OPT_SENDBUF, 10));
	TEST_NNG_PASS(nng_setopt_int(sub, NNG_OPT_RECVBUF, 10));
	TEST_NNG_PASS(nng_setopt_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(testutil_marry(pub, sub));
	TEST_NNG_SEND_STR(pub, "first");
	TEST_NNG_SEND_STR(pub, "second");
	TEST_NNG_SEND_STR(pub, "three musketeers");
	TEST_NNG_SEND_STR(pub, "four");
	testutil_sleep(50);
	TEST_NNG_RECV_STR(sub, "first");
	TEST_NNG_RECV_STR(sub, "second");
	TEST_NNG_RECV_STR(sub, "three musketeers");
	TEST_NNG_RECV_STR(sub, "four");

	TEST_NNG_PASS(nng_close(pub));
	TEST_NNG_PASS(nng_close(sub));
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
test_pub_send_buf_option(void)
{
	nng_socket  pub;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_SENDBUF;

	TEST_NNG_PASS(nng_pub0_open(&pub));

	TEST_NNG_PASS(nng_setopt_int(pub, opt, 1));
	TEST_NNG_FAIL(nng_setopt_int(pub, opt, 0), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(pub, opt, -1), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(pub, opt, 1000000), NNG_EINVAL);
	TEST_NNG_PASS(nng_setopt_int(pub, opt, 3));
	TEST_NNG_PASS(nng_getopt_int(pub, opt, &v));
	TEST_CHECK(v == 3);
	v  = 0;
	sz = sizeof(v);
	TEST_NNG_PASS(nng_getopt(pub, opt, &v, &sz));
	TEST_CHECK(v == 3);
	TEST_CHECK(sz == sizeof(v));

	TEST_NNG_FAIL(nng_setopt(pub, opt, "", 1), NNG_EINVAL);
	sz = 1;
	TEST_NNG_FAIL(nng_getopt(pub, opt, &v, &sz), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_bool(pub, opt, true), NNG_EBADTYPE);
	TEST_NNG_FAIL(nng_getopt_bool(pub, opt, &b), NNG_EBADTYPE);

	TEST_NNG_PASS(nng_close(pub));
}

static void
test_pub_cooked(void)
{
	nng_socket s;
	bool       b;

	TEST_NNG_PASS(nng_pub0_open(&s));
	TEST_NNG_PASS(nng_getopt_bool(s, NNG_OPT_RAW, &b));
	TEST_CHECK(!b);
	TEST_NNG_FAIL(nng_setopt_bool(s, NNG_OPT_RAW, true), NNG_EREADONLY);
	TEST_NNG_PASS(nng_close(s));

	// raw pub only differs in the option setting
	TEST_NNG_PASS(nng_pub0_open_raw(&s));
	TEST_NNG_PASS(nng_getopt_bool(s, NNG_OPT_RAW, &b));
	TEST_CHECK(b);
	TEST_NNG_PASS(nng_close(s));
}

TEST_LIST = {
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
