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
test_xsub_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	TEST_NNG_PASS(nng_sub0_open_raw(&s));
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
test_xsub_cannot_send(void)
{
	nng_socket sub;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_FAIL(nng_send(sub, "", 0, 0), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_xsub_not_writeable(void)
{
	int        fd;
	nng_socket sub;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_FAIL(nng_getopt_int(sub, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_xsub_poll_readable(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_setopt_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(pub, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_getopt_int(sub, NNG_OPT_RECVFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not readable if not connected!
	TEST_CHECK(testutil_pollfd(fd) == false);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(pub, sub));
	TEST_CHECK(testutil_pollfd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	TEST_NNG_SEND_STR(pub, "abc");
	testutil_sleep(200);

	TEST_CHECK(testutil_pollfd(fd) == true);

	// and receiving makes it no longer ready
	TEST_NNG_RECV_STR(sub, "abc");
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(nng_close(pub));
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_xsub_recv_late(void)
{
	int        fd;
	nng_socket pub;
	nng_socket sub;
	nng_aio *  aio;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
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
test_xsub_no_context(void)
{
	nng_socket sub;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_FAIL(nng_ctx_open(&ctx, sub), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(sub));
}

void
test_xsub_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_sub0_open_raw(&s1));
	TEST_NNG_PASS(nng_sub0_open_raw(&s2));

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
test_xsub_recv_closed(void)
{
	nng_socket sub;
	nng_aio *  aio;
	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_close(sub);
	nng_recv_aio(sub, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
}

static void
test_xsub_close_recv(void)
{
	nng_socket sub;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, 1000);
	nng_recv_aio(sub, aio);
	TEST_NNG_PASS(nng_close(sub));
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECLOSED);

	nng_aio_free(aio);
}

static void
test_xsub_recv_nonblock(void)
{
	nng_socket sub;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_recv_aio(sub, aio);

	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(sub));
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

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));

	TEST_NNG_PASS(nng_setopt_int(sub, opt, 1));
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
test_xsub_subscribe_option(void)
{
	nng_socket  sub;
	const char *opt = NNG_OPT_SUB_SUBSCRIBE;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_FAIL(nng_setopt(sub, opt, "abc", 3), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_xsub_unsubscribe_option(void)
{
	nng_socket  sub;
	const char *opt = NNG_OPT_SUB_UNSUBSCRIBE;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_FAIL(nng_setopt(sub, opt, "abc", 3), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_xsub_raw(void)
{
	nng_socket s;
	bool       b;

	TEST_NNG_PASS(nng_sub0_open_raw(&s));
	TEST_NNG_PASS(nng_getopt_bool(s, NNG_OPT_RAW, &b));
	TEST_CHECK(b);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_xsub_close_during_recv(void)
{
	nng_socket sub;
	nng_socket pub;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_setopt_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(pub, NNG_OPT_SENDTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_int(sub, NNG_OPT_RECVBUF, 5));
	TEST_NNG_PASS(nng_setopt_int(pub, NNG_OPT_SENDBUF, 20));

	TEST_NNG_PASS(testutil_marry(pub, sub));

	for (unsigned i = 0; i < 100; i++) {
		TEST_NNG_PASS(nng_send(pub, "abc", 3, 0));
	}
	TEST_NNG_PASS(nng_close(pub));
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_xsub_close_during_pipe_recv(void)
{
	nng_socket sub;
	nng_socket pub;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_PASS(nng_pub0_open(&pub));
	TEST_NNG_PASS(nng_setopt_ms(sub, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(pub, NNG_OPT_SENDTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_int(sub, NNG_OPT_RECVBUF, 5));
	TEST_NNG_PASS(nng_setopt_int(pub, NNG_OPT_SENDBUF, 20));

	TEST_NNG_PASS(testutil_marry(pub, sub));

	for (unsigned i = 0; i < 100; i++) {
		int rv;
		rv = nng_send(pub, "abc", 3, 0);
		if (rv == NNG_ETIMEDOUT) {
			break;
		}
		testutil_sleep(1);
	}
	TEST_NNG_PASS(nng_close(sub));
}

static void
test_xsub_recv_aio_stopped(void)
{
	nng_socket sub;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_sub0_open_raw(&sub));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_stop(aio);
	nng_recv_aio(sub, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	TEST_NNG_PASS(nng_close(sub));
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
