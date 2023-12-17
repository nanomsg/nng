//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

static void
test_surv_identity(void)
{
	nng_socket s;
	int        p;
	char      *n;

	NUTS_PASS(nng_surveyor0_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NNG_SURVEYOR0_SELF);
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p));
	NUTS_TRUE(p == NNG_SURVEYOR0_PEER); // 49
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n));
	NUTS_MATCH(n, NNG_SURVEYOR0_SELF_NAME);
	nng_strfree(n);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n));
	NUTS_MATCH(n, NNG_SURVEYOR0_PEER_NAME);
	nng_strfree(n);
	NUTS_CLOSE(s);
}

static void
test_surv_ttl_option(void)
{
	nng_socket  surv;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	NUTS_PASS(nng_surveyor0_open(&surv));

	NUTS_PASS(nng_socket_set_int(surv, opt, 1));
	NUTS_FAIL(nng_socket_set_int(surv, opt, 0), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(surv, opt, -1), NNG_EINVAL);
	// This test will fail if the NNI_MAX_MAX_TTL is changed from the
	// builtin default of 15.
	NUTS_FAIL(nng_socket_set_int(surv, opt, 16), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(surv, opt, 256), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(surv, opt, 3));
	NUTS_PASS(nng_socket_get_int(surv, opt, &v));
	NUTS_TRUE(v == 3);
	v  = 0;
	sz = sizeof(v);
	NUTS_PASS(nng_socket_get(surv, opt, &v, &sz));
	NUTS_TRUE(v == 3);
	NUTS_TRUE(sz == sizeof(v));

	NUTS_FAIL(nng_socket_set(surv, opt, "", 1), NNG_EINVAL);
	sz = 1;
	NUTS_FAIL(nng_socket_get(surv, opt, &v, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(surv, opt, true), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(surv, opt, &b), NNG_EBADTYPE);

	NUTS_CLOSE(surv);
}

static void
test_surv_survey_time_option(void)
{
	nng_socket   surv;
	nng_duration d;
	bool         b;
	size_t       sz  = sizeof(b);
	const char  *opt = NNG_OPT_SURVEYOR_SURVEYTIME;

	NUTS_PASS(nng_surveyor0_open(&surv));

	NUTS_PASS(nng_socket_set_ms(surv, opt, 10));
	NUTS_FAIL(nng_socket_set(surv, opt, "", 1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_get(surv, opt, &b, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(surv, opt, true), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(surv, opt, &b), NNG_EBADTYPE);

	NUTS_PASS(nng_socket_get_ms(surv, opt, &d));
	NUTS_TRUE(d == 10);
	NUTS_CLOSE(surv);
}

void
test_surv_recv_bad_state(void)
{
	nng_socket surv;
	nng_msg   *msg = NULL;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_FAIL(nng_recvmsg(surv, &msg, 0), NNG_ESTATE);
	NUTS_TRUE(msg == NULL);
	NUTS_CLOSE(surv);
}

static void
test_surv_recv_garbage(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg   *m;
	uint32_t   surv_id;

	NUTS_PASS(nng_respondent0_open_raw(&resp));
	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(surv, resp);

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_sendmsg(surv, m, 0));

	NUTS_PASS(nng_recvmsg(resp, &m, 0));

	// The message will have a header that contains the 32-bit pipe ID,
	// followed by the 32-bit request ID.  We will discard the request
	// ID before sending it out.
	NUTS_TRUE(nng_msg_header_len(m) == 8);
	NUTS_PASS(nng_msg_header_chop_u32(m, &surv_id));

	NUTS_PASS(nng_sendmsg(resp, m, 0));
	NUTS_FAIL(nng_recvmsg(surv, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

#define SECOND 1000

void
test_surv_resp_exchange(void)
{
	nng_socket surv;
	nng_socket resp;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));

	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, SECOND));

	NUTS_MARRY(resp, surv);

	NUTS_SEND(surv, "ping");
	NUTS_RECV(resp, "ping");
	NUTS_SEND(resp, "pong");
	NUTS_RECV(surv, "pong");

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

void
test_surv_cancel(void)
{
	nng_socket surv;
	nng_socket resp;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_surveyor0_open(&surv));

	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_SENDBUF, 16));

	NUTS_MARRY(resp, surv);

	// Send req #1 (abc).
	NUTS_SEND(surv, "abc");

	// Sleep a bit.  This is so that we ensure that our request gets
	// to the far side.  (If we cancel too fast, then our outgoing send
	// will be canceled before it gets to the peer.)
	NUTS_SLEEP(100);

	// Send the next request ("def").  Note that
	// the RESP side server will have already buffered the receive
	// request, and should simply be waiting for us to reply to abc.
	NUTS_SEND(surv, "def");

	// Receive the first request (should be abc) on the REP server.
	NUTS_RECV(resp, "abc");

	// RESP sends the reply to first command.  This will be discarded
	// by the SURV socket.
	NUTS_SEND(resp, "abc");

	// Now get the next command from the REP; should be "def".
	NUTS_RECV(resp, "def");

	// And send it back to REQ.
	NUTS_SEND(resp, "def");

	// Try a req command.  This should give back "def"
	NUTS_RECV(surv, "def");

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

void
test_surv_cancel_abort_recv(void)
{
	nng_aio     *aio;
	nng_duration time = SECOND * 10; // 10s (kind of never)
	nng_socket   surv;
	nng_socket   resp;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SURVEYOR_SURVEYTIME, time));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_SENDBUF, 16));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_RECVTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 5 * SECOND));

	NUTS_MARRY(resp, surv);

	// Send survey #1 (abc).
	NUTS_SEND(surv, "abc");

	// Wait for it to get ot the other side.
	NUTS_SLEEP(100);

	nng_aio_set_timeout(aio, 5 * SECOND);
	nng_recv_aio(surv, aio);

	// Give time for this recv to post properly.
	NUTS_SLEEP(100);

	// Send the next request ("def").  Note that
	// the respondent side server will have already buffered the receive
	// request, and should simply be waiting for us to reply to
	// abc.
	NUTS_SEND(surv, "def");

	// Our pending I/O should have been canceled.
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);

	// Receive the first request (should be abc) on the respondent.
	NUTS_RECV(resp, "abc");

	// Respondent sends the reply to first survey.  This will be
	// discarded by the SURV socket.
	NUTS_SEND(resp, "abc");

	// Now get the next survey from the RESP; should be "def".
	NUTS_RECV(resp, "def");

	// And send it back to REQ.
	NUTS_SEND(resp, "def");

	// Try a req command.  This should give back "def"
	NUTS_RECV(surv, "def");

	nng_aio_free(aio);
	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_surv_cancel_post_recv(void)
{
	nng_socket surv;
	nng_socket resp;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	NUTS_MARRY(surv, resp);

	NUTS_SEND(surv, "ONE");
	NUTS_RECV(resp, "ONE");
	NUTS_SEND(resp, "one");
	NUTS_SLEEP(100); // Make sure reply arrives!
	NUTS_SEND(surv, "TWO");
	NUTS_RECV(resp, "TWO");
	NUTS_SEND(resp, "two");
	NUTS_RECV(surv, "two");

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_surv_poll_writeable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_socket_get_int(surv, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Survey is broadcast, so we can always write.
	NUTS_TRUE(nuts_poll_fd(fd));

	NUTS_MARRY(surv, resp);

	// Now it's writable.
	NUTS_TRUE(nuts_poll_fd(fd));

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

void
test_surv_poll_readable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;
	nng_msg   *msg;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_socket_get_int(surv, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(surv, resp);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "xyz", 3));
	NUTS_PASS(nng_sendmsg(surv, msg, 0));
	NUTS_PASS(nng_recvmsg(resp, &msg, 0)); // recv on rep
	NUTS_PASS(nng_sendmsg(resp, msg, 0));  // echo it back
	NUTS_SLEEP(200); // give time for message to arrive

	NUTS_TRUE(nuts_poll_fd(fd) == true);

	// and receiving makes it no longer ready
	NUTS_PASS(nng_recvmsg(surv, &msg, 0));
	nng_msg_free(msg);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// TODO verify unsolicited response

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_surv_ctx_no_poll(void)
{
	int        fd;
	nng_socket surv;
	nng_ctx    ctx;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_ctx_open(&ctx, surv));
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	NUTS_PASS(nng_ctx_close(ctx));
	NUTS_CLOSE(surv);
}

static void
test_surv_ctx_recv_nonblock(void)
{
	nng_socket surv;
	nng_socket resp;
	nng_ctx    ctx;
	nng_aio   *aio;
	nng_msg   *msg;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_ctx_open(&ctx, surv));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_MARRY(surv, resp);

	nng_aio_set_msg(aio, msg);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
	nng_aio_free(aio);
}

static void
test_surv_ctx_send_recv_msg(void)
{
	nng_socket surv;
	nng_socket resp;
	nng_ctx    ctx1;
	nng_ctx    ctx2;
	nng_msg   *msg;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_ctx_open(&ctx1, surv));
	NUTS_PASS(nng_ctx_open(&ctx2, resp));
	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_MARRY(surv, resp);

	NUTS_PASS(nng_ctx_sendmsg(ctx1, msg, 0));
	NUTS_PASS(nng_ctx_recvmsg(ctx2, &msg, 0));
	nng_msg_free(msg);
	NUTS_PASS(nng_ctx_close(ctx1));
	NUTS_PASS(nng_ctx_close(ctx2));
	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_surv_ctx_send_nonblock(void)
{
	nng_socket surv;
	nng_ctx    ctx;
	nng_aio   *aio;
	nng_msg   *msg;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_ctx_open(&ctx, surv));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&msg, 0));

	nng_aio_set_msg(aio, msg);
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio)); // We never block
	NUTS_CLOSE(surv);
	nng_aio_free(aio);
}

static void
test_surv_send_best_effort(void)
{
	nng_socket surv;
	nng_socket resp;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_MARRY(surv, resp);

	for (int i = 0; i < 200; i++) {
		NUTS_SEND(surv, "junk");
	}

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_surv_survey_timeout(void)
{
	nng_socket surv;
	nng_socket resp;
	char       buf[16];
	size_t     sz;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SURVEYOR_SURVEYTIME, 50));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_RECVTIMEO, 100));

	NUTS_MARRY(surv, resp);

	NUTS_SEND(surv, "hello");
	NUTS_RECV(resp, "hello");

	sz = sizeof(buf);
	NUTS_FAIL(nng_recv(surv, buf, &sz, 0), NNG_ETIMEDOUT);
	NUTS_SEND(resp, "world");
	NUTS_FAIL(nng_recv(surv, buf, &sz, 0), NNG_ESTATE);

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_surv_ctx_recv_close_socket(void)
{
	nng_socket surv;
	nng_socket resp;
	nng_ctx    ctx;
	nng_aio   *aio;
	nng_msg   *m;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_ctx_open(&ctx, surv));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_MARRY(surv, resp);
	NUTS_PASS(nng_msg_alloc(&m, 0));
	nng_aio_set_msg(aio, m);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));

	nng_ctx_recv(ctx, aio);
	nng_close(surv);

	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
	NUTS_CLOSE(resp);
}

static void
test_surv_context_multi(void)
{
	nng_socket surv;
	nng_socket resp;
	nng_ctx    c[5];
	nng_aio   *aio;
	nng_msg   *m;
	int        cnt = sizeof(c) / sizeof(c[0]);

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_MARRY(surv, resp);
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SURVEYOR_SURVEYTIME, 200));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	for (int i = 0; i < cnt; i++) {
		NUTS_PASS(nng_ctx_open(&c[i], surv));
	}

	for (int i = 0; i < cnt; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 0));
		NUTS_PASS(nng_msg_append_u32(m, i));
		nng_aio_set_msg(aio, m);
		nng_ctx_send(c[i], aio);
		nng_aio_wait(aio);
		NUTS_PASS(nng_aio_result(aio));
	}

	for (int i = 0; i < cnt; i++) {
		NUTS_PASS(nng_recvmsg(resp, &m, 0));
		NUTS_PASS(nng_sendmsg(resp, m, 0));
	}

	for (int i = cnt - 1; i >= 0; i--) {
		uint32_t x;
		nng_ctx_recv(c[i], aio);
		nng_aio_wait(aio);
		NUTS_PASS(nng_aio_result(aio));
		m = nng_aio_get_msg(aio);
		TEST_ASSERT(m != NULL);
		NUTS_PASS(nng_msg_trim_u32(m, &x));
		NUTS_TRUE(x == (uint32_t) i);
		nng_msg_free(m);
	}

	for (int i = 0; i < cnt; i++) {
		nng_ctx_recv(c[i], aio);
		nng_aio_wait(aio);
		NUTS_TRUE(nng_aio_result(aio) != 0);
	}
	for (int i = 0; i < cnt; i++) {
		nng_ctx_close(c[i]);
	}
	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
	nng_aio_free(aio);
}

static void
test_surv_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat  *stats;
	nng_stat  *reject;
	char      *addr;

	NUTS_ADDR(addr, "inproc");
	NUTS_PASS(nng_surveyor0_open(&s1));
	NUTS_PASS(nng_surveyor0_open(&s2));

	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	NUTS_PASS(nng_dial(s2, addr, NULL, NNG_FLAG_NONBLOCK));

	NUTS_SLEEP(100);
	NUTS_PASS(nng_stats_get(&stats));

	NUTS_TRUE(stats != NULL);
	NUTS_TRUE((reject = nng_stat_find_socket(stats, s1)) != NULL);
	NUTS_TRUE((reject = nng_stat_find(reject, "reject")) != NULL);

	NUTS_TRUE(nng_stat_type(reject) == NNG_STAT_COUNTER);
	NUTS_TRUE(nng_stat_value(reject) > 0);

	NUTS_PASS(nng_close(s1));
	NUTS_PASS(nng_close(s2));
	nng_stats_free(stats);
}

TEST_LIST = {
	{ "survey identity", test_surv_identity },
	{ "survey ttl option", test_surv_ttl_option },
	{ "survey survey time option", test_surv_survey_time_option },
	{ "survey recv bad state", test_surv_recv_bad_state },
	{ "survey recv garbage", test_surv_recv_garbage },
	{ "survey respondent exchange", test_surv_resp_exchange },
	{ "survey cancel", test_surv_cancel },
	{ "survey cancel abort recv", test_surv_cancel_abort_recv },
	{ "survey cancel post recv", test_surv_cancel_post_recv },
	{ "survey poll writable", test_surv_poll_writeable },
	{ "survey poll readable", test_surv_poll_readable },
	{ "survey context does not poll", test_surv_ctx_no_poll },
	{ "survey context recv close socket",
	    test_surv_ctx_recv_close_socket },
	{ "survey context recv nonblock", test_surv_ctx_recv_nonblock },
	{ "survey context send nonblock", test_surv_ctx_send_nonblock },
	{ "survey context send recv msg", test_surv_ctx_send_recv_msg },
	{ "survey timeout", test_surv_survey_timeout },
	{ "survey send best effort", test_surv_send_best_effort },
	{ "survey context multi", test_surv_context_multi },
	{ "survey validate peer", test_surv_validate_peer },
	{ NULL, NULL },
};
