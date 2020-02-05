//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/survey0/survey.h>

#include <acutest.h>
#include <testutil.h>

static void
test_surv_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	TEST_NNG_PASS(nng_surveyor0_open(&s));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PROTO, &p));
	TEST_CHECK(p == NNG_SURVEYOR0_SELF);
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PEER, &p));
	TEST_CHECK(p == NNG_SURVEYOR0_PEER); // 49
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PROTONAME, &n));
	TEST_CHECK(strcmp(n, NNG_SURVEYOR0_SELF_NAME) == 0);
	nng_strfree(n);
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PEERNAME, &n));
	TEST_CHECK(strcmp(n, NNG_SURVEYOR0_PEER_NAME) == 0);
	nng_strfree(n);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_surv_ttl_option(void)
{
	nng_socket  surv;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));

	TEST_NNG_PASS(nng_setopt_int(surv, opt, 1));
	TEST_NNG_FAIL(nng_setopt_int(surv, opt, 0), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(surv, opt, -1), NNG_EINVAL);
	// This test will fail if the NNI_MAX_MAX_TTL is changed from the
	// builtin default of 15.
	TEST_NNG_FAIL(nng_setopt_int(surv, opt, 16), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(surv, opt, 256), NNG_EINVAL);
	TEST_NNG_PASS(nng_setopt_int(surv, opt, 3));
	TEST_NNG_PASS(nng_getopt_int(surv, opt, &v));
	TEST_CHECK(v == 3);
	v  = 0;
	sz = sizeof(v);
	TEST_NNG_PASS(nng_getopt(surv, opt, &v, &sz));
	TEST_CHECK(v == 3);
	TEST_CHECK(sz == sizeof(v));

	TEST_NNG_FAIL(nng_setopt(surv, opt, "", 1), NNG_EINVAL);
	sz = 1;
	TEST_NNG_FAIL(nng_getopt(surv, opt, &v, &sz), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_bool(surv, opt, true), NNG_EBADTYPE);
	TEST_NNG_FAIL(nng_getopt_bool(surv, opt, &b), NNG_EBADTYPE);

	TEST_NNG_PASS(nng_close(surv));
}

static void
test_surv_survey_time_option(void)
{
	nng_socket   surv;
	nng_duration d;
	bool         b;
	size_t       sz  = sizeof(b);
	const char * opt = NNG_OPT_SURVEYOR_SURVEYTIME;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));

	TEST_NNG_PASS(nng_setopt_ms(surv, opt, 10));
	TEST_NNG_FAIL(nng_setopt(surv, opt, "", 1), NNG_EINVAL);
	TEST_NNG_FAIL(nng_getopt(surv, opt, &b, &sz), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_bool(surv, opt, true), NNG_EBADTYPE);
	TEST_NNG_FAIL(nng_getopt_bool(surv, opt, &b), NNG_EBADTYPE);

	TEST_NNG_PASS(nng_getopt_ms(surv, opt, &d));
	TEST_CHECK(d == 10);
	TEST_NNG_PASS(nng_close(surv));
}

void
test_surv_recv_bad_state(void)
{
	nng_socket surv;
	nng_msg *  msg = NULL;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_FAIL(nng_recvmsg(surv, &msg, 0), NNG_ESTATE);
	TEST_CHECK(msg == NULL);
	TEST_NNG_PASS(nng_close(surv));
}

static void
test_surv_recv_garbage(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	uint32_t   surv_id;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_sendmsg(surv, m, 0));

	TEST_NNG_PASS(nng_recvmsg(resp, &m, 0));

	// The message will have a header that contains the 32-bit pipe ID,
	// followed by the 32-bit request ID.  We will discard the request
	// ID before sending it out.
	TEST_CHECK(nng_msg_header_len(m) == 8);
	TEST_NNG_PASS(nng_msg_header_chop_u32(m, &surv_id));

	TEST_NNG_PASS(nng_sendmsg(resp, m, 0));
	TEST_NNG_FAIL(nng_recvmsg(surv, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

#define SECOND 1000

void
test_surv_resp_exchange(void)
{
	nng_socket surv;
	nng_socket resp;
	nng_msg *  msg = NULL;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));

	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, SECOND));

	TEST_NNG_PASS(testutil_marry(resp, surv));

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_append(msg, "ping", 5));
	TEST_CHECK(nng_msg_len(msg) == 5);
	TEST_CHECK(strcmp(nng_msg_body(msg), "ping") == 0);
	TEST_NNG_PASS(nng_sendmsg(surv, msg, 0));
	msg = NULL;
	TEST_NNG_PASS(nng_recvmsg(resp, &msg, 0));
	TEST_CHECK(msg != NULL);
	TEST_CHECK(nng_msg_len(msg) == 5);
	TEST_CHECK(strcmp(nng_msg_body(msg), "ping") == 0);
	nng_msg_trim(msg, 5);
	TEST_NNG_PASS(nng_msg_append(msg, "pong", 5));
	TEST_NNG_PASS(nng_sendmsg(resp, msg, 0));
	msg = NULL;
	TEST_NNG_PASS(nng_recvmsg(surv, &msg, 0));
	TEST_CHECK(msg != NULL);
	TEST_CHECK(nng_msg_len(msg) == 5);
	TEST_CHECK(strcmp(nng_msg_body(msg), "pong") == 0);
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

void
test_surv_cancel(void)
{
	nng_msg *  abc;
	nng_msg *  def;
	nng_msg *  cmd;
	nng_socket surv;
	nng_socket resp;

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_surveyor0_open(&surv));

	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 5 * SECOND));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 5 * SECOND));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_SENDBUF, 16));

	TEST_NNG_PASS(nng_msg_alloc(&abc, 0));
	TEST_NNG_PASS(nng_msg_append(abc, "abc", 4));
	TEST_NNG_PASS(nng_msg_alloc(&def, 0));
	TEST_NNG_PASS(nng_msg_append(def, "def", 4));

	TEST_NNG_PASS(testutil_marry(resp, surv));

	// Send req #1 (abc).
	TEST_CHECK(nng_sendmsg(surv, abc, 0) == 0);

	// Sleep a bit.  This is so that we ensure that our request gets
	// to the far side.  (If we cancel too fast, then our outgoing send
	// will be canceled before it gets to the peer.)
	testutil_sleep(100);

	// Send the next next request ("def").  Note that
	// the RESP side server will have already buffered the receive
	// request, and should simply be waiting for us to reply to abc.
	TEST_NNG_PASS(nng_sendmsg(surv, def, 0));

	// Receive the first request (should be abc) on the REP server.
	TEST_NNG_PASS(nng_recvmsg(resp, &cmd, 0));
	TEST_ASSERT(cmd != NULL);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "abc") == 0);

	// RESP sends the reply to first command.  This will be discarded
	// by the SURV socket.
	TEST_NNG_PASS(nng_sendmsg(resp, cmd, 0));

	// Now get the next command from the REP; should be "def".
	TEST_NNG_PASS(nng_recvmsg(resp, &cmd, 0));
	TEST_ASSERT(cmd != NULL);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);
	TEST_MSG("Received body was %s", nng_msg_body(cmd));

	// And send it back to REQ.
	TEST_NNG_PASS(nng_sendmsg(resp, cmd, 0));

	// Try a req command.  This should give back "def"
	TEST_NNG_PASS(nng_recvmsg(surv, &cmd, 0));
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);
	nng_msg_free(cmd);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

void
test_surv_cancel_abort_recv(void)
{

	nng_msg *    abc;
	nng_msg *    def;
	nng_msg *    cmd;
	nng_aio *    aio;
	nng_duration time = SECOND * 10; // 10s (kind of never)
	nng_socket   surv;
	nng_socket   resp;

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SURVEYOR_SURVEYTIME, time));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_SENDBUF, 16));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 5 * SECOND));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 5 * SECOND));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 5 * SECOND));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 5 * SECOND));

	TEST_NNG_PASS(nng_msg_alloc(&abc, 0));
	TEST_NNG_PASS(nng_msg_append(abc, "abc", 4));
	TEST_NNG_PASS(nng_msg_alloc(&def, 0));
	TEST_NNG_PASS(nng_msg_append(def, "def", 4));

	TEST_NNG_PASS(testutil_marry(resp, surv));

	// Send survey #1 (abc).
	TEST_NNG_PASS(nng_sendmsg(surv, abc, 0));

	// Wait for it to get ot the other side.
	testutil_sleep(100);

	nng_aio_set_timeout(aio, 5 * SECOND);
	nng_recv_aio(surv, aio);

	// Give time for this recv to post properly.
	testutil_sleep(100);

	// Send the next next request ("def").  Note that
	// the respondent side server will have already buffered the receive
	// request, and should simply be waiting for us to reply to
	// abc.
	TEST_NNG_PASS(nng_sendmsg(surv, def, 0));

	// Our pending I/O should have been canceled.
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECANCELED);

	// Receive the first request (should be abc) on the respondent.
	TEST_NNG_PASS(nng_recvmsg(resp, &cmd, 0));
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "abc") == 0);

	// Respondent sends the reply to first survey.  This will be
	// discarded by the SURV socket.
	TEST_CHECK(nng_sendmsg(resp, cmd, 0) == 0);

	// Now get the next survey from the RESP; should be "def".
	TEST_NNG_PASS(nng_recvmsg(resp, &cmd, 0));
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);

	// And send it back to REQ.
	TEST_NNG_PASS(nng_sendmsg(resp, cmd, 0));

	// Try a req command.  This should give back "def"
	TEST_NNG_PASS(nng_recvmsg(surv, &cmd, 0));
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);
	nng_msg_free(cmd);

	nng_aio_free(aio);
	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_surv_cancel_post_recv(void)
{
	nng_socket surv;
	nng_socket resp;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(testutil_marry(surv, resp));

	TEST_NNG_SEND_STR(surv, "ONE");
	TEST_NNG_RECV_STR(resp, "ONE");
	TEST_NNG_SEND_STR(resp, "one");
	testutil_sleep(100); // Make sure reply arrives!
	TEST_NNG_SEND_STR(surv, "TWO");
	TEST_NNG_RECV_STR(resp, "TWO");
	TEST_NNG_SEND_STR(resp, "two");
	TEST_NNG_RECV_STR(surv, "two");

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_surv_poll_writeable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_getopt_int(surv, NNG_OPT_SENDFD, &fd));
	TEST_CHECK(fd >= 0);

	// Survey is broadcast, so we can always write.
	TEST_CHECK(testutil_pollfd(fd) == true);

	TEST_NNG_PASS(testutil_marry(surv, resp));

	// Now it's writable.
	TEST_CHECK(testutil_pollfd(fd) == true);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

void
test_surv_poll_readable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_getopt_int(surv, NNG_OPT_RECVFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not readable if not connected!
	TEST_CHECK(testutil_pollfd(fd) == false);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(surv, resp));
	TEST_CHECK(testutil_pollfd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_append(msg, "xyz", 3));
	TEST_NNG_PASS(nng_sendmsg(surv, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(resp, &msg, 0)); // recv on rep
	TEST_NNG_PASS(nng_sendmsg(resp, msg, 0));  // echo it back
	testutil_sleep(200); // give time for message to arrive

	TEST_CHECK(testutil_pollfd(fd) == true);

	// and receiving makes it no longer ready
	TEST_NNG_PASS(nng_recvmsg(surv, &msg, 0));
	nng_msg_free(msg);
	TEST_CHECK(testutil_pollfd(fd) == false);

	// TODO verify unsolicited response

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_surv_ctx_no_poll(void)
{
	int        fd;
	nng_socket surv;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_ctx_open(&ctx, surv));
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	TEST_NNG_PASS(nng_close(surv));
}

static void
test_surv_ctx_recv_nonblock(void)
{
	nng_socket surv;
	nng_socket resp;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_ctx_open(&ctx, surv));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	nng_aio_set_msg(aio, msg);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_PASS(nng_aio_result(aio));
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
	nng_aio_free(aio);
}

static void
test_surv_ctx_send_nonblock(void)
{
	nng_socket surv;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_ctx_open(&ctx, surv));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));

	nng_aio_set_msg(aio, msg);
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_PASS(nng_aio_result(aio)); // We never block
	TEST_NNG_PASS(nng_close(surv));
	nng_aio_free(aio);
}

static void
test_surv_send_best_effort(void)
{
	nng_socket surv;
	nng_socket resp;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(testutil_marry(surv, resp));

	for (int i = 0; i < 200; i++) {
		TEST_NNG_SEND_STR(surv, "junk");
	}

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_surv_survey_timeout(void)
{
	nng_socket surv;
	nng_socket resp;
	char       buf[16];
	size_t     sz;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SURVEYOR_SURVEYTIME, 50));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 100));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	TEST_NNG_SEND_STR(surv, "hello");
	TEST_NNG_RECV_STR(resp, "hello");

	sz = sizeof(buf);
	TEST_NNG_FAIL(nng_recv(surv, buf, &sz, 0), NNG_ETIMEDOUT);
	TEST_NNG_SEND_STR(resp, "world");
	TEST_NNG_FAIL(nng_recv(surv, buf, &sz, 0), NNG_ESTATE);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_surv_ctx_recv_close_socket(void)
{
	nng_socket surv;
	nng_socket resp;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  m;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_ctx_open(&ctx, surv));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(testutil_marry(surv, resp));
	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	nng_aio_set_msg(aio, m);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_PASS(nng_aio_result(aio));

	nng_ctx_recv(ctx, aio);
	nng_close(surv);

	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_surv_context_multi(void)
{
	nng_socket surv;
	nng_socket resp;
	nng_ctx    c[5];
	nng_aio *  aio;
	nng_msg *  m;
	int        cnt = sizeof(c) / sizeof(c[0]);

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(testutil_marry(surv, resp));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SURVEYOR_SURVEYTIME, 200));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	for (int i = 0; i < cnt; i++) {
		TEST_NNG_PASS(nng_ctx_open(&c[i], surv));
	}

	for (int i = 0; i < cnt; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 0));
		TEST_NNG_PASS(nng_msg_append_u32(m, i));
		nng_aio_set_msg(aio, m);
		nng_ctx_send(c[i], aio);
		nng_aio_wait(aio);
		TEST_NNG_PASS(nng_aio_result(aio));
	}

	for (int i = 0; i < cnt; i++) {
		TEST_NNG_PASS(nng_recvmsg(resp, &m, 0));
		TEST_NNG_PASS(nng_sendmsg(resp, m, 0));
	}

	for (int i = cnt - 1; i >= 0; i--) {
		uint32_t x;
		nng_ctx_recv(c[i], aio);
		nng_aio_wait(aio);
		TEST_NNG_PASS(nng_aio_result(aio));
		m = nng_aio_get_msg(aio);
		TEST_ASSERT(m != NULL);
		TEST_NNG_PASS(nng_msg_trim_u32(m, &x));
		TEST_CHECK(x == (uint32_t)i);
		nng_msg_free(m);
	}

	for (int i = 0; i < cnt; i++) {
		nng_ctx_recv(c[i], aio);
		nng_aio_wait(aio);
		TEST_CHECK(nng_aio_result(aio) != 0);
	}
	for (int i = 0; i < cnt; i++) {
		nng_ctx_close(c[i]);
	}
	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
	nng_aio_free(aio);
}

static void
test_surv_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_surveyor0_open(&s1));
	TEST_NNG_PASS(nng_surveyor0_open(&s2));

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
	{ "survey timeout", test_surv_survey_timeout },
	{ "survey send best effort", test_surv_send_best_effort },
	{ "survey context multi", test_surv_context_multi },
	{ "survey validate peer", test_surv_validate_peer },
	{ NULL, NULL },
};
