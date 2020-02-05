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
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>

#include <acutest.h>
#include <testutil.h>

static void
test_req_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	TEST_NNG_PASS(nng_req0_open(&s));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PROTO, &p));
	TEST_CHECK(p == NNG_REQ0_SELF);
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PEER, &p));
	TEST_CHECK(p == NNG_REQ0_PEER); // 49
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PROTONAME, &n));
	TEST_CHECK(strcmp(n, NNG_REQ0_SELF_NAME) == 0);
	nng_strfree(n);
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PEERNAME, &n));
	TEST_CHECK(strcmp(n, NNG_REQ0_PEER_NAME) == 0);
	nng_strfree(n);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_req_ttl_option(void)
{
	nng_socket  req;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	TEST_NNG_PASS(nng_req0_open(&req));

	TEST_NNG_PASS(nng_setopt_int(req, opt, 1));
	TEST_NNG_FAIL(nng_setopt_int(req, opt, 0), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(req, opt, -1), NNG_EINVAL);
	// This test will fail if the NNI_MAX_MAX_TTL is changed from the
	// builtin default of 15.
	TEST_NNG_FAIL(nng_setopt_int(req, opt, 16), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(req, opt, 256), NNG_EINVAL);
	TEST_NNG_PASS(nng_setopt_int(req, opt, 3));
	TEST_NNG_PASS(nng_getopt_int(req, opt, &v));
	TEST_CHECK(v == 3);
	v  = 0;
	sz = sizeof(v);
	TEST_NNG_PASS(nng_getopt(req, opt, &v, &sz));
	TEST_CHECK(v == 3);
	TEST_CHECK(sz == sizeof(v));

	TEST_NNG_FAIL(nng_setopt(req, opt, "", 1), NNG_EINVAL);
	sz = 1;
	TEST_NNG_FAIL(nng_getopt(req, opt, &v, &sz), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_bool(req, opt, true), NNG_EBADTYPE);
	TEST_NNG_FAIL(nng_getopt_bool(req, opt, &b), NNG_EBADTYPE);

	TEST_NNG_PASS(nng_close(req));
}

static void
test_req_resend_option(void)
{
	nng_socket   req;
	nng_duration d;
	bool         b;
	size_t       sz  = sizeof(b);
	const char * opt = NNG_OPT_REQ_RESENDTIME;

	TEST_NNG_PASS(nng_req0_open(&req));

	TEST_CHECK(nng_setopt_ms(req, opt, 10) == 0);
	TEST_NNG_FAIL(nng_setopt(req, opt, "", 1), NNG_EINVAL);
	TEST_NNG_FAIL(nng_getopt(req, opt, &b, &sz), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_bool(req, opt, true), NNG_EBADTYPE);
	TEST_NNG_FAIL(nng_getopt_bool(req, opt, &b), NNG_EBADTYPE);

	TEST_NNG_PASS(nng_getopt_ms(req, opt, &d));
	TEST_CHECK(d == 10);
	TEST_NNG_PASS(nng_close(req));
}

void
test_req_recv_bad_state(void)
{
	nng_socket req;
	nng_msg *  msg = NULL;

	TEST_CHECK(nng_req0_open(&req) == 0);
	TEST_CHECK(nng_recvmsg(req, &msg, 0) == NNG_ESTATE);
	TEST_CHECK(msg == NULL);
	TEST_CHECK(nng_close(req) == 0);
}

static void
test_req_recv_garbage(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	uint32_t   req_id;

	TEST_NNG_PASS(nng_rep0_open_raw(&rep));
	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry(req, rep));

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_sendmsg(req, m, 0));

	TEST_NNG_PASS(nng_recvmsg(rep, &m, 0));

	// The message will have a header that contains the 32-bit pipe ID,
	// followed by the 32-bit request ID.  We will discard the request
	// ID before sending it out.
	TEST_CHECK(nng_msg_header_len(m) == 8);
	TEST_NNG_PASS(nng_msg_header_chop_u32(m, &req_id));

	TEST_NNG_PASS(nng_sendmsg(rep, m, 0));
	TEST_NNG_FAIL(nng_recvmsg(req, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

#define SECOND 1000

void
test_req_rep_exchange(void)
{
	nng_socket req;
	nng_socket rep;
	nng_msg *  msg = NULL;

	TEST_CHECK(nng_req0_open(&req) == 0);
	TEST_CHECK(nng_rep0_open(&rep) == 0);

	TEST_CHECK(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, SECOND) == 0);

	TEST_CHECK(testutil_marry(rep, req) == 0);

	TEST_CHECK(nng_msg_alloc(&msg, 0) == 0);
	TEST_CHECK(nng_msg_append(msg, "ping", 5) == 0);
	TEST_CHECK(nng_msg_len(msg) == 5);
	TEST_CHECK(strcmp(nng_msg_body(msg), "ping") == 0);
	TEST_CHECK(nng_sendmsg(req, msg, 0) == 0);
	msg = NULL;
	TEST_CHECK(nng_recvmsg(rep, &msg, 0) == 0);
	TEST_CHECK(msg != NULL);
	TEST_CHECK(nng_msg_len(msg) == 5);
	TEST_CHECK(strcmp(nng_msg_body(msg), "ping") == 0);
	nng_msg_trim(msg, 5);
	TEST_CHECK(nng_msg_append(msg, "pong", 5) == 0);
	TEST_CHECK(nng_sendmsg(rep, msg, 0) == 0);
	msg = NULL;
	TEST_CHECK(nng_recvmsg(req, &msg, 0) == 0);
	TEST_CHECK(msg != NULL);
	TEST_CHECK(nng_msg_len(msg) == 5);
	TEST_CHECK(strcmp(nng_msg_body(msg), "pong") == 0);
	nng_msg_free(msg);

	TEST_CHECK(nng_close(req) == 0);
	TEST_CHECK(nng_close(rep) == 0);
}

void
test_req_resend(void)
{
	nng_socket req;
	nng_socket rep;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));

	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_REQ_RESENDTIME, 10));

	TEST_NNG_PASS(testutil_marry(rep, req));

	TEST_NNG_SEND_STR(req, "ping");
	TEST_NNG_RECV_STR(rep, "ping");
	TEST_NNG_RECV_STR(rep, "ping");
	TEST_NNG_RECV_STR(rep, "ping");

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_req_resend_reconnect(void)
{
	nng_socket req;
	nng_socket rep1;
	nng_socket rep2;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep1));
	TEST_NNG_PASS(nng_rep0_open(&rep2));

	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep1, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep2, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep1, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep2, NNG_OPT_SENDTIMEO, SECOND));
	// We intentionally set the retry time long; that way we only see
	// the retry from loss of our original peer.
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_REQ_RESENDTIME, 60 * SECOND));

	TEST_NNG_PASS(testutil_marry(rep1, req));

	TEST_NNG_SEND_STR(req, "ping");
	TEST_NNG_RECV_STR(rep1, "ping");

	TEST_NNG_PASS(nng_close(rep1));
	TEST_NNG_PASS(testutil_marry(rep2, req));

	TEST_NNG_RECV_STR(rep2, "ping");
	TEST_NNG_SEND_STR(rep2, "rep2");
	TEST_NNG_RECV_STR(req, "rep2");

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep2));
}

void
test_req_resend_disconnect(void)
{
	nng_socket req;
	nng_socket rep1;
	nng_socket rep2;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep1));
	TEST_NNG_PASS(nng_rep0_open(&rep2));

	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep1, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep2, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep1, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep2, NNG_OPT_SENDTIMEO, SECOND));
	// We intentionally set the retry time long; that way we only see
	// the retry from loss of our original peer.
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_REQ_RESENDTIME, 60 * SECOND));

	TEST_NNG_PASS(testutil_marry(rep1, req));
	TEST_NNG_SEND_STR(req, "ping");
	TEST_NNG_RECV_STR(rep1, "ping");

	TEST_NNG_PASS(testutil_marry(rep2, req));
	TEST_NNG_PASS(nng_close(rep1));

	TEST_NNG_RECV_STR(rep2, "ping");
	TEST_NNG_SEND_STR(rep2, "rep2");
	TEST_NNG_RECV_STR(req, "rep2");

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep2));
}

void
test_req_cancel(void)
{
	nng_msg *    abc;
	nng_msg *    def;
	nng_msg *    cmd;
	nng_duration retry = SECOND;
	nng_socket   req;
	nng_socket   rep;

	TEST_NNG_PASS(nng_rep_open(&rep));
	TEST_NNG_PASS(nng_req_open(&req));

	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 5 * SECOND));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 5 * SECOND));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_REQ_RESENDTIME, retry));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_SENDBUF, 16));

	TEST_NNG_PASS(nng_msg_alloc(&abc, 0));
	TEST_NNG_PASS(nng_msg_append(abc, "abc", 4));
	TEST_NNG_PASS(nng_msg_alloc(&def, 0));
	TEST_NNG_PASS(nng_msg_append(def, "def", 4));

	TEST_NNG_PASS(testutil_marry(rep, req));

	// Send req #1 (abc).
	TEST_CHECK(nng_sendmsg(req, abc, 0) == 0);

	// Sleep a bit.  This is so that we ensure that our request gets
	// to the far side.  (If we cancel too fast, then our outgoing send
	// will be canceled before it gets to the peer.)
	testutil_sleep(100);

	// Send the next next request ("def").  Note that
	// the REP side server will have already buffered the receive
	// request, and should simply be waiting for us to reply to abc.
	TEST_NNG_PASS(nng_sendmsg(req, def, 0));

	// Receive the first request (should be abc) on the REP server.
	TEST_NNG_PASS(nng_recvmsg(rep, &cmd, 0));
	TEST_ASSERT(cmd != NULL);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "abc") == 0);

	// REP sends the reply to first command.  This will be discarded
	// by the REQ socket.
	TEST_NNG_PASS(nng_sendmsg(rep, cmd, 0));

	// Now get the next command from the REP; should be "def".
	TEST_NNG_PASS(nng_recvmsg(rep, &cmd, 0));
	TEST_ASSERT(cmd != NULL);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);
	TEST_MSG("Received body was %s", nng_msg_body(cmd));

	// And send it back to REQ.
	TEST_NNG_PASS(nng_sendmsg(rep, cmd, 0));

	// Try a req command.  This should give back "def"
	TEST_NNG_PASS(nng_recvmsg(req, &cmd, 0));
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);
	nng_msg_free(cmd);

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_req_cancel_abort_recv(void)
{

	nng_msg *    abc;
	nng_msg *    def;
	nng_msg *    cmd;
	nng_aio *    aio;
	nng_duration retry = SECOND * 10; // 10s (kind of never)
	nng_socket   req;
	nng_socket   rep;

	TEST_CHECK(nng_rep_open(&rep) == 0);
	TEST_CHECK(nng_req_open(&req) == 0);
	TEST_CHECK(nng_aio_alloc(&aio, NULL, NULL) == 0);

	TEST_CHECK(nng_setopt_ms(req, NNG_OPT_REQ_RESENDTIME, retry) == 0);
	TEST_CHECK(nng_setopt_int(req, NNG_OPT_SENDBUF, 16) == 0);
	TEST_CHECK(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, 5 * SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 5 * SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 5 * SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 5 * SECOND) == 0);

	TEST_CHECK(nng_msg_alloc(&abc, 0) == 0);
	TEST_CHECK(nng_msg_append(abc, "abc", 4) == 0);
	TEST_CHECK(nng_msg_alloc(&def, 0) == 0);
	TEST_CHECK(nng_msg_append(def, "def", 4) == 0);

	TEST_CHECK(testutil_marry(rep, req) == 0);

	// Send req #1 (abc).
	TEST_CHECK(nng_sendmsg(req, abc, 0) == 0);

	// Wait for it to get ot the other side.
	testutil_sleep(100);

	nng_aio_set_timeout(aio, 5 * SECOND);
	nng_recv_aio(req, aio);

	// Give time for this recv to post properly.
	testutil_sleep(100);

	// Send the next next request ("def").  Note that
	// the REP side server will have already buffered the receive
	// request, and should simply be waiting for us to reply to
	// abc.
	TEST_CHECK(nng_sendmsg(req, def, 0) == 0);

	// Our pending I/O should have been canceled.
	nng_aio_wait(aio);
	TEST_CHECK(nng_aio_result(aio) == NNG_ECANCELED);

	// Receive the first request (should be abc) on the REP server.
	TEST_CHECK(nng_recvmsg(rep, &cmd, 0) == 0);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "abc") == 0);

	// REP sends the reply to first command.  This will be
	// discarded by the REQ socket.
	TEST_CHECK(nng_sendmsg(rep, cmd, 0) == 0);

	// Now get the next command from the REP; should be "def".
	TEST_CHECK(nng_recvmsg(rep, &cmd, 0) == 0);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);

	// And send it back to REQ.
	TEST_CHECK(nng_sendmsg(rep, cmd, 0) == 0);

	// Try a req command.  This should give back "def"
	TEST_CHECK(nng_recvmsg(req, &cmd, 0) == 0);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);
	nng_msg_free(cmd);

	nng_aio_free(aio);
	TEST_CHECK(nng_close(req) == 0);
	TEST_CHECK(nng_close(rep) == 0);
}

static void
test_req_cancel_post_recv(void)
{
	nng_socket req;
	nng_socket rep;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(testutil_marry(req, rep));

	TEST_NNG_SEND_STR(req, "ONE");
	TEST_NNG_RECV_STR(rep, "ONE");
	TEST_NNG_SEND_STR(rep, "one");
	testutil_sleep(100); // Make sure reply arrives!
	TEST_NNG_SEND_STR(req, "TWO");
	TEST_NNG_RECV_STR(rep, "TWO");
	TEST_NNG_SEND_STR(rep, "two");
	TEST_NNG_RECV_STR(req, "two");

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_req_poll_writeable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_getopt_int(req, NNG_OPT_SENDFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not writable before connect.
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(testutil_marry(req, rep));

	// It should be writable now.
	TEST_CHECK(testutil_pollfd(fd) == true);

	// Submit a bunch of jobs.  Note that we have to stall a bit
	// between each message to let it queue up.
	for (int i = 0; i < 10; i++) {
		int rv = nng_send(req, "", 0, NNG_FLAG_NONBLOCK);
		if (rv == NNG_EAGAIN) {
			break;
		}
		TEST_NNG_PASS(rv);
		testutil_sleep(50);
	}
	TEST_CHECK(testutil_pollfd(fd) == 0);
	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_req_poll_contention(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;
	nng_aio *  aio;
	nng_ctx    ctx[5];
	nng_aio *  ctx_aio[5];
	nng_msg *  ctx_msg[5];
	nng_msg *  msg;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(rep, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));

	for (int i = 0; i < 5; i++) {
		TEST_NNG_PASS(nng_ctx_open(&ctx[i], req));
		TEST_NNG_PASS(nng_aio_alloc(&ctx_aio[i], NULL, NULL));
		TEST_NNG_PASS(nng_msg_alloc(&ctx_msg[i], 0));
	}
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));

	TEST_NNG_PASS(nng_getopt_int(req, NNG_OPT_SENDFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not writable before connect.
	TEST_CHECK(testutil_pollfd(fd) == false);

	nng_aio_set_msg(aio, msg);
	nng_send_aio(req, aio);
	for (int i = 0; i < 5; i++) {
		nng_aio_set_msg(ctx_aio[i], ctx_msg[i]);
		nng_ctx_send(ctx[i], ctx_aio[i]);
	}
	testutil_sleep(50); // so everything is queued steady state

	TEST_NNG_PASS(testutil_marry(req, rep));

	// It should not be writable now.
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(nng_recvmsg(rep, &msg, 0));
	nng_msg_free(msg);

	// Still not writeable...
	TEST_CHECK(testutil_pollfd(fd) == false);
	for (int i = 0; i < 5; i++) {
		TEST_NNG_PASS(nng_recvmsg(rep, &msg, 0));
		nng_msg_free(msg);
	}
	// It can take a little bit of time for the eased back-pressure
	// to reflect across the network.
	testutil_sleep(100);

	// Should be come writeable now...
	TEST_CHECK(testutil_pollfd(fd) == true);

	for (int i = 0; i < 5; i++) {
		nng_aio_free(ctx_aio[i]);
	}
	nng_aio_free(aio);
	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_req_poll_multi_pipe(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep1;
	nng_socket rep2;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep1));
	TEST_NNG_PASS(nng_rep0_open(&rep2));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(nng_getopt_int(req, NNG_OPT_SENDFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not writable before connect.
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(testutil_marry(req, rep1));
	TEST_NNG_PASS(testutil_marry(req, rep2));

	TEST_CHECK(testutil_pollfd(fd) == true);
	TEST_NNG_SEND_STR(req, "ONE");
	TEST_CHECK(testutil_pollfd(fd) == true);

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep1));
	TEST_NNG_PASS(nng_close(rep2));
}

void
test_req_poll_readable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_getopt_int(req, NNG_OPT_RECVFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not readable if not connected!
	TEST_CHECK(testutil_pollfd(fd) == false);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(req, rep));
	TEST_CHECK(testutil_pollfd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_append(msg, "xyz", 3));
	TEST_NNG_PASS(nng_sendmsg(req, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(rep, &msg, 0)); // recv on rep
	TEST_NNG_PASS(nng_sendmsg(rep, msg, 0));  // echo it back
	testutil_sleep(200); // give time for message to arrive

	TEST_CHECK(testutil_pollfd(fd) == true);

	// and receiving makes it no longer ready
	TEST_NNG_PASS(nng_recvmsg(req, &msg, 0));
	nng_msg_free(msg);
	TEST_CHECK(testutil_pollfd(fd) == false);

	// TODO verify unsolicited response

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

static void
test_req_ctx_no_poll(void)
{
	int        fd;
	nng_socket req;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_ctx_open(&ctx, req));
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	TEST_NNG_PASS(nng_close(req));
}

static void
test_req_ctx_send_queued(void)
{
	nng_socket req;
	nng_socket rep;
	nng_ctx    ctx[3];
	nng_aio *  aio[3];
	nng_msg *  msg[3];

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 100));

	for (int i = 0; i < 3; i++) {
		TEST_NNG_PASS(nng_ctx_open(&ctx[i], req));
		TEST_NNG_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
		TEST_NNG_PASS(nng_msg_alloc(&msg[i], 0));
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_set_msg(aio[i], msg[i]);
		nng_ctx_send(ctx[i], aio[i]);
	}

	TEST_NNG_PASS(testutil_marry(req, rep));

	testutil_sleep(50); // Only to ensure stuff queues up
	for (int i = 0; i < 3; i++) {
		nng_msg *m;
		TEST_NNG_PASS(nng_recvmsg(rep, &m, 0));
		nng_msg_free(m);
	}

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
	for (int i = 0; i < 3; i++) {
		nng_aio_wait(aio[i]);
		TEST_NNG_PASS(nng_aio_result(aio[i]));
		nng_aio_free(aio[i]);
	}
}

static void
test_req_ctx_send_close(void)
{
	nng_socket req;
	nng_ctx    ctx[3];
	nng_aio *  aio[3];
	nng_msg *  msg[3];

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));

	for (int i = 0; i < 3; i++) {
		TEST_NNG_PASS(nng_ctx_open(&ctx[i], req));
		TEST_NNG_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
		TEST_NNG_PASS(nng_msg_alloc(&msg[i], 0));
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_set_msg(aio[i], msg[i]);
		nng_ctx_send(ctx[i], aio[i]);
	}

	for (int i = 0; i < 3; i++) {
		nng_ctx_close(ctx[i]);
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_wait(aio[i]);
		TEST_NNG_FAIL(nng_aio_result(aio[i]), NNG_ECLOSED);
		nng_aio_free(aio[i]);
		nng_msg_free(msg[i]);
	}
	TEST_NNG_PASS(nng_close(req));
}

static void
test_req_ctx_send_abort(void)
{
	nng_socket req;
	nng_ctx    ctx[3];
	nng_aio *  aio[3];
	nng_msg *  msg[3];

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));

	for (int i = 0; i < 3; i++) {
		TEST_NNG_PASS(nng_ctx_open(&ctx[i], req));
		TEST_NNG_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
		TEST_NNG_PASS(nng_msg_alloc(&msg[i], 0));
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_set_msg(aio[i], msg[i]);
		nng_ctx_send(ctx[i], aio[i]);
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_abort(aio[i], NNG_ECANCELED);
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_wait(aio[i]);
		TEST_NNG_FAIL(nng_aio_result(aio[i]), NNG_ECANCELED);
		nng_aio_free(aio[i]);
		nng_msg_free(msg[i]);
	}
	TEST_NNG_PASS(nng_close(req));
}

static void
test_req_ctx_send_twice(void)
{
	nng_socket req;
	nng_ctx    ctx;
	nng_aio *  aio[2];
	nng_msg *  msg[2];

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_ctx_open(&ctx, req));

	for (int i = 0; i < 2; i++) {
		TEST_NNG_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
		TEST_NNG_PASS(nng_msg_alloc(&msg[i], 0));
	}

	for (int i = 0; i < 2; i++) {
		nng_aio_set_msg(aio[i], msg[i]);
		nng_ctx_send(ctx, aio[i]);
		testutil_sleep(50);
	}

	TEST_NNG_PASS(nng_close(req));
	nng_aio_wait(aio[0]);
	nng_aio_wait(aio[1]);
	TEST_NNG_FAIL(nng_aio_result(aio[0]), NNG_ECANCELED);
	TEST_NNG_FAIL(nng_aio_result(aio[1]), NNG_ECLOSED);

	for (int i = 0; i < 2; i++) {
		nng_aio_free(aio[i]);
		nng_msg_free(msg[i]);
	}
}

static void
test_req_ctx_recv_nonblock(void)
{
	nng_socket req;
	nng_socket rep;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_ctx_open(&ctx, req));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));

	TEST_NNG_PASS(testutil_marry(req, rep));

	nng_aio_set_msg(aio, msg);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_PASS(nng_aio_result(aio));
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
	nng_aio_free(aio);
}

static void
test_req_ctx_send_nonblock(void)
{
	nng_socket req;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_ctx_open(&ctx, req));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));

	nng_aio_set_msg(aio, msg);
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(req));
	nng_aio_free(aio);
	nng_msg_free(msg);
}

static void
test_req_ctx_recv_close_socket(void)
{
	nng_socket req;
	nng_socket rep;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  m;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_ctx_open(&ctx, req));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(testutil_marry(req, rep));
	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	nng_aio_set_msg(aio, m);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_PASS(nng_aio_result(aio));

	nng_ctx_recv(ctx, aio);
	nng_close(req);

	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
	TEST_NNG_PASS(nng_close(rep));
}

static void
test_req_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_req0_open(&s1));
	TEST_NNG_PASS(nng_req0_open(&s2));

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
	{ "req identity", test_req_identity },
	{ "req ttl option", test_req_ttl_option },
	{ "req resend option", test_req_resend_option },
	{ "req recv bad state", test_req_recv_bad_state },
	{ "req recv garbage", test_req_recv_garbage },
	{ "req rep exchange", test_req_rep_exchange },
	{ "req resend", test_req_resend },
	{ "req resend disconnect", test_req_resend_disconnect },
	{ "req resend reconnect", test_req_resend_reconnect },
	{ "req cancel", test_req_cancel },
	{ "req cancel abort recv", test_req_cancel_abort_recv },
	{ "req cancel post recv", test_req_cancel_post_recv },
	{ "req poll writable", test_req_poll_writeable },
	{ "req poll contention", test_req_poll_contention },
	{ "req poll multi pipe", test_req_poll_multi_pipe },
	{ "req poll readable", test_req_poll_readable },
	{ "req context send queued", test_req_ctx_send_queued },
	{ "req context send close", test_req_ctx_send_close },
	{ "req context send abort", test_req_ctx_send_abort },
	{ "req context send twice", test_req_ctx_send_twice },
	{ "req context does not poll", test_req_ctx_no_poll },
	{ "req context recv close socket", test_req_ctx_recv_close_socket },
	{ "req context recv nonblock", test_req_ctx_recv_nonblock },
	{ "req context send nonblock", test_req_ctx_send_nonblock },
	{ "req validate peer", test_req_validate_peer },
	{ NULL, NULL },
};
