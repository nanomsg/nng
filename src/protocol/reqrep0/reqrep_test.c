//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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

#ifndef NNI_PROTO
#define NNI_PROTO(x, y) (((x) << 4u) | (y))
#endif

void
test_req_rep_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	TEST_CHECK(nng_req0_open(&s) == 0);
	TEST_CHECK(nng_getopt_int(s, NNG_OPT_PROTO, &p) == 0);
	TEST_CHECK(p == NNI_PROTO(3u, 0u)); // 48
	TEST_CHECK(nng_getopt_int(s, NNG_OPT_PEER, &p) == 0);
	TEST_CHECK(p == NNI_PROTO(3u, 1u)); // 49
	TEST_CHECK(nng_getopt_string(s, NNG_OPT_PROTONAME, &n) == 0);
	TEST_CHECK(strcmp(n, "req") == 0);
	nng_strfree(n);
	TEST_CHECK(nng_getopt_string(s, NNG_OPT_PEERNAME, &n) == 0);
	TEST_CHECK(strcmp(n, "rep") == 0);
	nng_strfree(n);
	TEST_CHECK(nng_close(s) == 0);

	TEST_CHECK(nng_rep0_open(&s) == 0);
	TEST_CHECK(nng_getopt_int(s, NNG_OPT_PROTO, &p) == 0);
	TEST_CHECK(p == NNI_PROTO(3u, 1u)); // 49
	TEST_CHECK(nng_getopt_int(s, NNG_OPT_PEER, &p) == 0);
	TEST_CHECK(p == NNI_PROTO(3u, 0u)); // 48
	TEST_CHECK(nng_getopt_string(s, NNG_OPT_PROTONAME, &n) == 0);
	TEST_CHECK(strcmp(n, "rep") == 0);
	nng_strfree(n);
	TEST_CHECK(nng_getopt_string(s, NNG_OPT_PEERNAME, &n) == 0);
	TEST_CHECK(strcmp(n, "req") == 0);
	nng_strfree(n);
	TEST_CHECK(nng_close(s) == 0);
}

void
test_resend_option(void)
{
	nng_socket  req;
	bool        b;
	size_t      sz  = sizeof(b);
	const char *opt = NNG_OPT_REQ_RESENDTIME;

	TEST_CHECK(nng_req0_open(&req) == 0);

	TEST_CHECK(nng_setopt_ms(req, opt, 10) == 0);
	TEST_CHECK(nng_setopt(req, opt, "", 1) == NNG_EINVAL);
	TEST_CHECK(nng_getopt(req, opt, &b, &sz) == NNG_EINVAL);
	TEST_CHECK(nng_setopt_bool(req, opt, true) == NNG_EBADTYPE);
	TEST_CHECK(nng_getopt_bool(req, opt, &b) == NNG_EBADTYPE);

	TEST_CHECK(nng_close(req) == 0);
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

void
test_rep_send_bad_state(void)
{
	nng_socket rep;
	nng_msg *  msg = NULL;

	TEST_CHECK(nng_rep0_open(&rep) == 0);
	TEST_CHECK(nng_msg_alloc(&msg, 0) == 0);
	TEST_CHECK(nng_sendmsg(rep, msg, 0) == NNG_ESTATE);
	nng_msg_free(msg);
	TEST_CHECK(nng_close(rep) == 0);
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
test_req_cancel(void)
{
	nng_msg *    abc;
	nng_msg *    def;
	nng_msg *    cmd;
	nng_duration retry = SECOND;
	nng_socket   req;
	nng_socket   rep;

	TEST_CHECK(nng_rep_open(&rep) == 0);
	TEST_CHECK(nng_req_open(&req) == 0);

	TEST_CHECK(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, SECOND) == 0);
	TEST_CHECK(nng_setopt_ms(req, NNG_OPT_REQ_RESENDTIME, retry) == 0);
	TEST_CHECK(nng_setopt_int(req, NNG_OPT_SENDBUF, 16) == 0);

	TEST_CHECK(nng_msg_alloc(&abc, 0) == 0);
	TEST_CHECK(nng_msg_append(abc, "abc", 4) == 0);
	TEST_CHECK(nng_msg_alloc(&def, 0) == 0);
	TEST_CHECK(nng_msg_append(def, "def", 4) == 0);

	TEST_CHECK(testutil_marry(rep, req) == 0);

	// Send req #1 (abc).
	TEST_CHECK(nng_sendmsg(req, abc, 0) == 0);

	// Sleep a bit.  This is so that we ensure that our request gets
	// to the far side.  (If we cancel too fast, then our outgoing send
	// will be canceled before it gets to the peer.)
	testutil_sleep(100);

	// Send the next next request ("def").  Note that
	// the REP side server will have already buffered the receive
	// request, and should simply be waiting for us to reply to abc.
	TEST_CHECK(nng_sendmsg(req, def, 0) == 0);

	// Receive the first request (should be abc) on the REP server.
	TEST_CHECK(nng_recvmsg(rep, &cmd, 0) == 0);
	TEST_ASSERT(cmd != NULL);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "abc") == 0);

	// REP sends the reply to first command.  This will be discarded
	// by the REQ socket.
	TEST_CHECK(nng_sendmsg(rep, cmd, 0) == 0);

	// Now get the next command from the REP; should be "def".
	TEST_CHECK(nng_recvmsg(rep, &cmd, 0) == 0);
	TEST_ASSERT(cmd != NULL);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);
	TEST_MSG("Received body was %s", nng_msg_body(cmd));

	// And send it back to REQ.
	TEST_CHECK(nng_sendmsg(rep, cmd, 0) == 0);

	// Try a req command.  This should give back "def"
	TEST_CHECK(nng_recvmsg(req, &cmd, 0) == 0);
	TEST_CHECK(nng_msg_len(cmd) == 4);
	TEST_CHECK(strcmp(nng_msg_body(cmd), "def") == 0);
	nng_msg_free(cmd);

	TEST_CHECK(nng_close(req) == 0);
	TEST_CHECK(nng_close(rep) == 0);
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

	// and receiving makes it no longer pollable
	TEST_NNG_PASS(nng_recvmsg(req, &msg, 0));
	nng_msg_free(msg);
	TEST_CHECK(testutil_pollfd(fd) == false);

	// TODO verify unsolicited response

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_req_context_not_pollable(void)
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

void
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
	{ "req rep identity", test_req_rep_identity },
	{ "resend option", test_resend_option },
	{ "req recv bad state", test_req_recv_bad_state },
	{ "rep send bad state", test_rep_send_bad_state },
	{ "req rep exchange", test_req_rep_exchange },
	{ "req cancel", test_req_cancel },
	{ "req cancel abort recv", test_req_cancel_abort_recv },
	{ "req poll writable", test_req_poll_writeable },
	{ "req poll readable", test_req_poll_readable },
	{ "req context not pollable", test_req_context_not_pollable },
	{ "req validate peer", test_req_validate_peer },
	{ NULL, NULL },
};
