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
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>

#include <acutest.h>
#include <testutil.h>

#ifndef NNI_PROTO
#define NNI_PROTO(x, y) (((x) << 4u) | (y))
#endif

void
test_rep_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

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

void
test_rep_poll_writeable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_getopt_int(rep, NNG_OPT_SENDFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not writable before connect.
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(testutil_marry(req, rep));

	// Still not writable.
	TEST_CHECK(testutil_pollfd(fd) == false);

	// If we get a job, *then* we become writeable
	TEST_NNG_SEND_STR(req, "abc");
	TEST_NNG_RECV_STR(rep, "abc");
	TEST_CHECK(testutil_pollfd(fd) == true);

	// And is no longer writable once we send a message
	TEST_NNG_SEND_STR(rep, "def");
	TEST_CHECK(testutil_pollfd(fd) == false);
	// Even after receiving it
	TEST_NNG_RECV_STR(req, "def");
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_rep_poll_readable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_getopt_int(rep, NNG_OPT_RECVFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not readable if not connected!
	TEST_CHECK(testutil_pollfd(fd) == false);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(req, rep));
	TEST_CHECK(testutil_pollfd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	TEST_NNG_SEND_STR(req, "abc");
	testutil_sleep(100);

	TEST_CHECK(testutil_pollfd(fd) == true);

	// and receiving makes it no longer pollable
	TEST_NNG_PASS(nng_recvmsg(rep, &msg, 0));
	nng_msg_free(msg);
	TEST_CHECK(testutil_pollfd(fd) == false);

	// TODO verify unsolicited response

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_rep_context_not_pollable(void)
{
	int        fd;
	nng_socket req;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_rep0_open(&req));
	TEST_NNG_PASS(nng_ctx_open(&ctx, req));
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	TEST_NNG_PASS(nng_close(req));
}

void
test_rep_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_rep0_open(&s1));
	TEST_NNG_PASS(nng_rep0_open(&s2));

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
	{ "rep identity", test_rep_identity },
	{ "rep send bad state", test_rep_send_bad_state },
	{ "rep poll readable", test_rep_poll_readable },
	{ "rep poll writable", test_rep_poll_writeable },
	{ "rep context not pollable", test_rep_context_not_pollable },
	{ "rep validate peer", test_rep_validate_peer },
	{ NULL, NULL },
};
