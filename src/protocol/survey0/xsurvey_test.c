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
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/survey0/survey.h>

#include <acutest.h>
#include <testutil.h>

#ifndef NNI_PROTO
#define NNI_PROTO(x, y) (((x) << 4u) | (y))
#endif

static void
test_xsurveyor_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	TEST_CHECK(nng_surveyor0_open_raw(&s) == 0);
	TEST_CHECK(nng_getopt_int(s, NNG_OPT_PROTO, &p) == 0);
	TEST_CHECK(p == NNI_PROTO(6u, 2u)); // 0x62
	TEST_CHECK(nng_getopt_int(s, NNG_OPT_PEER, &p) == 0);
	TEST_CHECK(p == NNI_PROTO(6u, 3u)); // 0x63
	TEST_CHECK(nng_getopt_string(s, NNG_OPT_PROTONAME, &n) == 0);
	TEST_CHECK(strcmp(n, "surveyor") == 0);
	nng_strfree(n);
	TEST_CHECK(nng_getopt_string(s, NNG_OPT_PEERNAME, &n) == 0);
	TEST_CHECK(strcmp(n, "respondent") == 0);
	nng_strfree(n);
	TEST_CHECK(nng_close(s) == 0);
}

static void
test_xsurveyor_raw(void)
{
	nng_socket s;
	bool       b;

	TEST_NNG_PASS(nng_surveyor0_open_raw(&s));
	TEST_NNG_PASS(nng_getopt_bool(s, NNG_OPT_RAW, &b));
	TEST_CHECK(b);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_xsurvey_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_surveyor0_open_raw(&s));
	TEST_NNG_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_xsurvey_poll_writeable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;

	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
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

static void
test_xsurvey_poll_readable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_getopt_int(surv, NNG_OPT_RECVFD, &fd));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));

	TEST_CHECK(fd >= 0);

	// Not readable if not connected!
	TEST_CHECK(testutil_pollfd(fd) == false);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(surv, resp));
	TEST_CHECK(testutil_pollfd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	// Request ID
	TEST_NNG_PASS(nng_msg_append_u32(msg, 0x80000000));
	TEST_NNG_PASS(nng_sendmsg(surv, msg, 0));

	TEST_NNG_PASS(nng_recvmsg(resp, &msg, 0));
	TEST_NNG_PASS(nng_sendmsg(resp, msg, 0));

	testutil_sleep(100);

	TEST_CHECK(testutil_pollfd(fd) == true);

	// and receiving makes it no longer ready
	TEST_NNG_PASS(nng_recvmsg(surv, &msg, 0));
	nng_msg_free(msg);
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xsurvey_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_surveyor0_open_raw(&s1));
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

static void
test_xsurvey_recv_aio_stopped(void)
{
	nng_socket surv;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_stop(aio);
	nng_recv_aio(surv, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	TEST_NNG_PASS(nng_close(surv));
	nng_aio_free(aio);
}

static void
test_xsurvey_recv_garbage(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	uint32_t   req_id;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_append_u32(m, 0x80000000));
	TEST_NNG_PASS(nng_sendmsg(surv, m, 0));

	TEST_NNG_PASS(nng_recvmsg(resp, &m, 0));

	// The message will have a header that contains the 32-bit pipe ID,
	// followed by the 32-bit request ID.  We will discard the request
	// ID before sending it out.
	TEST_CHECK(nng_msg_header_len(m) == 8);
	TEST_NNG_PASS(nng_msg_header_chop_u32(m, &req_id));
	TEST_CHECK(req_id == 0x80000000);

	TEST_NNG_PASS(nng_sendmsg(resp, m, 0));
	TEST_NNG_FAIL(nng_recvmsg(surv, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xsurvey_recv_header(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	nng_pipe   p;
	uint32_t   id;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry_ex(surv, resp, NULL, NULL, &p));

	// Simulate a few hops.
	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p)));
	TEST_NNG_PASS(nng_msg_header_append_u32(m, 0x2));
	TEST_NNG_PASS(nng_msg_header_append_u32(m, 0x1));
	TEST_NNG_PASS(nng_msg_header_append_u32(m, 0x80000123u));

	TEST_NNG_PASS(nng_sendmsg(resp, m, 0));

	TEST_NNG_PASS(nng_recvmsg(surv, &m, 0));
	TEST_CHECK(nng_msg_header_len(m) == 12);
	TEST_NNG_PASS(nng_msg_header_trim_u32(m, &id));
	TEST_CHECK(id == 0x2);
	TEST_NNG_PASS(nng_msg_header_trim_u32(m, &id));
	TEST_CHECK(id == 0x1);
	TEST_NNG_PASS(nng_msg_header_trim_u32(m, &id));
	TEST_CHECK(id == 0x80000123u);

	nng_msg_free(m);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xsurvey_close_during_recv(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	nng_pipe   p1;
	nng_pipe   p2;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_SENDBUF, 20));

	TEST_NNG_PASS(testutil_marry_ex(surv, resp, NULL, &p1, &p2));
	TEST_CHECK(nng_pipe_id(p1) > 0);
	TEST_CHECK(nng_pipe_id(p2) > 0);

	for (unsigned i = 0; i < 20; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p2)));
		TEST_NNG_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		testutil_sleep(10);
		TEST_NNG_PASS(nng_sendmsg(resp, m, 0));
	}
	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xsurvey_close_pipe_during_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	nng_pipe   p1;
	nng_pipe   p2;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_RECVBUF, 5));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_SENDBUF, 20));

	TEST_NNG_PASS(testutil_marry_ex(surv, resp, NULL, &p1, &p2));
	TEST_CHECK(nng_pipe_id(p1) > 0);
	TEST_CHECK(nng_pipe_id(p2) > 0);

	for (unsigned i = 0; i < 20; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		testutil_sleep(10);
		TEST_NNG_PASS(nng_sendmsg(surv, m, 0));
	}

	TEST_NNG_PASS(nng_pipe_close(p1));
	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xsurvey_ttl_option(void)
{
	nng_socket  s;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	TEST_NNG_PASS(nng_surveyor0_open_raw(&s));

	TEST_NNG_PASS(nng_setopt_int(s, opt, 1));
	TEST_NNG_FAIL(nng_setopt_int(s, opt, 0), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(s, opt, -1), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(s, opt, 16), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(s, opt, 256), NNG_EINVAL);
	TEST_NNG_PASS(nng_setopt_int(s, opt, 3));
	TEST_NNG_PASS(nng_getopt_int(s, opt, &v));
	TEST_CHECK(v == 3);
	v  = 0;
	sz = sizeof(v);
	TEST_NNG_PASS(nng_getopt(s, opt, &v, &sz));
	TEST_CHECK(v == 3);
	TEST_CHECK(sz == sizeof(v));

	TEST_CHECK(nng_setopt(s, opt, "", 1) == NNG_EINVAL);
	sz = 1;
	TEST_CHECK(nng_getopt(s, opt, &v, &sz) == NNG_EINVAL);
	TEST_CHECK(nng_setopt_bool(s, opt, true) == NNG_EBADTYPE);
	TEST_CHECK(nng_getopt_bool(s, opt, &b) == NNG_EBADTYPE);

	TEST_CHECK(nng_close(s) == 0);
}

static void
test_xsurvey_broadcast(void)
{
	nng_socket resp1;
	nng_socket resp2;
	nng_socket surv;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent0_open(&resp1));
	TEST_NNG_PASS(nng_respondent0_open(&resp2));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp1, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp2, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 100));

	TEST_NNG_PASS(testutil_marry(surv, resp1));
	TEST_NNG_PASS(testutil_marry(surv, resp2));

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_header_append_u32(m, 0x80000002u));
	TEST_NNG_PASS(nng_msg_append(m, "hello", 6));

	TEST_NNG_PASS(nng_sendmsg(surv, m, 0));
	TEST_NNG_RECV_STR(resp1, "hello");
	TEST_NNG_RECV_STR(resp2, "hello");

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp1));
	TEST_NNG_PASS(nng_close(resp2));
}

TEST_LIST = {
	{ "xsurvey identity", test_xsurveyor_identity },
	{ "xsurvey raw", test_xsurveyor_raw },
	{ "xsurvey no context", test_xsurvey_no_context },
	{ "xsurvey poll readable", test_xsurvey_poll_readable },
	{ "xsurvey poll writable", test_xsurvey_poll_writeable },
	{ "xsurvey validate peer", test_xsurvey_validate_peer },
	{ "xsurvey recv aio stopped", test_xsurvey_recv_aio_stopped },
	{ "xsurvey recv garbage", test_xsurvey_recv_garbage },
	{ "xsurvey recv header", test_xsurvey_recv_header },
	{ "xsurvey close during recv", test_xsurvey_close_during_recv },
	{ "xsurvey close pipe during send",
	    test_xsurvey_close_pipe_during_send },
	{ "xsurvey ttl option", test_xsurvey_ttl_option },
	{ "xsurvey broadcast", test_xsurvey_broadcast },
	{ NULL, NULL },
};
