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

static void
test_xresp_identity(void)
{
	nng_socket s;
	int        p1, p2;
	char *     n1;
	char *     n2;

	TEST_NNG_PASS(nng_respondent0_open_raw(&s));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PROTO, &p1));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PEER, &p2));
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PROTONAME, &n1));
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PEERNAME, &n2));
	TEST_NNG_PASS(nng_close(s));
	TEST_CHECK(p1 == NNG_RESPONDENT0_SELF);
	TEST_CHECK(p2 == NNG_RESPONDENT0_PEER);
	TEST_CHECK(strcmp(n1, NNG_RESPONDENT0_SELF_NAME) == 0);
	TEST_CHECK(strcmp(n2, NNG_RESPONDENT0_PEER_NAME) == 0);
	nng_strfree(n1);
	nng_strfree(n2);
}

static void
test_xresp_raw(void)
{
	nng_socket s;
	bool       b;

	TEST_NNG_PASS(nng_respondent0_open_raw(&s));
	TEST_NNG_PASS(nng_getopt_bool(s, NNG_OPT_RAW, &b));
	TEST_CHECK(b);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_xresp_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_respondent0_open_raw(&s));
	TEST_NNG_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_xresp_poll_writeable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_getopt_int(resp, NNG_OPT_SENDFD, &fd));
	TEST_CHECK(fd >= 0);

	// We are always writeable, even before connect.  This is so that
	// back-pressure from a bad peer can't trash others.  We assume
	// that peers won't send us requests faster than they can consume
	// the answers.  If they do, they will lose their answers.
	TEST_CHECK(testutil_pollfd(fd) == true);

	TEST_NNG_PASS(testutil_marry(surv, resp));

	// Now it's writable.
	TEST_CHECK(testutil_pollfd(fd) == true);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xresp_poll_readable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_getopt_int(resp, NNG_OPT_RECVFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not readable if not connected!
	TEST_CHECK(testutil_pollfd(fd) == false);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(surv, resp));
	TEST_CHECK(testutil_pollfd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	TEST_NNG_SEND_STR(surv, "abc");
	testutil_sleep(100);

	TEST_CHECK(testutil_pollfd(fd) == true);

	// and receiving makes it no longer ready
	TEST_NNG_PASS(nng_recvmsg(resp, &msg, 0));
	nng_msg_free(msg);
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xresp_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_respondent0_open_raw(&s1));
	TEST_NNG_PASS(nng_respondent0_open(&s2));

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
test_xresp_close_pipe_before_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_pipe   p;
	nng_aio *  aio1;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_aio_alloc(&aio1, NULL, NULL));

	TEST_NNG_PASS(testutil_marry(surv, resp));
	TEST_NNG_SEND_STR(surv, "test");

	nng_recv_aio(resp, aio1);
	nng_aio_wait(aio1);
	TEST_NNG_PASS(nng_aio_result(aio1));
	TEST_CHECK((m = nng_aio_get_msg(aio1)) != NULL);
	p = nng_msg_get_pipe(m);
	TEST_NNG_PASS(nng_pipe_close(p));
	TEST_NNG_PASS(nng_sendmsg(resp, m, 0));

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
	nng_aio_free(aio1);
}

static void
test_xresp_close_pipe_during_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_pipe   p;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_SENDBUF, 20));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_RECVBUF, 20));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_SENDBUF, 20));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_RECVBUF, 1));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	TEST_NNG_PASS(nng_msg_alloc(&m, 4));
	TEST_NNG_PASS(nng_msg_append_u32(m, (unsigned) 0x81000000u));
	TEST_NNG_PASS(nng_sendmsg(surv, m, 0));
	TEST_NNG_PASS(nng_recvmsg(resp, &m, 0));
	p = nng_msg_get_pipe(m);
	nng_msg_free(m);

	for (int i = 0; i < 100; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p)));
		TEST_NNG_PASS(
		    nng_msg_header_append_u32(m, (unsigned) i | 0x80000000u));
		// protocol does not exert back-pressure
		TEST_NNG_PASS(nng_sendmsg(resp, m, 0));
	}
	TEST_NNG_PASS(nng_pipe_close(p));

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xresp_close_during_recv(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_RECVBUF, 5));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_SENDBUF, 20));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	for (unsigned i = 0; i < 100; i++) {
		int rv;
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		rv = nng_sendmsg(surv, m, 0);
		if (rv == NNG_ETIMEDOUT) {
			nng_msg_free(m);
			break;
		}
	}
	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xresp_recv_aio_stopped(void)
{
	nng_socket resp;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_stop(aio);
	nng_recv_aio(resp, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	TEST_NNG_PASS(nng_close(resp));
	nng_aio_free(aio);
}

static void
test_xresp_send_no_header(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;

	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	TEST_NNG_PASS(nng_msg_alloc(&m, 4));
	TEST_NNG_PASS(nng_sendmsg(resp, m, 0));
	TEST_NNG_FAIL(nng_recvmsg(resp, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xresp_recv_garbage(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	TEST_NNG_PASS(nng_msg_alloc(&m, 4));
	TEST_NNG_PASS(nng_msg_append_u32(m, 1u));
	TEST_NNG_PASS(nng_sendmsg(surv, m, 0));
	TEST_NNG_FAIL(nng_recvmsg(resp, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_xresp_ttl_option(void)
{
	nng_socket  resp;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));

	TEST_NNG_PASS(nng_setopt_int(resp, opt, 1));
	TEST_NNG_FAIL(nng_setopt_int(resp, opt, 0), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(resp, opt, -1), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(resp, opt, 16), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(resp, opt, 256), NNG_EINVAL);
	TEST_NNG_PASS(nng_setopt_int(resp, opt, 3));
	TEST_NNG_PASS(nng_getopt_int(resp, opt, &v));
	TEST_CHECK(v == 3);
	v  = 0;
	sz = sizeof(v);
	TEST_NNG_PASS(nng_getopt(resp, opt, &v, &sz));
	TEST_CHECK(v == 3);
	TEST_CHECK(sz == sizeof(v));

	TEST_CHECK(nng_setopt(resp, opt, "", 1) == NNG_EINVAL);
	sz = 1;
	TEST_CHECK(nng_getopt(resp, opt, &v, &sz) == NNG_EINVAL);
	TEST_CHECK(nng_setopt_bool(resp, opt, true) == NNG_EBADTYPE);
	TEST_CHECK(nng_getopt_bool(resp, opt, &b) == NNG_EBADTYPE);

	TEST_CHECK(nng_close(resp) == 0);
}

static void
test_xresp_ttl_drop(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent0_open_raw(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_MAXTTL, 3));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	// Send messages.  Note that xresp implicitly adds a hop on receive.

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_append_u32(m, 1u)); // 2 hops
	TEST_NNG_PASS(nng_msg_append_u32(m, 0x80000001u));
	TEST_NNG_PASS(nng_msg_append(m, "PASS1", 6));
	TEST_NNG_PASS(nng_sendmsg(surv, m, 0));

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_append_u32(m, 1u)); // 4 hops -- discard!
	TEST_NNG_PASS(nng_msg_append_u32(m, 2u));
	TEST_NNG_PASS(nng_msg_append_u32(m, 3u));
	TEST_NNG_PASS(nng_msg_append_u32(m, 0x80000002u));
	TEST_NNG_PASS(nng_msg_append(m, "FAIL2", 6));
	TEST_NNG_PASS(nng_sendmsg(surv, m, 0));

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_append_u32(m, 1u)); // 3 hops - passes
	TEST_NNG_PASS(nng_msg_append_u32(m, 2u));
	TEST_NNG_PASS(nng_msg_append_u32(m, 0x80000003u));
	TEST_NNG_PASS(nng_msg_append(m, "PASS3", 6));
	TEST_NNG_PASS(nng_sendmsg(surv, m, 0));

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_append_u32(m, 1u)); // 4 hops -- discard!
	TEST_NNG_PASS(nng_msg_append_u32(m, 2u));
	TEST_NNG_PASS(nng_msg_append_u32(m, 3u));
	TEST_NNG_PASS(nng_msg_append_u32(m, 0x80000003u));
	TEST_NNG_PASS(nng_msg_append(m, "FAIL4", 6));
	TEST_NNG_PASS(nng_sendmsg(surv, m, 0));

	// So on receive we should see 80000001 and 80000003.
	TEST_NNG_PASS(nng_recvmsg(resp, &m, 0));
	TEST_CHECK(nng_msg_header_len(m) == 12);
	TEST_CHECK(nng_msg_len(m) == 6);
	TEST_CHECK(strcmp(nng_msg_body(m), "PASS1") == 0);
	nng_msg_free(m);

	TEST_NNG_PASS(nng_recvmsg(resp, &m, 0));
	TEST_CHECK(nng_msg_header_len(m) == 16); // 3 hops + ID
	TEST_CHECK(nng_msg_len(m) == 6);
	TEST_CHECK(strcmp(nng_msg_body(m), "PASS3") == 0);
	nng_msg_free(m);

	TEST_NNG_FAIL(nng_recvmsg(resp, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

TEST_LIST = {
	{ "xrespond identity", test_xresp_identity },
	{ "xrespond raw", test_xresp_raw },
	{ "xrespond no context", test_xresp_no_context },
	{ "xrespond poll readable", test_xresp_poll_readable },
	{ "xrespond poll writable", test_xresp_poll_writeable },
	{ "xrespond validate peer", test_xresp_validate_peer },
	{ "xrespond close pipe before send",
	    test_xresp_close_pipe_before_send },
	{ "xrespond close pipe during send",
	    test_xresp_close_pipe_during_send },
	{ "xrespond close during recv", test_xresp_close_during_recv },
	{ "xrespond recv aio stopped", test_xresp_recv_aio_stopped },
	{ "xrespond send no header", test_xresp_send_no_header },
	{ "xrespond recv garbage", test_xresp_recv_garbage },
	{ "xrespond ttl option", test_xresp_ttl_option },
	{ "xrespond ttl drop", test_xresp_ttl_drop },
	{ NULL, NULL },
};
