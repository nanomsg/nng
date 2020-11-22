//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

static void
test_xsurveyor_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	NUTS_PASS(nng_surveyor0_open_raw(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NNG_SURVEYOR0_SELF); // 0x62
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p));
	NUTS_TRUE(p == NNG_SURVEYOR0_PEER); // 0x62
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n));
	NUTS_MATCH(n, NNG_SURVEYOR0_SELF_NAME);
	nng_strfree(n);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n));
	NUTS_MATCH(n, NNG_SURVEYOR0_PEER_NAME);
	nng_strfree(n);
	NUTS_CLOSE(s);
}

static void
test_xsurveyor_raw(void)
{
	nng_socket s;
	bool       b;

	NUTS_PASS(nng_surveyor0_open_raw(&s));
	NUTS_PASS(nng_socket_get_bool(s, NNG_OPT_RAW, &b));
	NUTS_TRUE(b);
	NUTS_CLOSE(s);
}

static void
test_xsurvey_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	NUTS_PASS(nng_surveyor0_open_raw(&s));
	NUTS_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_xsurvey_poll_writeable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;

	NUTS_PASS(nng_surveyor0_open_raw(&surv));
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

static void
test_xsurvey_poll_readable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;
	nng_msg *  msg;

	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_socket_get_int(surv, NNG_OPT_RECVFD, &fd));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));

	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(surv, resp);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	// Request ID
	NUTS_PASS(nng_msg_append_u32(msg, 0x80000000));
	NUTS_PASS(nng_sendmsg(surv, msg, 0));

	NUTS_PASS(nng_recvmsg(resp, &msg, 0));
	NUTS_PASS(nng_sendmsg(resp, msg, 0));

	NUTS_SLEEP(100);

	NUTS_TRUE(nuts_poll_fd(fd) );

	// and receiving makes it no longer ready
	NUTS_PASS(nng_recvmsg(surv, &msg, 0));
	nng_msg_free(msg);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_xsurvey_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       *addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_surveyor0_open_raw(&s1));
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

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	nng_stats_free(stats);
}

static void
test_xsurvey_recv_aio_stopped(void)
{
	nng_socket surv;
	nng_aio *  aio;

	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_stop(aio);
	nng_recv_aio(surv, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(surv);
	nng_aio_free(aio);
}

static void
test_xsurvey_recv_garbage(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	uint32_t   req_id;

	NUTS_PASS(nng_respondent0_open_raw(&resp));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(surv, resp);

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 0x80000000));
	NUTS_PASS(nng_sendmsg(surv, m, 0));

	NUTS_PASS(nng_recvmsg(resp, &m, 0));

	// The message will have a header that contains the 32-bit pipe ID,
	// followed by the 32-bit request ID.  We will discard the request
	// ID before sending it out.
	NUTS_TRUE(nng_msg_header_len(m) == 8);
	NUTS_PASS(nng_msg_header_chop_u32(m, &req_id));
	NUTS_TRUE(req_id == 0x80000000);

	NUTS_PASS(nng_sendmsg(resp, m, 0));
	NUTS_FAIL(nng_recvmsg(surv, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_xsurvey_recv_header(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	nng_pipe   p;
	uint32_t   id;

	NUTS_PASS(nng_respondent0_open_raw(&resp));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY_EX(surv, resp, NULL, NULL, &p);

	// Simulate a few hops.
	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p)));
	NUTS_PASS(nng_msg_header_append_u32(m, 0x2));
	NUTS_PASS(nng_msg_header_append_u32(m, 0x1));
	NUTS_PASS(nng_msg_header_append_u32(m, 0x80000123u));

	NUTS_PASS(nng_sendmsg(resp, m, 0));

	NUTS_PASS(nng_recvmsg(surv, &m, 0));
	NUTS_TRUE(nng_msg_header_len(m) == 12);
	NUTS_PASS(nng_msg_header_trim_u32(m, &id));
	NUTS_TRUE(id == 0x2);
	NUTS_PASS(nng_msg_header_trim_u32(m, &id));
	NUTS_TRUE(id == 0x1);
	NUTS_PASS(nng_msg_header_trim_u32(m, &id));
	NUTS_TRUE(id == 0x80000123u);

	nng_msg_free(m);

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_xsurvey_close_during_recv(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	nng_pipe   p1;
	nng_pipe   p2;

	NUTS_PASS(nng_respondent0_open_raw(&resp));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_int(resp, NNG_OPT_SENDBUF, 20));

	NUTS_MARRY_EX(surv, resp, NULL, &p1, &p2);
	NUTS_TRUE(nng_pipe_id(p1) > 0);
	NUTS_TRUE(nng_pipe_id(p2) > 0);

	for (unsigned i = 0; i < 20; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p2)));
		NUTS_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		NUTS_SLEEP(10);
		NUTS_PASS(nng_sendmsg(resp, m, 0));
	}
	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_xsurvey_close_pipe_during_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	nng_pipe   p1;
	nng_pipe   p2;

	NUTS_PASS(nng_respondent0_open_raw(&resp));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_int(resp, NNG_OPT_RECVBUF, 5));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_SENDBUF, 20));

	NUTS_MARRY_EX(surv, resp, NULL, &p1, &p2);
	NUTS_TRUE(nng_pipe_id(p1) > 0);
	NUTS_TRUE(nng_pipe_id(p2) > 0);

	for (unsigned i = 0; i < 20; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		NUTS_SLEEP(10);
		NUTS_PASS(nng_sendmsg(surv, m, 0));
	}

	NUTS_PASS(nng_pipe_close(p1));
	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_xsurvey_ttl_option(void)
{
	nng_socket  s;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	NUTS_PASS(nng_surveyor0_open_raw(&s));

	NUTS_PASS(nng_socket_set_int(s, opt, 1));
	NUTS_FAIL(nng_socket_set_int(s, opt, 0), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, opt, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, opt, 16), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, opt, 256), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(s, opt, 3));
	NUTS_PASS(nng_socket_get_int(s, opt, &v));
	NUTS_TRUE(v == 3);
	v  = 0;
	sz = sizeof(v);
	NUTS_PASS(nng_socket_get(s, opt, &v, &sz));
	NUTS_TRUE(v == 3);
	NUTS_TRUE(sz == sizeof(v));

	NUTS_FAIL(nng_socket_set(s, opt, "", 1) , NNG_EINVAL);
	sz = 1;
	NUTS_FAIL(nng_socket_get(s, opt, &v, &sz) , NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(s, opt, true) , NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(s, opt, &b) , NNG_EBADTYPE);

	NUTS_CLOSE(s);
}

static void
test_xsurvey_broadcast(void)
{
	nng_socket resp1;
	nng_socket resp2;
	nng_socket surv;
	nng_msg *  m;

	NUTS_PASS(nng_respondent0_open(&resp1));
	NUTS_PASS(nng_respondent0_open(&resp2));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_ms(resp1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp2, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 100));

	NUTS_MARRY(surv, resp1);
	NUTS_MARRY(surv, resp2);

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_header_append_u32(m, 0x80000002u));
	NUTS_PASS(nng_msg_append(m, "hello", 6));

	NUTS_PASS(nng_sendmsg(surv, m, 0));
	NUTS_RECV(resp1, "hello");
	NUTS_RECV(resp2, "hello");

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp1);
	NUTS_CLOSE(resp2);
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
