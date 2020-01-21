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

static void
test_xreq_identity(void)
{
	nng_socket s;
	int        p1, p2;
	char *     n1;
	char *     n2;

	TEST_NNG_PASS(nng_req0_open_raw(&s));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PROTO, &p1));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PEER, &p2));
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PROTONAME, &n1));
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PEERNAME, &n2));
	TEST_NNG_PASS(nng_close(s));
	TEST_CHECK(p1 == NNG_REQ0_SELF);
	TEST_CHECK(p2 == NNG_REQ0_PEER);
	TEST_CHECK(strcmp(n1, NNG_REQ0_SELF_NAME) == 0);
	TEST_CHECK(strcmp(n2, NNG_REQ0_PEER_NAME) == 0);
	nng_strfree(n1);
	nng_strfree(n2);
}

static void
test_xreq_raw(void)
{
	nng_socket s;
	bool       b;

	TEST_NNG_PASS(nng_req0_open_raw(&s));
	TEST_NNG_PASS(nng_getopt_bool(s, NNG_OPT_RAW, &b));
	TEST_CHECK(b);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_xreq_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_req0_open_raw(&s));
	TEST_NNG_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_close(s));
}

static void
test_xreq_poll_writeable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;

	TEST_NNG_PASS(nng_req0_open_raw(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_getopt_int(req, NNG_OPT_SENDFD, &fd));
	TEST_CHECK(fd >= 0);

	// We can't write until we have a connection.
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(testutil_marry(req, rep));

	// Now it's writable.
	TEST_CHECK(testutil_pollfd(fd) == true);

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

static void
test_xreq_poll_readable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_req0_open_raw(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_getopt_int(req, NNG_OPT_RECVFD, &fd));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));

	TEST_CHECK(fd >= 0);

	// Not readable if not connected!
	TEST_CHECK(testutil_pollfd(fd) == false);

	// Even after connect (no message yet)
	TEST_NNG_PASS(testutil_marry(req, rep));
	TEST_CHECK(testutil_pollfd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	// Request ID
	TEST_NNG_PASS(nng_msg_append_u32(msg, 0x80000000));
	TEST_NNG_PASS(nng_sendmsg(req, msg, 0));

	TEST_NNG_PASS(nng_recvmsg(rep, &msg, 0));
	TEST_NNG_PASS(nng_sendmsg(rep, msg, 0));

	testutil_sleep(100);

	TEST_CHECK(testutil_pollfd(fd) == true);

	// and receiving makes it no longer ready
	TEST_NNG_PASS(nng_recvmsg(req, &msg, 0));
	nng_msg_free(msg);
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

static void
test_xreq_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_req0_open_raw(&s1));
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

static void
test_xreq_recv_aio_stopped(void)
{
	nng_socket req;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_req0_open_raw(&req));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_stop(aio);
	nng_recv_aio(req, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	TEST_NNG_PASS(nng_close(req));
	nng_aio_free(aio);
}

static void
test_xreq_recv_garbage(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	uint32_t   req_id;

	TEST_NNG_PASS(nng_rep0_open_raw(&rep));
	TEST_NNG_PASS(nng_req0_open_raw(&req));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry(req, rep));

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_append_u32(m, 0x80000000));
	TEST_NNG_PASS(nng_sendmsg(req, m, 0));

	TEST_NNG_PASS(nng_recvmsg(rep, &m, 0));

	// The message will have a header that contains the 32-bit pipe ID,
	// followed by the 32-bit request ID.  We will discard the request
	// ID before sending it out.
	TEST_CHECK(nng_msg_header_len(m) == 8);
	TEST_NNG_PASS(nng_msg_header_chop_u32(m, &req_id));
	TEST_CHECK(req_id == 0x80000000);

	TEST_NNG_PASS(nng_sendmsg(rep, m, 0));
	TEST_NNG_FAIL(nng_recvmsg(req, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

static void
test_xreq_recv_header(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	nng_pipe   p1, p2;
	uint32_t   id;

	TEST_NNG_PASS(nng_rep0_open_raw(&rep));
	TEST_NNG_PASS(nng_req0_open_raw(&req));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry_ex(req, rep, NULL, &p1, &p2));

	// Simulate a few hops.
	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p2)));
	TEST_NNG_PASS(nng_msg_header_append_u32(m, 0x2));
	TEST_NNG_PASS(nng_msg_header_append_u32(m, 0x1));
	TEST_NNG_PASS(nng_msg_header_append_u32(m, 0x80000123u));

	TEST_NNG_PASS(nng_sendmsg(rep, m, 0));

	TEST_NNG_PASS(nng_recvmsg(req, &m, 0));
	TEST_CHECK(nng_msg_header_len(m) == 12);
	TEST_NNG_PASS(nng_msg_header_trim_u32(m, &id));
	TEST_CHECK(id == 0x2);
	TEST_NNG_PASS(nng_msg_header_trim_u32(m, &id));
	TEST_CHECK(id == 0x1);
	TEST_NNG_PASS(nng_msg_header_trim_u32(m, &id));
	TEST_CHECK(id == 0x80000123u);

	nng_msg_free(m);

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

static void
test_xreq_close_during_recv(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	nng_pipe   p1;
	nng_pipe   p2;

	TEST_NNG_PASS(nng_rep0_open_raw(&rep));
	TEST_NNG_PASS(nng_req0_open_raw(&req));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_RECVBUF, 5));
	TEST_NNG_PASS(nng_setopt_int(rep, NNG_OPT_SENDBUF, 20));

	TEST_NNG_PASS(testutil_marry_ex(req, rep, NULL, &p1, &p2));
	TEST_CHECK(nng_pipe_id(p1) > 0);
	TEST_CHECK(nng_pipe_id(p2) > 0);

	for (unsigned i = 0; i < 20; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p2)));
		TEST_NNG_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		testutil_sleep(10);
		TEST_NNG_PASS(nng_sendmsg(rep, m, 0));
	}
	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

static void
test_xreq_close_pipe_during_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	nng_pipe   p1;
	nng_pipe   p2;

	TEST_NNG_PASS(nng_rep0_open_raw(&rep));
	TEST_NNG_PASS(nng_req0_open_raw(&req));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_int(rep, NNG_OPT_RECVBUF, 5));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_SENDBUF, 20));

	TEST_NNG_PASS(testutil_marry_ex(req, rep, NULL, &p1, &p2));
	TEST_CHECK(nng_pipe_id(p1) > 0);
	TEST_CHECK(nng_pipe_id(p2) > 0);

	for (unsigned i = 0; i < 20; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		testutil_sleep(10);
		TEST_NNG_PASS(nng_sendmsg(req, m, 0));
	}

	TEST_NNG_PASS(nng_pipe_close(p1));
	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

static void
test_xreq_ttl_option(void)
{
	nng_socket  rep;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	TEST_NNG_PASS(nng_req0_open_raw(&rep));

	TEST_NNG_PASS(nng_setopt_int(rep, opt, 1));
	TEST_NNG_FAIL(nng_setopt_int(rep, opt, 0), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(rep, opt, -1), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(rep, opt, 16), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(rep, opt, 256), NNG_EINVAL);
	TEST_NNG_PASS(nng_setopt_int(rep, opt, 3));
	TEST_NNG_PASS(nng_getopt_int(rep, opt, &v));
	TEST_CHECK(v == 3);
	v  = 0;
	sz = sizeof(v);
	TEST_NNG_PASS(nng_getopt(rep, opt, &v, &sz));
	TEST_CHECK(v == 3);
	TEST_CHECK(sz == sizeof(v));

	TEST_CHECK(nng_setopt(rep, opt, "", 1) == NNG_EINVAL);
	sz = 1;
	TEST_CHECK(nng_getopt(rep, opt, &v, &sz) == NNG_EINVAL);
	TEST_CHECK(nng_setopt_bool(rep, opt, true) == NNG_EBADTYPE);
	TEST_CHECK(nng_getopt_bool(rep, opt, &b) == NNG_EBADTYPE);

	TEST_CHECK(nng_close(rep) == 0);
}

TEST_LIST = {
	{ "xreq identity", test_xreq_identity },
	{ "xreq raw", test_xreq_raw },
	{ "xreq no context", test_xreq_no_context },
	{ "xreq poll readable", test_xreq_poll_readable },
	{ "xreq poll writable", test_xreq_poll_writeable },
	{ "xreq validate peer", test_xreq_validate_peer },
	{ "xreq recv aio stopped", test_xreq_recv_aio_stopped },
	{ "xreq recv garbage", test_xreq_recv_garbage },
	{ "xreq recv header", test_xreq_recv_header },
	{ "xreq close during recv", test_xreq_close_during_recv },
	{ "xreq close pipe during send", test_xreq_close_pipe_during_send },
	{ "xreq ttl option", test_xreq_ttl_option },
	{ NULL, NULL },
};
