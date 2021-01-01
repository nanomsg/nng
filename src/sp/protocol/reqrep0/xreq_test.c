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
test_xreq_identity(void)
{
	nng_socket s;
	int        p1, p2;
	char *     n1;
	char *     n2;

	NUTS_PASS(nng_req0_open_raw(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p1));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p2));
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n1));
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n2));
	NUTS_CLOSE(s);
	NUTS_TRUE(p1 == NNG_REQ0_SELF);
	NUTS_TRUE(p2 == NNG_REQ0_PEER);
	NUTS_MATCH(n1, NNG_REQ0_SELF_NAME);
	NUTS_MATCH(n2, NNG_REQ0_PEER_NAME);
	nng_strfree(n1);
	nng_strfree(n2);
}

static void
test_xreq_raw(void)
{
	nng_socket s;
	bool       b;

	NUTS_PASS(nng_req0_open_raw(&s));
	NUTS_PASS(nng_socket_get_bool(s, NNG_OPT_RAW, &b));
	NUTS_TRUE(b);
	NUTS_CLOSE(s);
}

static void
test_xreq_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	NUTS_PASS(nng_req0_open_raw(&s));
	NUTS_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_xreq_poll_writeable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;

	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_get_int(req, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// We can't write until we have a connection.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_MARRY(req, rep);

	// Now it's writable.
	NUTS_TRUE(nuts_poll_fd(fd) == true);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xreq_poll_readable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;
	nng_msg *  msg;

	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_get_int(req, NNG_OPT_RECVFD, &fd));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(req, rep);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	// Request ID
	NUTS_PASS(nng_msg_append_u32(msg, 0x80000000));
	NUTS_PASS(nng_sendmsg(req, msg, 0));

	NUTS_PASS(nng_recvmsg(rep, &msg, 0));
	NUTS_PASS(nng_sendmsg(rep, msg, 0));

	NUTS_SLEEP(100);

	NUTS_TRUE(nuts_poll_fd(fd) == true);

	// and receiving makes it no longer ready
	NUTS_PASS(nng_recvmsg(req, &msg, 0));
	nng_msg_free(msg);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xreq_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char *     addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_req0_open_raw(&s1));
	NUTS_PASS(nng_req0_open(&s2));

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
test_xreq_recv_aio_stopped(void)
{
	nng_socket req;
	nng_aio *  aio;

	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_stop(aio);
	nng_recv_aio(req, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(req);
	nng_aio_free(aio);
}

static void
test_xreq_recv_garbage(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	uint32_t   req_id;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(req, rep);

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 0x80000000));
	NUTS_PASS(nng_sendmsg(req, m, 0));

	NUTS_PASS(nng_recvmsg(rep, &m, 0));

	// The message will have a header that contains the 32-bit pipe ID,
	// followed by the 32-bit request ID.  We will discard the request
	// ID before sending it out.
	NUTS_TRUE(nng_msg_header_len(m) == 8);
	NUTS_PASS(nng_msg_header_chop_u32(m, &req_id));
	NUTS_TRUE(req_id == 0x80000000);

	NUTS_PASS(nng_sendmsg(rep, m, 0));
	NUTS_FAIL(nng_recvmsg(req, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xreq_recv_header(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	nng_pipe   p1, p2;
	uint32_t   id;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY_EX(req, rep, NULL, &p1, &p2);

	// Simulate a few hops.
	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p2)));
	NUTS_PASS(nng_msg_header_append_u32(m, 0x2));
	NUTS_PASS(nng_msg_header_append_u32(m, 0x1));
	NUTS_PASS(nng_msg_header_append_u32(m, 0x80000123u));

	NUTS_PASS(nng_sendmsg(rep, m, 0));

	NUTS_PASS(nng_recvmsg(req, &m, 0));
	NUTS_TRUE(nng_msg_header_len(m) == 12);
	NUTS_PASS(nng_msg_header_trim_u32(m, &id));
	NUTS_TRUE(id == 0x2);
	NUTS_PASS(nng_msg_header_trim_u32(m, &id));
	NUTS_TRUE(id == 0x1);
	NUTS_PASS(nng_msg_header_trim_u32(m, &id));
	NUTS_TRUE(id == 0x80000123u);

	nng_msg_free(m);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xreq_close_during_recv(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	nng_pipe   p1;
	nng_pipe   p2;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_RECVBUF, 5));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_SENDBUF, 20));

	NUTS_MARRY_EX(req, rep, NULL, &p1, &p2);
	NUTS_TRUE(nng_pipe_id(p1) > 0);
	NUTS_TRUE(nng_pipe_id(p2) > 0);

	for (unsigned i = 0; i < 20; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p2)));
		NUTS_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		NUTS_SLEEP(10);
		NUTS_PASS(nng_sendmsg(rep, m, 0));
	}
	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xreq_close_pipe_during_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	nng_pipe   p1;
	nng_pipe   p2;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_RECVBUF, 5));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 20));

	NUTS_MARRY_EX(req, rep, NULL, &p1, &p2);
	NUTS_TRUE(nng_pipe_id(p1) > 0);
	NUTS_TRUE(nng_pipe_id(p2) > 0);

	for (unsigned i = 0; i < 20; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		NUTS_SLEEP(10);
		NUTS_PASS(nng_sendmsg(req, m, 0));
	}

	NUTS_PASS(nng_pipe_close(p1));
	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xreq_ttl_option(void)
{
	nng_socket  rep;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	NUTS_PASS(nng_req0_open_raw(&rep));

	NUTS_PASS(nng_socket_set_int(rep, opt, 1));
	NUTS_FAIL(nng_socket_set_int(rep, opt, 0), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(rep, opt, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(rep, opt, 16), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(rep, opt, 256), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(rep, opt, 3));
	NUTS_PASS(nng_socket_get_int(rep, opt, &v));
	NUTS_TRUE(v == 3);
	v  = 0;
	sz = sizeof(v);
	NUTS_PASS(nng_socket_get(rep, opt, &v, &sz));
	NUTS_TRUE(v == 3);
	NUTS_TRUE(sz == sizeof(v));

	NUTS_TRUE(nng_socket_set(rep, opt, "", 1) == NNG_EINVAL);
	sz = 1;
	NUTS_TRUE(nng_socket_get(rep, opt, &v, &sz) == NNG_EINVAL);
	NUTS_TRUE(nng_socket_set_bool(rep, opt, true) == NNG_EBADTYPE);
	NUTS_TRUE(nng_socket_get_bool(rep, opt, &b) == NNG_EBADTYPE);

	NUTS_TRUE(nng_close(rep) == 0);
}

NUTS_TESTS = {
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
