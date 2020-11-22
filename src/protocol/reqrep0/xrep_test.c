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
test_xrep_identity(void)
{
	nng_socket s;
	int        p1, p2;
	char *     n1;
	char *     n2;

	NUTS_PASS(nng_rep0_open_raw(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p1));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p2));
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n1));
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n2));
	NUTS_CLOSE(s);
	NUTS_TRUE(p1 == NNG_REP0_SELF);
	NUTS_TRUE(p2 == NNG_REP0_PEER);
	NUTS_MATCH(n1, NNG_REP0_SELF_NAME);
	NUTS_MATCH(n2, NNG_REP0_PEER_NAME);
	nng_strfree(n1);
	nng_strfree(n2);
}

static void
test_xrep_raw(void)
{
	nng_socket s;
	bool       b;

	NUTS_PASS(nng_rep0_open_raw(&s));
	NUTS_PASS(nng_socket_get_bool(s, NNG_OPT_RAW, &b));
	NUTS_TRUE(b);
	NUTS_CLOSE(s);
}

static void
test_xrep_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	NUTS_PASS(nng_rep0_open_raw(&s));
	NUTS_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_xrep_poll_writeable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_socket_get_int(rep, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// We are always writeable, even before connect.  This is so that
	// back-pressure from a bad peer can't trash others.  We assume
	// that peers won't send us requests faster than they can consume
	// the answers.  If they do, they will lose their answers.
	NUTS_TRUE(nuts_poll_fd(fd) == true);

	NUTS_MARRY(req, rep);

	// Now it's writable.
	NUTS_TRUE(nuts_poll_fd(fd) == true);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xrep_poll_readable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;
	nng_msg *  msg;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_socket_get_int(rep, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(req, rep);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_SEND(req, "abc");
	NUTS_SLEEP(100);

	NUTS_TRUE(nuts_poll_fd(fd) == true);

	// and receiving makes it no longer ready
	NUTS_PASS(nng_recvmsg(rep, &msg, 0));
	nng_msg_free(msg);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xrep_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       *addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_rep0_open_raw(&s1));
	NUTS_PASS(nng_rep0_open(&s2));

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

static void
test_xrep_close_pipe_before_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_pipe   p;
	nng_aio *  aio1;
	nng_msg *  m;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));

	NUTS_MARRY(req, rep);
	NUTS_SEND(req, "test");

	nng_recv_aio(rep, aio1);
	nng_aio_wait(aio1);
	NUTS_PASS(nng_aio_result(aio1));
	NUTS_TRUE((m = nng_aio_get_msg(aio1)) != NULL);
	p = nng_msg_get_pipe(m);
	NUTS_PASS(nng_pipe_close(p));
	NUTS_PASS(nng_sendmsg(rep, m, 0));

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
	nng_aio_free(aio1);
}

static void
test_xrep_close_pipe_during_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_pipe   p;
	nng_msg *  m;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_SENDBUF, 20));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_RECVBUF, 20));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 20));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_RECVBUF, 1));

	NUTS_MARRY(req, rep);

	NUTS_PASS(nng_msg_alloc(&m, 4));
	NUTS_PASS(nng_msg_append_u32(m, (unsigned) 0x81000000u));
	NUTS_PASS(nng_sendmsg(req, m, 0));
	NUTS_PASS(nng_recvmsg(rep, &m, 0));
	p = nng_msg_get_pipe(m);
	nng_msg_free(m);

	for (int i = 0; i < 100; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_header_append_u32(m, nng_pipe_id(p)));
		NUTS_PASS(
		    nng_msg_header_append_u32(m, (unsigned) i | 0x80000000u));
		// xrep does not exert back-pressure
		NUTS_PASS(nng_sendmsg(rep, m, 0));
	}
	NUTS_PASS(nng_pipe_close(p));

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xrep_close_during_recv(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_RECVBUF, 5));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 20));

	NUTS_MARRY(req, rep);

	for (unsigned i = 0; i < 100; i++) {
		int rv;
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_header_append_u32(m, i | 0x80000000u));
		rv = nng_sendmsg(req, m, 0);
		if (rv == NNG_ETIMEDOUT) {
			nng_msg_free(m);
			break;
		}
	}
	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xrep_recv_aio_stopped(void)
{
	nng_socket rep;
	nng_aio *  aio;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_stop(aio);
	nng_recv_aio(rep, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(rep);
	nng_aio_free(aio);
}

static void
test_xrep_send_no_header(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;

	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(req, rep);

	NUTS_PASS(nng_msg_alloc(&m, 4));
	NUTS_PASS(nng_sendmsg(rep, m, 0));
	NUTS_FAIL(nng_recvmsg(rep, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xrep_recv_garbage(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(req, rep);

	NUTS_PASS(nng_msg_alloc(&m, 4));
	NUTS_PASS(nng_msg_append_u32(m, 1u));
	NUTS_PASS(nng_sendmsg(req, m, 0));
	NUTS_FAIL(nng_recvmsg(rep, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_xrep_ttl_option(void)
{
	nng_socket  rep;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	NUTS_PASS(nng_rep0_open_raw(&rep));

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

static void
test_xrep_ttl_drop(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_MAXTTL, 3));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(req, rep);

	// Send messages.  Note that xrep implicitly adds a hop on receive.

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 1u)); // 2 hops
	NUTS_PASS(nng_msg_append_u32(m, 0x80000001u));
	NUTS_PASS(nng_msg_append(m, "PASS1", 6));
	NUTS_PASS(nng_sendmsg(req, m, 0));

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 1u)); // 4 hops -- discard!
	NUTS_PASS(nng_msg_append_u32(m, 2u));
	NUTS_PASS(nng_msg_append_u32(m, 3u));
	NUTS_PASS(nng_msg_append_u32(m, 0x80000002u));
	NUTS_PASS(nng_msg_append(m, "FAIL2", 6));
	NUTS_PASS(nng_sendmsg(req, m, 0));

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 1u)); // 3 hops - passes
	NUTS_PASS(nng_msg_append_u32(m, 2u));
	NUTS_PASS(nng_msg_append_u32(m, 0x80000003u));
	NUTS_PASS(nng_msg_append(m, "PASS3", 6));
	NUTS_PASS(nng_sendmsg(req, m, 0));

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 1u)); // 4 hops -- discard!
	NUTS_PASS(nng_msg_append_u32(m, 2u));
	NUTS_PASS(nng_msg_append_u32(m, 3u));
	NUTS_PASS(nng_msg_append_u32(m, 0x80000003u));
	NUTS_PASS(nng_msg_append(m, "FAIL4", 6));
	NUTS_PASS(nng_sendmsg(req, m, 0));

	// So on receive we should see 80000001 and 80000003.
	NUTS_PASS(nng_recvmsg(rep, &m, 0));
	NUTS_TRUE(nng_msg_header_len(m) == 12);
	NUTS_TRUE(nng_msg_len(m) == 6);
	NUTS_TRUE(strcmp(nng_msg_body(m), "PASS1") == 0);
	nng_msg_free(m);

	NUTS_PASS(nng_recvmsg(rep, &m, 0));
	NUTS_TRUE(nng_msg_header_len(m) == 16); // 3 hops + ID
	NUTS_TRUE(nng_msg_len(m) == 6);
	NUTS_TRUE(strcmp(nng_msg_body(m), "PASS3") == 0);
	nng_msg_free(m);

	NUTS_FAIL(nng_recvmsg(rep, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

NUTS_TESTS = {
	{ "xrep identity", test_xrep_identity },
	{ "xrep raw", test_xrep_raw },
	{ "xrep no context", test_xrep_no_context },
	{ "xrep poll readable", test_xrep_poll_readable },
	{ "xrep poll writable", test_xrep_poll_writeable },
	{ "xrep validate peer", test_xrep_validate_peer },
	{ "xrep close pipe before send", test_xrep_close_pipe_before_send },
	{ "xrep close pipe during send", test_xrep_close_pipe_during_send },
	{ "xrep close during recv", test_xrep_close_during_recv },
	{ "xrep recv aio stopped", test_xrep_recv_aio_stopped },
	{ "xrep send no header", test_xrep_send_no_header },
	{ "xrep recv garbage", test_xrep_recv_garbage },
	{ "xrep ttl option", test_xrep_ttl_option },
	{ "xrep ttl drop", test_xrep_ttl_drop },
	{ NULL, NULL },
};
