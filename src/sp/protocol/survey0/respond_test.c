//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

void
test_resp_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	NUTS_PASS(nng_respondent0_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NNG_RESPONDENT0_SELF);
	NUTS_TRUE(nng_socket_get_int(s, NNG_OPT_PEER, &p) == 0);
	NUTS_TRUE(p == NNG_RESPONDENT0_PEER);
	NUTS_TRUE(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n) == 0);
	NUTS_MATCH(n, NNG_RESPONDENT0_SELF_NAME);
	nng_strfree(n);
	NUTS_TRUE(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n) == 0);
	NUTS_MATCH(n, NNG_RESPONDENT0_PEER_NAME);
	nng_strfree(n);
	NUTS_CLOSE(s);
}

void
test_resp_send_bad_state(void)
{
	nng_socket resp;
	nng_msg *  msg = NULL;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_FAIL(nng_sendmsg(resp, msg, 0), NNG_ESTATE);
	nng_msg_free(msg);
	NUTS_CLOSE(resp);
}

void
test_resp_poll_writeable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_socket_get_int(resp, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not writable before connect.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_MARRY(surv, resp);

	// Still not writable.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// If we get a job, *then* we become writable
	NUTS_SEND(surv, "abc");
	NUTS_RECV(resp, "abc");
	NUTS_TRUE(nuts_poll_fd(fd) == true);

	// And is no longer writable once we send a message
	NUTS_SEND(resp, "def");
	NUTS_TRUE(nuts_poll_fd(fd) == false);
	// Even after receiving it
	NUTS_RECV(surv, "def");
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

void
test_resp_poll_readable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;
	nng_msg *  msg;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_socket_get_int(resp, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(surv, resp);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_SEND(surv, "abc");
	NUTS_SLEEP(100);

	NUTS_TRUE(nuts_poll_fd(fd) == true);

	// and receiving makes it no longer ready
	NUTS_PASS(nng_recvmsg(resp, &msg, 0));
	nng_msg_free(msg);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// TODO verify unsolicited response

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

void
test_resp_context_no_poll(void)
{
	int        fd;
	nng_socket resp;
	nng_ctx    ctx;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_ctx_open(&ctx, resp));
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	NUTS_PASS(nng_ctx_close(ctx));
	NUTS_CLOSE(resp);
}

void
test_resp_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char *     addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_respondent0_open(&s1));
	NUTS_PASS(nng_respondent0_open(&s2));

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

void
test_resp_double_recv(void)
{
	nng_socket s1;
	nng_aio *  aio1;
	nng_aio *  aio2;

	NUTS_PASS(nng_respondent0_open(&s1));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	nng_recv_aio(s1, aio1);
	nng_recv_aio(s1, aio2);

	nng_aio_wait(aio2);
	NUTS_FAIL(nng_aio_result(aio2), NNG_ESTATE);
	NUTS_CLOSE(s1);
	NUTS_FAIL(nng_aio_result(aio1), NNG_ECLOSED);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
}

void
test_resp_close_pipe_before_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_pipe   p;
	nng_aio *  aio1;
	nng_msg *  m;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));

	NUTS_MARRY(surv, resp);
	NUTS_SEND(surv, "test");

	nng_recv_aio(resp, aio1);
	nng_aio_wait(aio1);
	NUTS_PASS(nng_aio_result(aio1));
	NUTS_TRUE((m = nng_aio_get_msg(aio1)) != NULL);
	p = nng_msg_get_pipe(m);
	NUTS_PASS(nng_pipe_close(p));
	NUTS_PASS(nng_sendmsg(resp, m, 0));

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
	nng_aio_free(aio1);
}

void
test_resp_close_pipe_during_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_pipe   p = NNG_PIPE_INITIALIZER;
	nng_msg *  m;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(resp, NNG_OPT_SENDBUF, 20));
	NUTS_PASS(nng_socket_set_int(resp, NNG_OPT_RECVBUF, 20));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_SENDBUF, 20));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_RECVBUF, 1));

	NUTS_MARRY(surv, resp);

	for (int i = 0; i < 100; i++) {
		int rv;
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		NUTS_PASS(nng_sendmsg(surv, m, 0));
		NUTS_PASS(nng_recvmsg(resp, &m, 0));
		p  = nng_msg_get_pipe(m);
		rv = nng_sendmsg(resp, m, 0);
		if (rv == NNG_ETIMEDOUT) {
			// Queue is backed up, senders are busy.
			nng_msg_free(m);
			break;
		}
		NUTS_PASS(rv);
	}
	NUTS_PASS(nng_pipe_close(p));

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

void
test_resp_ctx_recv_aio_stopped(void)
{
	nng_socket resp;
	nng_ctx    ctx;
	nng_aio *  aio;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_ctx_open(&ctx, resp));

	nng_aio_stop(aio);
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_PASS(nng_ctx_close(ctx));
	NUTS_CLOSE(resp);
	nng_aio_free(aio);
}

void
test_resp_close_pipe_context_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_pipe   p = NNG_PIPE_INITIALIZER;
	nng_msg *  m;
	nng_ctx    ctx[10];
	nng_aio *  aio[10];
	int        i;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(resp, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(resp, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_RECVBUF, 1));
	for (i = 0; i < 10; i++) {
		NUTS_PASS(nng_ctx_open(&ctx[i], resp));
		NUTS_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
	}

	NUTS_MARRY(surv, resp);

	for (i = 0; i < 10; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		NUTS_PASS(nng_sendmsg(surv, m, 0));
		nng_ctx_recv(ctx[i], aio[i]);
	}
	for (i = 0; i < 10; i++) {
		nng_aio_wait(aio[i]);
		NUTS_PASS(nng_aio_result(aio[i]));
		NUTS_TRUE((m = nng_aio_get_msg(aio[i])) != NULL);
		p = nng_msg_get_pipe(m);
		nng_aio_set_msg(aio[i], m);
		nng_ctx_send(ctx[i], aio[i]);
	}

	// Note that SURVEYOR socket is not reading the results.
	NUTS_PASS(nng_pipe_close(p));

	for (i = 0; i < 10; i++) {
		int rv;
		nng_aio_wait(aio[i]);
		rv = nng_aio_result(aio[i]);
		if (rv != 0) {
			NUTS_FAIL(rv, NNG_ECLOSED);
			nng_msg_free(nng_aio_get_msg(aio[i]));
		}
		nng_aio_free(aio[i]);
		NUTS_PASS(nng_ctx_close(ctx[i]));
	}
	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

void
test_resp_close_context_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;
	nng_ctx    ctx[10];
	nng_aio *  aio[10];
	int        i;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(resp, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(resp, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(surv, NNG_OPT_RECVBUF, 1));
	for (i = 0; i < 10; i++) {
		NUTS_PASS(nng_ctx_open(&ctx[i], resp));
		NUTS_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
	}

	NUTS_MARRY(surv, resp);

	for (i = 0; i < 10; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		NUTS_PASS(nng_sendmsg(surv, m, 0));
		nng_ctx_recv(ctx[i], aio[i]);
	}
	for (i = 0; i < 10; i++) {
		nng_aio_wait(aio[i]);
		NUTS_PASS(nng_aio_result(aio[i]));
		NUTS_TRUE((m = nng_aio_get_msg(aio[i])) != NULL);
		nng_aio_set_msg(aio[i], m);
		nng_ctx_send(ctx[i], aio[i]);
	}

	// Note that REQ socket is not reading the results.
	for (i = 0; i < 10; i++) {
		int rv;
		NUTS_PASS(nng_ctx_close(ctx[i]));
		nng_aio_wait(aio[i]);
		rv = nng_aio_result(aio[i]);
		if (rv != 0) {
			NUTS_FAIL(rv, NNG_ECLOSED);
			nng_msg_free(nng_aio_get_msg(aio[i]));
		}
		nng_aio_free(aio[i]);
	}
	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_resp_ctx_recv_nonblock(void)
{
	nng_socket resp;
	nng_ctx    ctx;
	nng_aio *  aio;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_ctx_open(&ctx, resp));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(resp);
	nng_aio_free(aio);
}

static void
test_resp_ctx_send_nonblock(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  msg;

	NUTS_PASS(nng_surveyor0_open(&surv));
	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_ctx_open(&ctx, resp));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_MARRY(surv, resp);

	NUTS_SEND(surv, "SEND");
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	// message carries over
	msg = nng_aio_get_msg(aio);
	nng_aio_set_msg(aio, msg);
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_send(ctx, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
	nng_aio_free(aio);
	nng_msg_free(msg);
}

void
test_resp_recv_garbage(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_SENDTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(surv, resp);

	NUTS_PASS(nng_msg_alloc(&m, 4));
	NUTS_PASS(nng_msg_append_u32(m, 1u));
	NUTS_PASS(nng_sendmsg(surv, m, 0));
	NUTS_FAIL(nng_recvmsg(resp, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(surv);
	NUTS_CLOSE(resp);
}

static void
test_resp_ttl_option(void)
{
	nng_socket  resp;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	NUTS_PASS(nng_respondent0_open(&resp));

	NUTS_PASS(nng_socket_set_int(resp, opt, 1));
	NUTS_FAIL(nng_socket_set_int(resp, opt, 0), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(resp, opt, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(resp, opt, 16), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(resp, opt, 256), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(resp, opt, 3));
	NUTS_PASS(nng_socket_get_int(resp, opt, &v));
	NUTS_TRUE(v == 3);
	v  = 0;
	sz = sizeof(v);
	NUTS_PASS(nng_socket_get(resp, opt, &v, &sz));
	NUTS_TRUE(v == 3);
	NUTS_TRUE(sz == sizeof(v));

	NUTS_FAIL(nng_socket_set(resp, opt, "", 1), NNG_EINVAL);
	sz = 1;
	NUTS_FAIL(nng_socket_get(resp, opt, &v, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(resp, opt, true), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(resp, opt, &b), NNG_EBADTYPE);

	NUTS_CLOSE(resp);
}

static void
test_resp_ttl_drop(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;

	NUTS_PASS(nng_respondent0_open(&resp));
	NUTS_PASS(nng_surveyor0_open_raw(&surv));
	NUTS_PASS(nng_socket_set_int(resp, NNG_OPT_MAXTTL, 3));
	NUTS_PASS(nng_socket_set_ms(resp, NNG_OPT_RECVTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(surv, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(surv, resp);

	// Send messages.  Note that xrep implicitly adds a hop on receive.

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 1u)); // 2 hops
	NUTS_PASS(nng_msg_append_u32(m, 0x80000001u));
	NUTS_PASS(nng_msg_append(m, "PASS1", 6));
	NUTS_PASS(nng_sendmsg(surv, m, 0));

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 1u)); // 4 hops -- discard!
	NUTS_PASS(nng_msg_append_u32(m, 2u));
	NUTS_PASS(nng_msg_append_u32(m, 3u));
	NUTS_PASS(nng_msg_append_u32(m, 0x80000002u));
	NUTS_PASS(nng_msg_append(m, "FAIL2", 6));
	NUTS_PASS(nng_sendmsg(surv, m, 0));

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 1u)); // 3 hops - passes
	NUTS_PASS(nng_msg_append_u32(m, 2u));
	NUTS_PASS(nng_msg_append_u32(m, 0x80000003u));
	NUTS_PASS(nng_msg_append(m, "PASS3", 6));
	NUTS_PASS(nng_sendmsg(surv, m, 0));

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 1u)); // 4 hops -- discard!
	NUTS_PASS(nng_msg_append_u32(m, 2u));
	NUTS_PASS(nng_msg_append_u32(m, 3u));
	NUTS_PASS(nng_msg_append_u32(m, 0x80000003u));
	NUTS_PASS(nng_msg_append(m, "FAIL4", 6));
	NUTS_PASS(nng_sendmsg(surv, m, 0));

	NUTS_RECV(resp, "PASS1");
	NUTS_RECV(resp, "PASS3");

	NUTS_FAIL(nng_recvmsg(resp, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(resp);
	NUTS_CLOSE(surv);
}

TEST_LIST = {
	{ "respond identity", test_resp_identity },
	{ "respond send bad state", test_resp_send_bad_state },
	{ "respond poll readable", test_resp_poll_readable },
	{ "respond poll writable", test_resp_poll_writeable },
	{ "respond context does not poll", test_resp_context_no_poll },
	{ "respond validate peer", test_resp_validate_peer },
	{ "respond double recv", test_resp_double_recv },
	{ "respond close pipe before send", test_resp_close_pipe_before_send },
	{ "respond close pipe during send", test_resp_close_pipe_during_send },
	{ "respond recv aio ctx stopped", test_resp_ctx_recv_aio_stopped },
	{ "respond close pipe context send",
	    test_resp_close_pipe_context_send },
	{ "respond close context send", test_resp_close_context_send },
	{ "respond context send nonblock", test_resp_ctx_send_nonblock },
	{ "respond context recv nonblock", test_resp_ctx_recv_nonblock },
	{ "respond recv garbage", test_resp_recv_garbage },
	{ "respond ttl option", test_resp_ttl_option },
	{ "respond ttl drop", test_resp_ttl_drop },
	{ NULL, NULL },
};
