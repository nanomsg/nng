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
test_rep_identity(void)
{
	nng_socket s;
	int        p1, p2;
	char *     n1;
	char *     n2;

	TEST_NNG_PASS(nng_rep0_open(&s));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PROTO, &p1));
	TEST_NNG_PASS(nng_getopt_int(s, NNG_OPT_PEER, &p2));
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PROTONAME, &n1));
	TEST_NNG_PASS(nng_getopt_string(s, NNG_OPT_PEERNAME, &n2));
	TEST_NNG_PASS(nng_close(s));
	TEST_CHECK(p1 == NNG_REP0_SELF);
	TEST_CHECK(p2 == NNG_REP0_PEER);
	TEST_CHECK(strcmp(n1, NNG_REP0_SELF_NAME) == 0);
	TEST_CHECK(strcmp(n2, NNG_REP0_PEER_NAME) == 0);
	nng_strfree(n1);
	nng_strfree(n2);
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

	// If we get a job, *then* we become writable
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

	// and receiving makes it no longer ready
	TEST_NNG_PASS(nng_recvmsg(rep, &msg, 0));
	nng_msg_free(msg);
	TEST_CHECK(testutil_pollfd(fd) == false);

	// TODO verify unsolicited response

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_rep_context_no_poll(void)
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

void
test_rep_double_recv(void)
{
	nng_socket s1;
	nng_aio *  aio1;
	nng_aio *  aio2;

	TEST_NNG_PASS(nng_rep0_open(&s1));
	TEST_NNG_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	TEST_NNG_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	nng_recv_aio(s1, aio1);
	nng_recv_aio(s1, aio2);

	nng_aio_wait(aio2);
	TEST_NNG_FAIL(nng_aio_result(aio2), NNG_ESTATE);
	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_FAIL(nng_aio_result(aio1), NNG_ECLOSED);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
}

void
test_rep_close_pipe_before_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_pipe   p;
	nng_aio *  aio1;
	nng_msg *  m;

	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_aio_alloc(&aio1, NULL, NULL));

	TEST_NNG_PASS(testutil_marry(req, rep));
	TEST_NNG_SEND_STR(req, "test");

	nng_recv_aio(rep, aio1);
	nng_aio_wait(aio1);
	TEST_NNG_PASS(nng_aio_result(aio1));
	TEST_CHECK((m = nng_aio_get_msg(aio1)) != NULL);
	p = nng_msg_get_pipe(m);
	TEST_NNG_PASS(nng_pipe_close(p));
	TEST_NNG_PASS(nng_sendmsg(rep, m, 0));

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
	nng_aio_free(aio1);
}

void
test_rep_close_pipe_during_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_pipe   p = NNG_PIPE_INITIALIZER;
	nng_msg *  m;

	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_req0_open_raw(&req));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_int(rep, NNG_OPT_SENDBUF, 20));
	TEST_NNG_PASS(nng_setopt_int(rep, NNG_OPT_RECVBUF, 20));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_SENDBUF, 20));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_RECVBUF, 1));

	TEST_NNG_PASS(testutil_marry(req, rep));

	for (int i = 0; i < 100; i++) {
		int rv;
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(
		    nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		TEST_NNG_PASS(nng_sendmsg(req, m, 0));
		TEST_NNG_PASS(nng_recvmsg(rep, &m, 0));
		p  = nng_msg_get_pipe(m);
		rv = nng_sendmsg(rep, m, 0);
		if (rv == NNG_ETIMEDOUT) {
			// Queue is backed up, senders are busy.
			nng_msg_free(m);
			break;
		}
		TEST_NNG_PASS(rv);
	}
	TEST_NNG_PASS(nng_pipe_close(p));

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_rep_ctx_recv_aio_stopped(void)
{
	nng_socket rep;
	nng_ctx    ctx;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(nng_ctx_open(&ctx, rep));

	nng_aio_stop(aio);
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	TEST_NNG_PASS(nng_close(rep));
	nng_aio_free(aio);
}

void
test_rep_close_pipe_context_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_pipe   p = NNG_PIPE_INITIALIZER;
	nng_msg *  m;
	nng_ctx    ctx[100];
	nng_aio *  aio[100];
	int        i;

	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_req0_open_raw(&req));
	for (i = 0; i < 100; i++) {
		TEST_NNG_PASS(nng_ctx_open(&ctx[i], rep));
		TEST_NNG_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
	}
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_int(rep, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(rep, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_RECVBUF, 1));

	TEST_NNG_PASS(testutil_marry(req, rep));

	for (i = 0; i < 100; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(
		    nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		TEST_NNG_PASS(nng_sendmsg(req, m, 0));
		nng_ctx_recv(ctx[i], aio[i]);
	}
	for (i = 0; i < 100; i++) {
		nng_aio_wait(aio[i]);
		TEST_NNG_PASS(nng_aio_result(aio[i]));
		TEST_CHECK((m = nng_aio_get_msg(aio[i])) != NULL);
		p = nng_msg_get_pipe(m);
		nng_aio_set_msg(aio[i], m);
		nng_ctx_send(ctx[i], aio[i]);
	}

	// Note that REQ socket is not reading the results.
	TEST_NNG_PASS(nng_pipe_close(p));

	for (i = 0; i < 100; i++) {
		int rv;
		nng_aio_wait(aio[i]);
		rv = nng_aio_result(aio[i]);
		if (rv != 0) {
			TEST_NNG_FAIL(rv, NNG_ECLOSED);
			nng_msg_free(nng_aio_get_msg(aio[i]));
		}
		nng_aio_free(aio[i]);
		TEST_NNG_PASS(nng_ctx_close(ctx[i]));
	}
	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

void
test_rep_close_context_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	nng_ctx    ctx[100];
	nng_aio *  aio[100];
	int        i;

	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_req0_open_raw(&req));
	for (i = 0; i < 100; i++) {
		TEST_NNG_PASS(nng_ctx_open(&ctx[i], rep));
		TEST_NNG_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
	}
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_int(rep, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(rep, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(req, NNG_OPT_RECVBUF, 1));

	TEST_NNG_PASS(testutil_marry(req, rep));

	for (i = 0; i < 100; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(
		    nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		TEST_NNG_PASS(nng_sendmsg(req, m, 0));
		nng_ctx_recv(ctx[i], aio[i]);
	}
	for (i = 0; i < 100; i++) {
		nng_aio_wait(aio[i]);
		TEST_NNG_PASS(nng_aio_result(aio[i]));
		TEST_CHECK((m = nng_aio_get_msg(aio[i])) != NULL);
		nng_aio_set_msg(aio[i], m);
		nng_ctx_send(ctx[i], aio[i]);
	}

	// Note that REQ socket is not reading the results.
	for (i = 0; i < 100; i++) {
		int rv;
		TEST_NNG_PASS(nng_ctx_close(ctx[i]));
		nng_aio_wait(aio[i]);
		rv = nng_aio_result(aio[i]);
		if (rv != 0) {
			TEST_NNG_FAIL(rv, NNG_ECLOSED);
			nng_msg_free(nng_aio_get_msg(aio[i]));
		}
		nng_aio_free(aio[i]);
	}
	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

static void
test_rep_ctx_recv_nonblock(void)
{
	nng_socket rep;
	nng_ctx    ctx;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_ctx_open(&ctx, rep));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(rep));
	nng_aio_free(aio);
}

static void
test_rep_ctx_send_nonblock(void)
{
	nng_socket rep;
	nng_socket req;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *msg;

	TEST_NNG_PASS(nng_req0_open(&req));
	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_ctx_open(&ctx, rep));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(testutil_marry(req, rep));

	TEST_NNG_SEND_STR(req, "SEND");
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_PASS(nng_aio_result(aio));
	// message carries over
	msg = nng_aio_get_msg(aio);
	nng_aio_set_msg(aio, msg);
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_send(ctx, aio);

	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(rep));
	TEST_NNG_PASS(nng_close(req));
	nng_aio_free(aio);
	nng_msg_free(msg);

}

void
test_rep_recv_garbage(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;

	TEST_NNG_PASS(nng_rep0_open(&rep));
	TEST_NNG_PASS(nng_req0_open_raw(&req));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_RECVTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(rep, NNG_OPT_SENDTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(req, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry(req, rep));

	TEST_NNG_PASS(nng_msg_alloc(&m, 4));
	TEST_NNG_PASS(nng_msg_append_u32(m, 1u));
	TEST_NNG_PASS(nng_sendmsg(req, m, 0));
	TEST_NNG_FAIL(nng_recvmsg(rep, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(req));
	TEST_NNG_PASS(nng_close(rep));
}

TEST_LIST = {
	{ "rep identity", test_rep_identity },
	{ "rep send bad state", test_rep_send_bad_state },
	{ "rep poll readable", test_rep_poll_readable },
	{ "rep poll writable", test_rep_poll_writeable },
	{ "rep context does not poll", test_rep_context_no_poll },
	{ "rep validate peer", test_rep_validate_peer },
	{ "rep double recv", test_rep_double_recv },
	{ "rep close pipe before send", test_rep_close_pipe_before_send },
	{ "rep close pipe during send", test_rep_close_pipe_during_send },
	{ "rep recv aio ctx stopped", test_rep_ctx_recv_aio_stopped },
	{ "rep close pipe context send", test_rep_close_pipe_context_send },
	{ "rep close context send", test_rep_close_context_send },
	{ "rep context send nonblock", test_rep_ctx_send_nonblock },
	{ "rep context recv nonblock", test_rep_ctx_recv_nonblock },
	{ "rep recv garbage", test_rep_recv_garbage },
	{ NULL, NULL },
};
