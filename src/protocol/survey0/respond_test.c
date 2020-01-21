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

#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>

#include <acutest.h>
#include <testutil.h>

#ifndef NNI_PROTO
#define NNI_PROTO(x, y) (((x) << 4u) | (y))
#endif

void
test_resp_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	TEST_CHECK(nng_respondent0_open(&s) == 0);
	TEST_CHECK(nng_getopt_int(s, NNG_OPT_PROTO, &p) == 0);
	TEST_CHECK(p == NNI_PROTO(6u, 3u));
	TEST_CHECK(nng_getopt_int(s, NNG_OPT_PEER, &p) == 0);
	TEST_CHECK(p == NNI_PROTO(6u, 2u));
	TEST_CHECK(nng_getopt_string(s, NNG_OPT_PROTONAME, &n) == 0);
	TEST_CHECK(strcmp(n, "respondent") == 0);
	nng_strfree(n);
	TEST_CHECK(nng_getopt_string(s, NNG_OPT_PEERNAME, &n) == 0);
	TEST_CHECK(strcmp(n, "surveyor") == 0);
	nng_strfree(n);
	TEST_CHECK(nng_close(s) == 0);
}

void
test_resp_send_bad_state(void)
{
	nng_socket resp;
	nng_msg *  msg = NULL;

	TEST_CHECK(nng_respondent0_open(&resp) == 0);
	TEST_CHECK(nng_msg_alloc(&msg, 0) == 0);
	TEST_CHECK(nng_sendmsg(resp, msg, 0) == NNG_ESTATE);
	nng_msg_free(msg);
	TEST_CHECK(nng_close(resp) == 0);
}

void
test_resp_poll_writeable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_getopt_int(resp, NNG_OPT_SENDFD, &fd));
	TEST_CHECK(fd >= 0);

	// Not writable before connect.
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(testutil_marry(surv, resp));

	// Still not writable.
	TEST_CHECK(testutil_pollfd(fd) == false);

	// If we get a job, *then* we become writable
	TEST_NNG_SEND_STR(surv, "abc");
	TEST_NNG_RECV_STR(resp, "abc");
	TEST_CHECK(testutil_pollfd(fd) == true);

	// And is no longer writable once we send a message
	TEST_NNG_SEND_STR(resp, "def");
	TEST_CHECK(testutil_pollfd(fd) == false);
	// Even after receiving it
	TEST_NNG_RECV_STR(surv, "def");
	TEST_CHECK(testutil_pollfd(fd) == false);

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

void
test_resp_poll_readable(void)
{
	int        fd;
	nng_socket surv;
	nng_socket resp;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
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

	// TODO verify unsolicited response

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

void
test_resp_context_no_poll(void)
{
	int        fd;
	nng_socket resp;
	nng_ctx    ctx;

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_ctx_open(&ctx, resp));
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	TEST_NNG_FAIL(
	    nng_ctx_getopt_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	TEST_NNG_PASS(nng_close(resp));
}

void
test_resp_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_respondent0_open(&s1));
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

void
test_resp_double_recv(void)
{
	nng_socket s1;
	nng_aio *  aio1;
	nng_aio *  aio2;

	TEST_NNG_PASS(nng_respondent0_open(&s1));
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
test_resp_close_pipe_before_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_pipe   p;
	nng_aio *  aio1;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent0_open(&resp));
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

void
test_resp_close_pipe_during_send(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_pipe   p = NNG_PIPE_INITIALIZER;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_SENDBUF, 20));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_RECVBUF, 20));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_SENDBUF, 20));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_RECVBUF, 1));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	for (int i = 0; i < 100; i++) {
		int rv;
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(
		    nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		TEST_NNG_PASS(nng_sendmsg(surv, m, 0));
		TEST_NNG_PASS(nng_recvmsg(resp, &m, 0));
		p  = nng_msg_get_pipe(m);
		rv = nng_sendmsg(resp, m, 0);
		if (rv == NNG_ETIMEDOUT) {
			// Queue is backed up, senders are busy.
			nng_msg_free(m);
			break;
		}
		TEST_NNG_PASS(rv);
	}
	TEST_NNG_PASS(nng_pipe_close(p));

	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

void
test_resp_ctx_recv_aio_stopped(void)
{
	nng_socket resp;
	nng_ctx    ctx;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(nng_ctx_open(&ctx, resp));

	nng_aio_stop(aio);
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	TEST_NNG_PASS(nng_ctx_close(ctx));
	TEST_NNG_PASS(nng_close(resp));
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

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_RECVBUF, 1));
	for (i = 0; i < 10; i++) {
		TEST_NNG_PASS(nng_ctx_open(&ctx[i], resp));
		TEST_NNG_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
	}

	TEST_NNG_PASS(testutil_marry(surv, resp));

	for (i = 0; i < 10; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(
		    nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		TEST_NNG_PASS(nng_sendmsg(surv, m, 0));
		nng_ctx_recv(ctx[i], aio[i]);
	}
	for (i = 0; i < 10; i++) {
		nng_aio_wait(aio[i]);
		TEST_NNG_PASS(nng_aio_result(aio[i]));
		TEST_CHECK((m = nng_aio_get_msg(aio[i])) != NULL);
		p = nng_msg_get_pipe(m);
		nng_aio_set_msg(aio[i], m);
		nng_ctx_send(ctx[i], aio[i]);
	}

	// Note that SURVEYOR socket is not reading the results.
	TEST_NNG_PASS(nng_pipe_close(p));

	for (i = 0; i < 10; i++) {
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
	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
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

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(surv, NNG_OPT_RECVBUF, 1));
	for (i = 0; i < 10; i++) {
		TEST_NNG_PASS(nng_ctx_open(&ctx[i], resp));
		TEST_NNG_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
	}

	TEST_NNG_PASS(testutil_marry(surv, resp));

	for (i = 0; i < 10; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&m, 4));
		TEST_NNG_PASS(
		    nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		TEST_NNG_PASS(nng_sendmsg(surv, m, 0));
		nng_ctx_recv(ctx[i], aio[i]);
	}
	for (i = 0; i < 10; i++) {
		nng_aio_wait(aio[i]);
		TEST_NNG_PASS(nng_aio_result(aio[i]));
		TEST_CHECK((m = nng_aio_get_msg(aio[i])) != NULL);
		nng_aio_set_msg(aio[i], m);
		nng_ctx_send(ctx[i], aio[i]);
	}

	// Note that REQ socket is not reading the results.
	for (i = 0; i < 10; i++) {
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
	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
}

static void
test_resp_ctx_recv_nonblock(void)
{
	nng_socket resp;
	nng_ctx    ctx;
	nng_aio *  aio;

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_ctx_open(&ctx, resp));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	TEST_NNG_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	TEST_NNG_PASS(nng_close(resp));
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

	TEST_NNG_PASS(nng_surveyor0_open(&surv));
	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 1000));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 1000));
	TEST_NNG_PASS(nng_ctx_open(&ctx, resp));
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_PASS(testutil_marry(surv, resp));

	TEST_NNG_SEND_STR(surv, "SEND");
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
	TEST_NNG_PASS(nng_close(surv));
	TEST_NNG_PASS(nng_close(resp));
	nng_aio_free(aio);
	nng_msg_free(msg);
}

void
test_resp_recv_garbage(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 200));
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
test_resp_ttl_option(void)
{
	nng_socket  resp;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	TEST_NNG_PASS(nng_respondent0_open(&resp));

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

	TEST_NNG_FAIL(nng_setopt(resp, opt, "", 1), NNG_EINVAL);
	sz = 1;
	TEST_NNG_FAIL(nng_getopt(resp, opt, &v, &sz), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_bool(resp, opt, true), NNG_EBADTYPE);
	TEST_NNG_FAIL(nng_getopt_bool(resp, opt, &b), NNG_EBADTYPE);

	TEST_NNG_PASS(nng_close(resp));
}

static void
test_resp_ttl_drop(void)
{
	nng_socket resp;
	nng_socket surv;
	nng_msg *  m;

	TEST_NNG_PASS(nng_respondent0_open(&resp));
	TEST_NNG_PASS(nng_surveyor0_open_raw(&surv));
	TEST_NNG_PASS(nng_setopt_int(resp, NNG_OPT_MAXTTL, 3));
	TEST_NNG_PASS(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 1000));

	TEST_NNG_PASS(testutil_marry(surv, resp));

	// Send messages.  Note that xrep implicitly adds a hop on receive.

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

	TEST_NNG_RECV_STR(resp, "PASS1");
	TEST_NNG_RECV_STR(resp, "PASS3");

	TEST_NNG_FAIL(nng_recvmsg(resp, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(resp));
	TEST_NNG_PASS(nng_close(surv));
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
	{ "respond close pipe context send", test_resp_close_pipe_context_send },
	{ "respond close context send", test_resp_close_context_send },
	{ "respond context send nonblock", test_resp_ctx_send_nonblock },
	{ "respond context recv nonblock", test_resp_ctx_recv_nonblock },
	{ "respond recv garbage", test_resp_recv_garbage },
	{ "respond ttl option", test_resp_ttl_option },
	{ "respond ttl drop", test_resp_ttl_drop },
	{ NULL, NULL },
};
