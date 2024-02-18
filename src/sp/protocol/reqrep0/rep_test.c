//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#include <nuts.h>

static void
test_rep_identity(void)
{
	nng_socket s;
	int        p1, p2;
	char      *n1;
	char      *n2;

	NUTS_PASS(nng_rep0_open(&s));
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

void
test_rep_send_bad_state(void)
{
	nng_socket rep;
	nng_msg   *msg = NULL;

	NUTS_TRUE(nng_rep0_open(&rep) == 0);
	NUTS_TRUE(nng_msg_alloc(&msg, 0) == 0);
	NUTS_TRUE(nng_sendmsg(rep, msg, 0) == NNG_ESTATE);
	nng_msg_free(msg);
	NUTS_CLOSE(rep);
}

void
test_rep_poll_writeable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_get_int(rep, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not writable before connect.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_MARRY(req, rep);

	// Still not writable.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// If we get a job, *then* we become writable
	NUTS_SEND(req, "abc");
	NUTS_RECV(rep, "abc");
	NUTS_TRUE(nuts_poll_fd(fd) == true);

	// And is no longer writable once we send a message
	NUTS_SEND(rep, "def");
	NUTS_TRUE(nuts_poll_fd(fd) == false);
	// Even after receiving it
	NUTS_RECV(req, "def");
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_rep_poll_readable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;
	nng_msg   *msg;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
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

	// TODO verify unsolicited response

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_rep_context_no_poll(void)
{
	int        fd;
	nng_socket req;
	nng_ctx    ctx;

	NUTS_PASS(nng_rep0_open(&req));
	NUTS_PASS(nng_ctx_open(&ctx, req));
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	NUTS_PASS(nng_ctx_close(ctx));
	NUTS_CLOSE(req);
}

void
test_rep_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat  *stats;
	nng_stat  *reject;
	char      *addr;

	NUTS_ADDR(addr, "inproc");
	NUTS_PASS(nng_rep0_open(&s1));
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

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	nng_stats_free(stats);
}

void
test_rep_double_recv(void)
{
	nng_socket s1;
	nng_aio   *aio1;
	nng_aio   *aio2;

	NUTS_PASS(nng_rep0_open(&s1));
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
test_rep_huge_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg   *m;
	nng_msg   *d;
	nng_aio   *aio;

	NUTS_PASS(nng_rep_open(&rep));
	NUTS_PASS(nng_req_open(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&m, 10 << 20)); // 10 MB
	NUTS_MARRY(req, rep);
	char *body = nng_msg_body(m);

	NUTS_ASSERT(nng_msg_len(m) == 10 << 20);
	for (size_t i = 0; i < nng_msg_len(m); i++) {
		body[i] = i % 16 + 'A';
	}
	NUTS_PASS(nng_msg_dup(&d, m));
	NUTS_SEND(req, "R");
	NUTS_RECV(rep, "R");
	nng_aio_set_msg(aio, m);
	nng_send_aio(rep, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	nng_aio_set_msg(aio, NULL);
	m = NULL;
	nng_recv_aio(req, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	m = nng_aio_get_msg(aio);
	NUTS_ASSERT(m != NULL);
	NUTS_ASSERT(nng_msg_len(m) == nng_msg_len(d));
	NUTS_ASSERT(
	    memcmp(nng_msg_body(m), nng_msg_body(d), nng_msg_len(m)) == 0);

	// make sure other messages still flow afterwards
	NUTS_SEND(req, "E");
	NUTS_RECV(rep, "E");
	NUTS_SEND(rep, "E");
	NUTS_RECV(req, "E");

	nng_aio_free(aio);
	nng_msg_free(m);
	nng_msg_free(d);
	NUTS_CLOSE(rep);
	NUTS_CLOSE(req);
}

void
test_rep_huge_send_socket(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg   *m;
	nng_msg   *d;
	nng_aio   *aio;

	NUTS_PASS(nng_rep_open(&rep));
	NUTS_PASS(nng_req_open(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&m, 10 << 20)); // 10 MB
	NUTS_PASS(nng_socket_set_size(req, NNG_OPT_RECVMAXSZ, 1 << 30));
	NUTS_PASS(nng_socket_set_size(rep, NNG_OPT_RECVMAXSZ, 1 << 30));
	NUTS_MARRY_EX(req, rep, "socket://", NULL, NULL);
	char *body = nng_msg_body(m);

	NUTS_ASSERT(nng_msg_len(m) == 10 << 20);
	for (size_t i = 0; i < nng_msg_len(m); i++) {
		body[i] = i % 16 + 'A';
	}
	NUTS_PASS(nng_msg_dup(&d, m));
	NUTS_SEND(req, "R");
	NUTS_RECV(rep, "R");
	nng_aio_set_msg(aio, m);
	nng_send_aio(rep, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	nng_aio_set_msg(aio, NULL);
	m = NULL;
	nng_recv_aio(req, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	m = nng_aio_get_msg(aio);
	NUTS_ASSERT(m != NULL);
	NUTS_ASSERT(nng_msg_len(m) == nng_msg_len(d));
	NUTS_ASSERT(
	    memcmp(nng_msg_body(m), nng_msg_body(d), nng_msg_len(m)) == 0);

	// make sure other messages still flow afterwards
	NUTS_SEND(req, "E");
	NUTS_RECV(rep, "E");
	NUTS_SEND(rep, "E");
	NUTS_RECV(req, "E");

	nng_aio_free(aio);
	nng_msg_free(m);
	nng_msg_free(d);
	NUTS_CLOSE(rep);
	NUTS_CLOSE(req);
}

void
test_rep_close_pipe_before_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_pipe   p;
	nng_aio   *aio1;
	nng_msg   *m;

	NUTS_PASS(nng_rep0_open(&rep));
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

void
test_rep_close_pipe_during_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_pipe   p = NNG_PIPE_INITIALIZER;
	nng_msg   *m;

	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_SENDBUF, 20));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_RECVBUF, 20));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 20));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_RECVBUF, 1));

	NUTS_MARRY(req, rep);

	for (int i = 0; i < 100; i++) {
		int rv;
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		NUTS_PASS(nng_sendmsg(req, m, 0));
		NUTS_PASS(nng_recvmsg(rep, &m, 0));
		p  = nng_msg_get_pipe(m);
		rv = nng_sendmsg(rep, m, 0);
		if (rv == NNG_ETIMEDOUT) {
			// Queue is backed up, senders are busy.
			nng_msg_free(m);
			break;
		}
		NUTS_PASS(rv);
	}
	NUTS_PASS(nng_pipe_close(p));

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_rep_ctx_recv_aio_stopped(void)
{
	nng_socket rep;
	nng_ctx    ctx;
	nng_aio   *aio;

	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_ctx_open(&ctx, rep));

	nng_aio_stop(aio);
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_PASS(nng_ctx_close(ctx));
	NUTS_CLOSE(rep);
	nng_aio_free(aio);
}

void
test_rep_close_pipe_context_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_pipe   p = NNG_PIPE_INITIALIZER;
	nng_msg   *m;
	nng_ctx    ctx[100];
	nng_aio   *aio[100];
	int        i;

	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	for (i = 0; i < 100; i++) {
		NUTS_PASS(nng_ctx_open(&ctx[i], rep));
		NUTS_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
	}
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_RECVBUF, 1));

	NUTS_MARRY(req, rep);

	for (i = 0; i < 100; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		NUTS_PASS(nng_sendmsg(req, m, 0));
		nng_ctx_recv(ctx[i], aio[i]);
	}
	for (i = 0; i < 100; i++) {
		nng_aio_wait(aio[i]);
		NUTS_PASS(nng_aio_result(aio[i]));
		NUTS_TRUE((m = nng_aio_get_msg(aio[i])) != NULL);
		p = nng_msg_get_pipe(m);
		nng_aio_set_msg(aio[i], m);
		nng_ctx_send(ctx[i], aio[i]);
	}

	// Note that REQ socket is not reading the results.
	NUTS_PASS(nng_pipe_close(p));

	for (i = 0; i < 100; i++) {
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
	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_rep_close_context_send(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg   *m;
	nng_ctx    ctx[100];
	nng_aio   *aio[100];
	int        i;

	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	for (i = 0; i < 100; i++) {
		NUTS_PASS(nng_ctx_open(&ctx[i], rep));
		NUTS_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
	}
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_RECVBUF, 1));

	NUTS_MARRY(req, rep);

	for (i = 0; i < 100; i++) {
		NUTS_PASS(nng_msg_alloc(&m, 4));
		NUTS_PASS(nng_msg_append_u32(m, (unsigned) i | 0x80000000u));
		NUTS_PASS(nng_sendmsg(req, m, 0));
		nng_ctx_recv(ctx[i], aio[i]);
	}
	for (i = 0; i < 100; i++) {
		nng_aio_wait(aio[i]);
		NUTS_PASS(nng_aio_result(aio[i]));
		NUTS_TRUE((m = nng_aio_get_msg(aio[i])) != NULL);
		nng_aio_set_msg(aio[i], m);
		nng_ctx_send(ctx[i], aio[i]);
	}

	// Note that REQ socket is not reading the results.
	for (i = 0; i < 100; i++) {
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
	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_rep_close_recv(void)
{
	nng_socket rep;
	nng_socket req;
	nng_aio   *aio;

	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(req, rep);
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_recv_aio(rep, aio);
	NUTS_CLOSE(rep);
	NUTS_CLOSE(req);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
}

struct rep_close_recv_cb_state {
	nng_aio *aio;
	nng_mtx *mtx;
	nng_cv  *cv;
	int      done;
	int      result;
	nng_msg *msg;
};

static void
rep_close_recv_cb(void *arg)
{
	struct rep_close_recv_cb_state *state = arg;

	nng_mtx_lock(state->mtx);
	state->result = nng_aio_result(state->aio);
	state->msg    = nng_aio_get_msg(state->aio);
	state->done   = true;
	nng_cv_wake(state->cv);
	nng_mtx_unlock(state->mtx);
}

void
test_rep_close_recv_cb(void)
{
	nng_socket                     rep;
	nng_socket                     req;
	struct rep_close_recv_cb_state state;

	memset(&state, 0, sizeof(state));
	NUTS_PASS(nng_mtx_alloc(&state.mtx));
	NUTS_PASS(nng_cv_alloc(&state.cv, state.mtx));

	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(req, rep);
	NUTS_PASS(nng_aio_alloc(&state.aio, rep_close_recv_cb, &state));
	nng_recv_aio(rep, state.aio);
	NUTS_CLOSE(rep);
	NUTS_CLOSE(req);
	nng_mtx_lock(state.mtx);
	while (!state.done) {
		NUTS_PASS(nng_cv_until(state.cv, nng_clock() + 1000));
	}
	nng_mtx_unlock(state.mtx);
	NUTS_TRUE(state.done != 0);
	NUTS_FAIL(nng_aio_result(state.aio), NNG_ECLOSED);
	NUTS_TRUE(nng_aio_get_msg(state.aio) == NULL);
	nng_aio_free(state.aio);
	nng_cv_free(state.cv);
	nng_mtx_free(state.mtx);
}

static void
test_rep_ctx_recv_nonblock(void)
{
	nng_socket rep;
	nng_ctx    ctx;
	nng_aio   *aio;

	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_ctx_open(&ctx, rep));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(rep);
	nng_aio_free(aio);
}

static void
test_rep_ctx_send_nonblock(void)
{
	nng_socket rep;
	nng_socket req;
	nng_ctx    ctx;
	nng_aio   *aio;
	nng_msg   *msg;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 2000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_ctx_open(&ctx, rep));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_MARRY(req, rep);

	NUTS_SEND(req, "SEND");
	nng_ctx_recv(ctx, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	// message carries over
	msg = nng_aio_get_msg(aio);
	nng_aio_set_msg(aio, msg);
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_send(ctx, aio);

	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_CLOSE(rep);
	NUTS_CLOSE(req);
	nng_aio_free(aio);
}

static void
test_rep_ctx_send_nonblock2(void)
{
	nng_socket rep;
	nng_socket req;
	nng_ctx    rep_ctx[10];
	nng_aio   *rep_aio[10];
	int        num_good = 0;
	int        num_fail = 0;

	// We are going to send a bunch of requests, receive them,
	// but then see that non-block pressure exerts for some, but
	// that at least one non-blocking send works.
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	for (int i = 0; i < 10; i++) {
		NUTS_PASS(nng_ctx_open(&rep_ctx[i], rep));
		NUTS_PASS(nng_aio_alloc(&rep_aio[i], NULL, NULL));
	}
	NUTS_MARRY(req, rep);

	for (int i = 0; i < 10; i++) {
		nng_msg *msg;
		NUTS_PASS(nng_msg_alloc(&msg, 4));
		NUTS_PASS(nng_msg_append_u32(msg, (unsigned) i | 0x80000000u));
		nng_ctx_recv(rep_ctx[i], rep_aio[i]);
		NUTS_PASS(nng_sendmsg(req, msg, 0));
	}
	for (int i = 0; i < 10; i++) {
		nng_msg *msg;
		nng_aio_wait(rep_aio[i]);
		NUTS_PASS(nng_aio_result(rep_aio[i]));
		msg = nng_aio_get_msg(rep_aio[i]);
		nng_aio_set_timeout(rep_aio[i], 0);
		nng_aio_set_msg(rep_aio[i], msg);
		nng_ctx_send(rep_ctx[i], rep_aio[i]);
	}

	for (int i = 0; i < 10; i++) {
		int rv;
		nng_aio_wait(rep_aio[i]);
		rv = nng_aio_result(rep_aio[i]);
		if (rv == 0) {
			num_good++;
		} else {
			NUTS_FAIL(rv, NNG_ETIMEDOUT);
			nng_msg_free(nng_aio_get_msg(rep_aio[i]));
			num_fail++;
		}
	}

	TEST_ASSERT(num_good > 0);
	TEST_ASSERT(num_fail > 0);

	for (int i = 0; i < 10; i++) {
		nng_aio_free(rep_aio[i]);
		nng_ctx_close(rep_ctx[i]);
	}
	NUTS_CLOSE(rep);
	NUTS_CLOSE(req);
}

static void
test_rep_send_nonblock(void)
{
	nng_socket rep;
	nng_socket req;
	int        rv;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_MARRY(req, rep);

	NUTS_SEND(req, "SEND");
	NUTS_RECV(rep, "SEND");

	// Use the nonblock flag
	rv = nng_send(rep, "RECV", 5, NNG_FLAG_NONBLOCK);

	NUTS_PASS(rv);
	NUTS_RECV(req, "RECV");
	NUTS_CLOSE(rep);
	NUTS_CLOSE(req);
}

void
test_rep_recv_garbage(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg   *m;

	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_req0_open_raw(&req));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 200));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(req, rep);

	NUTS_PASS(nng_msg_alloc(&m, 4));
	NUTS_PASS(nng_msg_append_u32(m, 1u));
	NUTS_PASS(nng_sendmsg(req, m, 0));
	NUTS_FAIL(nng_recvmsg(rep, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

NUTS_TESTS = {
	{ "rep identity", test_rep_identity },
	{ "rep send bad state", test_rep_send_bad_state },
	{ "rep poll readable", test_rep_poll_readable },
	{ "rep poll writable", test_rep_poll_writeable },
	{ "rep context does not poll", test_rep_context_no_poll },
	{ "rep validate peer", test_rep_validate_peer },
	{ "rep huge send", test_rep_huge_send },
	{ "rep huge send socket", test_rep_huge_send_socket },
	{ "rep double recv", test_rep_double_recv },
	{ "rep send nonblock", test_rep_send_nonblock },
	{ "rep close pipe before send", test_rep_close_pipe_before_send },
	{ "rep close pipe during send", test_rep_close_pipe_during_send },
	{ "rep recv aio ctx stopped", test_rep_ctx_recv_aio_stopped },
	{ "rep close pipe context send", test_rep_close_pipe_context_send },
	{ "rep close context send", test_rep_close_context_send },
	{ "rep close recv", test_rep_close_recv },
	{ "rep close recv cb", test_rep_close_recv_cb },
	{ "rep context send nonblock", test_rep_ctx_send_nonblock },
	{ "rep context send nonblock 2", test_rep_ctx_send_nonblock2 },
	{ "rep context recv nonblock", test_rep_ctx_recv_nonblock },
	{ "rep recv garbage", test_rep_recv_garbage },
	{ NULL, NULL },
};
