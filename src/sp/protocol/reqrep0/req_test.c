//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

static void
test_req_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	NUTS_PASS(nng_req0_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NNG_REQ0_SELF);
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p));
	NUTS_TRUE(p == NNG_REQ0_PEER); // 49
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n));
	NUTS_MATCH(n, NNG_REQ0_SELF_NAME);
	nng_strfree(n);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n));
	NUTS_MATCH(n, NNG_REQ0_PEER_NAME);
	nng_strfree(n);
	NUTS_CLOSE(s);
}

static void
test_req_ttl_option(void)
{
	nng_socket  req;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_MAXTTL;

	NUTS_PASS(nng_req0_open(&req));

	NUTS_PASS(nng_socket_set_int(req, opt, 1));
	NUTS_FAIL(nng_socket_set_int(req, opt, 0), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(req, opt, -1), NNG_EINVAL);
	// This test will fail if the NNI_MAX_MAX_TTL is changed from the
	// builtin default of 15.
	NUTS_FAIL(nng_socket_set_int(req, opt, 16), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(req, opt, 256), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(req, opt, 3));
	NUTS_PASS(nng_socket_get_int(req, opt, &v));
	NUTS_TRUE(v == 3);
	v  = 0;
	sz = sizeof(v);
	NUTS_PASS(nng_socket_get(req, opt, &v, &sz));
	NUTS_TRUE(v == 3);
	NUTS_TRUE(sz == sizeof(v));

	NUTS_FAIL(nng_socket_set(req, opt, "", 1), NNG_EINVAL);
	sz = 1;
	NUTS_FAIL(nng_socket_get(req, opt, &v, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(req, opt, true), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(req, opt, &b), NNG_EBADTYPE);

	NUTS_CLOSE(req);
}

static void
test_req_resend_option(void)
{
	nng_socket   req;
	nng_duration d;
	bool         b;
	size_t       sz  = sizeof(b);
	const char * opt = NNG_OPT_REQ_RESENDTIME;

	NUTS_PASS(nng_req0_open(&req));

	NUTS_TRUE(nng_socket_set_ms(req, opt, 10) == 0);
	NUTS_FAIL(nng_socket_set(req, opt, "", 1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_get(req, opt, &b, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(req, opt, true), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(req, opt, &b), NNG_EBADTYPE);

	NUTS_PASS(nng_socket_get_ms(req, opt, &d));
	NUTS_TRUE(d == 10);
	NUTS_CLOSE(req);
}

void
test_req_recv_bad_state(void)
{
	nng_socket req;
	nng_msg *  msg = NULL;

	NUTS_TRUE(nng_req0_open(&req) == 0);
	NUTS_TRUE(nng_recvmsg(req, &msg, 0) == NNG_ESTATE);
	NUTS_NULL(msg);
	NUTS_CLOSE(req);
}

static void
test_req_recv_garbage(void)
{
	nng_socket rep;
	nng_socket req;
	nng_msg *  m;
	uint32_t   req_id;

	NUTS_PASS(nng_rep0_open_raw(&rep));
	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));

	NUTS_MARRY(req, rep);

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_sendmsg(req, m, 0));

	NUTS_PASS(nng_recvmsg(rep, &m, 0));

	// The message will have a header that contains the 32-bit pipe ID,
	// followed by the 32-bit request ID.  We will discard the request
	// ID before sending it out.
	NUTS_TRUE(nng_msg_header_len(m) == 8);
	NUTS_PASS(nng_msg_header_chop_u32(m, &req_id));

	NUTS_PASS(nng_sendmsg(rep, m, 0));
	NUTS_FAIL(nng_recvmsg(req, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

#define SECOND 1000

void
test_req_rep_exchange(void)
{
	nng_socket req;
	nng_socket rep;

	NUTS_TRUE(nng_req0_open(&req) == 0);
	NUTS_TRUE(nng_rep0_open(&rep) == 0);

	NUTS_TRUE(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, SECOND) == 0);
	NUTS_TRUE(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, SECOND) == 0);
	NUTS_TRUE(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, SECOND) == 0);
	NUTS_TRUE(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, SECOND) == 0);

	NUTS_MARRY(rep, req);

	NUTS_SEND(req, "ping");
	NUTS_RECV(rep, "ping");
	NUTS_SEND(rep, "pong");
	NUTS_RECV(req, "pong");

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_req_resend(void)
{
	nng_socket req;
	nng_socket rep;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));

	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_REQ_RESENDTIME, 10));

	NUTS_MARRY(rep, req);

	NUTS_SEND(req, "ping");
	NUTS_RECV(rep, "ping");
	NUTS_RECV(rep, "ping");
	NUTS_RECV(rep, "ping");

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_req_resend_reconnect(void)
{
	nng_socket req;
	nng_socket rep1;
	nng_socket rep2;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep1));
	NUTS_PASS(nng_rep0_open(&rep2));

	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep1, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep2, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep1, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep2, NNG_OPT_SENDTIMEO, SECOND));
	// We intentionally set the retry time long; that way we only see
	// the retry from loss of our original peer.
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_REQ_RESENDTIME, 60 * SECOND));

	NUTS_MARRY(rep1, req);

	NUTS_SEND(req, "ping");
	NUTS_RECV(rep1, "ping");

	NUTS_CLOSE(rep1);
	NUTS_MARRY(rep2, req);

	NUTS_RECV(rep2, "ping");
	NUTS_SEND(rep2, "rep2");
	NUTS_RECV(req, "rep2");

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep2);
}

void
test_req_resend_disconnect(void)
{
	nng_socket req;
	nng_socket rep1;
	nng_socket rep2;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep1));
	NUTS_PASS(nng_rep0_open(&rep2));

	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep1, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep2, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep1, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep2, NNG_OPT_SENDTIMEO, SECOND));
	// We intentionally set the retry time long; that way we only see
	// the retry from loss of our original peer.
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_REQ_RESENDTIME, 60 * SECOND));

	NUTS_MARRY(rep1, req);
	NUTS_SEND(req, "ping");
	NUTS_RECV(rep1, "ping");

	NUTS_MARRY(rep2, req);
	NUTS_CLOSE(rep1);

	NUTS_RECV(rep2, "ping");
	NUTS_SEND(rep2, "rep2");
	NUTS_RECV(req, "rep2");

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep2);
}

void
test_req_disconnect_no_retry(void)
{
	nng_socket req;
	nng_socket rep1;
	nng_socket rep2;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep1));
	NUTS_PASS(nng_rep0_open(&rep2));

	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep1, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep2, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep1, NNG_OPT_SENDTIMEO, SECOND / 10));
	// Setting the resend time to zero so we will force an error
	// if the peer disconnects without sending us an answer.
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_REQ_RESENDTIME, 0));

	NUTS_MARRY(rep1, req);
	NUTS_SEND(req, "ping");
	NUTS_RECV(rep1, "ping");

	NUTS_MARRY(rep2, req);
	NUTS_CLOSE(rep1);

	nng_msg *msg = NULL;
	NUTS_FAIL(nng_recvmsg(req, &msg, 0), NNG_ECONNRESET);
	NUTS_FAIL(nng_recvmsg(rep2, &msg, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep2);
}

void
test_req_disconnect_abort(void)
{
	nng_socket req;
	nng_socket rep1;
	nng_socket rep2;
	nng_aio *  aio;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep1));
	NUTS_PASS(nng_rep0_open(&rep2));
	NUTS_PASS(nng_aio_alloc(&aio, 0, 0));

	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep1, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep2, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep1, NNG_OPT_SENDTIMEO, SECOND / 10));
	// Setting the resend time to zero so we will force an error
	// if the peer disconnects without sending us an answer.
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_REQ_RESENDTIME, 0));

	NUTS_MARRY(rep1, req);
	NUTS_SEND(req, "ping");
	NUTS_RECV(rep1, "ping");
	nng_recv_aio(req, aio);

	NUTS_MARRY(rep2, req);
	NUTS_CLOSE(rep1);

	nng_msg *msg = NULL;
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECONNRESET);
	NUTS_FAIL(nng_recvmsg(rep2, &msg, 0), NNG_ETIMEDOUT);
	nng_aio_free(aio);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep2);
}

void
test_req_cancel(void)
{
	nng_duration retry = SECOND;
	nng_socket   req;
	nng_socket   rep;

	NUTS_PASS(nng_rep_open(&rep));
	NUTS_PASS(nng_req_open(&req));

	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_REQ_RESENDTIME, retry));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 16));

	NUTS_MARRY(rep, req);

	// Send req #1 (abc).
	NUTS_SEND(req, "abc");

	// Sleep a bit.  This is so that we ensure that our request gets
	// to the far side.  (If we cancel too fast, then our outgoing send
	// will be canceled before it gets to the peer.)
	NUTS_SLEEP(100);

	// Send the next next request ("def").  Note that
	// the REP side server will have already buffered the receive
	// request, and should simply be waiting for us to reply to abc.
	NUTS_SEND(req, "def");

	// Receive the first request (should be abc) on the REP server.
	NUTS_RECV(rep, "abc");

	// REP sends the reply to first command.  This will be discarded
	// by the REQ socket.
	NUTS_SEND(rep, "abc");

	// Now get the next command from the REP; should be "def".
	NUTS_RECV(rep, "def");

	// And send it back to REQ.
	NUTS_SEND(rep, "def");

	// And we got back only the second result.
	NUTS_RECV(req, "def");

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_req_cancel_abort_recv(void)
{
	nng_aio *    aio;
	nng_duration retry = SECOND * 10; // 10s (kind of never)
	nng_socket   req;
	nng_socket   rep;

	NUTS_PASS(nng_rep_open(&rep));
	NUTS_PASS(nng_req_open(&req));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_REQ_RESENDTIME, retry));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 16));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 5 * SECOND));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 5 * SECOND));

	NUTS_MARRY(rep, req);

	// Send req #1 (abc).
	NUTS_SEND(req, "abc");

	// Wait for it to get ot the other side.
	NUTS_SLEEP(100);

	nng_aio_set_timeout(aio, 5 * SECOND);
	nng_recv_aio(req, aio);

	// Give time for this recv to post properly.
	NUTS_SLEEP(100);

	// Send the next next request ("def").  Note that
	// the REP side server will have already buffered the receive
	// request, and should simply be waiting for us to reply to
	// abc.
	NUTS_SEND(req, "def");

	// Our pending I/O should have been canceled.
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);

	// Receive the first request (should be abc) on the REP server.
	NUTS_RECV(rep, "abc");

	// REP sends the reply to first command.  This will be
	// discarded by the REQ socket.
	NUTS_SEND(rep, "abc");

	// Now get the next command from the REP; should be "def".
	NUTS_RECV(rep, "def");

	// And send it back to REQ.
	NUTS_SEND(rep, "def");

	// Try a req command.  This should give back "def"
	NUTS_RECV(req, "def");

	nng_aio_free(aio);
	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_req_cancel_post_recv(void)
{
	nng_socket req;
	nng_socket rep;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));
	NUTS_MARRY(req, rep);

	NUTS_SEND(req, "ONE");
	NUTS_RECV(rep, "ONE");
	NUTS_SEND(rep, "one");
	NUTS_SLEEP(100); // Make sure reply arrives!
	NUTS_SEND(req, "TWO");
	NUTS_RECV(rep, "TWO");
	NUTS_SEND(rep, "two");
	NUTS_RECV(req, "two");

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_req_poll_writeable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_get_int(req, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not writable before connect.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_MARRY(req, rep);

	// It should be writable now.
	NUTS_TRUE(nuts_poll_fd(fd));

	// Submit a bunch of jobs.  Note that we have to stall a bit
	// between each message to let it queue up.
	for (int i = 0; i < 10; i++) {
		int rv = nng_send(req, "", 0, NNG_FLAG_NONBLOCK);
		if (rv == NNG_EAGAIN) {
			break;
		}
		NUTS_PASS(rv);
		NUTS_SLEEP(50);
	}
	NUTS_TRUE(nuts_poll_fd(fd) == false);
	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_req_poll_contention(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;
	nng_aio *  aio;
	nng_ctx    ctx[5];
	nng_aio *  ctx_aio[5];
	nng_msg *  ctx_msg[5];
	nng_msg *  msg;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(rep, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 1000));

	for (int i = 0; i < 5; i++) {
		NUTS_PASS(nng_ctx_open(&ctx[i], req));
		NUTS_PASS(nng_aio_alloc(&ctx_aio[i], NULL, NULL));
		NUTS_PASS(nng_msg_alloc(&ctx_msg[i], 0));
	}
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_PASS(nng_socket_get_int(req, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not writable before connect.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	nng_aio_set_msg(aio, msg);
	nng_send_aio(req, aio);
	for (int i = 0; i < 5; i++) {
		nng_aio_set_msg(ctx_aio[i], ctx_msg[i]);
		nng_ctx_send(ctx[i], ctx_aio[i]);
	}
	NUTS_SLEEP(50); // so everything is queued steady state

	NUTS_MARRY(req, rep);

	// It should not be writable now.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_PASS(nng_recvmsg(rep, &msg, 0));
	nng_msg_free(msg);

	// Still not writeable...
	NUTS_TRUE(nuts_poll_fd(fd) == false);
	for (int i = 0; i < 5; i++) {
		NUTS_PASS(nng_recvmsg(rep, &msg, 0));
		nng_msg_free(msg);
	}
	// It can take a little bit of time for the eased back-pressure
	// to reflect across the network.
	NUTS_SLEEP(100);

	// Should be come writeable now...
	NUTS_TRUE(nuts_poll_fd(fd) == true);

	for (int i = 0; i < 5; i++) {
		nng_aio_free(ctx_aio[i]);
	}
	nng_aio_free(aio);
	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

void
test_req_poll_multi_pipe(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep1;
	nng_socket rep2;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep1));
	NUTS_PASS(nng_rep0_open(&rep2));
	NUTS_PASS(nng_socket_set_int(req, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	NUTS_PASS(nng_socket_get_int(req, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not writable before connect.
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_MARRY(req, rep1);
	NUTS_MARRY(req, rep2);

	NUTS_TRUE(nuts_poll_fd(fd) == true);
	NUTS_SEND(req, "ONE");
	NUTS_TRUE(nuts_poll_fd(fd) == true);

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep1);
	NUTS_CLOSE(rep2);
}

void
test_req_poll_readable(void)
{
	int        fd;
	nng_socket req;
	nng_socket rep;
	nng_msg *  msg;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_get_int(req, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(req, rep);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "xyz", 3));
	NUTS_PASS(nng_sendmsg(req, msg, 0));
	NUTS_PASS(nng_recvmsg(rep, &msg, 0)); // recv on rep
	NUTS_PASS(nng_sendmsg(rep, msg, 0));  // echo it back
	NUTS_SLEEP(200); // give time for message to arrive

	NUTS_TRUE(nuts_poll_fd(fd) == true);

	// and receiving makes it no longer ready
	NUTS_PASS(nng_recvmsg(req, &msg, 0));
	nng_msg_free(msg);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// TODO verify unsolicited response

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
}

static void
test_req_ctx_no_poll(void)
{
	int        fd;
	nng_socket req;
	nng_ctx    ctx;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_ctx_open(&ctx, req));
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_SENDFD, &fd), NNG_ENOTSUP);
	NUTS_FAIL(nng_ctx_get_int(ctx, NNG_OPT_RECVFD, &fd), NNG_ENOTSUP);
	NUTS_PASS(nng_ctx_close(ctx));
	NUTS_CLOSE(req);
}

static void
test_req_ctx_send_queued(void)
{
	nng_socket req;
	nng_socket rep;
	nng_ctx    ctx[3];
	nng_aio *  aio[3];
	nng_msg *  msg[3];

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(rep, NNG_OPT_RECVTIMEO, 100));

	for (int i = 0; i < 3; i++) {
		NUTS_PASS(nng_ctx_open(&ctx[i], req));
		NUTS_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
		NUTS_PASS(nng_msg_alloc(&msg[i], 0));
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_set_msg(aio[i], msg[i]);
		nng_ctx_send(ctx[i], aio[i]);
	}

	NUTS_MARRY(req, rep);

	NUTS_SLEEP(50); // Only to ensure stuff queues up
	for (int i = 0; i < 3; i++) {
		nng_msg *m;
		NUTS_PASS(nng_recvmsg(rep, &m, 0));
		nng_msg_free(m);
	}

	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
	for (int i = 0; i < 3; i++) {
		nng_aio_wait(aio[i]);
		NUTS_PASS(nng_aio_result(aio[i]));
		nng_aio_free(aio[i]);
	}
}

static void
test_req_ctx_send_close(void)
{
	nng_socket req;
	nng_ctx    ctx[3];
	nng_aio *  aio[3];
	nng_msg *  msg[3];

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	for (int i = 0; i < 3; i++) {
		NUTS_PASS(nng_ctx_open(&ctx[i], req));
		NUTS_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
		NUTS_PASS(nng_msg_alloc(&msg[i], 0));
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_set_msg(aio[i], msg[i]);
		nng_ctx_send(ctx[i], aio[i]);
	}

	for (int i = 0; i < 3; i++) {
		nng_ctx_close(ctx[i]);
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_wait(aio[i]);
		NUTS_FAIL(nng_aio_result(aio[i]), NNG_ECLOSED);
		nng_aio_free(aio[i]);
		nng_msg_free(msg[i]);
	}
	NUTS_CLOSE(req);
}

static void
test_req_ctx_send_abort(void)
{
	nng_socket req;
	nng_ctx    ctx[3];
	nng_aio *  aio[3];
	nng_msg *  msg[3];

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));

	for (int i = 0; i < 3; i++) {
		NUTS_PASS(nng_ctx_open(&ctx[i], req));
		NUTS_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
		NUTS_PASS(nng_msg_alloc(&msg[i], 0));
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_set_msg(aio[i], msg[i]);
		nng_ctx_send(ctx[i], aio[i]);
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_abort(aio[i], NNG_ECANCELED);
	}

	for (int i = 0; i < 3; i++) {
		nng_aio_wait(aio[i]);
		NUTS_FAIL(nng_aio_result(aio[i]), NNG_ECANCELED);
		nng_aio_free(aio[i]);
		nng_msg_free(msg[i]);
	}
	NUTS_CLOSE(req);
}

static void
test_req_ctx_send_twice(void)
{
	nng_socket req;
	nng_ctx    ctx;
	nng_aio *  aio[2];
	nng_msg *  msg[2];

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_socket_set_ms(req, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_ctx_open(&ctx, req));

	for (int i = 0; i < 2; i++) {
		NUTS_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
		NUTS_PASS(nng_msg_alloc(&msg[i], 0));
	}

	for (int i = 0; i < 2; i++) {
		nng_aio_set_msg(aio[i], msg[i]);
		nng_ctx_send(ctx, aio[i]);
		NUTS_SLEEP(50);
	}

	NUTS_CLOSE(req);
	nng_aio_wait(aio[0]);
	nng_aio_wait(aio[1]);
	NUTS_FAIL(nng_aio_result(aio[0]), NNG_ECANCELED);
	NUTS_FAIL(nng_aio_result(aio[1]), NNG_ECLOSED);

	for (int i = 0; i < 2; i++) {
		nng_aio_free(aio[i]);
		nng_msg_free(msg[i]);
	}
}

static void
test_req_ctx_recv_nonblock(void)
{
	nng_socket req;
	nng_socket rep;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  msg;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_ctx_open(&ctx, req));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_MARRY(req, rep);

	nng_aio_set_msg(aio, msg);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_recv(ctx, aio);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(req);
	NUTS_CLOSE(rep);
	nng_aio_free(aio);
}

static void
test_req_ctx_send_nonblock(void)
{
	nng_socket req;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  msg;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_ctx_open(&ctx, req));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&msg, 0));

	nng_aio_set_msg(aio, msg);
	nng_aio_set_timeout(aio, 0); // Instant timeout
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_CLOSE(req);
	nng_aio_free(aio);
	nng_msg_free(msg);
}

static void
test_req_ctx_recv_close_socket(void)
{
	nng_socket req;
	nng_socket rep;
	nng_ctx    ctx;
	nng_aio *  aio;
	nng_msg *  m;

	NUTS_PASS(nng_req0_open(&req));
	NUTS_PASS(nng_rep0_open(&rep));
	NUTS_PASS(nng_ctx_open(&ctx, req));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_MARRY(req, rep);
	NUTS_PASS(nng_msg_alloc(&m, 0));
	nng_aio_set_msg(aio, m);
	nng_ctx_send(ctx, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));

	nng_ctx_recv(ctx, aio);
	nng_close(req);

	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
	NUTS_CLOSE(rep);
}

static void
test_req_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char      * addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_req0_open(&s1));
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

NUTS_TESTS = {
	{ "req identity", test_req_identity },
	{ "req ttl option", test_req_ttl_option },
	{ "req resend option", test_req_resend_option },
	{ "req recv bad state", test_req_recv_bad_state },
	{ "req recv garbage", test_req_recv_garbage },
	{ "req rep exchange", test_req_rep_exchange },
	{ "req resend", test_req_resend },
	{ "req resend disconnect", test_req_resend_disconnect },
	{ "req disconnect no retry", test_req_disconnect_no_retry },
	{ "req disconnect abort", test_req_disconnect_abort },
	{ "req resend reconnect", test_req_resend_reconnect },
	{ "req cancel", test_req_cancel },
	{ "req cancel abort recv", test_req_cancel_abort_recv },
	{ "req cancel post recv", test_req_cancel_post_recv },
	{ "req poll writable", test_req_poll_writeable },
	{ "req poll contention", test_req_poll_contention },
	{ "req poll multi pipe", test_req_poll_multi_pipe },
	{ "req poll readable", test_req_poll_readable },
	{ "req context send queued", test_req_ctx_send_queued },
	{ "req context send close", test_req_ctx_send_close },
	{ "req context send abort", test_req_ctx_send_abort },
	{ "req context send twice", test_req_ctx_send_twice },
	{ "req context does not poll", test_req_ctx_no_poll },
	{ "req context recv close socket", test_req_ctx_recv_close_socket },
	{ "req context recv nonblock", test_req_ctx_recv_nonblock },
	{ "req context send nonblock", test_req_ctx_send_nonblock },
	{ "req validate peer", test_req_validate_peer },
	{ NULL, NULL },
};
