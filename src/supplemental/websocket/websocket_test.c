//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <string.h>

#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

#include "supplemental/sha1/sha1.h"

#include <acutest.h>
#include <testutil.h>

void
test_websocket_wildcard(void)
{
	nng_stream_dialer *  d = NULL;
	nng_stream_listener *l = NULL;
	nng_sockaddr         sa1;
	nng_sockaddr         sa2;
	size_t               sz;
	nng_aio *            daio = NULL;
	nng_aio *            laio = NULL;
	nng_aio *            aio1 = NULL;
	nng_aio *            aio2 = NULL;
	nng_stream *         c1   = NULL;
	nng_stream *         c2   = NULL;
	nng_iov              iov;
	char                 buf1[8];
	char                 buf2[8];
	char                 uri[64];

	TEST_NNG_PASS(nng_stream_listener_alloc(&l, "ws://127.0.0.1:0/test"));

	TEST_NNG_PASS(nng_stream_listener_listen(l));

	// Let's get the address we're going to use to dial -- also check
	// that it is correct.
	sz = sizeof(sa1);
	TEST_NNG_PASS(nng_stream_listener_get(l, NNG_OPT_LOCADDR, &sa1, &sz));
	TEST_CHECK(sz == sizeof(sa1));
	TEST_CHECK(sa1.s_in.sa_port != 0);
	TEST_CHECK(sa1.s_family == NNG_AF_INET);
	TEST_CHECK(testutil_htonl(sa1.s_in.sa_addr) == 0x7F000001u);

	(void) snprintf(uri, sizeof(uri), "ws://127.0.0.1:%d/test",
	    testutil_htons(sa1.s_in.sa_port));

	TEST_NNG_PASS(nng_stream_dialer_alloc(&d, uri));
	TEST_NNG_PASS(nng_aio_alloc(&daio, NULL, NULL));
	TEST_NNG_PASS(nng_aio_alloc(&laio, NULL, NULL));
	TEST_NNG_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	TEST_NNG_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(daio, 5000); // 5 seconds
	nng_aio_set_timeout(laio, 5000);
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	nng_stream_dialer_dial(d, daio);
	nng_stream_listener_accept(l, laio);

	nng_aio_wait(laio);
	nng_aio_wait(daio);

	TEST_NNG_PASS(nng_aio_result(laio));
	TEST_NNG_PASS(nng_aio_result(daio));
	c1 = nng_aio_get_output(laio, 0);
	c2 = nng_aio_get_output(daio, 0);
	TEST_CHECK(c1 != NULL);
	TEST_CHECK(c2 != NULL);

	//  Let's compare the peer addresses
	TEST_NNG_PASS(nng_stream_get_addr(c2, NNG_OPT_REMADDR, &sa2));
	TEST_CHECK(sa1.s_family == sa2.s_family);
	TEST_CHECK(sa1.s_in.sa_addr == sa2.s_in.sa_addr);
	TEST_CHECK(sa1.s_in.sa_port == sa2.s_in.sa_port);

	TEST_NNG_PASS(nng_stream_get_addr(c1, NNG_OPT_REMADDR, &sa1));
	TEST_NNG_PASS(nng_stream_get_addr(c2, NNG_OPT_LOCADDR, &sa2));
	TEST_CHECK_(sa1.s_family == sa2.s_family, "families match %x == %x",
	    sa1.s_family, sa2.s_family);
	TEST_CHECK_(sa1.s_in.sa_addr == sa2.s_in.sa_addr,
	    "addresses match %x == %x", testutil_htonl(sa1.s_in.sa_addr),
	    testutil_htonl(sa2.s_in.sa_addr));
	TEST_CHECK_(sa1.s_in.sa_port == sa2.s_in.sa_port,
	    "ports match %u == %u", testutil_htons(sa1.s_in.sa_port),
	    testutil_htons(sa2.s_in.sa_port));

	// This relies on send completing for for just 5 bytes, and on
	// recv doing the same.  Technically this isn't/ guaranteed, but
	// it would be weird to split such a small payload.

	memcpy(buf1, "TEST", 5);
	memset(buf2, 0, 5);
	iov.iov_buf = buf1;
	iov.iov_len = 5;
	TEST_NNG_PASS(nng_aio_set_iov(aio1, 1, &iov));

	iov.iov_buf = buf2;
	iov.iov_len = 5;
	TEST_NNG_PASS(nng_aio_set_iov(aio2, 1, &iov));

	nng_stream_send(c1, aio1);
	nng_stream_recv(c2, aio2);
	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	TEST_NNG_PASS(nng_aio_result(aio1));
	TEST_CHECK(nng_aio_count(aio1) == 5);

	TEST_NNG_PASS(nng_aio_result(aio2));
	TEST_CHECK(nng_aio_count(aio2) == 5);
	TEST_CHECK(memcmp(buf1, buf2, 5) == 0);

	nng_stream_close(c1);
	nng_stream_free(c1);
	nng_stream_close(c2);
	nng_stream_free(c2);
	nng_aio_free(daio);
	nng_aio_free(laio);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_stream_listener_free(l);
	nng_stream_dialer_free(d);
}

void
test_websocket_conn_props(void)
{
	nng_stream_dialer *  d = NULL;
	nng_stream_listener *l = NULL;
	nng_sockaddr         sa1;
	nng_sockaddr         sa2;
	size_t               sz;
	nng_aio *            daio = NULL;
	nng_aio *            laio = NULL;
	nng_stream *         c1   = NULL;
	nng_stream *         c2   = NULL;
	char                 uri[64];
	bool                 on;
	char *               str;
	uint16_t             port = testutil_next_port();

	(void) snprintf(uri, sizeof(uri), "ws://127.0.0.1:%d/test", port);

	TEST_NNG_PASS(nng_aio_alloc(&daio, NULL, NULL));
	TEST_NNG_PASS(nng_aio_alloc(&laio, NULL, NULL));
	nng_aio_set_timeout(daio, 5000); // 5 seconds
	nng_aio_set_timeout(laio, 5000);

	TEST_NNG_PASS(nng_stream_listener_alloc(&l, uri));
	TEST_NNG_PASS(nng_stream_listener_listen(l));
	TEST_NNG_PASS(nng_stream_dialer_alloc(&d, uri));

	nng_stream_dialer_dial(d, daio);
	nng_stream_listener_accept(l, laio);

	nng_aio_wait(laio);
	nng_aio_wait(daio);

	TEST_NNG_PASS(nng_aio_result(laio));
	TEST_NNG_PASS(nng_aio_result(daio));
	c1 = nng_aio_get_output(laio, 0);
	c2 = nng_aio_get_output(daio, 0);
	TEST_CHECK(c1 != NULL);
	TEST_CHECK(c2 != NULL);

	//  Let's compare the peer addresses
	TEST_NNG_PASS(nng_stream_get_addr(c1, NNG_OPT_LOCADDR, &sa1));
	TEST_NNG_PASS(nng_stream_get_addr(c2, NNG_OPT_REMADDR, &sa2));
	TEST_CHECK_(sa1.s_family == sa2.s_family, "families match %x == %x",
		    sa1.s_family, sa2.s_family);
	TEST_CHECK_(sa1.s_in.sa_addr == sa2.s_in.sa_addr,
		    "addresses match %x == %x", testutil_htonl(sa1.s_in.sa_addr),
		    testutil_htonl(sa2.s_in.sa_addr));
	TEST_CHECK_(sa1.s_in.sa_port == sa2.s_in.sa_port,
		    "ports match %u == %u", testutil_htons(sa1.s_in.sa_port),
		    testutil_htons(sa2.s_in.sa_port));

	TEST_NNG_PASS(nng_stream_get_addr(c1, NNG_OPT_REMADDR, &sa1));
	TEST_NNG_PASS(nng_stream_get_addr(c2, NNG_OPT_LOCADDR, &sa2));
	TEST_CHECK_(sa1.s_family == sa2.s_family, "families match %x == %x",
		    sa1.s_family, sa2.s_family);
	TEST_CHECK_(sa1.s_in.sa_addr == sa2.s_in.sa_addr,
		    "addresses match %x == %x", testutil_htonl(sa1.s_in.sa_addr),
		    testutil_htonl(sa2.s_in.sa_addr));
	TEST_CHECK_(sa1.s_in.sa_port == sa2.s_in.sa_port,
		    "ports match %u == %u", testutil_htons(sa1.s_in.sa_port),
		    testutil_htons(sa2.s_in.sa_port));

	on = true;
	TEST_NNG_PASS(nng_stream_set_bool(c1, NNG_OPT_TCP_NODELAY, on));
	TEST_NNG_PASS(nng_stream_set_bool(c2, NNG_OPT_TCP_NODELAY, on));

	TEST_NNG_PASS(nng_stream_set_bool(c1, NNG_OPT_TCP_KEEPALIVE, on));
	TEST_NNG_PASS(nng_stream_set_bool(c2, NNG_OPT_TCP_KEEPALIVE, on));
	TEST_NNG_FAIL(nng_stream_set_string(c1, NNG_OPT_TCP_KEEPALIVE, "nope"),
	    NNG_EBADTYPE);

	on = false;
	sz = sizeof(on);
	TEST_NNG_PASS(nng_stream_get(c1, NNG_OPT_TCP_NODELAY, &on, &sz));
	TEST_CHECK(sz == sizeof(on));
	TEST_CHECK(on == true);

	on = false;
	sz = sizeof(on);
	TEST_NNG_PASS(nng_stream_get(c2, NNG_OPT_TCP_KEEPALIVE, &on, &sz));
	TEST_CHECK(sz == sizeof(on));
	TEST_CHECK(on == true);

	TEST_NNG_FAIL(
	    nng_stream_get_size(c1, NNG_OPT_TCP_NODELAY, &sz), NNG_EBADTYPE);

	TEST_NNG_PASS(nng_stream_get_string(
	    c1, NNG_OPT_WS_REQUEST_HEADER "Sec-WebSocket-Version", &str));
	TEST_CHECK(str != NULL);
	TEST_CHECK(strcmp(str, "13") == 0);
	nng_strfree(str);

	nng_stream_close(c1);
	nng_stream_free(c1);
	nng_stream_close(c2);
	nng_stream_free(c2);
	nng_aio_free(daio);
	nng_aio_free(laio);
	nng_stream_listener_free(l);
	nng_stream_dialer_free(d);
}

typedef struct recv_state {
	nng_stream * c;
	int          total;
	int          xfr;
	nng_mtx *    lock;
	nng_cv *     cv;
	nng_aio *    aio;
	int          err;
	bool         done;
	uint8_t *    send_buf;
	uint8_t *    buf;
	nni_sha1_ctx sum;
} recv_state;

static void
frag_recv_cb(void *arg)
{
	recv_state *s = arg;

	if ((s->err = nng_aio_result(s->aio)) == 0) {
		int len   = (int) nng_aio_count(s->aio);
		int resid = s->total - s->xfr;

		nni_sha1_update(&s->sum, s->buf, (size_t) len);
		s->buf += len;
		s->xfr += len;
		resid -= len;

		if (resid > 0) {
			nng_iov iov;
			iov.iov_buf = s->buf;
			iov.iov_len = resid > 1024 ? 1024 : resid;
			nng_aio_set_iov(s->aio, 1, &iov);

			nng_aio_set_timeout(s->aio, 2000);
			nng_stream_recv(s->c, s->aio);
			return;
		}
	}

	nng_mtx_lock(s->lock);
	s->done = true;
	nng_cv_wake(s->cv);
	nng_mtx_unlock(s->lock);
}

// This case tests some edges where receive and transmit fragmentation
// don't align.  See bug 986.
void
test_websocket_fragmentation(void)
{
	nng_stream_listener *l = NULL;
	nng_stream_dialer *  d = NULL;
	nng_stream *         c = NULL;
	uint16_t             port;
	char                 url[64];
	nng_aio *            daio = NULL;
	nng_aio *            laio = NULL;
	nng_aio *            caio = NULL;
	int                  resid;
	recv_state           state;
	uint8_t              sum1[20];
	uint8_t              sum2[20];
	uint8_t *            recv_buf;
	uint8_t *            send_buf;
	uint8_t *            buf;
	nng_iov              iov;

	memset(&state, 0, sizeof(state));
	state.total = 200000; // total to send
	state.xfr   = 0;
	state.err   = 0;
	TEST_CHECK((recv_buf = nng_alloc(state.total)) != NULL);
	TEST_CHECK((send_buf = nng_alloc(state.total)) != NULL);
	TEST_NNG_PASS(nng_mtx_alloc(&state.lock));
	TEST_NNG_PASS(nng_cv_alloc(&state.cv, state.lock));
	TEST_NNG_PASS(nng_aio_alloc(&state.aio, frag_recv_cb, &state));
	nng_aio_set_timeout(state.aio, 2000);
	state.buf = recv_buf;

	// Random fill the send buffer.
	for (int i = 0; i < state.total; i++) {
		send_buf[i] = nng_random() % 0xff;
	}

	nni_sha1(send_buf, state.total, sum1);
	nni_sha1_init(&state.sum);

	port = testutil_next_port();
	(void) snprintf(url, sizeof(url), "ws://127.0.0.1:%u", port);

	TEST_NNG_PASS(nng_stream_listener_alloc(&l, url));
	TEST_NNG_PASS(nng_stream_dialer_alloc(&d, url));
	TEST_NNG_PASS(nng_aio_alloc(&daio, NULL, NULL));
	TEST_NNG_PASS(nng_aio_alloc(&laio, NULL, NULL));
	TEST_NNG_PASS(nng_aio_alloc(&caio, NULL, NULL));

	TEST_NNG_PASS(
	    nng_stream_listener_set_bool(l, NNG_OPT_TCP_NODELAY, true));
	TEST_NNG_PASS(
	    nng_stream_listener_set_size(l, NNG_OPT_WS_SENDMAXFRAME, 1000000));
	TEST_NNG_PASS(nng_stream_listener_listen(l));

	nng_aio_set_timeout(laio, 2000);
	nng_aio_set_timeout(daio, 2000);

	nng_stream_listener_accept(l, laio);
	nng_stream_dialer_dial(d, daio);

	nng_aio_wait(laio);
	nng_aio_wait(daio);

	TEST_NNG_PASS(nng_aio_result(laio));
	TEST_NNG_PASS(nng_aio_result(daio));
	state.c = nng_aio_get_output(daio, 0);
	c       = nng_aio_get_output(laio, 0);

	// start the receiver
	iov.iov_buf = state.buf;
	iov.iov_len = 1024;
	nng_aio_set_iov(state.aio, 1, &iov);
	nng_stream_recv(state.c, state.aio);

	buf   = send_buf;
	resid = state.total;
	while (resid > 0) {
		int len     = resid < 9500 ? resid : 9500;
		iov.iov_len = len;
		iov.iov_buf = buf;

		TEST_NNG_PASS(nng_aio_set_iov(caio, 1, &iov));
		nng_stream_send(c, caio);
		nng_aio_wait(caio);
		TEST_NNG_PASS(nng_aio_result(caio));
		TEST_CHECK(nng_aio_count(caio) > 0);
		len = nng_aio_count(caio);

		resid -= len;
		buf += len;
	}

	nng_mtx_lock(state.lock);
	while (!state.done) {
		nng_cv_wait(state.cv);
	}
	nng_mtx_unlock(state.lock);

	TEST_NNG_PASS(state.err);
	TEST_CHECK_(state.xfr == state.total,
	    "send count (%d) == recv count (%d)", state.total, state.xfr);

	nni_sha1_final(&state.sum, sum2);
	TEST_CHECK(memcmp(recv_buf, send_buf, state.total) == 0);
	TEST_CHECK(memcmp(sum1, sum2, 20) == 0);

	nng_aio_free(caio);
	nng_stream_close(c);
	nng_stream_free(c);

	nng_aio_free(state.aio);
	nng_stream_free(state.c);
	nng_cv_free(state.cv);
	nng_mtx_free(state.lock);

	nng_free(send_buf, state.total);
	nng_free(recv_buf, state.total);
	nng_aio_free(daio);
	nng_aio_free(laio);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
}

TEST_LIST = {
	{ "websocket stream wildcard", test_websocket_wildcard },
	{ "websocket conn properties", test_websocket_conn_props },
	{ "websocket fragmentation", test_websocket_fragmentation },
	{ NULL, NULL },
};
