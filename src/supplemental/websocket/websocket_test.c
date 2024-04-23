//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <string.h>

#include <nng/nng.h>

#include <nuts.h>

void
test_websocket_wildcard(void)
{
	nng_stream_dialer   *d = NULL;
	nng_stream_listener *l = NULL;
	nng_sockaddr         sa1;
	nng_sockaddr         sa2;
	size_t               sz;
	nng_aio             *daio = NULL;
	nng_aio             *laio = NULL;
	nng_aio             *aio1 = NULL;
	nng_aio             *aio2 = NULL;
	nng_stream          *c1   = NULL;
	nng_stream          *c2   = NULL;
	nng_iov              iov;
	char                 buf1[8];
	char                 buf2[8];
	char                 uri[64];

	NUTS_PASS(nng_stream_listener_alloc(&l, "ws://127.0.0.1:0/test"));

	NUTS_PASS(nng_stream_listener_listen(l));

	// Let's get the address we're going to use to dial -- also check
	// that it is correct.
	sz = sizeof(sa1);
	NUTS_PASS(nng_stream_listener_get(l, NNG_OPT_LOCADDR, &sa1, &sz));
	NUTS_TRUE(sz == sizeof(sa1));
	NUTS_TRUE(sa1.s_in.sa_port != 0);
	NUTS_TRUE(sa1.s_family == NNG_AF_INET);
	NUTS_TRUE(nuts_be32(sa1.s_in.sa_addr) == 0x7F000001u);

	(void) snprintf(uri, sizeof(uri), "ws://127.0.0.1:%d/test",
	    nuts_be16(sa1.s_in.sa_port));

	NUTS_PASS(nng_stream_dialer_alloc(&d, uri));
	NUTS_PASS(nng_aio_alloc(&daio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&laio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(daio, 5000); // 5 seconds
	nng_aio_set_timeout(laio, 5000);
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	nng_stream_dialer_dial(d, daio);
	nng_stream_listener_accept(l, laio);

	nng_aio_wait(laio);
	nng_aio_wait(daio);

	NUTS_PASS(nng_aio_result(laio));
	NUTS_PASS(nng_aio_result(daio));
	c1 = nng_aio_get_output(laio, 0);
	c2 = nng_aio_get_output(daio, 0);
	NUTS_TRUE(c1 != NULL);
	NUTS_TRUE(c2 != NULL);

	//  Let's compare the peer addresses
	NUTS_PASS(nng_stream_get_addr(c2, NNG_OPT_REMADDR, &sa2));
	NUTS_TRUE(sa1.s_family == sa2.s_family);
	NUTS_TRUE(sa1.s_in.sa_addr == sa2.s_in.sa_addr);
	NUTS_TRUE(sa1.s_in.sa_port == sa2.s_in.sa_port);

	NUTS_PASS(nng_stream_get_addr(c1, NNG_OPT_REMADDR, &sa1));
	NUTS_PASS(nng_stream_get_addr(c2, NNG_OPT_LOCADDR, &sa2));
	NUTS_TRUE(sa1.s_family == sa2.s_family);
	NUTS_TRUE(sa1.s_in.sa_addr == sa2.s_in.sa_addr);
	NUTS_TRUE(sa1.s_in.sa_port == sa2.s_in.sa_port);

	// This relies on send completing for for just 5 bytes, and on
	// recv doing the same.  Technically this isn't/ guaranteed, but
	// it would be weird to split such a small payload.

	memcpy(buf1, "TEST", 5);
	memset(buf2, 0, 5);
	iov.iov_buf = buf1;
	iov.iov_len = 5;
	NUTS_PASS(nng_aio_set_iov(aio1, 1, &iov));

	iov.iov_buf = buf2;
	iov.iov_len = 5;
	NUTS_PASS(nng_aio_set_iov(aio2, 1, &iov));

	nng_stream_send(c1, aio1);
	nng_stream_recv(c2, aio2);
	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_TRUE(nng_aio_count(aio1) == 5);

	NUTS_PASS(nng_aio_result(aio2));
	NUTS_TRUE(nng_aio_count(aio2) == 5);
	NUTS_TRUE(memcmp(buf1, buf2, 5) == 0);

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
	nng_stream_dialer   *d = NULL;
	nng_stream_listener *l = NULL;
	nng_sockaddr         sa1;
	nng_sockaddr         sa2;
	size_t               sz;
	nng_aio             *daio = NULL;
	nng_aio             *laio = NULL;
	nng_stream          *c1   = NULL;
	nng_stream          *c2   = NULL;
	char                 uri[64];
	bool                 on;
	char                *str;
	uint16_t             port = nuts_next_port();

	(void) snprintf(uri, sizeof(uri), "ws://127.0.0.1:%d/test", port);

	NUTS_PASS(nng_aio_alloc(&daio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&laio, NULL, NULL));
	nng_aio_set_timeout(daio, 5000); // 5 seconds
	nng_aio_set_timeout(laio, 5000);

	NUTS_PASS(nng_stream_listener_alloc(&l, uri));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(nng_stream_dialer_alloc(&d, uri));

	nng_stream_dialer_dial(d, daio);
	nng_stream_listener_accept(l, laio);

	nng_aio_wait(laio);
	nng_aio_wait(daio);

	NUTS_PASS(nng_aio_result(laio));
	NUTS_PASS(nng_aio_result(daio));
	c1 = nng_aio_get_output(laio, 0);
	c2 = nng_aio_get_output(daio, 0);
	NUTS_TRUE(c1 != NULL);
	NUTS_TRUE(c2 != NULL);

	//  Let's compare the peer addresses
	NUTS_PASS(nng_stream_get_addr(c1, NNG_OPT_LOCADDR, &sa1));
	NUTS_PASS(nng_stream_get_addr(c2, NNG_OPT_REMADDR, &sa2));
	NUTS_TRUE(sa1.s_family == sa2.s_family);
	NUTS_TRUE(sa1.s_in.sa_addr == sa2.s_in.sa_addr);
	NUTS_TRUE(sa1.s_in.sa_port == sa2.s_in.sa_port);

	NUTS_PASS(nng_stream_get_addr(c1, NNG_OPT_REMADDR, &sa1));
	NUTS_PASS(nng_stream_get_addr(c2, NNG_OPT_LOCADDR, &sa2));
	NUTS_TRUE(sa1.s_family == sa2.s_family);
	NUTS_TRUE(sa1.s_in.sa_addr == sa2.s_in.sa_addr);
	NUTS_TRUE(sa1.s_in.sa_port == sa2.s_in.sa_port);

	on = true;
	NUTS_PASS(nng_stream_set_bool(c1, NNG_OPT_TCP_NODELAY, on));
	NUTS_PASS(nng_stream_set_bool(c2, NNG_OPT_TCP_NODELAY, on));

	NUTS_PASS(nng_stream_set_bool(c1, NNG_OPT_TCP_KEEPALIVE, on));
	NUTS_PASS(nng_stream_set_bool(c2, NNG_OPT_TCP_KEEPALIVE, on));
	NUTS_FAIL(nng_stream_set_string(c1, NNG_OPT_TCP_KEEPALIVE, "nope"),
	    NNG_EBADTYPE);

	on = false;
	sz = sizeof(on);
	NUTS_PASS(nng_stream_get(c1, NNG_OPT_TCP_NODELAY, &on, &sz));
	NUTS_TRUE(sz == sizeof(on));
	NUTS_TRUE(on == true);

	on = false;
	sz = sizeof(on);
	NUTS_PASS(nng_stream_get(c2, NNG_OPT_TCP_KEEPALIVE, &on, &sz));
	NUTS_TRUE(sz == sizeof(on));
	NUTS_TRUE(on == true);

	NUTS_FAIL(
	    nng_stream_get_size(c1, NNG_OPT_TCP_NODELAY, &sz), NNG_EBADTYPE);

	NUTS_PASS(nng_stream_get_string(
	    c1, NNG_OPT_WS_REQUEST_HEADER "Sec-WebSocket-Version", &str));
	NUTS_TRUE(str != NULL);
	NUTS_TRUE(strcmp(str, "13") == 0);
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

void
test_websocket_text_mode(void)
{
	nng_stream_dialer   *d    = NULL;
	nng_stream_listener *l    = NULL;
	nng_aio             *daio = NULL;
	nng_aio             *laio = NULL;
	nng_aio             *aio1 = NULL;
	nng_aio             *aio2 = NULL;
	nng_stream          *c1   = NULL;
	nng_stream          *c2   = NULL;
	char                 uri[64];
	char                 txb[5];
	char                 rxb[5];
	bool                 on;
	uint16_t             port = nuts_next_port();
	nng_iov              iov;

	(void) snprintf(uri, sizeof(uri), "ws://127.0.0.1:%d/test", port);

	NUTS_PASS(nng_aio_alloc(&daio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&laio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(daio, 5000); // 5 seconds
	nng_aio_set_timeout(laio, 5000);
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	NUTS_PASS(nng_stream_listener_alloc(&l, uri));
	NUTS_PASS(nng_stream_dialer_alloc(&d, uri));

	on = true;
	NUTS_PASS(nng_stream_dialer_set_bool(d, NNG_OPT_WS_SEND_TEXT, on));
	NUTS_PASS(nng_stream_listener_set_bool(l, NNG_OPT_WS_RECV_TEXT, on));

	NUTS_PASS(nng_stream_dialer_get_bool(d, NNG_OPT_WS_SEND_TEXT, &on));
	NUTS_TRUE(on);
	NUTS_PASS(nng_stream_dialer_get_bool(d, NNG_OPT_WS_RECV_TEXT, &on));
	NUTS_TRUE(on == false);

	NUTS_PASS(nng_stream_listener_get_bool(l, NNG_OPT_WS_SEND_TEXT, &on));
	NUTS_TRUE(on == false);
	NUTS_PASS(nng_stream_listener_get_bool(l, NNG_OPT_WS_RECV_TEXT, &on));
	NUTS_TRUE(on);

	on = false;
	NUTS_PASS(nng_stream_dialer_set_bool(d, NNG_OPT_WS_RECV_TEXT, on));
	NUTS_PASS(nng_stream_listener_set_bool(l, NNG_OPT_WS_SEND_TEXT, on));
	NUTS_PASS(nng_stream_listener_get_bool(l, NNG_OPT_WS_SEND_TEXT, &on));
	NUTS_TRUE(on == false);
	NUTS_PASS(nng_stream_dialer_get_bool(d, NNG_OPT_WS_RECV_TEXT, &on));
	NUTS_TRUE(on == false);

	NUTS_PASS(nng_stream_listener_listen(l));
	nng_stream_dialer_dial(d, daio);
	nng_stream_listener_accept(l, laio);

	nng_aio_wait(laio);
	nng_aio_wait(daio);

	NUTS_PASS(nng_aio_result(laio));
	NUTS_PASS(nng_aio_result(daio));
	c1 = nng_aio_get_output(laio, 0);
	c2 = nng_aio_get_output(daio, 0);
	NUTS_TRUE(c1 != NULL);
	NUTS_TRUE(c2 != NULL);

	NUTS_PASS(nng_stream_get_bool(c1, NNG_OPT_WS_SEND_TEXT, &on));
	NUTS_TRUE(on == false);
	NUTS_PASS(nng_stream_get_bool(c1, NNG_OPT_WS_RECV_TEXT, &on));
	NUTS_TRUE(on);
	NUTS_PASS(nng_stream_listener_set_bool(l, NNG_OPT_WS_RECV_TEXT, on));

	NUTS_PASS(nng_stream_get_bool(c2, NNG_OPT_WS_SEND_TEXT, &on));
	NUTS_TRUE(on);
	NUTS_PASS(nng_stream_get_bool(c2, NNG_OPT_WS_RECV_TEXT, &on));
	NUTS_TRUE(on == false);

	memcpy(txb, "PING", 5);
	iov.iov_buf = txb;
	iov.iov_len = 5;
	nng_aio_set_iov(aio1, 1, &iov);
	nng_stream_send(c1, aio1);
	iov.iov_buf = rxb;
	iov.iov_len = 5;
	nng_aio_set_iov(aio2, 1, &iov);
	nng_stream_recv(c2, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);
	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));
	NUTS_TRUE(memcmp(rxb, txb, 5) == 0);

	memset(rxb, 0, 5);
	memcpy(txb, "PONG", 5);

	iov.iov_buf = txb;
	iov.iov_len = 5;
	nng_aio_set_iov(aio2, 1, &iov);
	nng_stream_send(c2, aio2);
	iov.iov_buf = rxb;
	iov.iov_len = 5;
	nng_aio_set_iov(aio1, 1, &iov);
	nng_stream_recv(c1, aio1);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);
	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));
	NUTS_TRUE(memcmp(rxb, txb, 5) == 0);

	nng_stream_close(c1);
	nng_stream_free(c1);
	nng_stream_close(c2);
	nng_stream_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_aio_free(daio);
	nng_aio_free(laio);
	nng_stream_listener_free(l);
	nng_stream_dialer_free(d);
}

typedef struct recv_state {
	nng_stream  *c;
	int          total;
	int          xfr;
	nng_mtx     *lock;
	nng_cv      *cv;
	nng_aio     *aio;
	int          err;
	bool         done;
	uint8_t     *send_buf;
	uint8_t     *buf;
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
	nng_stream_dialer   *d = NULL;
	nng_stream          *c = NULL;
	uint16_t             port;
	char                 url[64];
	nng_aio             *daio = NULL;
	nng_aio             *laio = NULL;
	nng_aio             *caio = NULL;
	int                  resid;
	recv_state           state;
	uint8_t              sum1[20];
	uint8_t              sum2[20];
	uint8_t             *recv_buf;
	uint8_t             *send_buf;
	uint8_t             *buf;
	nng_iov              iov;

	memset(&state, 0, sizeof(state));
	state.total = 200000; // total to send
	state.xfr   = 0;
	state.err   = 0;
	NUTS_TRUE((recv_buf = nng_alloc(state.total)) != NULL);
	NUTS_TRUE((send_buf = nng_alloc(state.total)) != NULL);
	NUTS_PASS(nng_mtx_alloc(&state.lock));
	NUTS_PASS(nng_cv_alloc(&state.cv, state.lock));
	NUTS_PASS(nng_aio_alloc(&state.aio, frag_recv_cb, &state));
	nng_aio_set_timeout(state.aio, 2000);
	state.buf = recv_buf;

	// Random fill the send buffer.
	for (int i = 0; i < state.total; i++) {
		send_buf[i] = nng_random() % 0xff;
	}

	nni_sha1(send_buf, state.total, sum1);
	nni_sha1_init(&state.sum);

	port = nuts_next_port();
	(void) snprintf(url, sizeof(url), "ws://127.0.0.1:%u", port);

	NUTS_PASS(nng_stream_listener_alloc(&l, url));
	NUTS_PASS(nng_stream_dialer_alloc(&d, url));
	NUTS_PASS(nng_aio_alloc(&daio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&laio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&caio, NULL, NULL));

	NUTS_PASS(nng_stream_listener_set_bool(l, NNG_OPT_TCP_NODELAY, true));
	NUTS_PASS(
	    nng_stream_listener_set_size(l, NNG_OPT_WS_SENDMAXFRAME, 1000000));
	NUTS_PASS(nng_stream_listener_listen(l));

	nng_aio_set_timeout(laio, 2000);
	nng_aio_set_timeout(daio, 2000);

	nng_stream_listener_accept(l, laio);
	nng_stream_dialer_dial(d, daio);

	nng_aio_wait(laio);
	nng_aio_wait(daio);

	NUTS_PASS(nng_aio_result(laio));
	NUTS_PASS(nng_aio_result(daio));
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

		NUTS_PASS(nng_aio_set_iov(caio, 1, &iov));
		nng_stream_send(c, caio);
		nng_aio_wait(caio);
		NUTS_PASS(nng_aio_result(caio));
		NUTS_TRUE(nng_aio_count(caio) > 0);
		len = (int) nng_aio_count(caio);

		resid -= len;
		buf += len;
	}

	nng_mtx_lock(state.lock);
	while (!state.done) {
		nng_cv_wait(state.cv);
	}
	nng_mtx_unlock(state.lock);

	NUTS_PASS(state.err);
	NUTS_TRUE(state.xfr == state.total);

	nni_sha1_final(&state.sum, sum2);
	NUTS_TRUE(memcmp(recv_buf, send_buf, state.total) == 0);
	NUTS_TRUE(memcmp(sum1, sum2, 20) == 0);

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

NUTS_TESTS = {
	{ "websocket stream wildcard", test_websocket_wildcard },
	{ "websocket conn properties", test_websocket_conn_props },
	{ "websocket fragmentation", test_websocket_fragmentation },
	{ "websocket text mode", test_websocket_text_mode },
	{ NULL, NULL },
};
