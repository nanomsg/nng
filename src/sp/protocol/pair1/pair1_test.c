//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

#define SECOND 1000

#define APPEND_STR(m, s) NUTS_TRUE(nng_msg_append(m, s, strlen(s)) == 0)
#define CHECK_STR(m, s)                         \
	NUTS_TRUE(nng_msg_len(m) == strlen(s)); \
	NUTS_TRUE(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

static void
test_mono_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NUTS_PROTO(1u, 1u)); // 32
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p));
	NUTS_TRUE(p == NUTS_PROTO(1u, 1u)); // 33
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n));
	NUTS_MATCH(n, "pair1");
	nng_strfree(n);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n));
	NUTS_MATCH(n, "pair1");
	nng_strfree(n);
	NUTS_CLOSE(s);
}

void
test_mono_cooked(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;

	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_PASS(nng_pair1_open(&c1));
	NUTS_PASS(nuts_marry(s1, c1));

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "ALPHA", strlen("ALPHA") + 1));
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	NUTS_TRUE(nng_msg_len(msg) == strlen("ALPHA") + 1);
	NUTS_MATCH(nng_msg_body(msg), "ALPHA");
	nng_msg_free(msg);

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "BETA", strlen("BETA") + 1));
	NUTS_PASS(nng_sendmsg(s1, msg, 0));
	NUTS_PASS(nng_recvmsg(c1, &msg, 0));
	NUTS_TRUE(nng_msg_len(msg) == strlen("BETA") + 1);
	NUTS_MATCH(nng_msg_body(msg), "BETA");

	nng_msg_free(msg);
	NUTS_CLOSE(c1);
	NUTS_CLOSE(s1);
}

void
test_mono_faithful(void)
{
	nng_socket  s1;
	nng_socket  c1;
	nng_socket  c2;
	nng_msg *   msg;
	const char *addr = "inproc://pair1_mono_faithful";

	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_PASS(nng_pair1_open(&c1));
	NUTS_PASS(nng_pair1_open(&c2));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, SECOND / 4));
	NUTS_PASS(nng_socket_set_ms(c1, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(c2, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_int(c2, NNG_OPT_SENDBUF, 2));

	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	NUTS_MARRY(s1, c1);
	NUTS_PASS(nng_dial(c2, addr, NULL, 0));

	NUTS_SLEEP(100);

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "ONE");
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	CHECK_STR(msg, "ONE");
	nng_msg_free(msg);

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "TWO");
	NUTS_PASS(nng_sendmsg(c2, msg, 0));
	NUTS_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(c1);
	NUTS_CLOSE(c2);
}

void
test_mono_back_pressure(void)
{
	nng_socket   s1;
	nng_socket   c1;
	int          i;
	int          rv;
	nng_msg *    msg;
	nng_duration to = 100;

	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_PASS(nng_pair1_open(&c1));
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(c1, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, to));

	NUTS_MARRY(s1, c1);

	// We choose to allow some buffering.  In reality the
	// buffer size is just 1, and we will fail after 2.
	for (i = 0, rv = 0; i < 10; i++) {
		NUTS_PASS(nng_msg_alloc(&msg, 0));
		if ((rv = nng_sendmsg(s1, msg, 0)) != 0) {
			nng_msg_free(msg);
			break;
		}
	}
	NUTS_FAIL(rv, NNG_ETIMEDOUT);
	NUTS_TRUE(i < 10);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(c1);
}

void
test_send_no_peer(void)
{
	nng_socket   s1;
	nng_msg *    msg;
	nng_duration to = 100;

	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, to));

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_FAIL(nng_sendmsg(s1, msg, 0), NNG_ETIMEDOUT);
	nng_msg_free(msg);
	NUTS_CLOSE(s1);
}

void
test_mono_raw_exchange(void)
{
	nng_socket s1;
	nng_socket c1;

	nng_msg *msg;
	uint32_t hops;

	NUTS_PASS(nng_pair1_open_raw(&s1));
	NUTS_PASS(nng_pair1_open_raw(&c1));

	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(c1, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_MARRY(s1, c1);

	nng_pipe p = NNG_PIPE_INITIALIZER;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "GAMMA");
	NUTS_PASS(nng_msg_header_append_u32(msg, 1));
	NUTS_TRUE(nng_msg_header_len(msg) == sizeof(uint32_t));
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	p = nng_msg_get_pipe(msg);
	NUTS_TRUE(nng_pipe_id(p) > 0);

	CHECK_STR(msg, "GAMMA");
	NUTS_TRUE(nng_msg_header_len(msg) == sizeof(uint32_t));
	NUTS_PASS(nng_msg_header_trim_u32(msg, &hops));
	NUTS_TRUE(hops == 2);
	nng_msg_free(msg);

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "EPSILON");
	NUTS_PASS(nng_msg_header_append_u32(msg, 1));
	NUTS_PASS(nng_sendmsg(s1, msg, 0));
	NUTS_PASS(nng_recvmsg(c1, &msg, 0));
	CHECK_STR(msg, "EPSILON");
	NUTS_TRUE(nng_msg_header_len(msg) == sizeof(uint32_t));
	NUTS_PASS(nng_msg_header_trim_u32(msg, &hops));
	p = nng_msg_get_pipe(msg);
	NUTS_TRUE(nng_pipe_id(p) > 0);

	NUTS_TRUE(hops == 2);
	nng_msg_free(msg);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(c1);
}

void
test_mono_raw_header(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;
	uint32_t   v;

	NUTS_PASS(nng_pair1_open_raw(&s1));
	NUTS_PASS(nng_pair1_open_raw(&c1));

	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, SECOND / 5));
	NUTS_PASS(nng_socket_set_ms(c1, NNG_OPT_RECVTIMEO, SECOND / 5));
	NUTS_MARRY(s1, c1);

	// Missing bits in the header
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_FAIL(nng_sendmsg(c1, msg, 0), NNG_EPROTO);
	nng_msg_free(msg);

	// Valid header works
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append_u32(msg, 0xFEEDFACE));
	NUTS_PASS(nng_msg_header_append_u32(msg, 1));
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	NUTS_PASS(nng_msg_trim_u32(msg, &v));
	NUTS_TRUE(v == 0xFEEDFACE);
	nng_msg_free(msg);

	// Header with reserved bits set dropped
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append_u32(msg, 0xDEAD0000));
	NUTS_FAIL(nng_sendmsg(c1, msg, 0), NNG_EPROTO);
	nng_msg_free(msg);

	// Header with no chance to add another hop gets dropped
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append_u32(msg, 0xff));
	NUTS_FAIL(nng_sendmsg(c1, msg, 0), NNG_EPROTO);
	nng_msg_free(msg);

	// With the same bits clear it works
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append_u32(msg, 0xFEEDFACE));
	NUTS_PASS(nng_msg_header_append_u32(msg, 1));
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	NUTS_PASS(nng_msg_trim_u32(msg, &v));
	NUTS_TRUE(v == 0xFEEDFACE);
	nng_msg_free(msg);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(c1);
}

void
test_pair1_send_closed_aio(void)
{
	nng_socket s1;
	nng_aio *  aio;
	nng_msg *  msg;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_pair1_open(&s1));
	nng_aio_set_msg(aio, msg);
	nng_aio_stop(aio);
	nng_send_aio(s1, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	nng_msg_free(msg);
	nng_aio_free(aio);
	NUTS_PASS(nng_close(s1));
}

void
test_pair1_raw(void)
{
	nng_socket s1;
	bool       raw;

	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_PASS(nng_socket_get_bool(s1, NNG_OPT_RAW, &raw));
	NUTS_TRUE(raw == false);
	NUTS_FAIL(nng_socket_set_bool(s1, NNG_OPT_RAW, true), NNG_EREADONLY);
	NUTS_PASS(nng_close(s1));

	NUTS_PASS(nng_pair1_open_raw(&s1));
	NUTS_PASS(nng_socket_get_bool(s1, NNG_OPT_RAW, &raw));
	NUTS_TRUE(raw == true);
	NUTS_FAIL(nng_socket_set_bool(s1, NNG_OPT_RAW, false), NNG_EREADONLY);
	NUTS_PASS(nng_close(s1));
}

void
test_pair1_ttl(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;
	uint32_t   val;
	int        ttl;

	NUTS_PASS(nng_pair1_open_raw(&s1));
	NUTS_PASS(nng_pair1_open_raw(&c1));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, SECOND / 5));
	NUTS_PASS(nng_socket_set_ms(c1, NNG_OPT_RECVTIMEO, SECOND / 5));

	// cannot set insane TTLs
	NUTS_FAIL(nng_socket_set_int(s1, NNG_OPT_MAXTTL, 0), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s1, NNG_OPT_MAXTTL, 1000), NNG_EINVAL);
	ttl = 8;
	NUTS_FAIL(nng_socket_set(s1, NNG_OPT_MAXTTL, &ttl, 1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(s1, NNG_OPT_MAXTTL, true), NNG_EBADTYPE);

	NUTS_MARRY(s1, c1);

	// Let's check enforcement of TTL
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_MAXTTL, 4));
	NUTS_PASS(nng_socket_get_int(s1, NNG_OPT_MAXTTL, &ttl));
	NUTS_TRUE(ttl == 4);

	// Bad TTL bounces
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append_u32(msg, 4));
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);

	// Good TTL passes
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append_u32(msg, 0xFEEDFACE));
	NUTS_PASS(nng_msg_header_append_u32(msg, 3));
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	NUTS_PASS(nng_msg_trim_u32(msg, &val));
	NUTS_TRUE(val == 0xFEEDFACE);
	NUTS_PASS(nng_msg_header_trim_u32(msg, &val));
	NUTS_TRUE(val == 4);
	nng_msg_free(msg);

	// Large TTL passes
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_MAXTTL, 15));
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append_u32(msg, 1234));
	NUTS_PASS(nng_msg_header_append_u32(msg, 14));
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	NUTS_PASS(nng_msg_trim_u32(msg, &val));
	NUTS_TRUE(val == 1234);
	NUTS_PASS(nng_msg_header_trim_u32(msg, &val));
	NUTS_TRUE(val == 15);
	nng_msg_free(msg);

	// Max TTL fails
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_MAXTTL, 15));
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append_u32(msg, 15));
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(c1);
}

void
test_pair1_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char *     addr;

	NUTS_ADDR(addr, "inproc");
	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_PASS(nng_pair0_open(&s2));

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
test_pair1_recv_no_header(void)
{
	nng_socket s;
	nng_socket c;
	nng_msg *  m;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_PASS(nng_pair1_open(&c));
	NUTS_PASS(nng_socket_set_bool(c, "pair1_test_inject_header", true));
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_SENDTIMEO, 200));

	NUTS_MARRY(c, s);

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_sendmsg(c, m, 0));
	NUTS_FAIL(nng_recvmsg(s, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(c);
	NUTS_CLOSE(s);
}

void
test_pair1_recv_garbage(void)
{
	nng_socket s;
	nng_socket c;
	nng_msg *  m;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_PASS(nng_pair1_open(&c));
	NUTS_PASS(nng_socket_set_bool(c, "pair1_test_inject_header", true));
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_SENDTIMEO, 200));

	NUTS_MARRY(c, s);

	// ridiculous hop count
	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_header_append_u32(m, 0x1000));
	NUTS_PASS(nng_sendmsg(c, m, 0));
	NUTS_FAIL(nng_recvmsg(s, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(c);
	NUTS_CLOSE(s);
}

static void
test_pair1_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_pair1_send_buffer(void)
{
	nng_socket s;
	int        v;
	bool       b;
	size_t     sz;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_SENDBUF, &v));
	NUTS_TRUE(v == 0);
	NUTS_FAIL(nng_socket_get_bool(s, NNG_OPT_SENDBUF, &b), NNG_EBADTYPE);
	sz = 1;
	NUTS_FAIL(nng_socket_get(s, NNG_OPT_SENDBUF, &b, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, NNG_OPT_SENDBUF, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, NNG_OPT_SENDBUF, 100000), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(s, NNG_OPT_SENDBUF, false), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_set(s, NNG_OPT_SENDBUF, &b, 1), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(s, NNG_OPT_SENDBUF, 100));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_SENDBUF, &v));
	NUTS_TRUE(v == 100);
	NUTS_CLOSE(s);
}

static void
test_pair1_recv_buffer(void)
{
	nng_socket s;
	int        v;
	bool       b;
	size_t     sz;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_RECVBUF, &v));
	NUTS_TRUE(v == 0);
	NUTS_FAIL(nng_socket_get_bool(s, NNG_OPT_RECVBUF, &b), NNG_EBADTYPE);
	sz = 1;
	NUTS_FAIL(nng_socket_get(s, NNG_OPT_RECVBUF, &b, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, NNG_OPT_RECVBUF, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, NNG_OPT_RECVBUF, 100000), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(s, NNG_OPT_RECVBUF, false), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_set(s, NNG_OPT_RECVBUF, &b, 1), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(s, NNG_OPT_RECVBUF, 100));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_RECVBUF, &v));
	NUTS_TRUE(v == 100);
	NUTS_CLOSE(s);
}

static void
test_pair1_poll_readable(void)
{
	int        fd;
	nng_socket s1;
	nng_socket s2;

	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_PASS(nng_pair1_open(&s2));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_get_int(s1, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(s1, s2);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_SEND(s2, "abc");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));

	// and receiving makes it no longer ready
	NUTS_RECV(s1, "abc");
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// also let's confirm handling when we shrink the buffer size.
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_RECVBUF, 1));
	NUTS_SEND(s2, "def");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_RECVBUF, 0));
	NUTS_TRUE(nuts_poll_fd(fd) == false);
	// growing doesn't magically make it readable either
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_RECVBUF, 10));
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

static void
test_pair1_poll_writable(void)
{
	int        fd;
	nng_socket s1;
	nng_socket s2;

	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_PASS(nng_pair1_open(&s2));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_get_int(s1, NNG_OPT_SENDFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not writable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But after connect, we can.
	NUTS_MARRY(s1, s2);
	NUTS_TRUE(nuts_poll_fd(fd));

	// We are unbuffered.
	NUTS_SEND(s1, "abc"); // first one in the receiver
	NUTS_SEND(s1, "def"); // second one on the sending pipe
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// and receiving makes it ready
	NUTS_RECV(s2, "abc");
	NUTS_SLEEP(100); // time for the sender to complete
	NUTS_TRUE(nuts_poll_fd(fd));

	// close the peer for now.
	NUTS_CLOSE(s2);
	NUTS_SLEEP(100);

	// resize up, makes us writable.
	NUTS_TRUE(nuts_poll_fd(fd) == false);
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_SENDBUF, 1));
	NUTS_TRUE(nuts_poll_fd(fd));
	// resize down and we aren't anymore.
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_SENDBUF, 0));
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(s1);
}

NUTS_TESTS = {
	{ "pair1 mono identity", test_mono_identity },
	{ "pair1 mono cooked", test_mono_cooked },
	{ "pair1 mono faithful", test_mono_faithful },
	{ "pair1 mono back pressure", test_mono_back_pressure },
	{ "pair1 send no peer", test_send_no_peer },
	{ "pair1 mono raw exchange", test_mono_raw_exchange },
	{ "pair1 mono raw header", test_mono_raw_header },
	{ "pair1 send closed aio", test_pair1_send_closed_aio },
	{ "pair1 raw", test_pair1_raw },
	{ "pair1 ttl", test_pair1_ttl },
	{ "pair1 validate peer", test_pair1_validate_peer },
	{ "pair1 recv no header", test_pair1_recv_no_header },
	{ "pair1 recv garbage", test_pair1_recv_garbage },
	{ "pair1 no context", test_pair1_no_context },
	{ "pair1 send buffer", test_pair1_send_buffer },
	{ "pair1 recv buffer", test_pair1_recv_buffer },
	{ "pair1 poll readable", test_pair1_poll_readable },
	{ "pair1 poll writable", test_pair1_poll_writable },

	{ NULL, NULL },
};
