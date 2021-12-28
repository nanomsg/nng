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

#define APPEND_STR(m, s) NUTS_PASS(nng_msg_append(m, s, strlen(s)))
#define CHECK_STR(m, s)                         \
	NUTS_TRUE(nng_msg_len(m) == strlen(s)); \
	NUTS_TRUE(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

static void
test_poly_identity(void)
{
	nng_socket s;
	int        p;
	char *     n;

	NUTS_PASS(nng_pair1_open_poly(&s));
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
test_poly_best_effort(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;

	NUTS_PASS(nng_pair1_open_poly(&s1));
	NUTS_PASS(nng_pair1_open(&c1));

	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(c1, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, SECOND));

	NUTS_MARRY(s1, c1);

	for (int i = 0; i < 10; i++) {
		NUTS_PASS(nng_msg_alloc(&msg, 0));
		NUTS_PASS(nng_sendmsg(s1, msg, 0));
	}

	NUTS_CLOSE(s1);
	NUTS_CLOSE(c1);
}

void
test_poly_cooked(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_socket c2;
	nng_msg *  msg;
	bool       v;
	nng_pipe   p1;
	nng_pipe   p2;

	NUTS_PASS(nng_pair1_open_poly(&s1));
	NUTS_PASS(nng_pair1_open(&c1));
	NUTS_PASS(nng_pair1_open(&c2));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(c1, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(c2, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, SECOND / 10));
	NUTS_PASS(nng_socket_set_ms(c1, NNG_OPT_RECVTIMEO, SECOND / 10));
	NUTS_PASS(nng_socket_set_ms(c2, NNG_OPT_RECVTIMEO, SECOND / 10));

	NUTS_PASS(nng_socket_get_bool(s1, NNG_OPT_PAIR1_POLY, &v));
	NUTS_TRUE(v);

	NUTS_MARRY(s1, c1);
	NUTS_MARRY(s1, c2);

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "ONE");
	NUTS_PASS(nng_sendmsg(c1, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	CHECK_STR(msg, "ONE");
	p1 = nng_msg_get_pipe(msg);
	NUTS_TRUE(nng_pipe_id(p1) > 0);
	nng_msg_free(msg);

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "TWO");
	NUTS_PASS(nng_sendmsg(c2, msg, 0));
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	CHECK_STR(msg, "TWO");
	p2 = nng_msg_get_pipe(msg);
	NUTS_TRUE(nng_pipe_id(p2) > 0);
	nng_msg_free(msg);

	NUTS_TRUE(nng_pipe_id(p1) != nng_pipe_id(p2));

	NUTS_PASS(nng_msg_alloc(&msg, 0));

	nng_msg_set_pipe(msg, p1);
	APPEND_STR(msg, "UNO");
	NUTS_PASS(nng_sendmsg(s1, msg, 0));
	NUTS_PASS(nng_recvmsg(c1, &msg, 0));
	CHECK_STR(msg, "UNO");
	nng_msg_free(msg);

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	nng_msg_set_pipe(msg, p2);
	APPEND_STR(msg, "DOS");
	NUTS_PASS(nng_sendmsg(s1, msg, 0));
	NUTS_PASS(nng_recvmsg(c2, &msg, 0));
	CHECK_STR(msg, "DOS");
	nng_msg_free(msg);

	NUTS_CLOSE(c1);

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	nng_msg_set_pipe(msg, p1);
	APPEND_STR(msg, "EIN");
	NUTS_PASS(nng_sendmsg(s1, msg, 0));
	NUTS_FAIL(nng_recvmsg(c2, &msg, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(c2);
}

void
test_poly_default(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_socket c2;
	nng_msg *  msg;

	NUTS_PASS(nng_pair1_open_poly(&s1));
	NUTS_PASS(nng_pair1_open(&c1));
	NUTS_PASS(nng_pair1_open(&c2));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(c1, NNG_OPT_SENDTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(c2, NNG_OPT_SENDTIMEO, SECOND));

	NUTS_MARRY(s1, c1);
	NUTS_MARRY(s1, c2);

	// This assumes poly picks the first suitor.  Applications
	// should not make the same assumption.
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "YES");
	NUTS_PASS(nng_sendmsg(s1, msg, 0));
	NUTS_PASS(nng_recvmsg(c1, &msg, 0));
	CHECK_STR(msg, "YES");
	nng_msg_free(msg);

	NUTS_CLOSE(c1);
	NUTS_SLEEP(10);

	// Verify that the other pipe is chosen as the next suitor.
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "AGAIN");
	NUTS_PASS(nng_sendmsg(s1, msg, 0));
	NUTS_PASS(nng_recvmsg(c2, &msg, 0));
	CHECK_STR(msg, "AGAIN");
	nng_msg_free(msg);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(c2);
}

void
test_poly_close_abort(void)
{
	nng_socket s;
	nng_socket c;

	NUTS_PASS(nng_pair1_open_poly(&s));
	NUTS_PASS(nng_pair1_open(&c));
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_SENDTIMEO, 200));
	NUTS_PASS(nng_socket_set_int(s, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_int(c, NNG_OPT_SENDBUF, 20));

	NUTS_MARRY(c, s);

	for (int i = 0; i < 20; i++) {
		NUTS_SEND(c, "TEST");
	}
	NUTS_SLEEP(50);

	NUTS_CLOSE(s);
	NUTS_CLOSE(c);
}

void
test_poly_recv_no_header(void)
{
	nng_socket s;
	nng_socket c;
	nng_msg *  m;

	NUTS_PASS(nng_pair1_open_poly(&s));
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
test_poly_recv_garbage(void)
{
	nng_socket s;
	nng_socket c;
	nng_msg *  m;

	NUTS_PASS(nng_pair1_open_poly(&s));
	NUTS_PASS(nng_pair1_open(&c));
	NUTS_PASS(nng_socket_set_bool(c, "pair1_test_inject_header", true));
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_SENDTIMEO, 200));

	NUTS_MARRY(c, s);

	// ridiculous hop count
	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append_u32(m, 0x1000));
	NUTS_PASS(nng_sendmsg(c, m, 0));
	NUTS_FAIL(nng_recvmsg(s, &m, 0), NNG_ETIMEDOUT);

	NUTS_CLOSE(c);
	NUTS_CLOSE(s);
}

void
test_poly_ttl(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;
	uint32_t   val;
	int        ttl;

	NUTS_PASS(nng_pair1_open_poly(&s1));
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
test_poly_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char *     addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_pair1_open_poly(&s1));
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

TEST_LIST = {
	{ "pair1 poly identity", test_poly_identity },
	{ "pair1 poly best effort", test_poly_best_effort },
	{ "pair1 poly cooked", test_poly_cooked },
	{ "pair1 poly default", test_poly_default },
	{ "pair1 poly recv no header", test_poly_recv_no_header },
	{ "pair1 poly recv garbage", test_poly_recv_garbage },
	{ "pair1 poly ttl", test_poly_ttl },
	{ "pair1 poly close abort", test_poly_close_abort },
	{ "pair1 poly validate peer", test_poly_validate_peer },

	{ NULL, NULL },
};
