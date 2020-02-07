//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/pair0/pair.h>
#include <nng/protocol/pair1/pair.h>

#include <testutil.h>

#include <acutest.h>

#define SECOND 1000

#define APPEND_STR(m, s) TEST_NNG_PASS(nng_msg_append(m, s, strlen(s)))
#define CHECK_STR(m, s)                          \
	TEST_CHECK(nng_msg_len(m) == strlen(s)); \
	TEST_CHECK(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

void
test_poly_best_effort(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_pair1_open_poly(&s1));
	TEST_NNG_PASS(nng_pair1_open(&c1));

	TEST_NNG_PASS(nng_setopt_int(s1, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(s1, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(c1, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, SECOND));

	TEST_NNG_PASS(testutil_marry(s1, c1));

	for (int i = 0; i < 10; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
		TEST_NNG_PASS(nng_sendmsg(s1, msg, 0));
	}

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(c1));
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

	TEST_NNG_PASS(nng_pair1_open_poly(&s1));
	TEST_NNG_PASS(nng_pair1_open(&c1));
	TEST_NNG_PASS(nng_pair1_open(&c2));
	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(c1, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(c2, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, SECOND / 10));
	TEST_NNG_PASS(nng_setopt_ms(c1, NNG_OPT_RECVTIMEO, SECOND / 10));
	TEST_NNG_PASS(nng_setopt_ms(c2, NNG_OPT_RECVTIMEO, SECOND / 10));

	TEST_NNG_PASS(nng_getopt_bool(s1, NNG_OPT_PAIR1_POLY, &v));
	TEST_CHECK(v == true);

	TEST_NNG_PASS(testutil_marry(s1, c1));
	TEST_NNG_PASS(testutil_marry(s1, c2));

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "ONE");
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(s1, &msg, 0));
	CHECK_STR(msg, "ONE");
	p1 = nng_msg_get_pipe(msg);
	TEST_CHECK(nng_pipe_id(p1) > 0);
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "TWO");
	TEST_NNG_PASS(nng_sendmsg(c2, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(s1, &msg, 0));
	CHECK_STR(msg, "TWO");
	p2 = nng_msg_get_pipe(msg);
	TEST_CHECK(nng_pipe_id(p2) > 0);
	nng_msg_free(msg);

	TEST_CHECK(nng_pipe_id(p1) != nng_pipe_id(p2));

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));

	nng_msg_set_pipe(msg, p1);
	APPEND_STR(msg, "UNO");
	TEST_NNG_PASS(nng_sendmsg(s1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(c1, &msg, 0));
	CHECK_STR(msg, "UNO");
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	nng_msg_set_pipe(msg, p2);
	APPEND_STR(msg, "DOS");
	TEST_NNG_PASS(nng_sendmsg(s1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(c2, &msg, 0));
	CHECK_STR(msg, "DOS");
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_close(c1));

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	nng_msg_set_pipe(msg, p1);
	APPEND_STR(msg, "EIN");
	TEST_NNG_PASS(nng_sendmsg(s1, msg, 0));
	TEST_NNG_FAIL(nng_recvmsg(c2, &msg, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(c2));
}

void
test_poly_default(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_socket c2;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_pair1_open_poly(&s1));
	TEST_NNG_PASS(nng_pair1_open(&c1));
	TEST_NNG_PASS(nng_pair1_open(&c2));
	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(c1, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(c2, NNG_OPT_SENDTIMEO, SECOND));

	TEST_NNG_PASS(testutil_marry(s1, c1));
	TEST_NNG_PASS(testutil_marry(s1, c2));

	// This assumes poly picks the first suitor.  Applications
	// should not make the same assumption.
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "YES");
	TEST_NNG_PASS(nng_sendmsg(s1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(c1, &msg, 0));
	CHECK_STR(msg, "YES");
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_close(c1));
	testutil_sleep(10);

	// Verify that the other pipe is chosen as the next suitor.
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "AGAIN");
	TEST_NNG_PASS(nng_sendmsg(s1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(c2, &msg, 0));
	CHECK_STR(msg, "AGAIN");
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(c2));
}

void
test_poly_close_abort(void)
{
	nng_socket s;
	nng_socket c;

	TEST_NNG_PASS(nng_pair1_open_poly(&s));
	TEST_NNG_PASS(nng_pair1_open(&c));
	TEST_NNG_PASS(nng_setopt_ms(s, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(s, NNG_OPT_SENDTIMEO, 200));
	TEST_NNG_PASS(nng_setopt_int(s, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(c, NNG_OPT_SENDBUF, 20));

	TEST_NNG_PASS(testutil_marry(c, s));

	for (int i = 0; i < 20; i++) {
		TEST_NNG_SEND_STR(c, "TEST");
	}
	testutil_sleep(50);

	TEST_NNG_PASS(nng_close(s));
	TEST_NNG_PASS(nng_close(c));
}


void
test_poly_recv_no_header(void)
{
	nng_socket s;
	nng_socket c;
	nng_msg *  m;

	TEST_NNG_PASS(nng_pair1_open_poly(&s));
	TEST_NNG_PASS(nng_pair1_open(&c));
	TEST_NNG_PASS(nng_setopt_bool(c, "pair1_test_inject_header", true));
	TEST_NNG_PASS(nng_setopt_ms(s, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(s, NNG_OPT_SENDTIMEO, 200));

	TEST_NNG_PASS(testutil_marry(c, s));

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_sendmsg(c, m, 0));
	TEST_NNG_FAIL(nng_recvmsg(s, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(c));
	TEST_NNG_PASS(nng_close(s));
}

void
test_poly_recv_garbage(void)
{
	nng_socket s;
	nng_socket c;
	nng_msg *  m;

	TEST_NNG_PASS(nng_pair1_open_poly(&s));
	TEST_NNG_PASS(nng_pair1_open(&c));
	TEST_NNG_PASS(nng_setopt_bool(c, "pair1_test_inject_header", true));
	TEST_NNG_PASS(nng_setopt_ms(s, NNG_OPT_RECVTIMEO, 100));
	TEST_NNG_PASS(nng_setopt_ms(s, NNG_OPT_SENDTIMEO, 200));

	TEST_NNG_PASS(testutil_marry(c, s));

	// ridiculous hop count
	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_append_u32(m, 0x1000));
	TEST_NNG_PASS(nng_sendmsg(c, m, 0));
	TEST_NNG_FAIL(nng_recvmsg(s, &m, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(c));
	TEST_NNG_PASS(nng_close(s));
}

void
test_poly_ttl(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;
	uint32_t   val;
	int        ttl;

	TEST_NNG_PASS(nng_pair1_open_poly(&s1));
	TEST_NNG_PASS(nng_pair1_open_raw(&c1));
	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, SECOND / 5));
	TEST_NNG_PASS(nng_setopt_ms(c1, NNG_OPT_RECVTIMEO, SECOND / 5));

	// cannot set insane TTLs
	TEST_NNG_FAIL(nng_setopt_int(s1, NNG_OPT_MAXTTL, 0), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_int(s1, NNG_OPT_MAXTTL, 1000), NNG_EINVAL);
	ttl = 8;
	TEST_NNG_FAIL(nng_setopt(s1, NNG_OPT_MAXTTL, &ttl, 1), NNG_EINVAL);
	TEST_NNG_FAIL(nng_setopt_bool(s1, NNG_OPT_MAXTTL, true), NNG_EBADTYPE);

	TEST_NNG_PASS(testutil_marry(s1, c1));

	// Let's check enforcement of TTL
	TEST_NNG_PASS(nng_setopt_int(s1, NNG_OPT_MAXTTL, 4));
	TEST_NNG_PASS(nng_getopt_int(s1, NNG_OPT_MAXTTL, &ttl));
	TEST_CHECK(ttl == 4);

	// Bad TTL bounces
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 4));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);

	// Good TTL passes
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_append_u32(msg, 0xFEEDFACE));
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 3));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(s1, &msg, 0));
	TEST_NNG_PASS(nng_msg_trim_u32(msg, &val));
	TEST_CHECK(val == 0xFEEDFACE);
	TEST_NNG_PASS(nng_msg_header_trim_u32(msg, &val));
	TEST_CHECK(val == 4);
	nng_msg_free(msg);

	// Large TTL passes
	TEST_NNG_PASS(nng_setopt_int(s1, NNG_OPT_MAXTTL, 15));
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_append_u32(msg, 1234));
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 14));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(s1, &msg, 0));
	TEST_NNG_PASS(nng_msg_trim_u32(msg, &val));
	TEST_CHECK(val == 1234);
	TEST_NNG_PASS(nng_msg_header_trim_u32(msg, &val));
	TEST_CHECK(val == 15);
	nng_msg_free(msg);

	// Max TTL fails
	TEST_NNG_PASS(nng_setopt_int(s1, NNG_OPT_MAXTTL, 15));
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 15));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(c1));
}

void
test_poly_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_pair1_open_poly(&s1));
	TEST_NNG_PASS(nng_pair0_open(&s2));

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

TEST_LIST = {
	{ "pair1 polyamorous best effort", test_poly_best_effort },
	{ "pair1 polyamorous cooked", test_poly_cooked },
	{ "pair1 polyamorous default", test_poly_default },
	{ "pair1 polyamorous recv no header", test_poly_recv_no_header },
	{ "pair1 polyamorous recv garbage", test_poly_recv_garbage },
	{ "pair1 polyamorous ttl", test_poly_ttl },
	{ "pair1 polyamorous close abort", test_poly_close_abort },
	{ "pair1 polyamorous validate peer", test_poly_validate_peer },

	{ NULL, NULL },
};
