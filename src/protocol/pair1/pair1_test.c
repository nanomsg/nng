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

#define APPEND_STR(m, s) TEST_CHECK(nng_msg_append(m, s, strlen(s)) == 0)
#define CHECK_STR(m, s)                          \
	TEST_CHECK(nng_msg_len(m) == strlen(s)); \
	TEST_CHECK(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

void
test_mono_cooked(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;

	TEST_NNG_PASS(nng_pair1_open(&s1));
	TEST_NNG_PASS(nng_pair1_open(&c1));
	TEST_NNG_PASS(testutil_marry(s1, c1));

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_append(msg, "ALPHA", strlen("ALPHA") + 1));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(s1, &msg, 0));
	TEST_CHECK(nng_msg_len(msg) == strlen("ALPHA") + 1);
	TEST_CHECK(strcmp(nng_msg_body(msg), "ALPHA") == 0);
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_append(msg, "BETA", strlen("BETA") + 1));
	TEST_NNG_PASS(nng_sendmsg(s1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(c1, &msg, 0));
	TEST_CHECK(nng_msg_len(msg) == strlen("BETA") + 1);
	TEST_CHECK(strcmp(nng_msg_body(msg), "BETA") == 0);

	nng_msg_free(msg);
	TEST_NNG_PASS(nng_close(c1));
	TEST_NNG_PASS(nng_close(s1));
}

void
test_mono_faithful(void)
{
	nng_socket  s1;
	nng_socket  c1;
	nng_socket  c2;
	nng_msg *   msg;
	const char *addr = "inproc://pair1_mono_faithful";

	TEST_NNG_PASS(nng_pair1_open(&s1));
	TEST_NNG_PASS(nng_pair1_open(&c1));
	TEST_NNG_PASS(nng_pair1_open(&c2));
	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, SECOND / 4));
	TEST_NNG_PASS(nng_setopt_ms(c1, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(c2, NNG_OPT_SENDTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_int(c2, NNG_OPT_SENDBUF, 2));

	TEST_NNG_PASS(nng_listen(s1, addr, NULL, 0));
	TEST_NNG_PASS(testutil_marry(s1, c1));
	TEST_NNG_PASS(nng_dial(c2, addr, NULL, 0));

	testutil_sleep(100);

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "ONE");
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(s1, &msg, 0));
	CHECK_STR(msg, "ONE");
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "TWO");
	TEST_NNG_PASS(nng_sendmsg(c2, msg, 0));
	TEST_NNG_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(c1));
	TEST_NNG_PASS(nng_close(c2));
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

	TEST_NNG_PASS(nng_pair1_open(&s1));
	TEST_NNG_PASS(nng_pair1_open(&c1));
	TEST_NNG_PASS(nng_setopt_int(s1, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(s1, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(c1, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, to));

	TEST_NNG_PASS(testutil_marry(s1, c1));

	// We choose to allow some buffering.  In reality the
	// buffer size is just 1, and we will fail after 2.
	for (i = 0, rv = 0; i < 10; i++) {
		TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
		if ((rv = nng_sendmsg(s1, msg, 0)) != 0) {
			nng_msg_free(msg);
			break;
		}
	}
	TEST_NNG_FAIL(rv, NNG_ETIMEDOUT);
	TEST_CHECK(i < 10);
	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(c1));
}

void
test_mono_raw_exchange(void)
{
	nng_socket s1;
	nng_socket c1;

	nng_msg *msg;
	uint32_t hops;

	TEST_NNG_PASS(nng_pair1_open_raw(&s1));
	TEST_NNG_PASS(nng_pair1_open_raw(&c1));

	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(nng_setopt_ms(c1, NNG_OPT_RECVTIMEO, SECOND));
	TEST_NNG_PASS(testutil_marry(s1, c1));

	nng_pipe p = NNG_PIPE_INITIALIZER;
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "GAMMA");
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 1));
	TEST_CHECK(nng_msg_header_len(msg) == sizeof(uint32_t));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(s1, &msg, 0));
	p = nng_msg_get_pipe(msg);
	TEST_CHECK(nng_pipe_id(p) > 0);

	CHECK_STR(msg, "GAMMA");
	TEST_CHECK(nng_msg_header_len(msg) == sizeof(uint32_t));
	TEST_NNG_PASS(nng_msg_header_trim_u32(msg, &hops));
	TEST_CHECK(hops == 2);
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	APPEND_STR(msg, "EPSILON");
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 1));
	TEST_NNG_PASS(nng_sendmsg(s1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(c1, &msg, 0));
	CHECK_STR(msg, "EPSILON");
	TEST_CHECK(nng_msg_header_len(msg) == sizeof(uint32_t));
	TEST_NNG_PASS(nng_msg_header_trim_u32(msg, &hops));
	p = nng_msg_get_pipe(msg);
	TEST_CHECK(nng_pipe_id(p) > 0);

	TEST_CHECK(hops == 2);
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(c1));
}

void
test_mono_raw_header(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;
	uint32_t   v;

	TEST_NNG_PASS(nng_pair1_open_raw(&s1));
	TEST_NNG_PASS(nng_pair1_open_raw(&c1));

	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, SECOND / 5));
	TEST_NNG_PASS(nng_setopt_ms(c1, NNG_OPT_RECVTIMEO, SECOND / 5));
	TEST_NNG_PASS(testutil_marry(s1, c1));

	// Missing bits in the header
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);

	// Valid header works
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_append_u32(msg, 0xFEEDFACE));
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 1));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(s1, &msg, 0));
	TEST_NNG_PASS(nng_msg_trim_u32(msg, &v));
	TEST_CHECK(v == 0xFEEDFACE);
	nng_msg_free(msg);

	// Header with reserved bits set dropped
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 0xDEAD0000));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);

	// Header with no chance to add another hop gets dropped
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 0xff));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);

	// With the same bits clear it works
	TEST_NNG_PASS(nng_msg_alloc(&msg, 0));
	TEST_NNG_PASS(nng_msg_append_u32(msg, 0xFEEDFACE));
	TEST_NNG_PASS(nng_msg_header_append_u32(msg, 1));
	TEST_NNG_PASS(nng_sendmsg(c1, msg, 0));
	TEST_NNG_PASS(nng_recvmsg(s1, &msg, 0));
	TEST_NNG_PASS(nng_msg_trim_u32(msg, &v));
	TEST_CHECK(v == 0xFEEDFACE);
	nng_msg_free(msg);

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(c1));
}

void
test_pair1_raw(void)
{
	nng_socket s1;
	bool       raw;

	TEST_NNG_PASS(nng_pair1_open(&s1));
	TEST_NNG_PASS(nng_getopt_bool(s1, NNG_OPT_RAW, &raw));
	TEST_CHECK(raw == false);
	TEST_NNG_FAIL(nng_setopt_bool(s1, NNG_OPT_RAW, true), NNG_EREADONLY);
	TEST_NNG_PASS(nng_close(s1));

	TEST_NNG_PASS(nng_pair1_open_raw(&s1));
	TEST_NNG_PASS(nng_getopt_bool(s1, NNG_OPT_RAW, &raw));
	TEST_CHECK(raw == true);
	TEST_NNG_FAIL(nng_setopt_bool(s1, NNG_OPT_RAW, false), NNG_EREADONLY);
	TEST_NNG_PASS(nng_close(s1));
}

void
test_pair1_ttl(void)
{
	nng_socket s1;
	nng_socket c1;
	nng_msg *  msg;
	uint32_t   val;
	int        ttl;

	TEST_NNG_PASS(nng_pair1_open_raw(&s1));
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
test_pair1_validate_peer(void)
{
	nng_socket s1, s2;
	nng_stat * stats;
	nng_stat * reject;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_pair1_open(&s1));
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

void
test_pair1_recv_no_header(void)
{
	nng_socket s;
	nng_socket c;
	nng_msg *  m;

	TEST_NNG_PASS(nng_pair1_open(&s));
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
test_pair1_recv_garbage(void)
{
	nng_socket s;
	nng_socket c;
	nng_msg *  m;

	TEST_NNG_PASS(nng_pair1_open(&s));
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

TEST_LIST = {
	{ "pair1 monogamous cooked", test_mono_cooked },
	{ "pair1 monogamous faithful", test_mono_faithful },
	{ "pair1 monogamous back pressure", test_mono_back_pressure },
	{ "pair1 monogamous raw exchange", test_mono_raw_exchange },
	{ "pair1 monogamous raw header", test_mono_raw_header },
	{ "pair1 raw", test_pair1_raw },
	{ "pair1 ttl", test_pair1_ttl },
	{ "pair1 validate peer", test_pair1_validate_peer },
	{ "pair1 recv no header", test_pair1_recv_no_header },
	{ "pair1 recv garbage", test_pair1_recv_garbage },

	{ NULL, NULL },
};
