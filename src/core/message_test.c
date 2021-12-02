//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>

#include "nuts.h"

void
test_msg_option(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_FAIL(nng_msg_getopt(msg, 0, NULL, NULL), NNG_ENOTSUP);
	nng_msg_free(msg);
}

void
test_msg_empty(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_ASSERT(nng_msg_len(msg) == 0);
	NUTS_ASSERT(nng_msg_header_len(msg) == 0);
	nng_msg_free(msg);
}

void
test_msg_append_body(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "pad", 4));
	NUTS_ASSERT(nng_msg_len(msg) == 4);
	NUTS_ASSERT(strcmp(nng_msg_body(msg), "pad") == 0);
	nng_msg_free(msg);
}

void
test_msg_append_header(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append(msg, "123", 4));
	NUTS_ASSERT(nng_msg_header_len(msg) == 4);
	NUTS_ASSERT(strcmp(nng_msg_header(msg), "123") == 0);
	nng_msg_free(msg);
}

void
test_msg_insert_body(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "xyz", 4));
	NUTS_PASS(nng_msg_insert(msg, "uvw", 3));
	NUTS_PASS(nng_msg_insert(msg, "st", 2));
	NUTS_ASSERT(nng_msg_len(msg) == 9);
	NUTS_ASSERT(strcmp(nng_msg_body(msg), "stuvwxyz") == 0);
	nng_msg_free(msg);
}

void
test_msg_insert_header(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append(msg, "def", 4));
	NUTS_PASS(nng_msg_header_insert(msg, "abc", 3));
	NUTS_ASSERT(nng_msg_header_len(msg) == 7);
	NUTS_ASSERT(strcmp(nng_msg_header(msg), "abcdef") == 0);
	nng_msg_free(msg);
}

void
test_msg_trim_body(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "uvwxyz", 7));
	NUTS_ASSERT(nng_msg_len(msg) == 7);
	NUTS_PASS(nng_msg_trim(msg, 2));
	NUTS_ASSERT(nng_msg_len(msg) == 5);
	NUTS_ASSERT(strcmp(nng_msg_body(msg), "wxyz") == 0);
	NUTS_FAIL(nng_msg_trim(msg, 10), NNG_EINVAL);
	nng_msg_free(msg);
}
void
test_msg_trim_header(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append(msg, "abcdef", 7));
	NUTS_ASSERT(nng_msg_header_len(msg) == 7);
	NUTS_PASS(nng_msg_header_trim(msg, 2));
	NUTS_ASSERT(nng_msg_header_len(msg) == 5);
	NUTS_ASSERT(strcmp(nng_msg_header(msg), "cdef") == 0);
	NUTS_FAIL(nng_msg_header_trim(msg, 10), NNG_EINVAL);
	nng_msg_free(msg);
}

void
test_msg_chop_body(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "123456", 7));
	NUTS_ASSERT(nng_msg_len(msg) == 7);
	NUTS_PASS(nng_msg_chop(msg, 5));
	NUTS_ASSERT(nng_msg_len(msg) == 2);
	NUTS_ASSERT(memcmp(nng_msg_body(msg), "12", 2) == 0);
	NUTS_FAIL(nng_msg_chop(msg, 10), NNG_EINVAL);
	nng_msg_free(msg);
}

void
test_msg_chop_header(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append(msg, "abcdef", 7));
	NUTS_ASSERT(nng_msg_header_len(msg) == 7);
	NUTS_PASS(nng_msg_header_chop(msg, 5));
	NUTS_ASSERT(nng_msg_header_len(msg) == 2);
	NUTS_ASSERT(memcmp(nng_msg_header(msg), "ab", 2) == 0);
	NUTS_FAIL(nng_msg_header_chop(msg, 10), NNG_EINVAL);
	nng_msg_free(msg);
}

void
test_msg_clear_body(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append(msg, "header", 7));
	NUTS_PASS(nng_msg_append(msg, "body", 5));
	NUTS_ASSERT(nng_msg_header_len(msg) == 7);
	NUTS_ASSERT(nng_msg_len(msg) == 5);
	nng_msg_clear(msg);
	NUTS_ASSERT(nng_msg_len(msg) == 0);
	NUTS_ASSERT(nng_msg_header_len(msg) == 7);
	NUTS_ASSERT(strcmp(nng_msg_header(msg), "header") == 0);

	nng_msg_free(msg);
}

void
test_msg_clear_header(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append(msg, "header", 7));
	NUTS_PASS(nng_msg_append(msg, "body", 5));
	NUTS_ASSERT(nng_msg_header_len(msg) == 7);
	NUTS_ASSERT(nng_msg_len(msg) == 5);
	nng_msg_header_clear(msg);
	NUTS_ASSERT(nng_msg_len(msg) == 5);
	NUTS_ASSERT(nng_msg_header_len(msg) == 0);
	NUTS_ASSERT(strcmp(nng_msg_body(msg), "body") == 0);

	nng_msg_free(msg);
}

void
test_msg_pipe(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	nng_pipe p  = NNG_PIPE_INITIALIZER;
	nng_pipe p0 = NNG_PIPE_INITIALIZER;

	NUTS_ASSERT(nng_pipe_id(p0) < 0);
	p = nng_msg_get_pipe(msg);
	NUTS_ASSERT(nng_pipe_id(p) < 0);
	memset(&p, 0x22, sizeof(p));
	nng_msg_set_pipe(msg, p);
	p = nng_msg_get_pipe(msg);
	NUTS_ASSERT(nng_pipe_id(p) != nng_pipe_id(p0));
	NUTS_ASSERT(nng_pipe_id(p) == 0x22222222);

	nng_msg_free(msg);
}

void
test_msg_reallocate(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_PASS(nng_msg_append(msg, "abc", 4));
	NUTS_PASS(nng_msg_realloc(msg, 1500));
	NUTS_ASSERT(nng_msg_len(msg) == 1500);
	NUTS_ASSERT(strcmp(nng_msg_body(msg), "abc") == 0);
	NUTS_ASSERT(nng_msg_realloc(msg, 2) == 0);
	NUTS_ASSERT(nng_msg_len(msg) == 2);
	NUTS_ASSERT(memcmp(nng_msg_body(msg), "abc", 3) == 0);
	NUTS_PASS(nng_msg_append(msg, "CDEF", strlen("CDEF") + 1));
	NUTS_ASSERT(nng_msg_len(msg) == strlen("abCDEF") + 1);
	NUTS_ASSERT(strcmp(nng_msg_body(msg), "abCDEF") == 0);
	nng_msg_free(msg);
}

void
test_msg_large(void)
{
	nng_msg *msg;
	char     chunk[1024];
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	memset(chunk, '+', sizeof(chunk));
	NUTS_PASS(nng_msg_append(msg, "abc", strlen("abc") + 1));
	NUTS_ASSERT(nng_msg_len(msg) == strlen("abc") + 1);
	NUTS_PASS(nng_msg_insert(msg, chunk, sizeof(chunk)));
	NUTS_ASSERT(nng_msg_len(msg) == strlen("abc") + 1 + sizeof(chunk));
	NUTS_ASSERT(memcmp(chunk, nng_msg_body(msg), sizeof(chunk)) == 0);
	NUTS_ASSERT(
	    strcmp((char *) nng_msg_body(msg) + sizeof(chunk), "abc") == 0);
	NUTS_PASS(nng_msg_trim(msg, sizeof(chunk) - 2));
	NUTS_ASSERT(strcmp(nng_msg_body(msg), "++abc") == 0);
	nng_msg_free(msg);
}

void
test_msg_dup(void)
{
	nng_msg *msg;
	nng_msg *m2;

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_header_append(msg, "front", strlen("front") + 1));
	NUTS_PASS(nng_msg_append(msg, "back", strlen("back") + 1));

	NUTS_PASS(nng_msg_dup(&m2, msg));

	NUTS_ASSERT(msg != m2);
	NUTS_ASSERT(nng_msg_len(msg) == strlen("front"));
	NUTS_ASSERT(nng_msg_len(m2) == strlen("front"));
	NUTS_ASSERT(nng_msg_header_len(msg) == nng_msg_header_len(m2));

	NUTS_PASS(nng_msg_insert(msg, "way", 3));
	NUTS_ASSERT(nng_msg_len(msg) == strlen("wayback") + 1);
	NUTS_ASSERT(nng_msg_len(m2) == strlen("back") + 1);
	NUTS_ASSERT(strcmp(nng_msg_body(msg), "wayback") == 0);
	NUTS_ASSERT(strcmp(nng_msg_body(m2), "back") == 0);
	NUTS_PASS(nng_msg_chop(m2, 1));
	NUTS_PASS(nng_msg_append(m2, "2basics", strlen("2basics") + 1));
	NUTS_ASSERT(nng_msg_len(msg) == strlen("wayback") + 1);
	NUTS_ASSERT(strcmp(nng_msg_body(msg), "wayback") == 0);
	NUTS_ASSERT(nng_msg_len(m2) == strlen("back2basics") + 1);
	NUTS_ASSERT(strcmp(nng_msg_body(m2), "back2basics") == 0);

	nng_msg_free(m2);
	nng_msg_free(msg);
}

void
test_msg_dup_pipe(void)
{
	nng_msg *msg;
	nng_msg *m2;
	nng_pipe p;

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	memset(&p, 0x22, sizeof(p));
	nng_msg_set_pipe(msg, p);
	NUTS_PASS(nng_msg_dup(&m2, msg));
	p = nng_msg_get_pipe(m2);
	NUTS_ASSERT(nng_pipe_id(p) == 0x22222222);
	nng_msg_free(msg);
	nng_msg_free(m2);
}

void
test_msg_body_uint16(void)
{
	nng_msg *msg;
	uint16_t v;
	uint8_t  data[] = { 0, 1, 0, 2, 0, 3 };

	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_PASS(nng_msg_append_u16(msg, 2));
	NUTS_PASS(nng_msg_insert_u16(msg, 1));
	NUTS_PASS(nng_msg_append_u16(msg, 3));
	NUTS_PASS(nng_msg_insert_u16(msg, 0));
	NUTS_PASS(nng_msg_trim_u16(msg, &v));
	NUTS_ASSERT(v == 0);
	NUTS_ASSERT(nng_msg_len(msg) == sizeof(data));
	NUTS_ASSERT(memcmp(nng_msg_body(msg), data, sizeof(data)) == 0);
	NUTS_PASS(nng_msg_trim_u16(msg, &v));
	NUTS_ASSERT(v == 1);
	NUTS_PASS(nng_msg_chop_u16(msg, &v));
	NUTS_ASSERT(v == 3);
	NUTS_PASS(nng_msg_trim_u16(msg, &v));
	NUTS_ASSERT(v == 2);
	NUTS_FAIL(nng_msg_trim_u16(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_chop_u16(msg, &v), NNG_EINVAL);

	nng_msg_clear(msg);
	NUTS_PASS(nng_msg_append(msg, &v, 1));
	NUTS_FAIL(nng_msg_trim_u16(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_chop_u16(msg, &v), NNG_EINVAL);

	nng_msg_free(msg);
}

void
test_msg_body_uint32(void)
{
	nng_msg *msg;
	uint32_t v;
	uint8_t  data[] = { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 };

	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_PASS(nng_msg_append_u32(msg, 2));
	NUTS_PASS(nng_msg_insert_u32(msg, 1));
	NUTS_PASS(nng_msg_append_u32(msg, 3));
	NUTS_PASS(nng_msg_insert_u32(msg, 0));
	NUTS_PASS(nng_msg_trim_u32(msg, &v));
	NUTS_ASSERT(v == 0);
	NUTS_ASSERT(nng_msg_len(msg) == sizeof(data));
	NUTS_ASSERT(memcmp(nng_msg_body(msg), data, sizeof(data)) == 0);
	NUTS_PASS(nng_msg_trim_u32(msg, &v));
	NUTS_ASSERT(v == 1);
	NUTS_PASS(nng_msg_chop_u32(msg, &v));
	NUTS_ASSERT(v == 3);
	NUTS_PASS(nng_msg_trim_u32(msg, &v));
	NUTS_ASSERT(v == 2);
	NUTS_FAIL(nng_msg_trim_u32(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_chop_u32(msg, &v), NNG_EINVAL);

	nng_msg_clear(msg);
	NUTS_PASS(nng_msg_append(msg, &v, 1));
	NUTS_FAIL(nng_msg_trim_u32(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_chop_u32(msg, &v), NNG_EINVAL);

	nng_msg_free(msg);
}
void
test_msg_body_uint64(void)
{
	nng_msg *msg;
	uint64_t v;
	uint8_t  data[] = { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0,
                0, 0, 0, 0, 0, 0, 3 };

	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_PASS(nng_msg_append_u64(msg, 2));
	NUTS_PASS(nng_msg_insert_u64(msg, 1));
	NUTS_PASS(nng_msg_append_u64(msg, 3));
	NUTS_PASS(nng_msg_insert_u64(msg, 0));
	NUTS_PASS(nng_msg_trim_u64(msg, &v));
	NUTS_ASSERT(v == 0);
	NUTS_ASSERT(nng_msg_len(msg) == sizeof(data));
	NUTS_ASSERT(memcmp(nng_msg_body(msg), data, sizeof(data)) == 0);
	NUTS_PASS(nng_msg_trim_u64(msg, &v));
	NUTS_ASSERT(v == 1);
	NUTS_PASS(nng_msg_chop_u64(msg, &v));
	NUTS_ASSERT(v == 3);
	NUTS_PASS(nng_msg_trim_u64(msg, &v));
	NUTS_ASSERT(v == 2);
	NUTS_FAIL(nng_msg_trim_u64(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_chop_u64(msg, &v), NNG_EINVAL);

	nng_msg_clear(msg);
	NUTS_PASS(nng_msg_append(msg, &v, 1));
	NUTS_FAIL(nng_msg_trim_u64(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_chop_u64(msg, &v), NNG_EINVAL);

	nng_msg_free(msg);
}

void
test_msg_header_uint16(void)
{
	nng_msg *msg;
	uint16_t v;
	uint8_t  data[] = { 0, 1, 0, 2, 0, 3 };

	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_PASS(nng_msg_header_append_u16(msg, 2));
	NUTS_PASS(nng_msg_header_insert_u16(msg, 1));
	NUTS_PASS(nng_msg_header_append_u16(msg, 3));
	NUTS_PASS(nng_msg_header_insert_u16(msg, 0));
	NUTS_PASS(nng_msg_header_trim_u16(msg, &v));
	NUTS_ASSERT(v == 0);
	NUTS_ASSERT(nng_msg_header_len(msg) == sizeof(data));
	NUTS_ASSERT(memcmp(nng_msg_header(msg), data, sizeof(data)) == 0);
	NUTS_PASS(nng_msg_header_trim_u16(msg, &v));
	NUTS_ASSERT(v == 1);
	NUTS_PASS(nng_msg_header_chop_u16(msg, &v));
	NUTS_ASSERT(v == 3);
	NUTS_PASS(nng_msg_header_trim_u16(msg, &v));
	NUTS_ASSERT(v == 2);
	NUTS_FAIL(nng_msg_header_trim_u16(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_header_chop_u16(msg, &v), NNG_EINVAL);

	nng_msg_clear(msg);
	NUTS_PASS(nng_msg_append(msg, &v, 1));
	NUTS_FAIL(nng_msg_trim_u16(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_chop_u16(msg, &v), NNG_EINVAL);

	nng_msg_free(msg);
}

void
test_msg_header_uint32(void)
{
	nng_msg *msg;
	uint32_t v;
	uint8_t  data[] = { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 };

	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_PASS(nng_msg_header_append_u32(msg, 2));
	NUTS_PASS(nng_msg_header_insert_u32(msg, 1));
	NUTS_PASS(nng_msg_header_append_u32(msg, 3));
	NUTS_PASS(nng_msg_header_insert_u32(msg, 0));
	NUTS_PASS(nng_msg_header_trim_u32(msg, &v));
	NUTS_ASSERT(v == 0);
	NUTS_ASSERT(nng_msg_header_len(msg) == sizeof(data));
	NUTS_ASSERT(memcmp(nng_msg_header(msg), data, sizeof(data)) == 0);
	NUTS_PASS(nng_msg_header_trim_u32(msg, &v));
	NUTS_ASSERT(v == 1);
	NUTS_PASS(nng_msg_header_chop_u32(msg, &v));
	NUTS_ASSERT(v == 3);
	NUTS_PASS(nng_msg_header_trim_u32(msg, &v));
	NUTS_ASSERT(v == 2);
	NUTS_FAIL(nng_msg_header_trim_u32(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_header_chop_u32(msg, &v), NNG_EINVAL);

	nng_msg_clear(msg);
	NUTS_PASS(nng_msg_append(msg, &v, 1));
	NUTS_FAIL(nng_msg_trim_u32(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_chop_u32(msg, &v), NNG_EINVAL);

	nng_msg_free(msg);
}

void
test_msg_header_uint64(void)
{
	nng_msg *msg;
	uint64_t v;
	uint8_t  data[] = { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0,
                0, 0, 0, 0, 0, 0, 3 };

	NUTS_PASS(nng_msg_alloc(&msg, 0));

	NUTS_PASS(nng_msg_header_append_u64(msg, 2));
	NUTS_PASS(nng_msg_header_insert_u64(msg, 1));
	NUTS_PASS(nng_msg_header_append_u64(msg, 3));
	NUTS_PASS(nng_msg_header_insert_u64(msg, 0));
	NUTS_PASS(nng_msg_header_trim_u64(msg, &v));
	NUTS_ASSERT(v == 0);
	NUTS_ASSERT(nng_msg_header_len(msg) == sizeof(data));
	NUTS_ASSERT(memcmp(nng_msg_header(msg), data, sizeof(data)) == 0);
	NUTS_PASS(nng_msg_header_trim_u64(msg, &v));
	NUTS_ASSERT(v == 1);
	NUTS_PASS(nng_msg_header_chop_u64(msg, &v));
	NUTS_ASSERT(v == 3);
	NUTS_PASS(nng_msg_header_trim_u64(msg, &v));
	NUTS_ASSERT(v == 2);
	NUTS_FAIL(nng_msg_header_trim_u64(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_header_chop_u64(msg, &v), NNG_EINVAL);

	nng_msg_clear(msg);
	NUTS_PASS(nng_msg_append(msg, &v, 1));
	NUTS_FAIL(nng_msg_trim_u64(msg, &v), NNG_EINVAL);
	NUTS_FAIL(nng_msg_chop_u64(msg, &v), NNG_EINVAL);

	nng_msg_free(msg);
}

void
test_msg_capacity(void)
{
	nng_msg *msg;
	char *   body;
	char     junk[64];

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_ASSERT(nng_msg_capacity(msg) == 32); // initial empty
	NUTS_PASS(nng_msg_append(msg, "abc", 4));
	NUTS_ASSERT(nng_msg_capacity(msg) == 32); // initial empty
	NUTS_ASSERT(nng_msg_len(msg) == 4);
	body = nng_msg_body(msg);
	NUTS_PASS(nng_msg_append(msg, junk, 64));
	NUTS_ASSERT(nng_msg_len(msg) == 68);
	NUTS_ASSERT(nng_msg_capacity(msg) >= 68);
	NUTS_ASSERT(body != nng_msg_body(msg));
	NUTS_ASSERT(memcmp(nng_msg_body(msg), "abc", 4) == 0);
	nng_msg_free(msg);
}

void
test_msg_reserve(void)
{
	nng_msg *msg;
	char *   body;

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_ASSERT(nng_msg_capacity(msg) == 32); // initial empty
	NUTS_PASS(nng_msg_append(msg, "abc", 4));
	NUTS_ASSERT(nng_msg_capacity(msg) == 32); // initial empty
	NUTS_ASSERT(nng_msg_len(msg) == 4);
	body = nng_msg_body(msg);
	NUTS_PASS(nng_msg_reserve(msg, 64));
	NUTS_ASSERT(nng_msg_len(msg) == 4);
	NUTS_ASSERT(nng_msg_capacity(msg) == 64);
	NUTS_ASSERT(body != nng_msg_body(msg));
	NUTS_ASSERT(memcmp(nng_msg_body(msg), "abc", 4) == 0);
	nng_msg_free(msg);
}

TEST_LIST = {
	{ "msg option", test_msg_option },
	{ "msg empty", test_msg_empty },
	{ "msg append body", test_msg_append_body },
	{ "msg append header", test_msg_append_header },
	{ "msg insert body", test_msg_insert_body },
	{ "msg insert header", test_msg_insert_header },
	{ "msg trim body", test_msg_trim_body },
	{ "msg trim header", test_msg_trim_header },
	{ "msg chop body", test_msg_chop_body },
	{ "msg chop header", test_msg_chop_header },
	{ "msg clear body", test_msg_clear_body },
	{ "msg clear header", test_msg_clear_header },
	{ "msg pipe", test_msg_pipe },
	{ "msg reallocate", test_msg_reallocate },
	{ "msg large", test_msg_large },
	{ "msg dup", test_msg_dup },
	{ "msg dup pipe", test_msg_dup_pipe },
	{ "msg body u16", test_msg_body_uint16 },
	{ "msg header u32", test_msg_header_uint16 },
	{ "msg body u32", test_msg_body_uint32 },
	{ "msg header u32", test_msg_header_uint32 },
	{ "msg body u64", test_msg_body_uint64 },
	{ "msg header u64", test_msg_header_uint64 },
	{ "msg capacity", test_msg_capacity },
	{ "msg reserve", test_msg_reserve },
	{ NULL, NULL },
};
