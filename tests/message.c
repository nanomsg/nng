//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>

#include "convey.h"

static uint8_t dat123[] = { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 };

TestMain("Message Tests", {
	nng_msg *msg;

	Convey("Given an empty message", {
		So(nng_msg_alloc(&msg, 0) == 0);

		Reset({ nng_msg_free(msg); });

		Convey("Get opt returns ENOTSUP", {
			So(nng_msg_getopt(msg, 0, NULL, NULL) == NNG_ENOTSUP);
		});

		Convey("Lengths are empty", {
			So(nng_msg_len(msg) == 0);
			So(nng_msg_header_len(msg) == 0);
		});

		Convey("We can append to the header", {
			So(nng_msg_header_append(msg, "pad", 4) == 0);
			So(nng_msg_header_len(msg) == 4);
			So(strcmp(nng_msg_header(msg), "pad") == 0);
		});

		Convey("We can append to the body", {
			So(nng_msg_append(msg, "123", 4) == 0);
			So(nng_msg_len(msg) == 4);
			So(strcmp(nng_msg_body(msg), "123") == 0);
		});

		Convey("We can insert to the header", {
			So(nng_msg_header_append(msg, "def", 4) == 0);
			So(nng_msg_header_insert(msg, "abc", 3) == 0);
			So(nng_msg_header_len(msg) == 7);
			So(strcmp(nng_msg_header(msg), "abcdef") == 0);

			Convey("We can delete from the front", {
				So(nng_msg_header_trim(msg, 2) == 0);
				So(nng_msg_header_len(msg) == 5);
				So(strcmp(nng_msg_header(msg), "cdef") == 0);
			});

			Convey("We can delete from the back", {
				So(nng_msg_header_chop(msg, 5) == 0);
				So(nng_msg_header_len(msg) == 2);
				So(memcmp(nng_msg_header(msg), "ab", 2) == 0);
			});
		});

		Convey("We can insert to the body", {
			So(nng_msg_append(msg, "xyz", 4) == 0);
			So(nng_msg_insert(msg, "uvw", 3) == 0);
			So(nng_msg_len(msg) == 7);
			So(strcmp(nng_msg_body(msg), "uvwxyz") == 0);

			Convey("We can delete from the front", {
				So(nng_msg_trim(msg, 2) == 0);
				So(nng_msg_len(msg) == 5);
				So(strcmp(nng_msg_body(msg), "wxyz") == 0);
			});

			Convey("We can delete from the back", {
				So(nng_msg_chop(msg, 5) == 0);
				So(nng_msg_len(msg) == 2);
				So(memcmp(nng_msg_body(msg), "uv", 2) == 0);
			});
		});

		Convey("Clearing the header works", {
			So(nng_msg_header_append(msg, "bogus", 6) == 0);
			So(nng_msg_header_len(msg) == 6);
			nng_msg_header_clear(msg);
			So(nng_msg_header_len(msg) == 0);
		});

		Convey("Clearing the body works", {
			nng_msg_header_append(msg, "bogus", 6);
			So(nng_msg_append(msg, "bogus", 6) == 0);
			So(nng_msg_len(msg) == 6);
			nng_msg_clear(msg);
			So(nng_msg_len(msg) == 0);
			// It shouldn't clear the header
			So(nng_msg_header_len(msg) == 6);
		});

		Convey("We cannot delete more header than exists", {
			So(nng_msg_header_append(
			       msg, "short", strlen("short") + 1) == 0);
			So(nng_msg_header_trim(msg, 16) == NNG_EINVAL);
			So(nng_msg_header_len(msg) == strlen("short") + 1);
			So(nng_msg_header_chop(msg, 16) == NNG_EINVAL);
			So(nng_msg_header_len(msg) == strlen("short") + 1);
			So(strcmp(nng_msg_header(msg), "short") == 0);
		});

		Convey("We cannot delete more body than exists", {
			So(nng_msg_append(msg, "short", strlen("short") + 1) ==
			    0);
			So(nng_msg_trim(msg, 16) == NNG_EINVAL);
			So(nng_msg_len(msg) == strlen("short") + 1);
			So(nng_msg_chop(msg, 16) == NNG_EINVAL);
			So(nng_msg_len(msg) == strlen("short") + 1);
			So(strcmp(nng_msg_body(msg), "short") == 0);
		});

		Convey("Pipe retrievals work", {
			nng_pipe p  = NNG_PIPE_INITIALIZER;
			nng_pipe p0 = NNG_PIPE_INITIALIZER;

			So(nng_pipe_id(p0) < 0);
			p = nng_msg_get_pipe(msg);
			So(nng_pipe_id(p) < 0);
			memset(&p, 0x22, sizeof(p));
			nng_msg_set_pipe(msg, p);
			p = nng_msg_get_pipe(msg);
			So(nng_pipe_id(p) != nng_pipe_id(p0));
			So(nng_pipe_id(p) == 0x22222222);
		});

		Convey("Message realloc works", {
			So(nng_msg_append(msg, "abc", 4) == 0);
			So(nng_msg_realloc(msg, 1500) == 0);
			So(nng_msg_len(msg) == 1500);
			So(strcmp(nng_msg_body(msg), "abc") == 0);
			So(nng_msg_realloc(msg, 2) == 0);
			So(nng_msg_len(msg) == 2);
			So(memcmp(nng_msg_body(msg), "abc", 3) == 0);
			So(nng_msg_append(msg, "CDEF", strlen("CDEF") + 1) ==
			    0);
			So(nng_msg_len(msg) == strlen("abCDEF") + 1);
			So(strcmp(nng_msg_body(msg), "abCDEF") == 0);
		});

		Convey("Inserting a lot of data works", {
			char chunk[1024];
			memset(chunk, '+', sizeof(chunk));
			So(nng_msg_append(msg, "abc", strlen("abc") + 1) == 0);
			So(nng_msg_len(msg) == strlen("abc") + 1);
			So(nng_msg_insert(msg, chunk, sizeof(chunk)) == 0);
			So(nng_msg_len(msg) ==
			    strlen("abc") + 1 + sizeof(chunk));
			So(memcmp(chunk, nng_msg_body(msg), sizeof(chunk)) ==
			    0);
			So(strcmp((char *) nng_msg_body(msg) + sizeof(chunk),
			       "abc") == 0);
			So(nng_msg_trim(msg, sizeof(chunk) - 2) == 0);
			So(strcmp(nng_msg_body(msg), "++abc") == 0);
		});

		Convey("Message dup works", {
			nng_msg *m2;

			So(nng_msg_header_append(
			       msg, "front", strlen("front") + 1) == 0);
			So(nng_msg_append(msg, "back", strlen("back") + 1) ==
			    0);

			So(nng_msg_dup(&m2, msg) == 0);
			Reset({ nng_msg_free(m2); });

			So(nng_msg_len(msg) == strlen("front"));
			So(nng_msg_len(m2) == strlen("front"));
			So(nng_msg_header_len(msg) == nng_msg_header_len(m2));

			So(nng_msg_insert(msg, "way", 3) == 0);
			So(nng_msg_len(msg) == strlen("wayback") + 1);
			So(nng_msg_len(m2) == strlen("back") + 1);
			So(strcmp(nng_msg_body(msg), "wayback") == 0);
			So(strcmp(nng_msg_body(m2), "back") == 0);
			So(nng_msg_chop(m2, 1) == 0);
			So(nng_msg_append(
			       m2, "2basics", strlen("2basics") + 1) == 0);
			So(nng_msg_len(msg) == strlen("wayback") + 1);
			So(strcmp(nng_msg_body(msg), "wayback") == 0);
			So(nng_msg_len(m2) == strlen("back2basics") + 1);
			So(strcmp(nng_msg_body(m2), "back2basics") == 0);
		});

		Convey("Message dup copies pipe", {
			nng_pipe p = NNG_PIPE_INITIALIZER;
			nng_msg *m2;
			memset(&p, 0x22, sizeof(p));
			nng_msg_set_pipe(msg, p);
			So(nng_msg_dup(&m2, msg) == 0);
			Reset({ nng_msg_free(m2); });
			p = nng_msg_get_pipe(m2);
			So(nng_pipe_id(p) == 0x22222222);
		});

		Convey("Uint32 body operations work", {
			uint32_t v;
			So(nng_msg_append_u32(msg, 2) == 0);
			So(nng_msg_insert_u32(msg, 1) == 0);
			So(nng_msg_append_u32(msg, 3) == 0);
			So(nng_msg_insert_u32(msg, 0) == 0);
			So(nng_msg_trim_u32(msg, &v) == 0);
			So(v == 0);
			So(nng_msg_len(msg) == sizeof(dat123));
			So(memcmp(nng_msg_body(msg), dat123, sizeof(dat123)) ==
			    0);
			So(nng_msg_trim_u32(msg, &v) == 0);
			So(v == 1);
			So(nng_msg_chop_u32(msg, &v) == 0);
			So(v == 3);
			So(nng_msg_trim_u32(msg, &v) == 0);
			So(v == 2);
			So(nng_msg_trim_u32(msg, &v) == NNG_EINVAL);
			So(nng_msg_trim_u32(msg, &v) == NNG_EINVAL);

			Convey("Single byte is inadequate", {
				nng_msg_clear(msg);
				So(nng_msg_append(msg, &v, 1) == 0);
				So(nng_msg_trim_u32(msg, &v) == NNG_EINVAL);
				So(nng_msg_trim_u32(msg, &v) == NNG_EINVAL);
			});
		});

		Convey("Uint32 header operations work", {
			uint32_t v;
			So(nng_msg_header_append_u32(msg, 2) == 0);
			So(nng_msg_header_insert_u32(msg, 1) == 0);
			So(nng_msg_header_append_u32(msg, 3) == 0);
			So(nng_msg_header_insert_u32(msg, 0) == 0);
			So(nng_msg_header_trim_u32(msg, &v) == 0);
			So(v == 0);
			So(nng_msg_header_len(msg) == sizeof(dat123));
			So(nng_msg_len(msg) == 0);
			So(memcmp(nng_msg_header(msg), dat123,
			       sizeof(dat123)) == 0);
			So(nng_msg_header_trim_u32(msg, &v) == 0);
			So(v == 1);
			So(nng_msg_header_chop_u32(msg, &v) == 0);
			So(v == 3);
			So(nng_msg_header_trim_u32(msg, &v) == 0);
			So(v == 2);
			So(nng_msg_header_trim_u32(msg, &v) == NNG_EINVAL);
			So(nng_msg_header_trim_u32(msg, &v) == NNG_EINVAL);

			Convey("Single byte is inadequate", {
				nng_msg_header_clear(msg);
				So(nng_msg_header_append(msg, &v, 1) == 0);
				So(nng_msg_header_trim_u32(msg, &v) ==
				    NNG_EINVAL);
				So(nng_msg_header_trim_u32(msg, &v) ==
				    NNG_EINVAL);
			});
		});
	});
})
