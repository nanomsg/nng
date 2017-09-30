//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "trantest.h"

#include <string.h>

#define APPENDSTR(m, s) nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)                   \
	So(nng_msg_len(m) == strlen(s)); \
	So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

TestMain("PAIRv1 protocol", {
	const char *templ = "inproc://pairv1/%u";
	char        addr[NNG_MAXADDRLEN + 1];
	nng_socket  s1 = 0;
	nng_socket  c1 = 0;
	nng_socket  c2 = 0;
	uint64_t    tmo;
	uint32_t    v;
	size_t      sz;

	atexit(nng_fini);

	Convey("Given a few sockets", {
		trantest_next_address(addr, templ);
		So(nng_pair1_open(&s1) == 0);
		So(nng_pair1_open(&c1) == 0);
		So(nng_pair1_open(&c2) == 0);

		Reset({
			nng_close(s1);
			nng_close(c1);
			nng_close(c2);
		});

		tmo = 300000;
		So(nng_setopt_usec(s1, NNG_OPT_RECVTIMEO, tmo) == 0);
		So(nng_setopt_usec(c1, NNG_OPT_RECVTIMEO, tmo) == 0);
		So(nng_setopt_usec(c2, NNG_OPT_RECVTIMEO, tmo) == 0);
		tmo = 0;
		So(nng_getopt_usec(s1, NNG_OPT_RECVTIMEO, &tmo) == 0);
		So(tmo == 300000);

		Convey("Monogamous cooked mode works", {
			nng_msg *msg;

			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			nng_usleep(20000);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "ALPHA");
			So(nng_sendmsg(c1, msg, 0) == 0);
			So(nng_recvmsg(s1, &msg, 0) == 0);
			CHECKSTR(msg, "ALPHA");
			nng_msg_free(msg);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "BETA");
			So(nng_sendmsg(s1, msg, 0) == 0);
			So(nng_recvmsg(c1, &msg, 0) == 0);
			CHECKSTR(msg, "BETA");
			nng_msg_free(msg);
		});

		Convey("Monogamous mode ignores new conns", {
			nng_msg *msg;

			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			nng_usleep(100000);
			So(nng_dial(c2, addr, NULL, 0) == 0);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "ONE");
			So(nng_sendmsg(c1, msg, 0) == 0);
			So(nng_recvmsg(s1, &msg, 0) == 0);
			CHECKSTR(msg, "ONE");
			nng_msg_free(msg);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "TWO");
			So(nng_sendmsg(c2, msg, 0) == 0);
			So(nng_recvmsg(s1, &msg, 0) == NNG_ETIMEDOUT);
		});

		Convey("Cannot set raw mode after connect", {
			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			nng_usleep(100000);

			So(nng_setopt_int(s1, NNG_OPT_RAW, 1) == NNG_ESTATE);
			So(nng_setopt_int(c1, NNG_OPT_RAW, 1) == NNG_ESTATE);
		});

		Convey("Polyamorous mode is best effort", {
			int      rv;
			int      i;
			nng_msg *msg;

			So(nng_setopt_int(s1, NNG_OPT_PAIR1_POLY, 1) == 0);

			So(nng_setopt_int(s1, NNG_OPT_RECVBUF, 1) == 0);
			So(nng_setopt_int(s1, NNG_OPT_SENDBUF, 1) == 0);
			So(nng_setopt_int(c1, NNG_OPT_RECVBUF, 1) == 0);
			So(nng_setopt_usec(s1, NNG_OPT_SENDTIMEO, 100000) ==
			    0);

			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			nng_usleep(20000);

			for (i = 0, rv = 0; i < 10; i++) {
				So(nng_msg_alloc(&msg, 0) == 0);
				if ((rv = nng_sendmsg(s1, msg, 0)) != 0) {
					nng_msg_free(msg);
					break;
				}
			}
			So(rv == 0);
			So(i == 10);
		});

		Convey("Monogamous mode exerts backpressure", {
			int      i;
			int      rv;
			nng_msg *msg;

			So(nng_setopt_int(s1, NNG_OPT_RECVBUF, 1) == 0);
			So(nng_setopt_int(s1, NNG_OPT_SENDBUF, 1) == 0);
			So(nng_setopt_int(c1, NNG_OPT_RECVBUF, 1) == 0);
			So(nng_setopt_usec(s1, NNG_OPT_SENDTIMEO, 30000) == 0);

			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			nng_usleep(20000);

			// We choose to allow some buffering.  In reality the
			// buffer size is just 1, and we will fail after 2.
			for (i = 0, rv = 0; i < 10; i++) {
				So(nng_msg_alloc(&msg, 0) == 0);
				if ((rv = nng_sendmsg(s1, msg, 0)) != 0) {
					nng_msg_free(msg);
					break;
				}
			}
			So(rv == NNG_ETIMEDOUT);
			So(i < 10);
		});

		Convey("Cannot set polyamorous mode after connect", {
			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			nng_usleep(100000);

			So(nng_setopt_int(s1, NNG_OPT_PAIR1_POLY, 1) ==
			    NNG_ESTATE);
		});

		Convey("Monogamous raw mode works", {
			nng_msg *msg;
			uint32_t hops;

			So(nng_setopt_int(s1, NNG_OPT_RAW, 1) == 0);
			So(nng_setopt_int(c1, NNG_OPT_RAW, 1) == 0);
			So(nng_setopt_int(c2, NNG_OPT_RAW, 1) == 0);

			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			nng_usleep(20000);

			Convey("Send/recv work", {
				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "GAMMA");
				So(nng_msg_header_append_u32(msg, 1) == 0);
				So(nng_msg_header_len(msg) ==
				    sizeof(uint32_t));
				So(nng_sendmsg(c1, msg, 0) == 0);
				So(nng_recvmsg(s1, &msg, 0) == 0);
				So(nng_msg_get_pipe(msg) != 0);
				CHECKSTR(msg, "GAMMA");
				So(nng_msg_header_len(msg) ==
				    sizeof(uint32_t));
				So(nng_msg_header_trim_u32(msg, &hops) == 0);
				So(hops == 2);
				nng_msg_free(msg);

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "EPSILON");
				So(nng_msg_header_append_u32(msg, 1) == 0);
				So(nng_sendmsg(s1, msg, 0) == 0);
				So(nng_recvmsg(c1, &msg, 0) == 0);
				CHECKSTR(msg, "EPSILON");
				So(nng_msg_header_len(msg) ==
				    sizeof(uint32_t));
				So(nng_msg_header_trim_u32(msg, &hops) == 0);
				So(nng_msg_get_pipe(msg) != 0);
				So(hops == 2);
				nng_msg_free(msg);
			});

			Convey("Missing raw header fails", {
				So(nng_msg_alloc(&msg, 0) == 0);
				So(nng_sendmsg(c1, msg, 0) == 0);
				So(nng_recvmsg(s1, &msg, 0) == NNG_ETIMEDOUT);

				So(nng_msg_alloc(&msg, 0) == 0);
				So(nng_msg_append_u32(msg, 0xFEEDFACE) == 0);
				So(nng_msg_header_append_u32(msg, 1) == 0);
				So(nng_sendmsg(c1, msg, 0) == 0);
				So(nng_recvmsg(s1, &msg, 0) == 0);
				So(nng_msg_trim_u32(msg, &v) == 0);
				So(v == 0xFEEDFACE);
				nng_msg_free(msg);
			});

			Convey("Reserved bits in raw header", {

				Convey("Nonzero bits fail", {
					So(nng_msg_alloc(&msg, 0) == 0);
					So(nng_msg_header_append_u32(
					       msg, 0xDEAD0000) == 0);
					So(nng_sendmsg(c1, msg, 0) == 0);
					So(nng_recvmsg(s1, &msg, 0) ==
					    NNG_ETIMEDOUT);
				});
				Convey("Zero bits pass", {
					So(nng_msg_alloc(&msg, 0) == 0);
					So(nng_msg_append_u32(
					       msg, 0xFEEDFACE) == 0);
					So(nng_msg_header_append_u32(msg, 1) ==
					    0);
					So(nng_sendmsg(c1, msg, 0) == 0);
					So(nng_recvmsg(s1, &msg, 0) == 0);
					So(nng_msg_trim_u32(msg, &v) == 0);
					So(v == 0xFEEDFACE);
					nng_msg_free(msg);
				});
			});

			Convey("TTL is honored", {
				int ttl;

				So(nng_setopt_int(s1, NNG_OPT_MAXTTL, 4) == 0);
				So(nng_getopt_int(s1, NNG_OPT_MAXTTL, &ttl) ==
				    0);
				So(ttl == 4);
				Convey("Bad TTL bounces", {
					So(nng_msg_alloc(&msg, 0) == 0);
					So(nng_msg_header_append_u32(msg, 4) ==
					    0);
					So(nng_sendmsg(c1, msg, 0) == 0);
					So(nng_recvmsg(s1, &msg, 0) ==
					    NNG_ETIMEDOUT);
				});
				Convey("Good TTL passes", {
					So(nng_msg_alloc(&msg, 0) == 0);
					So(nng_msg_append_u32(
					       msg, 0xFEEDFACE) == 0);
					So(nng_msg_header_append_u32(msg, 3) ==
					    0);
					So(nng_sendmsg(c1, msg, 0) == 0);
					So(nng_recvmsg(s1, &msg, 0) == 0);
					So(nng_msg_trim_u32(msg, &v) == 0);
					So(v == 0xFEEDFACE);
					So(nng_msg_header_trim_u32(msg, &v) ==
					    0);
					So(v == 4);
					nng_msg_free(msg);
				});

				Convey("Large TTL passes", {
					ttl = 0xff;
					So(nng_setopt_int(
					       s1, NNG_OPT_MAXTTL, 0xff) == 0);
					So(nng_msg_alloc(&msg, 0) == 0);
					So(nng_msg_append_u32(msg, 1234) == 0);
					So(nng_msg_header_append_u32(
					       msg, 0xfe) == 0);
					So(nng_sendmsg(c1, msg, 0) == 0);
					So(nng_recvmsg(s1, &msg, 0) == 0);
					So(nng_msg_trim_u32(msg, &v) == 0);
					So(v == 1234);
					So(nng_msg_header_trim_u32(msg, &v) ==
					    0);
					So(v == 0xff);
					nng_msg_free(msg);
				});

				Convey("Max TTL fails", {
					ttl = 0xff;
					So(nng_setopt_int(
					       s1, NNG_OPT_MAXTTL, 0xff) == 0);
					So(nng_msg_alloc(&msg, 0) == 0);
					So(nng_msg_header_append_u32(
					       msg, 0xff) == 0);
					So(nng_sendmsg(c1, msg, 0) == 0);
					So(nng_recvmsg(s1, &msg, 0) ==
					    NNG_ETIMEDOUT);
				});
			});
		});

		Convey("We cannot set insane TTLs", {
			int ttl;

			ttl = 0;
			So(nng_setopt_int(s1, NNG_OPT_MAXTTL, 0) ==
			    NNG_EINVAL);

			So(nng_setopt_int(s1, NNG_OPT_MAXTTL, 1000) ==
			    NNG_EINVAL);

			sz  = 1;
			ttl = 8;
			So(nng_setopt(s1, NNG_OPT_MAXTTL, &ttl, sz) ==
			    NNG_EINVAL);
		});

		Convey("Polyamorous cooked mode works", {
			nng_msg *msg;
			int      v;
			nng_pipe p1;
			nng_pipe p2;

			So(nng_getopt_int(s1, NNG_OPT_PAIR1_POLY, &v) == 0);
			So(v == 0);

			So(nng_setopt_int(s1, NNG_OPT_PAIR1_POLY, 1) == 0);
			So(nng_getopt_int(s1, NNG_OPT_PAIR1_POLY, &v) == 0);
			So(v == 1);

			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			So(nng_dial(c2, addr, NULL, 0) == 0);
			nng_usleep(20000);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "ONE");
			So(nng_sendmsg(c1, msg, 0) == 0);
			So(nng_recvmsg(s1, &msg, 0) == 0);
			CHECKSTR(msg, "ONE");
			p1 = nng_msg_get_pipe(msg);
			So(p1 != 0);
			nng_msg_free(msg);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "TWO");
			So(nng_sendmsg(c2, msg, 0) == 0);
			So(nng_recvmsg(s1, &msg, 0) == 0);
			CHECKSTR(msg, "TWO");
			p2 = nng_msg_get_pipe(msg);
			So(p2 != 0);
			nng_msg_free(msg);

			So(p1 != p2);

			So(nng_msg_alloc(&msg, 0) == 0);

			nng_msg_set_pipe(msg, p1);
			APPENDSTR(msg, "UNO");
			So(nng_sendmsg(s1, msg, 0) == 0);
			So(nng_recvmsg(c1, &msg, 0) == 0);
			CHECKSTR(msg, "UNO");
			nng_msg_free(msg);

			So(nng_msg_alloc(&msg, 0) == 0);
			nng_msg_set_pipe(msg, p2);
			APPENDSTR(msg, "DOS");
			So(nng_sendmsg(s1, msg, 0) == 0);
			So(nng_recvmsg(c2, &msg, 0) == 0);
			CHECKSTR(msg, "DOS");
			nng_msg_free(msg);

			nng_close(c1);

			So(nng_msg_alloc(&msg, 0) == 0);
			nng_msg_set_pipe(msg, p1);
			APPENDSTR(msg, "EIN");
			So(nng_sendmsg(s1, msg, 0) == 0);
			So(nng_recvmsg(c2, &msg, 0) == NNG_ETIMEDOUT);
		});

		Convey("Polyamorous default works", {
			nng_msg *msg;

			So(nng_setopt_int(s1, NNG_OPT_PAIR1_POLY, 1) == 0);

			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			nng_usleep(100000);
			So(nng_dial(c2, addr, NULL, 0) == 0);
			nng_usleep(20000);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "YES");
			So(nng_sendmsg(s1, msg, 0) == 0);
			So(nng_recvmsg(c1, &msg, 0) == 0);
			CHECKSTR(msg, "YES");
			nng_msg_free(msg);

			nng_close(c1);
			nng_usleep(10000);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "AGAIN");
			So(nng_sendmsg(s1, msg, 0) == 0);
			So(nng_recvmsg(c2, &msg, 0) == 0);
			CHECKSTR(msg, "AGAIN");
			nng_msg_free(msg);
		});

		Convey("Polyamorous raw mode works", {
			nng_msg *msg;
			int      v;
			uint32_t hops;
			nng_pipe p1;
			nng_pipe p2;

			So(nng_getopt_int(s1, NNG_OPT_PAIR1_POLY, &v) == 0);
			So(v == 0);

			So(nng_setopt_int(s1, NNG_OPT_PAIR1_POLY, 1) == 0);
			So(nng_getopt_int(s1, NNG_OPT_PAIR1_POLY, &v) == 0);
			So(v == 1);

			v = 0;
			So(nng_setopt_int(s1, NNG_OPT_RAW, 1) == 0);
			So(nng_getopt_int(s1, NNG_OPT_RAW, &v) == 0);
			So(v == 1);

			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(c1, addr, NULL, 0) == 0);
			So(nng_dial(c2, addr, NULL, 0) == 0);
			nng_usleep(20000);

			Convey("Send/recv works", {
				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "ONE");
				So(nng_sendmsg(c1, msg, 0) == 0);
				So(nng_recvmsg(s1, &msg, 0) == 0);
				CHECKSTR(msg, "ONE");
				p1 = nng_msg_get_pipe(msg);
				So(p1 != 0);
				So(nng_msg_header_trim_u32(msg, &hops) == 0);
				So(hops == 1);
				nng_msg_free(msg);

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "TWO");
				So(nng_sendmsg(c2, msg, 0) == 0);
				So(nng_recvmsg(s1, &msg, 0) == 0);
				CHECKSTR(msg, "TWO");
				p2 = nng_msg_get_pipe(msg);
				So(p2 != 0);
				So(nng_msg_header_trim_u32(msg, &hops) == 0);
				So(hops == 1);
				nng_msg_free(msg);

				So(p1 != p2);

				So(nng_msg_alloc(&msg, 0) == 0);
				nng_msg_set_pipe(msg, p1);
				APPENDSTR(msg, "UNO");
				So(nng_msg_header_append_u32(msg, 1) == 0);
				So(nng_sendmsg(s1, msg, 0) == 0);
				So(nng_recvmsg(c1, &msg, 0) == 0);
				CHECKSTR(msg, "UNO");
				nng_msg_free(msg);

				So(nng_msg_alloc(&msg, 0) == 0);
				nng_msg_set_pipe(msg, p2);
				APPENDSTR(msg, "DOS");
				So(nng_msg_header_append_u32(msg, 1) == 0);
				So(nng_sendmsg(s1, msg, 0) == 0);
				So(nng_recvmsg(c2, &msg, 0) == 0);
				CHECKSTR(msg, "DOS");
				nng_msg_free(msg);
			});

			Convey("Closed pipes don't work", {
				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "ONE");
				So(nng_sendmsg(c1, msg, 0) == 0);
				So(nng_recvmsg(s1, &msg, 0) == 0);
				CHECKSTR(msg, "ONE");
				p1 = nng_msg_get_pipe(msg);
				So(p1 != 0);
				nng_msg_free(msg);

				nng_close(c1);

				So(nng_msg_alloc(&msg, 0) == 0);
				nng_msg_set_pipe(msg, p1);
				APPENDSTR(msg, "EIN");
				So(nng_msg_header_append_u32(msg, 1) == 0);
				So(nng_sendmsg(s1, msg, 0) == 0);
				So(nng_recvmsg(c2, &msg, 0) == NNG_ETIMEDOUT);
			});
		});
	});
})
