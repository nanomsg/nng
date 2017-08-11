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
#include "core/nng_impl.h"
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

	Reset({
		nng_close(s1);
		nng_close(c1);
		nng_close(c2);
		nni_fini();
	});

	Convey("Given a few sockets", {
		trantest_next_address(addr, templ);
		So(nng_pair1_open(&s1) == 0);
		So(nng_pair1_open(&c1) == 0);
		So(nng_pair1_open(&c2) == 0);

		tmo = 500000;
		So(nng_setopt(s1, NNG_OPT_RCVTIMEO, &tmo, sizeof(tmo)) == 0);
		So(nng_setopt(c1, NNG_OPT_RCVTIMEO, &tmo, sizeof(tmo)) == 0);
		So(nng_setopt(c2, NNG_OPT_RCVTIMEO, &tmo, sizeof(tmo)) == 0);

		Convey("Monogamous cooked mode works", {
			nng_msg *msg;
			int      rv;

			So(nng_listen(s1, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(c1, addr, NULL, NNG_FLAG_SYNCH) == 0);

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

		Convey("Monogamous mode rejects new conns", {
			So(nng_dial(c2, addr, NULL, NNG_FLAG_SYNCH) ==
			    NNG_ECONNREFUSED);
		});

		Convey("Monogamous raw mode works", {
			nng_msg *msg;
			int      r = 1;
			uint32_t hops;

			So(nng_setopt(s1, NNG_OPT_RAW, &r, sizeof(r)) == 0);
			So(nng_setopt(c1, NNG_OPT_RAW, &r, sizeof(r)) == 0);
			So(nng_setopt(c2, NNG_OPT_RAW, &r, sizeof(r)) == 0);

			So(nng_listen(s1, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(c1, addr, NULL, NNG_FLAG_SYNCH) == 0);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "GAMMA");
			So(nng_msg_header_append_u32(msg, 1) == 0);
			So(nng_msg_header_len(msg) == sizeof(uint32_t));
			So(nng_sendmsg(c1, msg, 0) == 0);
			So(nng_recvmsg(s1, &msg, 0) == 0);
			So(nng_msg_get_pipe(msg) != 0);
			CHECKSTR(msg, "GAMMA");
			So(nng_msg_header_len(msg) == sizeof(uint32_t));
			So(nng_msg_header_trim_u32(msg, &hops) == 0);
			So(hops == 2);
			nng_msg_free(msg);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "EPSILON");
			So(nng_msg_header_append_u32(msg, 1) == 0);
			So(nng_sendmsg(s1, msg, 0) == 0);
			So(nng_recvmsg(c1, &msg, 0) == 0);
			CHECKSTR(msg, "EPSILON");
			So(nng_msg_header_len(msg) == sizeof(uint32_t));
			So(nng_msg_header_trim_u32(msg, &hops) == 0);
			So(nng_msg_get_pipe(msg) != 0);
			So(hops == 2);
			nng_msg_free(msg);
		});

		Convey("Polyamorous cooked mode works", {
			nng_msg *msg;
			int      rv;
			int      poly;
			nng_pipe p1;
			nng_pipe p2;
			size_t   sz;

			sz = sizeof(poly);
			So(nng_getopt(s1, NNG_OPT_POLYAMOROUS, &poly, &sz) ==
			    0);
			So(poly == 0);

			poly = 1;
			So(nng_setopt(s1, NNG_OPT_POLYAMOROUS, &poly,
			       sizeof(poly)) == 0);
			So(nng_getopt(s1, NNG_OPT_POLYAMOROUS, &poly, &sz) ==
			    0);
			So(poly == 1);

			So(nng_listen(s1, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(c1, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(c2, addr, NULL, NNG_FLAG_SYNCH) == 0);

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

		Convey("Polyamorous raw mode works", {
			nng_msg *msg;
			int      rv;
			int      poly;
			int      raw;
			uint32_t hops;
			nng_pipe p1;
			nng_pipe p2;
			size_t   sz;

			sz = sizeof(poly);
			So(nng_getopt(s1, NNG_OPT_POLYAMOROUS, &poly, &sz) ==
			    0);
			So(poly == 0);

			poly = 1;
			So(nng_setopt(s1, NNG_OPT_POLYAMOROUS, &poly,
			       sizeof(poly)) == 0);
			So(nng_getopt(s1, NNG_OPT_POLYAMOROUS, &poly, &sz) ==
			    0);
			So(poly == 1);

			raw = 1;
			So(nng_setopt(s1, NNG_OPT_RAW, &raw, sizeof(poly)) ==
			    0);

			So(nng_listen(s1, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(c1, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(c2, addr, NULL, NNG_FLAG_SYNCH) == 0);

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

			nng_close(c1);

			So(nng_msg_alloc(&msg, 0) == 0);
			nng_msg_set_pipe(msg, p1);
			APPENDSTR(msg, "EIN");
			So(nng_msg_header_append_u32(msg, 1) == 0);
			So(nng_sendmsg(s1, msg, 0) == 0);
			So(nng_recvmsg(c2, &msg, 0) == NNG_ETIMEDOUT);
		});
	});
})
