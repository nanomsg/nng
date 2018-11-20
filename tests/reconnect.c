//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

#define APPENDSTR(m, s) nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)                   \
	So(nng_msg_len(m) == strlen(s)); \
	So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

TestMain("Reconnect works", {
	atexit(nng_fini);
	const char *addr = "inproc://test";
	Convey("We can create a pipeline", {
		nng_socket push;
		nng_socket pull;

		So(nng_push_open(&push) == 0);
		So(nng_pull_open(&pull) == 0);

		Reset({
			nng_close(push);
			nng_close(pull);
		});

		So(nng_setopt_ms(pull, NNG_OPT_RECONNMINT, 10) == 0);
		So(nng_setopt_ms(pull, NNG_OPT_RECONNMAXT, 10) == 0);

		Convey("Dialing before listening works", {
			So(nng_dial(push, addr, NULL, NNG_FLAG_NONBLOCK) == 0);
			nng_msleep(100);
			So(nng_listen(pull, addr, NULL, 0) == 0);

			Convey("We can send a frame", {
				nng_msg *msg;

				nng_msleep(100);
				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "hello");
				So(nng_sendmsg(push, msg, 0) == 0);
				msg = NULL;
				So(nng_recvmsg(pull, &msg, 0) == 0);
				So(msg != NULL);
				CHECKSTR(msg, "hello");
				nng_msg_free(msg);
			});
		});
		Convey("Reconnection works", {
			nng_listener l;
			So(nng_dial(push, addr, NULL, NNG_FLAG_NONBLOCK) == 0);
			So(nng_listen(pull, addr, &l, 0) == 0);
			nng_msleep(100);
			nng_listener_close(l);
			So(nng_listen(pull, addr, NULL, 0) == 0);

			Convey("They still exchange frames", {
				nng_msg *msg;
				nng_pipe p1;

				nng_msleep(100);
				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "hello");
				So(nng_sendmsg(push, msg, 0) == 0);
				msg = NULL;
				So(nng_recvmsg(pull, &msg, 0) == 0);
				So(msg != NULL);
				CHECKSTR(msg, "hello");
				p1 = nng_msg_get_pipe(msg);
				nng_msg_free(msg);

				Convey("Even after pipe close", {
					nng_pipe p2;

					nng_pipe_close(p1);
					nng_msleep(100);
					So(nng_msg_alloc(&msg, 0) == 0);
					APPENDSTR(msg, "again");
					So(nng_sendmsg(push, msg, 0) == 0);
					msg = NULL;
					So(nng_recvmsg(pull, &msg, 0) == 0);
					So(msg != NULL);
					CHECKSTR(msg, "again");
					p2 = nng_msg_get_pipe(msg);
					nng_msg_free(msg);
					So(nng_pipe_id(p2) != nng_pipe_id(p1));
				});
			});
		});
	});
})
