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
#define MILLISECOND(x) (x)

TestMain("PIPELINE (PUSH/PULL) pattern", {
	atexit(nng_fini);
	const char *addr = "inproc://test";
	Convey("We can create a PUSH socket", {
		nng_socket push;

		So(nng_push_open(&push) == 0);

		Reset({ nng_close(push); });

		Convey("Recv fails", {
			nng_msg *msg;
			So(nng_recvmsg(push, &msg, 0) == NNG_ENOTSUP);
		});
	});

	Convey("We can create a PULL socket", {
		nng_socket pull;
		So(nng_pull_open(&pull) == 0);

		Reset({ nng_close(pull); });

		Convey("Send fails", {
			nng_msg *msg;
			So(nng_msg_alloc(&msg, 0) == 0);
			So(nng_sendmsg(pull, msg, 0) == NNG_ENOTSUP);
			nng_msg_free(msg);
		});
	});

	Convey("We can create a linked PUSH/PULL pair", {
		nng_socket push;
		nng_socket pull;
		nng_socket what;

		So(nng_push_open(&push) == 0);
		So(nng_pull_open(&pull) == 0);
		So(nng_push_open(&what) == 0);

		Reset({
			nng_close(push);
			nng_close(pull);
			nng_close(what);
		});

		// Its important to avoid a startup race that the
		// sender be the dialer.  Otherwise you need a delay
		// since the server accept is really asynchronous.
		So(nng_listen(pull, addr, NULL, 0) == 0);
		So(nng_dial(push, addr, NULL, 0) == 0);
		So(nng_dial(what, addr, NULL, 0) == 0);
		So(nng_close(what) == 0);

		nng_msleep(20);

		Convey("Push can send messages, and pull can recv", {
			nng_msg *msg;

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

	Convey("Load balancing", {
		nng_msg *    abc;
		nng_msg *    def;
		nng_duration msecs;
		nng_socket   push;
		nng_socket   pull1;
		nng_socket   pull2;
		nng_socket   pull3;

		So(nng_push_open(&push) == 0);
		So(nng_pull_open(&pull1) == 0);
		So(nng_pull_open(&pull2) == 0);
		So(nng_pull_open(&pull3) == 0);

		Reset({
			nng_close(push);
			nng_close(pull1);
			nng_close(pull2);
			nng_close(pull3);
		});

		// We need to increase the buffer from zero, because
		// there is no guarantee that the various listeners
		// will be present, which means that they will push
		// back during load balancing.  Adding a small buffer
		// ensures that we can write to each stream, even if
		// the listeners are not running yet.
		So(nng_setopt_int(push, NNG_OPT_RECVBUF, 4) == 0);
		So(nng_setopt_int(push, NNG_OPT_SENDBUF, 4) == 0);
		So(nng_setopt_int(pull1, NNG_OPT_RECVBUF, 4) == 0);
		So(nng_setopt_int(pull1, NNG_OPT_SENDBUF, 4) == 0);
		So(nng_setopt_int(pull2, NNG_OPT_RECVBUF, 4) == 0);
		So(nng_setopt_int(pull2, NNG_OPT_SENDBUF, 4) == 0);
		So(nng_setopt_int(pull3, NNG_OPT_RECVBUF, 4) == 0);
		So(nng_setopt_int(pull3, NNG_OPT_SENDBUF, 4) == 0);

		So(nng_msg_alloc(&abc, 0) == 0);
		APPENDSTR(abc, "abc");
		So(nng_msg_alloc(&def, 0) == 0);
		APPENDSTR(def, "def");

		msecs = MILLISECOND(100);
		So(nng_setopt_ms(pull1, NNG_OPT_RECVTIMEO, msecs) == 0);
		So(nng_setopt_ms(pull2, NNG_OPT_RECVTIMEO, msecs) == 0);
		So(nng_setopt_ms(pull3, NNG_OPT_RECVTIMEO, msecs) == 0);
		So(nng_listen(push, addr, NULL, 0) == 0);
		So(nng_dial(pull1, addr, NULL, 0) == 0);
		So(nng_dial(pull2, addr, NULL, 0) == 0);
		So(nng_dial(pull3, addr, NULL, 0) == 0);
		So(nng_close(pull3) == 0);

		// So pull3 might not be done accepting yet, but pull1
		// and pull2 definitely are, because otherwise the
		// server couldn't have gotten to the accept.  (The
		// accept logic is single threaded.)  Let's wait a bit
		// though, to ensure that stuff has settled.
		nng_msleep(100);

		So(nng_sendmsg(push, abc, 0) == 0);
		So(nng_sendmsg(push, def, 0) == 0);

		abc = NULL;
		def = NULL;

		So(nng_recvmsg(pull1, &abc, 0) == 0);
		CHECKSTR(abc, "abc");
		So(nng_recvmsg(pull2, &def, 0) == 0);
		CHECKSTR(def, "def");
		nng_msg_free(abc);
		nng_msg_free(def);

		So(nng_recvmsg(pull1, &abc, 0) == NNG_ETIMEDOUT);
		So(nng_recvmsg(pull2, &abc, 0) == NNG_ETIMEDOUT);
	});
})
