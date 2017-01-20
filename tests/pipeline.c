//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "core/nng_impl.h"
#include <string.h>

#define	APPENDSTR(m, s)	nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)	So(nng_msg_len(m) == strlen(s));\
			So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

Main({
	const char *addr = "inproc://test";

	nni_init();

	Test("PIPELINE (PUSH/PULL) pattern", {
		Convey("We can create a PUSH socket", {
			nng_socket push;

			So(nng_open(&push, NNG_PROTO_PUSH) == 0);
			So(push != NULL);

			Reset({
				nng_close(push);
			})

			Convey("Protocols match", {
				So(nng_protocol(push) == NNG_PROTO_PUSH);
				So(nng_peer(push) == NNG_PROTO_PULL);
			})

			Convey("Recv fails", {
				nng_msg *msg;
				So(nng_recvmsg(push, &msg, 0) == NNG_ENOTSUP);
			})
		})

		Convey("We can create a PULL socket", {
			nng_socket pull;
			So(nng_open(&pull, NNG_PROTO_PULL) == 0);
			So(pull != NULL);

			Reset({
				nng_close(pull);
			})

			Convey("Protocols match", {
				So(nng_protocol(pull) == NNG_PROTO_PULL);
				So(nng_peer(pull) == NNG_PROTO_PUSH);
			})

			Convey("Send fails", {
				nng_msg *msg;
				So(nng_msg_alloc(&msg, 0) == 0);
				So(nng_sendmsg(pull, msg, 0) == NNG_ENOTSUP);
				nng_msg_free(msg);
			})
		})

		Convey("We can create a linked PUSH/PULL pair", {
			nng_socket push = NULL;
			nng_socket pull = NULL;
			nng_socket what = NULL;

			So(nng_open(&push, NNG_PROTO_PUSH) == 0);
			So(nng_open(&pull, NNG_PROTO_PULL) == 0);
			So(nng_open(&what, NNG_PROTO_PUSH) == 0);

			Reset({
				nng_close(push);
				nng_close(pull);
				nng_close(what);
			})

			// Its important to avoid a startup race that the
			// sender be the dialer.  Otherwise you need a delay
			// since the server accept is really asynchronous.
			So(nng_listen(pull, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(push, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(what, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_shutdown(what) == 0);

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
			})
		})

		Convey("Load balancing", {
			nng_msg *abc;
			nng_msg *def;
			uint64_t usecs;
			int len;
			nng_socket push;
			nng_socket pull1;
			nng_socket pull2;
			nng_socket pull3;

			So(nng_open(&push, NNG_PROTO_PUSH) == 0);
			So(nng_open(&pull1, NNG_PROTO_PULL) == 0);
			So(nng_open(&pull2, NNG_PROTO_PULL) == 0);
			So(nng_open(&pull3, NNG_PROTO_PULL) == 0);

			Reset({
				nng_close(push);
				nng_close(pull1);
				nng_close(pull2);
				nng_close(pull3);
			})

			// We need to increase the buffer from zero, because
			// there is no guarantee that the various listeners
			// will be present, which means that they will push
			// back during load balancing.  Adding a small buffer
			// ensures that we can write to each stream, even if
			// the listeners are not running yet.
			len = 4;
			So(nng_setopt(push, NNG_OPT_RCVBUF, &len, sizeof (len)) == 0);
			So(nng_setopt(push, NNG_OPT_SNDBUF, &len, sizeof (len)) == 0);
			So(nng_setopt(pull1, NNG_OPT_RCVBUF, &len, sizeof (len)) == 0);
			So(nng_setopt(pull1, NNG_OPT_SNDBUF, &len, sizeof (len)) == 0);
			So(nng_setopt(pull2, NNG_OPT_RCVBUF, &len, sizeof (len)) == 0);
			So(nng_setopt(pull2, NNG_OPT_SNDBUF, &len, sizeof (len)) == 0);
			So(nng_setopt(pull3, NNG_OPT_RCVBUF, &len, sizeof (len)) == 0);
			So(nng_setopt(pull3, NNG_OPT_SNDBUF, &len, sizeof (len)) == 0);

			So(nng_msg_alloc(&abc, 0) == 0);
			APPENDSTR(abc, "abc");
			So(nng_msg_alloc(&def, 0) == 0);
			APPENDSTR(def, "def");

			usecs = 100000;
			So(nng_setopt(pull1, NNG_OPT_RCVTIMEO, &usecs, sizeof (usecs)) == 0);
			So(nng_setopt(pull2, NNG_OPT_RCVTIMEO, &usecs, sizeof (usecs)) == 0);
			So(nng_setopt(pull3, NNG_OPT_RCVTIMEO, &usecs, sizeof (usecs)) == 0);
			So(nng_listen(push, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(pull1, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(pull2, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(pull3, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_shutdown(pull3) == 0);

			// So pull3 might not be done accepting yet, but pull1
			// and pull2 definitely are, because otherwise the
			// server couldn't have gotten to the accept.  (The
			// accept logic is single threaded.)  Let's wait a bit
			// though, to ensure that stuff has settled.
			nni_usleep(100000);

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
		})
	})

	nni_fini();
})
