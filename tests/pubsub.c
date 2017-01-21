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
	int rv;
	const char *addr = "inproc://test";
	nni_init();

	Test("PUB/SUB pattern", {
		Convey("We can create a PUB socket", {
			nng_socket pub;

			So(nng_open(&pub, NNG_PROTO_PUB) == 0);

			Reset({
				nng_close(pub);
			})

			Convey("Protocols match", {
				So(nng_protocol(pub) == NNG_PROTO_PUB);
				So(nng_peer(pub) == NNG_PROTO_SUB);
			})

			Convey("Recv fails", {
				nng_msg *msg;
				So(nng_recvmsg(pub, &msg, 0) == NNG_ENOTSUP);
			})
		})

		Convey("We can create a SUB socket", {
			nng_socket sub;
			So(nng_open(&sub, NNG_PROTO_SUB) == 0);

			Reset({
				nng_close(sub);
			})

			Convey("Protocols match", {
				So(nng_protocol(sub) == NNG_PROTO_SUB);
				So(nng_peer(sub) == NNG_PROTO_PUB);
			})

			Convey("Send fails", {
				nng_msg *msg;
				So(nng_msg_alloc(&msg, 0) == 0);
				So(nng_sendmsg(sub, msg, 0) == NNG_ENOTSUP);
				nng_msg_free(msg);
			})
		})

		Convey("We can create a linked PUB/SUB pair", {
			nng_socket pub;
			nng_socket sub;

			So(nng_open(&pub, NNG_PROTO_PUB) == 0);

			So(nng_open(&sub, NNG_PROTO_SUB) == 0);

			Reset({
				nng_close(pub);
				nng_close(sub);
			})

			// Most consumers will usually have the pub listen,
			// and the sub dial.  However, this creates a problem
			// for our tests, since we can wind up trying to push
			// data before the pipe is fully registered (the
			// accept runs in an asynch thread.)  Doing the reverse
			// here ensures that we won't lose data.
			So(nng_listen(sub, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(pub, addr, NULL, NNG_FLAG_SYNCH) == 0);

			Convey("Sub can subscribe", {
				So(nng_setopt(sub, NNG_OPT_SUBSCRIBE, "ABC", 3) == 0);
				So(nng_setopt(sub, NNG_OPT_SUBSCRIBE, "", 0) == 0);
				Convey("Unsubscribe works", {
					So(nng_setopt(sub, NNG_OPT_UNSUBSCRIBE, "ABC", 3) == 0);
					So(nng_setopt(sub, NNG_OPT_UNSUBSCRIBE, "", 0) == 0);

					So(nng_setopt(sub, NNG_OPT_UNSUBSCRIBE, "", 0) == NNG_ENOENT);
					So(nng_setopt(sub, NNG_OPT_UNSUBSCRIBE, "HELLO", 0) == NNG_ENOENT);
				})
			})

			Convey("Pub cannot subscribe", {
				So(nng_setopt(pub, NNG_OPT_SUBSCRIBE, "", 0) == NNG_ENOTSUP);
			})

			Convey("Subs can receive from pubs", {
				nng_msg *msg;
				uint64_t rtimeo;


				So(nng_setopt(sub, NNG_OPT_SUBSCRIBE, "/some/", strlen("/some/")) == 0);
				rtimeo = 50000; // 50ms
				So(nng_setopt(sub, NNG_OPT_RCVTIMEO, &rtimeo, sizeof (rtimeo)) == 0);

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "/some/like/it/hot");
				So(nng_sendmsg(pub, msg, 0) == 0);
				So(nng_recvmsg(sub, &msg, 0) == 0);
				CHECKSTR(msg, "/some/like/it/hot");
				nng_msg_free(msg);

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "/somewhere/over/the/rainbow");
				CHECKSTR(msg, "/somewhere/over/the/rainbow");

				So(nng_sendmsg(pub, msg, 0) == 0);
				So(nng_recvmsg(sub, &msg, 0) == NNG_ETIMEDOUT);

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "/some/day/some/how");
				CHECKSTR(msg, "/some/day/some/how");

				So(nng_sendmsg(pub, msg, 0) == 0);
				So(nng_recvmsg(sub, &msg, 0) == 0);
				CHECKSTR(msg, "/some/day/some/how");
				nng_msg_free(msg);
			})

			Convey("Subs without subsciptions don't receive", {

				uint64_t rtimeo = 50000; // 50ms
				nng_msg *msg;
				So(nng_setopt(sub, NNG_OPT_RCVTIMEO, &rtimeo, sizeof (rtimeo)) == 0);

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "/some/don't/like/it");
				So(nng_sendmsg(pub, msg, 0) == 0);
				So(nng_recvmsg(sub, &msg, 0) == NNG_ETIMEDOUT);
			})

			Convey("Subs in raw receive", {

				uint64_t rtimeo = 50000; // 500ms
				int raw = 1;
				nng_msg *msg;

				So(nng_setopt(sub, NNG_OPT_RCVTIMEO, &rtimeo, sizeof (rtimeo)) == 0);
				So(nng_setopt(sub, NNG_OPT_RAW, &raw, sizeof (raw)) == 0);

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "/some/like/it/raw");
				So(nng_sendmsg(pub, msg, 0) == 0);
				So(nng_recvmsg(sub, &msg, 0) == 0);
				CHECKSTR(msg, "/some/like/it/raw");
				nng_msg_free(msg);
			})

		})
	})

	nni_fini();
})
