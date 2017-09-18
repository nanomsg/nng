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

#include <string.h>

#define APPENDSTR(m, s) nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)                   \
	So(nng_msg_len(m) == strlen(s)); \
	So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

TestMain("PUB/SUB pattern", {
	const char *addr = "inproc://test";

	Reset({ nng_fini(); });

	Convey("We can create a PUB socket", {
		nng_socket pub;

		So(nng_pub_open(&pub) == 0);

		Reset({ nng_close(pub); });

		Convey("Protocols match", {
			So(nng_protocol(pub) == NNG_PROTO_PUB);
			So(nng_peer(pub) == NNG_PROTO_SUB);
		});

		Convey("Recv fails", {
			nng_msg *msg;
			So(nng_recvmsg(pub, &msg, 0) == NNG_ENOTSUP);
		});
	});

	Convey("We can create a SUB socket", {
		nng_socket sub;
		So(nng_sub_open(&sub) == 0);

		Reset({ nng_close(sub); });

		Convey("Protocols match", {
			So(nng_protocol(sub) == NNG_PROTO_SUB);
			So(nng_peer(sub) == NNG_PROTO_PUB);
		});

		Convey("Send fails", {
			nng_msg *msg;
			So(nng_msg_alloc(&msg, 0) == 0);
			So(nng_sendmsg(sub, msg, 0) == NNG_ENOTSUP);
			nng_msg_free(msg);
		});
	});

	Convey("We can create a linked PUB/SUB pair", {
		nng_socket pub;
		nng_socket sub;

		So(nng_pub_open(&pub) == 0);

		So(nng_sub_open(&sub) == 0);

		Reset({
			nng_close(pub);
			nng_close(sub);
		});

		// Most applications will usually have the pub listen,
		// and the sub dial.  However, this creates a problem
		// for our tests, since we can wind up trying to push
		// data before the pipe is fully registered (the accept
		// runs asynchronously.)
		So(nng_listen(sub, addr, NULL, 0) == 0);
		So(nng_dial(pub, addr, NULL, 0) == 0);

		nng_usleep(20000); // give time for connecting threads

		Convey("Sub can subscribe", {
			So(nng_setopt(
			       sub, nng_optid_sub_subscribe, "ABC", 3) == 0);
			So(nng_setopt(sub, nng_optid_sub_subscribe, "", 0) ==
			    0);
			Convey("Unsubscribe works", {
				So(nng_setopt(sub, nng_optid_sub_unsubscribe,
				       "ABC", 3) == 0);
				So(nng_setopt(sub, nng_optid_sub_unsubscribe,
				       "", 0) == 0);

				So(nng_setopt(sub, nng_optid_sub_unsubscribe,
				       "", 0) == NNG_ENOENT);
				So(nng_setopt(sub, nng_optid_sub_unsubscribe,
				       "HELLO", 0) == NNG_ENOENT);
			});
		});

		Convey("Pub cannot subscribe", {
			So(nng_setopt(pub, nng_optid_sub_subscribe, "", 0) ==
			    NNG_ENOTSUP);
		});

		Convey("Subs can receive from pubs", {
			nng_msg *msg;

			So(nng_setopt(sub, nng_optid_sub_subscribe, "/some/",
			       strlen("/some/")) == 0);
			So(nng_setopt_usec(sub, nng_optid_recvtimeo, 90000) ==
			    0);

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
		});

		Convey("Subs without subsciptions don't receive", {

			nng_msg *msg;
			So(nng_setopt_usec(sub, nng_optid_recvtimeo, 90000) ==
			    0);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "/some/don't/like/it");
			So(nng_sendmsg(pub, msg, 0) == 0);
			So(nng_recvmsg(sub, &msg, 0) == NNG_ETIMEDOUT);
		});

		Convey("Subs in raw receive", {

			nng_msg *msg;

			So(nng_setopt_usec(sub, nng_optid_recvtimeo, 90000) ==
			    0);
			So(nng_setopt_int(sub, nng_optid_raw, 1) == 0);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "/some/like/it/raw");
			So(nng_sendmsg(pub, msg, 0) == 0);
			So(nng_recvmsg(sub, &msg, 0) == 0);
			CHECKSTR(msg, "/some/like/it/raw");
			nng_msg_free(msg);
		});
	});
})
