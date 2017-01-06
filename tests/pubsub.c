//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"

#include <string.h>

Main({
	int rv;
	const char *addr = "inproc://test";

	Test("PUB/SUB pattern", {
		Convey("We can create a PUB socket", {
			nng_socket *pub;

			rv = nng_open(&pub, NNG_PROTO_PUB);
			So(rv == 0);
			So(pub != NULL);

			Reset({
				nng_close(pub);
			})

			Convey("Protocols match", {
				So(nng_protocol(pub) == NNG_PROTO_PUB);
				So(nng_peer(pub) == NNG_PROTO_SUB);
			})

			Convey("Recv fails", {
				nng_msg *msg;
				rv = nng_recvmsg(pub, &msg, 0);
				So(rv == NNG_ENOTSUP);
			})
		})

		Convey("We can create a SUB socket", {
			nng_socket *sub;
			rv = nng_open(&sub, NNG_PROTO_SUB);
			So(rv == 0);
			So(sub != NULL);

			Reset({
				nng_close(sub);
			})

			Convey("Protocols match", {
				So(nng_protocol(sub) == NNG_PROTO_SUB);
				So(nng_peer(sub) == NNG_PROTO_PUB);
			})

			Convey("Send fails", {
				nng_msg *msg;
				rv = nng_msg_alloc(&msg, 0);
				So(rv == 0);
				rv = nng_sendmsg(sub, msg, 0);
				So(rv == NNG_ENOTSUP);
				nng_msg_free(msg);
			})
		})

		Convey("We can create a linked PUB/SUB pair", {
			nng_socket *pub;
			nng_socket *sub;

			So((rv = nng_open(&pub, NNG_PROTO_PUB)) == 0);
			So(pub != NULL);

			So((rv = nng_open(&sub, NNG_PROTO_SUB)) == 0);
			So(sub != NULL);

			Reset({
				nng_close(pub);
				nng_close(sub);
			})

			So(nng_listen(pub, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(sub, addr, NULL, NNG_FLAG_SYNCH) == 0);

			Convey("Sub can subscribe", {
				So(nng_setopt(sub, NNG_OPT_SUBSCRIBE, "ABC", 3) == 0);
				So(nng_setopt(sub, NNG_OPT_SUBSCRIBE, "", 0) == 0);
				Convey("Unsubscribe works", {
					rv = nng_setopt(sub, NNG_OPT_UNSUBSCRIBE, "ABC", 3);
					So(nng_setopt(sub, NNG_OPT_UNSUBSCRIBE, "", 0) == 0);

					So(nng_setopt(sub, NNG_OPT_UNSUBSCRIBE, "", 0) == NNG_ENOENT);
					So(nng_setopt(sub, NNG_OPT_UNSUBSCRIBE, "HELLO", 0) == NNG_ENOENT);
				})
			})

			Convey("Pub cannot subscribe", {
				So(nng_setopt(pub, NNG_OPT_SUBSCRIBE, "", 0) == NNG_ENOTSUP);
			})
#if 0
			Convey("They can REQ/REP exchange", {
				nng_msg *ping;
				nng_msg *pong;
				char *body;
				size_t len;

				So(nng_msg_alloc(&ping, 0) == 0);
				So(nng_msg_append(ping, "ping", 5) == 0);
				body = nng_msg_body(ping, &len);
				So(len == 5);
				So(memcmp(body, "ping", 5) == 0);
				So(nng_sendmsg(req, ping, 0) == 0);
				pong = NULL;
				So(nng_recvmsg(rep, &pong, 0) == 0);
				So(pong != NULL);
				body = nng_msg_body(pong, &len);
				So(len == 5);
				So(memcmp(body, "ping", 5) == 0);
				nng_msg_trim(pong, 5);
				So(nng_msg_append(pong, "pong", 5) == 0);
				So(nng_sendmsg(rep, pong, 0) == 0);
				ping = 0;
				So(nng_recvmsg(req, &ping, 0) == 0);
				So(ping != NULL);
				body = nng_msg_body(ping, &len);
				So(len == 5);
				So(memcmp(body, "pong", 5) == 0);
				nng_msg_free(ping);
			})
#endif
		})

#if 0
		Convey("Request cancellation works", {
			nng_msg *abc;
			nng_msg *def;
			nng_msg *cmd;
			nng_msg *nvm;
			char *body;
			size_t len;
			uint64_t retry = 100000;	// 100 ms

			nng_socket *req;
			nng_socket *rep;

			So(nng_open(&rep, NNG_PROTO_REP) == 0);
			So(rep != NULL);

			So(nng_open(&req, NNG_PROTO_REQ) == 0);
			So(req != NULL);

			Reset({
				nng_close(rep);
				nng_close(req);
			})

			So(nng_setopt(req, NNG_OPT_RESENDTIME, &retry, sizeof (retry)) == 0);
			len = 16;
			So(nng_setopt(req, NNG_OPT_SNDBUF, &len, sizeof (len)) == 0);

			So(nng_msg_alloc(&abc, 0) == 0);
			So(nng_msg_append(abc, "abc", 4) == 0);
			So(nng_msg_alloc(&def, 0) == 0);
			So(nng_msg_append(def, "def", 4) == 0);

			So(nng_dial(req, addr, NULL, 0) == 0);

			So(nng_sendmsg(req, abc, 0) == 0);
			So(nng_sendmsg(req, def, 0) == 0);

			So(nng_listen(rep, addr, NULL, NNG_FLAG_SYNCH) == 0);

			So(nng_recvmsg(rep, &cmd, 0) == 0);
			So(cmd != NULL);
			So(nng_sendmsg(rep, cmd, 0) == 0);
			So(nng_recvmsg(rep, &cmd, 0) == 0);
			So(nng_sendmsg(rep, cmd, 0) == 0);

			So(nng_recvmsg(req, &cmd, 0) == 0);

			body = nng_msg_body(cmd, &len);
			So(len == 4);
			So(memcmp(body, "def", 4) == 0);
			nng_msg_free(cmd);
		})
#endif
	})
})
