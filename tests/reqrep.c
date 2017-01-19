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

Main({
	int rv;
	const char *addr = "inproc://test";
	nni_init();

	Test("REQ/REP pattern", {
		Convey("We can create a REQ socket", {
			nng_socket *req;

			rv = nng_open(&req, NNG_PROTO_REQ);
			So(rv == 0);
			So(req != NULL);

			Reset({
				nng_close(req);
			})

			Convey("Protocols match", {
				So(nng_protocol(req) == NNG_PROTO_REQ);
				So(nng_peer(req) == NNG_PROTO_REP);
			})

			Convey("Recv with no send fails", {
				nng_msg *msg;
				rv = nng_recvmsg(req, &msg, 0);
				So(rv == NNG_ESTATE);
			})
		})

		Convey("We can create a REP socket", {
			nng_socket *rep;
			rv = nng_open(&rep, NNG_PROTO_REP);
			So(rv == 0);
			So(rep != NULL);

			Reset({
				nng_close(rep);
			})

			Convey("Protocols match", {
				So(nng_protocol(rep) == NNG_PROTO_REP);
				So(nng_peer(rep) == NNG_PROTO_REQ);
			})

			Convey("Send with no recv fails", {
				nng_msg *msg;
				rv = nng_msg_alloc(&msg, 0);
				So(rv == 0);
				rv = nng_sendmsg(rep, msg, 0);
				So(rv == NNG_ESTATE);
				nng_msg_free(msg);
			})
		})

		Convey("We can create a linked REQ/REP pair", {
			nng_socket *req;
			nng_socket *rep;

			rv = nng_open(&rep, NNG_PROTO_REP);
			So(rv == 0);
			So(rep != NULL);

			rv = nng_open(&req, NNG_PROTO_REQ);
			So(rv == 0);
			So(req != NULL);

			Reset({
				nng_close(rep);
				nng_close(req);
			})

			rv = nng_listen(rep, addr, NULL, NNG_FLAG_SYNCH);
			So(rv == 0);

			rv = nng_dial(req, addr, NULL, NNG_FLAG_SYNCH);
			So(rv == 0);

			Convey("They can REQ/REP exchange", {
				nng_msg *ping;
				nng_msg *pong;

				So(nng_msg_alloc(&ping, 0) == 0);
				So(nng_msg_append(ping, "ping", 5) == 0);
				So(nng_msg_len(ping) == 5);
				So(memcmp(nng_msg_body(ping), "ping", 5) == 0);
				So(nng_sendmsg(req, ping, 0) == 0);
				pong = NULL;
				So(nng_recvmsg(rep, &pong, 0) == 0);
				So(pong != NULL);
				So(nng_msg_len(pong) == 5);
				So(memcmp(nng_msg_body(pong), "ping", 5) == 0);
				nng_msg_trim(pong, 5);
				So(nng_msg_append(pong, "pong", 5) == 0);
				So(nng_sendmsg(rep, pong, 0) == 0);
				ping = 0;
				So(nng_recvmsg(req, &ping, 0) == 0);
				So(ping != NULL);
				So(nng_msg_len(ping) == 5);
				So(memcmp(nng_msg_body(ping), "pong", 5) == 0);
				nng_msg_free(ping);
			})
		})

		Convey("Request cancellation works", {
			nng_msg *abc;
			nng_msg *def;
			nng_msg *cmd;
			uint64_t retry = 100000;	// 100 ms
			size_t len;

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

			So(nng_msg_len(cmd) == 4);
			So(memcmp(nng_msg_body(cmd), "def", 4) == 0);
			nng_msg_free(cmd);
		})
	})

	nni_fini();
})
