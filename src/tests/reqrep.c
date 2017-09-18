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

extern const char *nng_opt_req_resendtime;
extern int         nng_optid_req_resendtime;

TestMain("REQ/REP pattern", {
	int         rv;
	const char *addr = "inproc://test";
	Convey("We can create a REQ socket", {
		nng_socket req;

		So(nng_req_open(&req) == 0);

		Reset({ nng_close(req); });

		Convey("Protocols match", {
			So(nng_protocol(req) == NNG_PROTO_REQ);
			So(nng_peer(req) == NNG_PROTO_REP);
		});

		Convey("Resend time option id works", {
			int         opt;
			const char *name;
			opt = nng_option_lookup(nng_opt_req_resendtime);
			So(opt >= 0);
			So(opt == nng_optid_req_resendtime);
			name = nng_option_name(opt);
			So(name != NULL);
			So(strcmp(name, nng_opt_req_resendtime) == 0);

			// Set timeout.
			So(nng_setopt_usec(req, opt, 10000) == 0);
			// Check invalid size
			So(nng_setopt(req, opt, name, 1) == NNG_EINVAL);
		});

		Convey("Recv with no send fails", {
			nng_msg *msg;
			rv = nng_recvmsg(req, &msg, 0);
			So(rv == NNG_ESTATE);
		});
	});

	Convey("We can create a REP socket", {
		nng_socket rep;
		So(nng_rep_open(&rep) == 0);

		Reset({ nng_close(rep); });

		Convey("Protocols match", {
			So(nng_protocol(rep) == NNG_PROTO_REP);
			So(nng_peer(rep) == NNG_PROTO_REQ);
		});

		Convey("Send with no recv fails", {
			nng_msg *msg;
			rv = nng_msg_alloc(&msg, 0);
			So(rv == 0);
			rv = nng_sendmsg(rep, msg, 0);
			So(rv == NNG_ESTATE);
			nng_msg_free(msg);
		});

		Convey("Cannot set resend time", {
			So(nng_setopt_usec(rep, nng_optid_req_resendtime,
			       100) == NNG_ENOTSUP);
		});
	});

	Convey("We can create a linked REQ/REP pair", {
		nng_socket req;
		nng_socket rep;

		So(nng_rep_open(&rep) == 0);

		So(nng_req_open(&req) == 0);

		Reset({
			nng_close(rep);
			nng_close(req);
		});

		So(nng_listen(rep, addr, NULL, 0) == 0);
		So(nng_dial(req, addr, NULL, 0) == 0);

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
		});
	});

	Convey("Request cancellation works", {
		nng_msg *abc;
		nng_msg *def;
		nng_msg *cmd;
		uint64_t retry = 100000; // 100 ms

		nng_socket req;
		nng_socket rep;

		So(nng_rep_open(&rep) == 0);

		So(nng_req_open(&req) == 0);

		Reset({
			nng_close(rep);
			nng_close(req);
		});

		So(nng_setopt_usec(req, nng_optid_req_resendtime, retry) == 0);
		So(nng_setopt_int(req, nng_optid_sendbuf, 16) == 0);

		So(nng_msg_alloc(&abc, 0) == 0);
		So(nng_msg_append(abc, "abc", 4) == 0);
		So(nng_msg_alloc(&def, 0) == 0);
		So(nng_msg_append(def, "def", 4) == 0);

		So(nng_listen(rep, addr, NULL, 0) == 0);
		So(nng_dial(req, addr, NULL, 0) == 0);

		So(nng_sendmsg(req, abc, 0) == 0);
		So(nng_sendmsg(req, def, 0) == 0);
		So(nng_recvmsg(rep, &cmd, 0) == 0);
		So(cmd != NULL);

		So(nng_sendmsg(rep, cmd, 0) == 0);
		So(nng_recvmsg(rep, &cmd, 0) == 0);
		So(nng_sendmsg(rep, cmd, 0) == 0);
		So(nng_recvmsg(req, &cmd, 0) == 0);

		So(nng_msg_len(cmd) == 4);
		So(memcmp(nng_msg_body(cmd), "def", 4) == 0);
		nng_msg_free(cmd);
	});
	nng_fini();
})
