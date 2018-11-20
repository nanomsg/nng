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
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

TestMain("REQ/REP pattern", {
	int         rv;
	const char *addr = "inproc://test";
	Convey("We can create a REQ socket", {
		nng_socket req;

		So(nng_req_open(&req) == 0);

		Reset({ nng_close(req); });

		Convey("Protocol & peer options match", {
			int   p;
			char *s;
			So(nng_getopt_int(req, NNG_OPT_PROTO, &p) == 0);
			So(p == 48);
			So(nng_getopt_string(req, NNG_OPT_PROTONAME, &s) == 0);
			So(strcmp(s, "req") == 0);
			nng_strfree(s);
			So(nng_getopt_int(req, NNG_OPT_PEER, &p) == 0);
			So(p == 49);
			So(nng_getopt_string(req, NNG_OPT_PEERNAME, &s) == 0);
			So(strcmp(s, "rep") == 0);
			nng_strfree(s);
		});

		Convey("Resend time option id works", {
			// Set timeout.
			So(nng_setopt_ms(req, NNG_OPT_REQ_RESENDTIME, 10) ==
			    0);
			// Check invalid size
			So(nng_setopt(req, NNG_OPT_REQ_RESENDTIME, "", 1) ==
			    NNG_EINVAL);
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

		Convey("Protocol & peer options match", {
			int   p;
			char *s;
			So(nng_getopt_int(rep, NNG_OPT_PROTO, &p) == 0);
			So(p == 49);
			So(nng_getopt_string(rep, NNG_OPT_PROTONAME, &s) == 0);
			So(strcmp(s, "rep") == 0);
			nng_strfree(s);
			So(nng_getopt_int(rep, NNG_OPT_PEER, &p) == 0);
			So(p == 48);
			So(nng_getopt_string(rep, NNG_OPT_PEERNAME, &s) == 0);
			So(strcmp(s, "req") == 0);
			nng_strfree(s);
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
			So(nng_setopt_ms(rep, NNG_OPT_REQ_RESENDTIME, 100) ==
			    NNG_ENOTSUP);
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
		nng_msg *    abc;
		nng_msg *    def;
		nng_msg *    cmd;
		nng_duration retry = 100; // 100 ms

		nng_socket req;
		nng_socket rep;

		So(nng_rep_open(&rep) == 0);

		So(nng_req_open(&req) == 0);

		Reset({
			nng_close(rep);
			nng_close(req);
		});

		So(nng_setopt_ms(req, NNG_OPT_REQ_RESENDTIME, retry) == 0);
		So(nng_setopt_int(req, NNG_OPT_SENDBUF, 16) == 0);

		So(nng_msg_alloc(&abc, 0) == 0);
		So(nng_msg_append(abc, "abc", 4) == 0);
		So(nng_msg_alloc(&def, 0) == 0);
		So(nng_msg_append(def, "def", 4) == 0);

		So(nng_listen(rep, addr, NULL, 0) == 0);
		So(nng_dial(req, addr, NULL, 0) == 0);

		// Send req #1 (abc).
		So(nng_sendmsg(req, abc, 0) == 0);

		// Sleep a bit.  This is so that we ensure that our
		// request gets to the far side.  (If we cancel too
		// fast, then our outgoing send will be canceled before
		// it gets to the wire.)
		nng_msleep(20);

		// Send the next next request ("def").  Note that
		// the REP side server will have already buffered the receive
		// request, and should simply be waiting for us to reply to
		// abc.
		So(nng_sendmsg(req, def, 0) == 0);

		// Receive the first request (should be abc) on the REP server.
		So(nng_recvmsg(rep, &cmd, 0) == 0);
		So(nng_msg_len(cmd) == 4);
		So(strcmp(nng_msg_body(cmd), "abc") == 0);

		// REP sends the reply to first command.  This will be
		// discarded by the REQ server.
		So(nng_sendmsg(rep, cmd, 0) == 0);

		// Now get the next command from the REP; should be "def".
		So(nng_recvmsg(rep, &cmd, 0) == 0);
		So(nng_msg_len(cmd) == 4);
		So(strcmp(nng_msg_body(cmd), "def") == 0);

		// And send it back to REQ.
		So(nng_sendmsg(rep, cmd, 0) == 0);

		// Try a req command.  This should give back "def"
		So(nng_recvmsg(req, &cmd, 0) == 0);
		So(nng_msg_len(cmd) == 4);
		So(strcmp(nng_msg_body(cmd), "def") == 0);
		nng_msg_free(cmd);
	});

	Convey("Request cancellation aborts pending recv", {
		nng_msg *    abc;
		nng_msg *    def;
		nng_msg *    cmd;
		nng_aio *    aio;
		nng_duration retry = 100; // 100 ms

		nng_socket req;
		nng_socket rep;

		So(nng_rep_open(&rep) == 0);

		So(nng_req_open(&req) == 0);
		So(nng_aio_alloc(&aio, NULL, NULL) == 0);

		Reset({
			nng_close(rep);
			nng_close(req);
			nng_aio_free(aio);
		});

		So(nng_setopt_ms(req, NNG_OPT_REQ_RESENDTIME, retry) == 0);
		So(nng_setopt_int(req, NNG_OPT_SENDBUF, 16) == 0);

		So(nng_msg_alloc(&abc, 0) == 0);
		So(nng_msg_append(abc, "abc", 4) == 0);
		So(nng_msg_alloc(&def, 0) == 0);
		So(nng_msg_append(def, "def", 4) == 0);

		So(nng_listen(rep, addr, NULL, 0) == 0);
		So(nng_dial(req, addr, NULL, 0) == 0);

		// Send req #1 (abc).
		So(nng_sendmsg(req, abc, 0) == 0);

		// Sleep a bit.  This is so that we ensure that our
		// request gets to the far side.  (If we cancel too
		// fast, then our outgoing send will be canceled before
		// it gets to the wire.)
		nng_msleep(20);

		nng_aio_set_timeout(aio, 1000); // an entire second
		nng_recv_aio(req, aio);

		// Give time for this recv to post properly.
		nng_msleep(20);

		// Send the next next request ("def").  Note that
		// the REP side server will have already buffered the receive
		// request, and should simply be waiting for us to reply to
		// abc.
		So(nng_sendmsg(req, def, 0) == 0);

		nng_aio_wait(aio);
		So(nng_aio_result(aio) == NNG_ECANCELED);

		// Receive the first request (should be abc) on the REP server.
		So(nng_recvmsg(rep, &cmd, 0) == 0);
		So(nng_msg_len(cmd) == 4);
		So(strcmp(nng_msg_body(cmd), "abc") == 0);

		// REP sends the reply to first command.  This will be
		// discarded by the REQ server.
		So(nng_sendmsg(rep, cmd, 0) == 0);

		// Now get the next command from the REP; should be "def".
		So(nng_recvmsg(rep, &cmd, 0) == 0);
		So(nng_msg_len(cmd) == 4);
		So(strcmp(nng_msg_body(cmd), "def") == 0);

		// And send it back to REQ.
		So(nng_sendmsg(rep, cmd, 0) == 0);

		// Try a req command.  This should give back "def"
		So(nng_recvmsg(req, &cmd, 0) == 0);
		So(nng_msg_len(cmd) == 4);
		So(strcmp(nng_msg_body(cmd), "def") == 0);
		nng_msg_free(cmd);
	});

	nng_fini();
})
