//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

#define APPENDSTR(m, s) nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)                   \
	So(nng_msg_len(m) == strlen(s)); \
	So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

TestMain("SURVEY pattern", {
	const char *addr = "inproc://test";

	atexit(nng_fini);

	Convey("We can create a SURVEYOR socket", {
		nng_socket surv;

		So(nng_surveyor_open(&surv) == 0);

		Reset({ nng_close(surv); });

		Convey("Recv with no survey fails", {
			nng_msg *msg;
			So(nng_recvmsg(surv, &msg, 0) == NNG_ESTATE);
		});

		Convey("Survey without responder times out", {
			nng_msg *msg;

			So(nng_setopt_ms(
			       surv, NNG_OPT_SURVEYOR_SURVEYTIME, 50) == 0);
			So(nng_msg_alloc(&msg, 0) == 0);
			So(nng_sendmsg(surv, msg, 0) == 0);
			So(nng_recvmsg(surv, &msg, 0) == NNG_ETIMEDOUT);
		});
	});

	Convey("We can create a RESPONDENT socket", {
		nng_socket resp;
		So(nng_respondent_open(&resp) == 0);

		Reset({ nng_close(resp); });

		Convey("Send fails with no survey", {
			nng_msg *msg;
			So(nng_msg_alloc(&msg, 0) == 0);
			So(nng_sendmsg(resp, msg, 0) == NNG_ESTATE);
			nng_msg_free(msg);
		});
	});

	Convey("We can create a linked survey pair", {
		nng_socket surv;
		nng_socket resp;
		nng_socket sock;

		So(nng_surveyor_open(&surv) == 0);
		So(nng_respondent_open(&resp) == 0);

		Reset({
			nng_close(surv);
			nng_close(resp);
		});

		So(nng_setopt_ms(surv, NNG_OPT_SURVEYOR_SURVEYTIME, 50) == 0);
		So(nng_listen(surv, addr, NULL, 0) == 0);
		So(nng_dial(resp, addr, NULL, 0) == 0);

		// We dial another socket as that will force
		// the earlier dial to have completed *fully*.
		// This is a hack that only works because our
		// listen logic is single threaded.
		So(nng_respondent_open(&sock) == 0);
		So(nng_dial(sock, addr, NULL, 0) == 0);
		nng_close(sock);

		Convey("Survey works", {
			nng_msg *msg;

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "abc");
			So(nng_sendmsg(surv, msg, 0) == 0);
			msg = NULL;
			So(nng_recvmsg(resp, &msg, 0) == 0);
			CHECKSTR(msg, "abc");
			nng_msg_chop(msg, 3);
			APPENDSTR(msg, "def");
			So(nng_sendmsg(resp, msg, 0) == 0);
			msg = NULL;
			So(nng_recvmsg(surv, &msg, 0) == 0);
			CHECKSTR(msg, "def");
			nng_msg_free(msg);

			So(nng_recvmsg(surv, &msg, 0) == NNG_ETIMEDOUT);

			Convey("And goes to non-survey state", {
				So(nng_setopt_ms(
				       surv, NNG_OPT_RECVTIMEO, 200) == 0);
				So(nng_recvmsg(surv, &msg, 0) == NNG_ESTATE);
			});
		});

		Convey("Second send cancels pending recv", {
			nng_msg *msg;
			nng_aio *aio;

			So(nng_aio_alloc(&aio, NULL, NULL) == 0);
			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "one");
			So(nng_sendmsg(surv, msg, 0) == 0);
			msg = NULL;
			nng_recv_aio(surv, aio);
			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "two");
			So(nng_sendmsg(surv, msg, 0) == 0);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == NNG_ECANCELED);
			nng_aio_free(aio);
		});

		Convey("Sending a NULL message does not panic", {
			nng_aio *aio;

			So(nng_aio_alloc(&aio, NULL, NULL) == 0);
			Reset({ nng_aio_free(aio); });
			So(nng_sendmsg(surv, NULL, 0) == NNG_EINVAL);
			nng_send_aio(surv, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == NNG_EINVAL);
		});

		Convey("Disconnecting before getting response", {
			nng_msg *msg;

			So(nng_msg_alloc(&msg, 0) == 0);
			So(nng_sendmsg(surv, msg, 0) == 0);
			So(nng_recvmsg(resp, &msg, 0) == 0);
			nng_close(surv);
			nng_msleep(100);
			So(nng_sendmsg(resp, msg, 0) == 0);
		});
	});

	Convey("Bad backtrace survey is ignored", {
		nng_socket surv;
		nng_socket resp;
		nng_msg *  msg;
		So(nng_surveyor0_open_raw(&surv) == 0);
		So(nng_respondent0_open(&resp) == 0);
		Reset({
			nng_close(surv);
			nng_close(resp);
		});
		So(nng_listen(resp, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_dial(surv, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200) == 0);
		nng_msleep(100);
		So(nng_msg_alloc(&msg, 0) == 0);
		So(nng_msg_header_append_u32(msg, 1) ==
		    0); // high order bit not set!
		So(nng_sendmsg(surv, msg, 0) == 0);
		So(nng_recvmsg(resp, &msg, 0) == NNG_ETIMEDOUT);
	});

	Convey("Bad backtrace survey is ignored (raw)", {
		nng_socket surv;
		nng_socket resp;
		nng_msg *  msg;
		So(nng_surveyor0_open_raw(&surv) == 0);
		So(nng_respondent0_open_raw(&resp) == 0);
		Reset({
			nng_close(surv);
			nng_close(resp);
		});
		So(nng_listen(resp, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_dial(surv, "inproc://badsurvback", NULL, 0) == 0);
		nng_msleep(100);
		So(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_msg_alloc(&msg, 0) == 0);
		So(nng_msg_header_append_u32(msg, 1) ==
		    0); // high order bit not set!
		So(nng_sendmsg(surv, msg, 0) == 0);
		So(nng_recvmsg(resp, &msg, 0) == NNG_ETIMEDOUT);
	});

	Convey("Missing backtrace survey is ignored", {
		nng_socket surv;
		nng_socket resp;
		nng_msg *  msg;
		So(nng_surveyor0_open_raw(&surv) == 0);
		So(nng_respondent0_open(&resp) == 0);
		Reset({
			nng_close(surv);
			nng_close(resp);
		});
		So(nng_listen(resp, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_dial(surv, "inproc://badsurvback", NULL, 0) == 0);
		nng_msleep(100);
		So(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_msg_alloc(&msg, 0) == 0);
		So(nng_sendmsg(surv, msg, 0) == 0);
		So(nng_recvmsg(resp, &msg, 0) == NNG_ETIMEDOUT);
	});

	Convey("Missing backtrace survey is ignored (raw)", {
		nng_socket surv;
		nng_socket resp;
		nng_msg *  msg;
		So(nng_surveyor0_open_raw(&surv) == 0);
		So(nng_respondent0_open_raw(&resp) == 0);
		Reset({
			nng_close(surv);
			nng_close(resp);
		});
		So(nng_listen(resp, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_dial(surv, "inproc://badsurvback", NULL, 0) == 0);
		nng_msleep(100);
		So(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_msg_alloc(&msg, 0) == 0);
		So(nng_sendmsg(surv, msg, 0) == 0);
		So(nng_recvmsg(resp, &msg, 0) == NNG_ETIMEDOUT);
	});

	Convey("Bad backtrace response is ignored", {
		nng_socket surv;
		nng_socket resp;
		nng_msg *  msg;
		So(nng_surveyor0_open(&surv) == 0);
		So(nng_respondent0_open_raw(&resp) == 0);
		Reset({
			nng_close(surv);
			nng_close(resp);
		});
		So(nng_listen(resp, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_dial(surv, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 200) == 0);
		nng_msleep(100);
		So(nng_msg_alloc(&msg, 0) == 0);
		So(nng_sendmsg(surv, msg, 0) == 0);
		So(nng_recvmsg(resp, &msg, 0) == 0);
		nng_msg_header_clear(msg);
		nng_msg_header_append_u32(msg, 1);
		So(nng_sendmsg(resp, msg, 0) == 0);
		So(nng_recvmsg(surv, &msg, 0) == NNG_ETIMEDOUT);
	});

	Convey("Bad backtrace response is ignored (raw)", {
		nng_socket surv;
		nng_socket resp;
		nng_msg *  msg;
		So(nng_surveyor0_open_raw(&surv) == 0);
		So(nng_respondent0_open_raw(&resp) == 0);
		Reset({
			nng_close(surv);
			nng_close(resp);
		});
		So(nng_listen(resp, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_dial(surv, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 200) == 0);
		nng_msleep(100);
		So(nng_msg_alloc(&msg, 0) == 0);
		So(nng_msg_header_append_u32(msg, 0x80000000) == 0);
		So(nng_sendmsg(surv, msg, 0) == 0);
		So(nng_recvmsg(resp, &msg, 0) == 0);
		nng_msg_header_clear(msg);
		nng_msg_header_append_u32(msg, 1);
		So(nng_sendmsg(resp, msg, 0) == 0);
		So(nng_recvmsg(surv, &msg, 0) == NNG_ETIMEDOUT);
	});

	Convey("Missing backtrace response is ignored", {
		nng_socket surv;
		nng_socket resp;
		nng_msg *  msg;
		So(nng_surveyor0_open(&surv) == 0);
		So(nng_respondent0_open_raw(&resp) == 0);
		Reset({
			nng_close(surv);
			nng_close(resp);
		});
		So(nng_listen(resp, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_dial(surv, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 200) == 0);
		nng_msleep(100);
		So(nng_msg_alloc(&msg, 0) == 0);
		So(nng_sendmsg(surv, msg, 0) == 0);
		So(nng_recvmsg(resp, &msg, 0) == 0);
		nng_msg_header_clear(msg);
		So(nng_sendmsg(resp, msg, 0) == 0);
		So(nng_recvmsg(surv, &msg, 0) == NNG_ETIMEDOUT);
	});

	Convey("Missing backtrace response is ignored (raw)", {
		nng_socket surv;
		nng_socket resp;
		nng_msg *  msg;
		So(nng_surveyor0_open_raw(&surv) == 0);
		So(nng_respondent0_open_raw(&resp) == 0);
		Reset({
			nng_close(surv);
			nng_close(resp);
		});
		So(nng_listen(resp, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_dial(surv, "inproc://badsurvback", NULL, 0) == 0);
		So(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 200) == 0);
		nng_msleep(100);
		So(nng_msg_alloc(&msg, 0) == 0);
		So(nng_msg_header_append_u32(msg, 0x80000000) == 0);
		So(nng_sendmsg(surv, msg, 0) == 0);
		So(nng_recvmsg(resp, &msg, 0) == 0);
		nng_msg_header_clear(msg);
		So(nng_sendmsg(resp, msg, 0) == 0);
		So(nng_recvmsg(surv, &msg, 0) == NNG_ETIMEDOUT);
	});
})
