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
#include "protocol/survey0/respond.h"
#include "protocol/survey0/survey.h"
#include "stubs.h"

#include <string.h>

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
	});
});
