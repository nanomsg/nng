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

#include <string.h>

#define	APPENDSTR(m, s)	nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)	So(nng_msg_len(m) == strlen(s));\
			So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

Main({
	int rv;
	const char *addr = "inproc://test";

	Test("SURVEY pattern", {
		Convey("We can create a SURVEYOR socket", {
			nng_socket *surv;

			So(nng_open(&surv, NNG_PROTO_SURVEYOR) == 0);
			So(surv != NULL);

			Reset({
				nng_close(surv);
			})

			Convey("Protocols match", {
				So(nng_protocol(surv) == NNG_PROTO_SURVEYOR);
				So(nng_peer(surv) == NNG_PROTO_RESPONDENT);
			})

			Convey("Recv with no survey fails", {
				nng_msg *msg;
				So(nng_recvmsg(surv, &msg, 0) == NNG_ESTATE);
			})

			Convey("Survey without responder times out", {
				uint64_t expire = 1000;
				nng_msg *msg;

				So(nng_setopt(surv, NNG_OPT_SURVEYTIME, &expire, sizeof (expire)) == 0);
				So(nng_msg_alloc(&msg, 0) == 0);
				So(nng_sendmsg(surv, msg, 0) == 0);
				So(nng_recvmsg(surv, &msg, 0) == NNG_ETIMEDOUT);
			})
		})

		Convey("We can create a RESPONDENT socket", {
			nng_socket *resp;
			So(nng_open(&resp, NNG_PROTO_RESPONDENT) == 0);
			So(resp != NULL);

			Reset({
				nng_close(resp);
			})

			Convey("Protocols match", {
				So(nng_protocol(resp) == NNG_PROTO_RESPONDENT);
				So(nng_peer(resp) == NNG_PROTO_SURVEYOR);
			})

			Convey("Send fails with no suvey", {
				nng_msg *msg;
				So(nng_msg_alloc(&msg, 0) == 0);
				So(nng_sendmsg(resp, msg, 0) == NNG_ESTATE);
				nng_msg_free(msg);
			})
		})

		Convey("We can create a linked survey pair", {
			nng_socket *surv;
			nng_socket *resp;
			uint64_t expire;

			So((rv = nng_open(&surv, NNG_PROTO_SURVEYOR)) == 0);
			So(surv != NULL);

			So((rv = nng_open(&resp, NNG_PROTO_RESPONDENT)) == 0);
			So(resp != NULL);

			Reset({
				nng_close(surv);
				nng_close(resp);
			})

			expire = 10000;
			So(nng_setopt(surv, NNG_OPT_SURVEYTIME, &expire, sizeof (expire)) == 0);

			So(nng_listen(surv, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(resp, addr, NULL, NNG_FLAG_SYNCH) == 0);

			Convey("Survey works", {
				nng_msg *msg;
				uint64_t rtimeo;

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "abc");
				So(nng_sendmsg(surv, msg, 0) == 0);
				msg = NULL;
				So(nng_recvmsg(resp, &msg, 0) == 0);
				CHECKSTR(msg, "abc");
				nng_msg_trunc(msg, 3);
				APPENDSTR(msg, "def");
				So(nng_sendmsg(resp, msg, 0) == 0);
				msg = NULL;
				So(nng_recvmsg(surv, &msg, 0) == 0);
				CHECKSTR(msg, "def");
				nng_msg_free(msg);

				So(nng_recvmsg(surv, &msg, 0) == NNG_ETIMEDOUT);

				Convey("And goes to non-survey state", {
					printf("WAITING HERE");
					rtimeo = 50000;
					So(nng_setopt(surv, NNG_OPT_RCVTIMEO, &rtimeo, sizeof (rtimeo)) == 0);
					rv = nng_recvmsg(surv, &msg, 0);
					So(rv== NNG_ESTATE);
				})
			})
		})
	})
})
