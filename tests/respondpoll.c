//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/nng.h>
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

TestMain("Respondent pollable", {
	atexit(nng_fini);

	Convey("Given a connected survey pair", {
		nng_socket surv;
		nng_socket resp;
		nng_ctx    ctx;

		So(nng_surveyor0_open(&surv) == 0);
		So(nng_respondent0_open(&resp) == 0);
		So(nng_ctx_open(&ctx, resp) == 0);

		So(nng_setopt_ms(surv, NNG_OPT_SENDTIMEO, 2000) == 0);
		So(nng_setopt_ms(resp, NNG_OPT_SENDTIMEO, 2000) == 0);
		So(nng_setopt_ms(surv, NNG_OPT_RECVTIMEO, 2000) == 0);
		So(nng_setopt_ms(resp, NNG_OPT_RECVTIMEO, 2000) == 0);

		Reset({
			nng_ctx_close(ctx);
			nng_close(surv);
			nng_close(resp);
		});
		So(nng_listen(resp, "inproc://ctx1", NULL, 0) == 0);

		Convey("Respondent ctx not pollable", {
			int fd;

			So(nng_ctx_getopt_int(ctx, NNG_OPT_SENDFD, &fd) ==
			    NNG_ENOTSUP);
			So(nng_ctx_getopt_int(ctx, NNG_OPT_RECVFD, &fd) ==
			    NNG_ENOTSUP);
		});

		Convey("Respondent starts not writable", {
			int fd;

			So(nng_getopt_int(resp, NNG_OPT_SENDFD, &fd) == 0);
			So(fdready(fd) == false);

			Convey("And remains unwritable on connect", {
				So(nng_dial(surv, "inproc://ctx1", NULL, 0) ==
				    0);
				nng_msleep(100);
				So(fdready(fd) == false);

				Convey("Becomes writable after recv", {
					nng_msg *m;
					So(nng_msg_alloc(&m, 0) == 0);
					So(nng_sendmsg(surv, m, 0) == 0);
					So(nng_recvmsg(resp, &m, 0) == 0);
					nng_msg_free(m);
					So(fdready(fd) == true);
				});
			});
		});

		Convey("Respondent starts not readable", {
			int fd;

			So(nng_getopt_int(resp, NNG_OPT_RECVFD, &fd) == 0);
			So(fdready(fd) == false);

			Convey("And doesn't become readable on connect", {
				So(nng_dial(surv, "inproc://ctx1", NULL, 0) ==
				    0);
				nng_msleep(100);
				So(fdready(fd) == false);
			});

			Convey("And becomes readable on data", {
				nng_msg *msg;

				So(nng_dial(surv, "inproc://ctx1", NULL, 0) ==
				    0);
				nng_msleep(200);

				So(nng_msg_alloc(&msg, 0) == 0);
				So(fdready(fd) == false);
				So(nng_msg_append(msg, "xyz", 3) == 0);
				So(nng_sendmsg(surv, msg, 0) == 0);
				nng_msleep(300); // give time for msg to arrive
				So(fdready(fd) == true);
				Convey("Is no longer readable after recv", {
					So(nng_recvmsg(resp, &msg, 0) == 0);
					nng_msg_free(msg);
					So(fdready(fd) == false);
				});
			});
		});
	});
})
