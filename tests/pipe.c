//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "protocol/pipeline0/pull.h"
#include "protocol/pipeline0/push.h"
#include "supplemental/util/platform.h"

#include "stubs.h"
#include <string.h>

#define APPENDSTR(m, s) nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)                   \
	So(nng_msg_len(m) == strlen(s)); \
	So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

struct testcase {
	nng_socket   s;
	nng_dialer   d;
	nng_listener l;
	nng_pipe     p;
	int          add;
	int          rem;
	int          err;
};

void
notify(nng_pipe p, nng_pipe_action act, void *arg)
{
	struct testcase *t = arg;

	if ((nng_socket_id(nng_pipe_socket(p)) != nng_socket_id(t->s)) ||
	    (nng_listener_id(nng_pipe_listener(p)) != nng_listener_id(t->l)) ||
	    (nng_dialer_id(nng_pipe_dialer(p)) != nng_dialer_id(t->d))) {
		t->err++;
		return;
	}
	switch (act) {
	case NNG_PIPE_ADD:
		t->add++;
		break;
	case NNG_PIPE_REM:
		t->rem++;
		break;
	default:
		t->err++;
		return;
	}
	t->p = p;
}

char       addr[64];
static int cnt;

TestMain("Pipe notify works", {
	atexit(nng_fini);

	Convey("We can create a pipeline", {
		struct testcase push;
		struct testcase pull;
		sprintf(addr, "inproc://test%d", cnt++);

		memset(&pull, 0, sizeof(pull));
		memset(&push, 0, sizeof(push));
		So(nng_push_open(&push.s) == 0);
		So(nng_pull_open(&pull.s) == 0);

		Reset({
			nng_close(push.s);
			nng_close(pull.s);
		});

		So(nng_pipe_notify(push.s, notify, &push) == 0);
		So(nng_pipe_notify(pull.s, notify, &pull) == 0);

		So(nng_setopt_ms(push.s, NNG_OPT_RECONNMINT, 10) == 0);
		So(nng_setopt_ms(push.s, NNG_OPT_RECONNMAXT, 10) == 0);

		Convey("Dialing works", {
			So(nng_listener_create(&pull.l, pull.s, addr) == 0);
			So(nng_dialer_create(&push.d, push.s, addr) == 0);
			So(nng_listener_id(pull.l) > 0);
			So(nng_dialer_id(push.d) > 0);
			So(nng_listener_start(pull.l, 0) == 0);
			So(nng_dialer_start(push.d, 0) == 0);
			nng_msleep(100);
			So(pull.add == 1);
			So(pull.rem == 0);
			So(pull.err == 0);
			So(push.add == 1);
			So(push.rem == 0);
			So(push.err == 0);
			Convey("We can send a frame", {
				nng_msg *msg;

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "hello");
				So(nng_sendmsg(push.s, msg, 0) == 0);
				msg = NULL;
				So(nng_recvmsg(pull.s, &msg, 0) == 0);
				So(msg != NULL);
				CHECKSTR(msg, "hello");
				So(nng_pipe_id(nng_msg_get_pipe(msg)) ==
				    nng_pipe_id(pull.p));
				nng_msg_free(msg);
			});

			Convey("Reconnection works", {
				So(pull.add == 1);
				nng_pipe_close(pull.p);
				nng_msleep(200);

				So(pull.err == 0);
				So(pull.rem == 1);
				So(pull.add == 2);

				So(push.err == 0);
				So(push.rem == 1);
				So(push.add == 2);

				Convey("They still exchange frames", {
					nng_msg *msg;
					nng_pipe p1;

					nng_msleep(200);
					So(nng_msg_alloc(&msg, 0) == 0);
					APPENDSTR(msg, "hello");
					So(nng_sendmsg(push.s, msg, 0) == 0);
					msg = NULL;
					So(nng_recvmsg(pull.s, &msg, 0) == 0);
					So(msg != NULL);
					CHECKSTR(msg, "hello");
					p1 = nng_msg_get_pipe(msg);
					nng_msg_free(msg);
					So(nng_pipe_id(p1) ==
					    nng_pipe_id(pull.p));
				});
			});
		});
	});
})
