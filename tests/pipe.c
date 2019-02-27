//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

#define APPENDSTR(m, s) nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)                   \
	So(nng_msg_len(m) == strlen(s)); \
	So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

struct testcase {
	nng_socket   s;
	nng_dialer   d;
	nng_listener l;
	nng_pipe     p;
	int          add_pre;
	int          add_post;
	int          rem;
	int          err;
	int          rej;
	nng_mtx *    lk;
	nng_cv *     cv;
};

static bool
expect(struct testcase *t, int *vp, int v)
{
	bool     ok;
	nng_time when = nng_clock() + 5000; // five seconds

	nng_mtx_lock(t->lk);
	while (*vp != v) {
		if (nng_cv_until(t->cv, when) == NNG_ETIMEDOUT) {
			break;
		}
	}
	ok = (*vp == v) ? true : false;
	if (!ok) {
		printf("Expected %d but got %d\n", v, *vp);
	}
	nng_mtx_unlock(t->lk);
	return (ok);
}

void
notify(nng_pipe p, nng_pipe_ev act, void *arg)
{
	struct testcase *t = arg;

	nng_mtx_lock(t->lk);
	if ((nng_socket_id(nng_pipe_socket(p)) != nng_socket_id(t->s)) ||
	    (nng_listener_id(nng_pipe_listener(p)) != nng_listener_id(t->l)) ||
	    (nng_dialer_id(nng_pipe_dialer(p)) != nng_dialer_id(t->d))) {
		t->err++;
		nng_cv_wake(t->cv);
		nng_mtx_unlock(t->lk);
		return;
	}
	if (t->add_post > t->add_pre) {
		t->err++;
	}
	switch (act) {
	case NNG_PIPE_EV_ADD_PRE:
		t->add_pre++;
		break;
	case NNG_PIPE_EV_ADD_POST:
		t->add_post++;
		break;
	case NNG_PIPE_EV_REM_POST:
		t->rem++;
		break;
	default:
		t->err++;
		nng_cv_wake(t->cv);
		nng_mtx_unlock(t->lk);
		return;
	}
	t->p = p;
	nng_cv_wake(t->cv);
	nng_mtx_unlock(t->lk);
}

void
reject(nng_pipe p, nng_pipe_ev act, void *arg)
{
	struct testcase *t = arg;
	notify(p, act, arg);

	nng_mtx_lock(t->lk);
	if (!t->rej) {
		nng_pipe_close(p);
		t->rej++;
	}
	nng_mtx_unlock(t->lk);
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
		So(nng_mtx_alloc(&push.lk) == 0);
		So(nng_cv_alloc(&push.cv, push.lk) == 0);
		So(nng_mtx_alloc(&pull.lk) == 0);
		So(nng_cv_alloc(&pull.cv, pull.lk) == 0);
		So(nng_push_open(&push.s) == 0);
		So(nng_pull_open(&pull.s) == 0);

		Reset({
			nng_close(push.s);
			nng_close(pull.s);
			nng_cv_free(push.cv);
			nng_cv_free(pull.cv);
			nng_mtx_free(push.lk);
			nng_mtx_free(pull.lk);
		});

		So(nng_setopt_ms(push.s, NNG_OPT_RECONNMINT, 10) == 0);
		So(nng_setopt_ms(push.s, NNG_OPT_RECONNMAXT, 10) == 0);
		So(nng_setopt_ms(pull.s, NNG_OPT_RECONNMINT, 10) == 0);
		So(nng_setopt_ms(pull.s, NNG_OPT_RECONNMAXT, 10) == 0);

		So(nng_pipe_notify(
		       push.s, NNG_PIPE_EV_ADD_PRE, notify, &push) == 0);
		So(nng_pipe_notify(
		       push.s, NNG_PIPE_EV_ADD_POST, notify, &push) == 0);
		So(nng_pipe_notify(
		       push.s, NNG_PIPE_EV_REM_POST, notify, &push) == 0);
		So(nng_pipe_notify(
		       pull.s, NNG_PIPE_EV_ADD_PRE, notify, &pull) == 0);
		So(nng_pipe_notify(
		       pull.s, NNG_PIPE_EV_ADD_POST, notify, &pull) == 0);
		So(nng_pipe_notify(
		       pull.s, NNG_PIPE_EV_REM_POST, notify, &pull) == 0);

		Convey("Dialing works", {
			So(nng_listener_create(&pull.l, pull.s, addr) == 0);
			So(nng_dialer_create(&push.d, push.s, addr) == 0);
			So(nng_listener_id(pull.l) > 0);
			So(nng_dialer_id(push.d) > 0);
			So(nng_dialer_setopt_ms(
			       push.d, NNG_OPT_RECONNMINT, 10) == 0);
			So(nng_dialer_setopt_ms(
			       push.d, NNG_OPT_RECONNMAXT, 10) == 0);
			So(nng_listener_start(pull.l, 0) == 0);
			So(nng_dialer_start(push.d, 0) == 0);
			So(expect(&pull, &pull.add_pre, 1));
			So(expect(&pull, &pull.add_post, 1));
			So(expect(&pull, &pull.add_pre, 1));
			So(expect(&pull, &pull.add_post, 1));
			So(expect(&pull, &pull.rem, 0));
			So(expect(&pull, &pull.err, 0));
			So(expect(&push, &push.add_pre, 1));
			So(expect(&push, &push.add_post, 1));
			So(expect(&push, &push.rem, 0));
			So(expect(&push, &push.err, 0));
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
				So(expect(&pull, &pull.add_pre, 1));
				So(expect(&pull, &pull.add_post, 1));
				nng_pipe_close(pull.p);

				So(expect(&pull, &pull.rem, 1));
				So(expect(&pull, &pull.err, 0));
				So(expect(&pull, &pull.add_pre, 2));
				So(expect(&pull, &pull.add_post, 2));

				So(expect(&push, &push.rem, 1));
				So(expect(&push, &push.err, 0));
				So(expect(&push, &push.add_pre, 2));
				So(expect(&push, &push.add_post, 2));

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

		Convey("Reject works", {
			So(nng_pipe_notify(pull.s, NNG_PIPE_EV_ADD_PRE, reject,
			       &pull) == 0);
			So(nng_listener_create(&pull.l, pull.s, addr) == 0);
			So(nng_dialer_create(&push.d, push.s, addr) == 0);
			So(nng_listener_id(pull.l) > 0);
			So(nng_dialer_id(push.d) > 0);
			So(nng_listener_start(pull.l, 0) == 0);
			nng_msleep(100);
			So(nng_dialer_start(push.d, 0) == 0);
			So(expect(&pull, &pull.add_pre, 2));
			So(expect(&pull, &pull.add_post, 1));
			So(expect(&pull, &pull.rem, 1));
			So(expect(&pull, &pull.err, 0));
			So(expect(&push, &push.add_pre, 2));
			So(expect(&push, &push.add_post, 2));
			So(expect(&push, &push.rem, 1) == 1);
			So(expect(&push, &push.err, 0));
		});
	});
})
