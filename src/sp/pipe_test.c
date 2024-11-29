//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
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

#include <nuts.h>

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
	nng_mtx     *lk;
	nng_cv      *cv;
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
		NUTS_MSG("Expected %d but got %d\n", v, *vp);
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

static void
init_cases(char *addr, struct testcase *push, struct testcase *pull)
{
	memset(push, 0, sizeof(*push));
	memset(pull, 0, sizeof(*pull));
	NUTS_PASS(nng_mtx_alloc(&push->lk));
	NUTS_PASS(nng_cv_alloc(&push->cv, push->lk));
	NUTS_PASS(nng_mtx_alloc(&pull->lk));
	NUTS_PASS(nng_cv_alloc(&pull->cv, pull->lk));

	NUTS_PASS(nng_push_open(&push->s));
	NUTS_PASS(nng_pull_open(&pull->s));

	NUTS_PASS(nng_socket_set_ms(push->s, NNG_OPT_RECONNMINT, 10));
	NUTS_PASS(nng_socket_set_ms(push->s, NNG_OPT_RECONNMAXT, 10));
	NUTS_PASS(nng_socket_set_ms(pull->s, NNG_OPT_RECONNMINT, 10));
	NUTS_PASS(nng_socket_set_ms(pull->s, NNG_OPT_RECONNMAXT, 10));

	NUTS_PASS(nng_listener_create(&pull->l, pull->s, addr));
	NUTS_PASS(nng_dialer_create(&push->d, push->s, addr));
	NUTS_TRUE(nng_listener_id(pull->l) > 0);
	NUTS_TRUE(nng_dialer_id(push->d) > 0);
	NUTS_PASS(nng_dialer_set_ms(push->d, NNG_OPT_RECONNMINT, 10));
	NUTS_PASS(nng_dialer_set_ms(push->d, NNG_OPT_RECONNMAXT, 10));

	NUTS_PASS(nng_pipe_notify(push->s, NNG_PIPE_EV_ADD_PRE, notify, push));
	NUTS_PASS(
	    nng_pipe_notify(push->s, NNG_PIPE_EV_ADD_POST, notify, push));
	NUTS_PASS(
	    nng_pipe_notify(push->s, NNG_PIPE_EV_REM_POST, notify, push));
	NUTS_PASS(nng_pipe_notify(pull->s, NNG_PIPE_EV_ADD_PRE, notify, pull));
	NUTS_PASS(
	    nng_pipe_notify(pull->s, NNG_PIPE_EV_ADD_POST, notify, pull));
	NUTS_PASS(
	    nng_pipe_notify(pull->s, NNG_PIPE_EV_REM_POST, notify, pull));
}

static void
fini_cases(struct testcase *push, struct testcase *pull)
{
	nng_close(push->s);
	nng_close(pull->s);
	nng_cv_free(push->cv);
	nng_cv_free(pull->cv);
	nng_mtx_free(push->lk);
	nng_mtx_free(pull->lk);
}

static void
test_pipe_msg_id(void)
{
	static struct testcase push = { 0 };
	static struct testcase pull = { 0 };
	char                  *addr;
	nng_msg               *msg;

	NUTS_ADDR(addr, "inproc");

	init_cases(addr, &push, &pull);

	NUTS_PASS(nng_listener_start(pull.l, 0));
	NUTS_PASS(nng_dialer_start(push.d, 0));
	NUTS_TRUE(expect(&pull, &pull.add_pre, 1));
	NUTS_TRUE(expect(&pull, &pull.add_post, 1));
	NUTS_TRUE(expect(&pull, &pull.add_pre, 1));
	NUTS_TRUE(expect(&pull, &pull.add_post, 1));
	NUTS_TRUE(expect(&pull, &pull.rem, 0));
	NUTS_TRUE(expect(&pull, &pull.err, 0));
	NUTS_TRUE(expect(&push, &push.add_pre, 1));
	NUTS_TRUE(expect(&push, &push.add_post, 1));
	NUTS_TRUE(expect(&push, &push.rem, 0));
	NUTS_TRUE(expect(&push, &push.err, 0));

	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "hello", strlen("hello") + 1));
	NUTS_PASS(nng_sendmsg(push.s, msg, 0));
	msg = NULL;
	NUTS_PASS(nng_recvmsg(pull.s, &msg, 0));
	NUTS_TRUE(msg != NULL);
	NUTS_TRUE(nng_msg_len(msg) == strlen("hello") + 1);
	NUTS_MATCH(nng_msg_body(msg), "hello");
	NUTS_TRUE(nng_pipe_id(nng_msg_get_pipe(msg)) == nng_pipe_id(pull.p));
	nng_msg_free(msg);
	fini_cases(&push, &pull);
}

static void
test_pipe_reconnect(void)
{
	struct testcase push = { 0 };
	struct testcase pull = { 0 };
	char           *addr;
	nng_msg        *msg;

	NUTS_ADDR(addr, "inproc");

	init_cases(addr, &push, &pull);

	NUTS_PASS(nng_listener_start(pull.l, 0));
	NUTS_PASS(nng_dialer_start(push.d, 0));
	NUTS_TRUE(expect(&pull, &pull.add_pre, 1));
	NUTS_TRUE(expect(&pull, &pull.add_post, 1));
	NUTS_TRUE(expect(&pull, &pull.add_pre, 1));
	NUTS_TRUE(expect(&pull, &pull.add_post, 1));
	NUTS_TRUE(expect(&pull, &pull.rem, 0));
	NUTS_TRUE(expect(&pull, &pull.err, 0));
	NUTS_TRUE(expect(&push, &push.add_pre, 1));
	NUTS_TRUE(expect(&push, &push.add_post, 1));
	NUTS_TRUE(expect(&push, &push.rem, 0));
	NUTS_TRUE(expect(&push, &push.err, 0));

	NUTS_TRUE(expect(&pull, &pull.add_pre, 1));
	NUTS_TRUE(expect(&pull, &pull.add_post, 1));
	nng_pipe_close(pull.p);

	NUTS_TRUE(expect(&pull, &pull.rem, 1));
	NUTS_TRUE(expect(&pull, &pull.err, 0));
	NUTS_TRUE(expect(&pull, &pull.add_pre, 2));
	NUTS_TRUE(expect(&pull, &pull.add_post, 2));

	NUTS_TRUE(expect(&push, &push.rem, 1));
	NUTS_TRUE(expect(&push, &push.err, 0));
	NUTS_TRUE(expect(&push, &push.add_pre, 2));
	NUTS_TRUE(expect(&push, &push.add_post, 2));

	nng_msleep(200);
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "hello", strlen("hello") + 1));
	NUTS_PASS(nng_sendmsg(push.s, msg, 0));
	msg = NULL;
	NUTS_PASS(nng_recvmsg(pull.s, &msg, 0));
	NUTS_TRUE(msg != NULL);
	NUTS_MATCH(nng_msg_body(msg), "hello");
	nng_pipe p1 = nng_msg_get_pipe(msg);
	nng_msg_free(msg);
	NUTS_TRUE(nng_pipe_id(p1) == nng_pipe_id(pull.p));
	fini_cases(&push, &pull);
}

static void
test_pipe_reject(void)
{
	struct testcase push = { 0 };
	struct testcase pull = { 0 };
	char           *addr;

	NUTS_ADDR(addr, "inproc");

	init_cases(addr, &push, &pull);
	NUTS_PASS(nng_pipe_notify(pull.s, NNG_PIPE_EV_ADD_PRE, reject, &pull));
	NUTS_PASS(nng_listener_start(pull.l, 0));
	nng_msleep(100);
	NUTS_PASS(nng_dialer_start(push.d, 0));
	NUTS_TRUE(expect(&pull, &pull.add_pre, 2));
	NUTS_TRUE(expect(&pull, &pull.add_post, 1));
	NUTS_TRUE(expect(&pull, &pull.rem, 1));
	NUTS_TRUE(expect(&pull, &pull.err, 0));
	NUTS_TRUE(expect(&push, &push.add_pre, 2));
	NUTS_TRUE(expect(&push, &push.add_post, 2));
	NUTS_TRUE(expect(&push, &push.rem, 1) == 1);
	NUTS_TRUE(expect(&push, &push.err, 0));

	fini_cases(&push, &pull);
}

NUTS_TESTS = {
	{ "pipe msg id", test_pipe_msg_id },
	{ "pipe reconnect", test_pipe_reconnect },
	{ "pipe reject", test_pipe_reject },
	{ NULL, NULL },
};
