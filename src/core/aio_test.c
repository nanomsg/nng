//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "aio.h"

#include "../testing/nuts.h"

static void
cb_done(void *p)
{
	(*(int *) p)++;
}

static void
sleep_done(void *arg)
{
	*(nng_time *) arg = nng_clock();
}

static void
cancel(nng_aio *aio, void *arg, nng_err rv)
{
	*(int *) arg = rv;
	nng_aio_finish(aio, rv);
}

typedef struct stopped_recv {
	nng_msg *msg;
	void (*finish)(nni_aio *, nni_msg *);
} stopped_recv;

static void
stopped_recv_cancel(nng_aio *aio, void *arg, nng_err rv)
{
	stopped_recv *recv = arg;

	NUTS_FAIL(rv, NNG_ESTOPPED);
	recv->finish(aio, recv->msg);
	recv->msg = NULL;
}

static void
stopped_deferred_recv_cancel(nng_aio *aio, void *arg, nng_err rv)
{
	NUTS_FAIL(rv, NNG_ESTOPPED);
	NUTS_NULL(nng_aio_get_msg(aio));
	nni_aio_completions_run(arg);
}

typedef struct finish_msg_arg {
	nng_aio *aio;
	nng_msg *msg;
} finish_msg_arg;

static void
finish_msg(void *arg)
{
	finish_msg_arg *finish = arg;

	nni_aio_finish_msg(finish->aio, finish->msg);
}

void
test_sleep(void)
{
	nng_time start;
	nng_time end = 0;
	nng_aio *aio;

	NUTS_PASS(nng_aio_alloc(&aio, sleep_done, &end));
	start = nng_clock();
	nng_sleep_aio(200, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(end != 0);
	NUTS_TRUE((end - start) >= 200);
	NUTS_TRUE((end - start) <= 1000);
	NUTS_TRUE((nng_clock() - start) >= 200);
	NUTS_TRUE((nng_clock() - start) <= 1000);
	nng_aio_free(aio);
}

void
test_sleep_timeout(void)
{
	nng_time start;
	nng_time end = 0;
	nng_aio *aio;

	NUTS_TRUE(nng_aio_alloc(&aio, sleep_done, &end) == 0);
	nng_aio_set_timeout(aio, 100);
	start = nng_clock();
	nng_sleep_aio(2000, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ETIMEDOUT);
	NUTS_TRUE(end != 0);
	NUTS_TRUE((end - start) >= 100);
	NUTS_TRUE((end - start) <= 1000);
	NUTS_TRUE((nng_clock() - start) >= 100);
	NUTS_TRUE((nng_clock() - start) <= 1000);
	nng_aio_free(aio);
}

static void
sleep_reap(void *arg)
{
	nng_aio *aio = *(nng_aio **) arg;
	if (nng_aio_result(aio) != NNG_ESTOPPED) {
		NUTS_FAIL(nng_aio_result(aio), NNG_ESTOPPED);
	}
	nng_aio_reap(aio);
}

static void
test_sleep_fini(void)
{
	static nng_aio *aio;
	NUTS_TRUE(nng_aio_alloc(&aio, sleep_reap, &aio) == 0);
	nng_sleep_aio(20000, aio);
	nng_msleep(1);
	// intentionally we do not free the aio here. reap should clean it.
	nng_fini();
	nng_init(NULL); // so that TEST_FINI will reap
}

static void
test_sleep_fini_many(void)
{
#define NIOS 2000
	static nng_aio *aios[NIOS];
	for (int i = 0; i < NIOS; i++) {
		int rv = nng_aio_alloc(&(aios[i]), sleep_reap, &(aios[i]));
		if (rv != 0) {
			NUTS_ASSERT(rv == 0);
		}
	}
	for (int i = 0; i < NIOS; i++) {
		nng_sleep_aio(20000, aios[i]);
	}
	nng_fini();
	nng_init(NULL);
}

void
test_insane_nio(void)
{
	nng_aio *aio;
	nng_iov  iov;

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	NUTS_FAIL(nng_aio_set_iov(aio, 1024, &iov), NNG_EINVAL);
	nng_aio_free(aio);
}

void
test_provider_cancel(void)
{
	nng_aio *aio;
	int      rv = 0;
	// We fake an empty provider that does not do anything.
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_start(aio, cancel, &rv);
	nng_aio_cancel(aio);
	nng_aio_wait(aio);
	NUTS_TRUE(rv == NNG_ECANCELED);
	nng_aio_free(aio);
}

void
test_consumer_cancel(void)
{
	nng_aio   *a;
	nng_socket s1;
	int        done = 0;

	NUTS_TRUE(nng_pair1_open(&s1) == 0);
	NUTS_TRUE(nng_aio_alloc(&a, cb_done, &done) == 0);

	nng_aio_set_timeout(a, NNG_DURATION_INFINITE);
	nng_socket_recv(s1, a);
	nng_aio_cancel(a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_TRUE(nng_aio_result(a) == NNG_ECANCELED);

	nng_aio_free(a);
	NUTS_CLOSE(s1);
}

void
test_traffic(void)
{
	nng_socket s1;
	nng_socket s2;
	nng_aio   *tx_aio;
	nng_aio   *rx_aio;
	int        tx_done = 0;
	int        rx_done = 0;
	nng_msg   *m;
	char      *addr = "inproc://traffic";

	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_PASS(nng_pair1_open(&s2));

	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));

	NUTS_PASS(nng_aio_alloc(&rx_aio, cb_done, &rx_done));
	NUTS_PASS(nng_aio_alloc(&tx_aio, cb_done, &tx_done));

	nng_aio_set_timeout(rx_aio, 1000);
	nng_aio_set_timeout(tx_aio, 1000);

	NUTS_PASS(nng_msg_alloc(&m, 0));
	NUTS_PASS(nng_msg_append(m, "hello", strlen("hello")));

	nng_socket_recv(s2, rx_aio);

	nng_aio_set_msg(tx_aio, m);
	nng_socket_send(s1, tx_aio);

	nng_aio_wait(tx_aio);
	nng_aio_wait(rx_aio);

	NUTS_PASS(nng_aio_result(rx_aio));
	NUTS_PASS(nng_aio_result(tx_aio));

	NUTS_TRUE((m = nng_aio_get_msg(rx_aio)) != NULL);
	NUTS_TRUE(nng_msg_len(m) == strlen("hello"));
	NUTS_TRUE(memcmp(nng_msg_body(m), "hello", strlen("hello")) == 0);

	nng_msg_free(m);

	NUTS_TRUE(rx_done == 1);
	NUTS_TRUE(tx_done == 1);

	nng_aio_free(rx_aio);
	nng_aio_free(tx_aio);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
test_explicit_timeout(void)
{
	nng_socket s;
	nng_aio   *a;
	int        done = 0;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_PASS(nng_aio_alloc(&a, cb_done, &done));
	nng_aio_set_timeout(a, 40);
	nng_socket_recv(s, a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	NUTS_CLOSE(s);
}

void
test_explicit_expiration(void)
{
	nng_socket s;
	nng_aio   *a;
	int        done = 0;
	nng_time   now;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_PASS(nng_aio_alloc(&a, cb_done, &done));
	now = nng_clock();
	now += 40;
	nng_aio_set_expire(a, now);
	nng_socket_recv(s, a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	NUTS_CLOSE(s);
}

void
test_inherited_timeout(void)
{
	nng_socket s;
	nng_aio   *a;
	int        done = 0;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_PASS(nng_aio_alloc(&a, cb_done, &done));
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_RECVTIMEO, 40));
	nng_socket_recv(s, a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	NUTS_CLOSE(s);
}

void
test_zero_timeout(void)
{
	nng_socket s;
	nng_aio   *a;
	int        done = 0;

	NUTS_PASS(nng_pair1_open(&s));
	NUTS_PASS(nng_aio_alloc(&a, cb_done, &done));
	nng_aio_set_timeout(a, NNG_DURATION_ZERO);
	nng_socket_recv(s, a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	NUTS_CLOSE(s);
}

static void
aio_sleep_cb(void *arg)
{
	nng_aio *aio = *(nng_aio **) arg;
	nng_aio_reap(aio);
}

void
test_aio_reap(void)
{
	static nng_aio *a;
	NUTS_PASS(nng_aio_alloc(&a, aio_sleep_cb, &a));
	nng_sleep_aio(10, a);
	nng_msleep(100);
}

typedef struct sleep_loop {
	nng_aio     *aio;
	int          limit;
	int          count;
	nng_err      result;
	bool         done;
	nng_duration interval;
	nng_cv      *cv;
	nng_mtx     *mx;
} sleep_loop;

static void
aio_sleep_loop(void *arg)
{
	sleep_loop *sl = arg;
	nng_mtx_lock(sl->mx);
	if (nng_aio_result(sl->aio) != NNG_OK) {
		sl->result = nng_aio_result(sl->aio);
		sl->done   = true;
		nng_cv_wake(sl->cv);
		nng_mtx_unlock(sl->mx);
		return;
	}
	sl->count++;
	if (sl->count >= sl->limit) {
		sl->done   = true;
		sl->result = NNG_OK;
		nng_cv_wake(sl->cv);
		nng_mtx_unlock(sl->mx);
		return;
	}
	nng_mtx_unlock(sl->mx);
	nng_sleep_aio(sl->interval, sl->aio);
}

static bool
is_github_macos(void)
{
	char *env;
	if (((env = getenv("RUNNER_OS")) != NULL) &&
	    (strcmp(env, "macOS") == 0)) {
		return (true);
	}
	return (true);
}

void
test_sleep_loop(void)
{
	sleep_loop   sl;
	nng_time     start;
	nng_duration dur;

	sl.limit    = 3;
	sl.count    = 0;
	sl.interval = 50; // ms
	sl.done     = false;

	NUTS_PASS(nng_aio_alloc(&sl.aio, aio_sleep_loop, &sl));
	NUTS_PASS(nng_mtx_alloc(&sl.mx));
	NUTS_PASS(nng_cv_alloc(&sl.cv, sl.mx));

	start = nng_clock();
	nng_sleep_aio(100, sl.aio);
	nng_mtx_lock(sl.mx);
	while (!sl.done) {
		nng_cv_until(sl.cv, 2000);
	}
	nng_mtx_unlock(sl.mx);
	dur = (nng_duration) (nng_clock() - start);
	NUTS_ASSERT(dur >= 150);
	if (!is_github_macos()) {
		NUTS_ASSERT(dur <= 500); // allow for sloppy clocks
		NUTS_ASSERT(sl.count == 3);
	}
	NUTS_ASSERT(sl.done);
	NUTS_PASS(sl.result);

	nng_aio_free(sl.aio);
	nng_cv_free(sl.cv);
	nng_mtx_free(sl.mx);
}

void
test_sleep_cancel(void)
{
	sleep_loop   sl;
	nng_time     start;
	nng_duration dur;

	sl.limit    = 10;
	sl.count    = 0;
	sl.interval = 100; // ms
	sl.done     = false;

	NUTS_PASS(nng_aio_alloc(&sl.aio, aio_sleep_loop, &sl));
	NUTS_PASS(nng_mtx_alloc(&sl.mx));
	NUTS_PASS(nng_cv_alloc(&sl.cv, sl.mx));

	start = nng_clock();
	nng_sleep_aio(500, sl.aio);
	nng_msleep(150);
	nng_aio_cancel(sl.aio);
	nng_mtx_lock(sl.mx);
	while (!sl.done) {
		nng_cv_until(sl.cv, 2000);
	}
	nng_mtx_unlock(sl.mx);
	dur = (nng_duration) (nng_clock() - start);
	NUTS_ASSERT(dur >= 100);
	if (!is_github_macos()) {
		NUTS_ASSERT(dur <= 500); // allow for sloppy clocks
		NUTS_ASSERT(sl.count == 1);
	}
	NUTS_ASSERT(sl.done);
	NUTS_FAIL(sl.result, NNG_ECANCELED);

	nng_aio_free(sl.aio);
	nng_cv_free(sl.cv);
	nng_mtx_free(sl.mx);
}

void
test_aio_busy(void)
{
	nng_aio *aio;
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_sleep_aio(100, aio);
	NUTS_ASSERT(nng_aio_busy(aio));
	nng_aio_wait(aio);
	NUTS_ASSERT(!nng_aio_busy(aio));
	nng_aio_free(aio);
}

void
test_aio_stopped_direct_recv(void)
{
	nng_aio *aio;
	nng_msg *msg;
	int      done = 0;
	bool     skipped;

	NUTS_PASS(nng_aio_alloc(&aio, cb_done, &done));
	NUTS_PASS(nng_msg_alloc(&msg, 4));
	nng_aio_skip_callback(aio, &skipped);
	nng_aio_stop(aio);
	nni_aio_finish_msg(aio, msg);

	NUTS_TRUE(skipped);
	NUTS_TRUE(done == 0);
	NUTS_FAIL(nng_aio_result(aio), NNG_ESTOPPED);
	NUTS_TRUE(nng_aio_count(aio) == 0);
	NUTS_NULL(nng_aio_get_msg(aio));
	nng_aio_free(aio);
}

void
test_aio_stopped_direct_send(void)
{
	nng_aio *aio;
	nng_msg *msg;
	int      done = 0;

	NUTS_PASS(nng_aio_alloc(&aio, cb_done, &done));
	NUTS_PASS(nng_msg_alloc(&msg, 4));
	nng_aio_set_msg(aio, msg);
	nng_aio_stop(aio);
	nng_aio_finish(aio, NNG_OK);

	NUTS_TRUE(done == 0);
	NUTS_FAIL(nng_aio_result(aio), NNG_ESTOPPED);
	NUTS_TRUE(nng_aio_count(aio) == 0);
	NUTS_TRUE(nng_aio_get_msg(aio) == msg);
	nng_msg_free(msg);
	nng_aio_set_msg(aio, NULL);
	nng_aio_free(aio);
}

static void
stopped_started_recv(void (*finish)(nni_aio *, nni_msg *))
{
	nng_aio     *aio;
	stopped_recv recv;
	int          done = 0;

	NUTS_PASS(nng_aio_alloc(&aio, cb_done, &done));
	NUTS_PASS(nng_msg_alloc(&recv.msg, 4));
	recv.finish = finish;
	NUTS_TRUE(nng_aio_start(aio, stopped_recv_cancel, &recv));
	nng_aio_stop(aio);

	NUTS_NULL(recv.msg);
	NUTS_TRUE(done == 1);
	NUTS_FAIL(nng_aio_result(aio), NNG_ESTOPPED);
	NUTS_TRUE(nng_aio_count(aio) == 0);
	NUTS_NULL(nng_aio_get_msg(aio));
	nng_aio_free(aio);
}

void
test_aio_stopped_started_recv(void)
{
	stopped_started_recv(nni_aio_finish_msg);
}

void
test_aio_stopped_started_recv_sync(void)
{
	stopped_started_recv(nni_aio_finish_msg_sync);
}

void
test_aio_deferred_recv_stop(void)
{
	for (int stop_first = 0; stop_first < 2; stop_first++) {
		nng_aio            *aio;
		nng_msg            *msg;
		nni_aio_completions finish;
		int                 done = 0;

		nni_aio_completions_init(&finish);
		NUTS_PASS(nng_aio_alloc(&aio, cb_done, &done));
		NUTS_PASS(nng_msg_alloc(&msg, 4));
		NUTS_TRUE(
		    nni_aio_start(aio, stopped_deferred_recv_cancel, &finish));
		nni_aio_completions_add_msg(&finish, aio, msg);
		NUTS_NULL(nng_aio_get_msg(aio));
		if (!stop_first) {
			nni_aio_completions_run(&finish);
		}
		nng_aio_stop(aio);
		NUTS_TRUE(done == 1);
		NUTS_NULL(finish);
		if (stop_first) {
			NUTS_FAIL(nng_aio_result(aio), NNG_ESTOPPED);
			NUTS_TRUE(nng_aio_count(aio) == 0);
			NUTS_NULL(nng_aio_get_msg(aio));
		} else {
			NUTS_PASS(nng_aio_result(aio));
			NUTS_TRUE(nng_aio_count(aio) == 4);
			NUTS_TRUE(nng_aio_get_msg(aio) == msg);
			nng_msg_free(msg);
			nng_aio_set_msg(aio, NULL);
		}
		nng_aio_free(aio);
	}
}

void
test_aio_stopped_buffered_recv(void)
{
	struct {
		const char *name;
		int (*sender)(nng_socket *);
		int (*receiver)(nng_socket *);
	} protocols[] = {
		{ "pair0", nng_pair0_open, nng_pair0_open },
		{ "pair1", nng_pair1_open, nng_pair1_open },
		{ "bus", nng_bus0_open, nng_bus0_open },
		{ "pull", nng_push0_open, nng_pull0_open },
		{ "sub", nng_pub0_open, nng_sub0_open },
		{ "rep", nng_req0_open, nng_rep0_open },
		{ "respondent", nng_surveyor0_open, nng_respondent0_open },
		{ "req", nng_rep0_open, nng_req0_open },
		{ "surveyor", nng_respondent0_open, nng_surveyor0_open },
	};

	for (size_t i = 0; i < NNI_NUM_ELEMENTS(protocols); i++) {
		nng_socket sender;
		nng_socket receiver;
		nng_aio   *aio;
		nng_time   deadline;
		int        fd;
		int        done = 0;

		NUTS_CASE(protocols[i].name);
		NUTS_PASS(protocols[i].sender(&sender));
		NUTS_PASS(protocols[i].receiver(&receiver));
		if (protocols[i].receiver == nng_sub0_open) {
			NUTS_PASS(nng_sub0_socket_subscribe(receiver, "", 0));
		}
		NUTS_PASS(nng_socket_set_int(receiver, NNG_OPT_RECVBUF, 1));
		NUTS_PASS(nng_socket_get_recv_poll_fd(receiver, &fd));
		NUTS_MARRY(sender, receiver);
		if (protocols[i].receiver == nng_req0_open ||
		    protocols[i].receiver == nng_surveyor0_open) {
			NUTS_SEND(receiver, "request");
			NUTS_RECV(sender, "request");
		}
		NUTS_SEND(sender, "queued");
		deadline = nng_clock() + 1000;
		while (!nuts_poll_fd(fd) && nng_clock() < deadline) {
			nng_msleep(1);
		}
		NUTS_TRUE(nuts_poll_fd(fd));

		NUTS_PASS(nng_aio_alloc(&aio, cb_done, &done));
		nng_aio_stop(aio);
		nng_socket_recv(receiver, aio);
		NUTS_FAIL(nng_aio_result(aio), NNG_ESTOPPED);
		NUTS_TRUE(nng_aio_count(aio) == 0);
		NUTS_NULL(nng_aio_get_msg(aio));
		NUTS_TRUE(done == 0);
		nng_aio_free(aio);
		NUTS_CLOSE(sender);
		NUTS_CLOSE(receiver);
	}
}

void
test_aio_finish_before_stop(void)
{
	nng_aio *aio;
	nng_msg *msg;
	int      done = 0;

	NUTS_PASS(nng_aio_alloc(&aio, cb_done, &done));
	NUTS_PASS(nng_msg_alloc(&msg, 4));
	nni_aio_finish_msg(aio, msg);
	nng_aio_stop(aio);

	NUTS_TRUE(done == 1);
	NUTS_PASS(nng_aio_result(aio));
	NUTS_TRUE(nng_aio_count(aio) == 4);
	NUTS_TRUE(nng_aio_get_msg(aio) == msg);
	nng_msg_free(msg);
	nng_aio_set_msg(aio, NULL);
	nng_aio_free(aio);
}

void
test_aio_sleep_reset_finish_stop_race(void)
{
	for (int i = 0; i < 64; i++) {
		nng_aio       *aio;
		nng_msg       *msg;
		finish_msg_arg finish;
		nng_thread    *thread;
		int            done = 0;

		NUTS_PASS(nng_aio_alloc(&aio, cb_done, &done));
		nng_sleep_aio(1, aio);
		nng_aio_wait(aio);
		NUTS_PASS(nng_aio_result(aio));
		NUTS_TRUE(done == 1);

		nng_aio_reset(aio);
		NUTS_TRUE(!aio->a_started);
		NUTS_PASS(nng_msg_alloc(&msg, 4));
		finish.aio = aio;
		finish.msg = msg;
		NUTS_PASS(nng_thread_create(&thread, finish_msg, &finish));
		nng_aio_stop(aio);
		nng_thread_destroy(thread);

		if (nng_aio_result(aio) == NNG_OK) {
			NUTS_TRUE(done == 2);
			NUTS_TRUE(nng_aio_get_msg(aio) == msg);
			nng_msg_free(msg);
			nng_aio_set_msg(aio, NULL);
		} else {
			NUTS_FAIL(nng_aio_result(aio), NNG_ESTOPPED);
			NUTS_TRUE(done == 1);
			NUTS_NULL(nng_aio_get_msg(aio));
		}
		nng_aio_free(aio);
	}
}

void
test_aio_scatter_gather_too_many(void)
{
	nng_aio *aio;
	nng_iov  iov[32];

	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	for (int i = 0; i < 32; i++) {
		iov[i].iov_buf = "abc";
		iov[i].iov_len = 3;
	}

	NUTS_FAIL(nng_aio_set_iov(aio, 32, iov), NNG_EINVAL);

	nng_aio_free(aio);
}

NUTS_TESTS = {
	{ "sleep", test_sleep },
	{ "sleep timeout", test_sleep_timeout },
	{ "sleep fini", test_sleep_fini },
	{ "sleep fini many", test_sleep_fini_many },
	{ "insane nio", test_insane_nio },
	{ "provider cancel", test_provider_cancel },
	{ "consumer cancel", test_consumer_cancel },
	{ "traffic", test_traffic },
	{ "explicit timeout", test_explicit_timeout },
	{ "explicit expire", test_explicit_expiration },
	{ "inherited timeout", test_inherited_timeout },
	{ "zero timeout", test_zero_timeout },
	{ "aio reap", test_aio_reap },
	{ "sleep loop", test_sleep_loop },
	{ "sleep cancel", test_sleep_cancel },
	{ "aio busy", test_aio_busy },
	{ "aio stopped direct recv", test_aio_stopped_direct_recv },
	{ "aio stopped direct send", test_aio_stopped_direct_send },
	{ "aio stopped started recv", test_aio_stopped_started_recv },
	{ "aio stopped started recv sync",
	    test_aio_stopped_started_recv_sync },
	{ "aio deferred recv stop", test_aio_deferred_recv_stop },
	{ "aio stopped buffered recv", test_aio_stopped_buffered_recv },
	{ "aio finish before stop", test_aio_finish_before_stop },
	{ "aio sleep reset finish stop race",
	    test_aio_sleep_reset_finish_stop_race },
	{ "scatter gather too many", test_aio_scatter_gather_too_many },
	{ NULL, NULL },
};
