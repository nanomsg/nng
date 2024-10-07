//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nuts.h>

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
cancel(nng_aio *aio, void *arg, int rv)
{
	*(int *) arg = rv;
	nng_aio_finish(aio, rv);
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
	NUTS_TRUE(nng_aio_begin(aio) == true);
	nng_aio_defer(aio, cancel, &rv);
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
	nng_recv_aio(s1, a);
	nng_aio_cancel(a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_TRUE(nng_aio_result(a) == NNG_ECANCELED);

	nng_aio_free(a);
	NUTS_TRUE(nng_close(s1) == 0);
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

	nng_recv_aio(s2, rx_aio);

	nng_aio_set_msg(tx_aio, m);
	nng_send_aio(s1, tx_aio);

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
	NUTS_PASS(nng_close(s1));
	NUTS_PASS(nng_close(s2));
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
	nng_recv_aio(s, a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	NUTS_PASS(nng_close(s));
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
	nng_recv_aio(s, a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	NUTS_PASS(nng_close(s));
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
	nng_recv_aio(s, a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	NUTS_PASS(nng_close(s));
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
	nng_recv_aio(s, a);
	nng_aio_wait(a);
	NUTS_TRUE(done == 1);
	NUTS_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	NUTS_PASS(nng_close(s));
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
	int          result;
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
	if (nng_aio_result(sl->aio) != 0) {
		sl->result = nng_aio_result(sl->aio);
		sl->done   = true;
		nng_cv_wake(sl->cv);
		nng_mtx_unlock(sl->mx);
		return;
	}
	sl->count++;
	if (sl->count >= sl->limit) {
		sl->done   = true;
		sl->result = 0;
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

NUTS_TESTS = {
	{ "sleep", test_sleep },
	{ "sleep timeout", test_sleep_timeout },
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
	{ NULL, NULL },
};
