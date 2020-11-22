//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

struct add_arg {
	int          cnt;
	nng_duration delay;
	nng_mtx *    mx;
	nng_cv *     cv;
};

void
add(void *arg)
{
	struct add_arg *aa = arg;

	if (aa->delay > 0) {
		nng_msleep(aa->delay);
	}
	nng_mtx_lock(aa->mx);
	aa->cnt++;
	nng_cv_wake(aa->cv);
	nng_mtx_unlock(aa->mx);
}

#ifdef __has_feature
#if __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#define RELAXED_CLOCKS
#endif
#endif

void
test_sleep(void)
{
	uint64_t start;
	NUTS_CLOCK(start);
	nng_msleep(100);
	NUTS_AFTER(start + 100);
#ifndef RELAXED_CLOCKS
	NUTS_BEFORE(start + 500);
#endif
}

void
test_clock(void)
{
	uint64_t s0, s1;
	nng_time t0, t1;

	NUTS_CLOCK(s0);
	t0 = nng_clock();
	nng_msleep(200);
	t1 = nng_clock();
	NUTS_CLOCK(s1);

	NUTS_TRUE(t1 > t0);
	NUTS_TRUE((t1 - t0) >= 200);
	NUTS_TRUE((t1 - t0) < 500);

#ifndef RELAXED_CLOCKS
	NUTS_TRUE(abs((int) (s1 - s0) - (int) (t1 - t0)) < 50);
#endif
}

void
test_mutex(void)
{
	nng_mtx *mx, *mx2;

	NUTS_PASS(nng_mtx_alloc(&mx));
	nng_mtx_lock(mx);
	nng_mtx_unlock(mx);

	nng_mtx_lock(mx);
	nng_mtx_unlock(mx);
	nng_mtx_free(mx);

	// Verify that the mutexes are not always the same!
	NUTS_PASS(nng_mtx_alloc(&mx));
	NUTS_PASS(nng_mtx_alloc(&mx2));
	NUTS_TRUE(mx != mx2);
	nng_mtx_free(mx);
	nng_mtx_free(mx2);
}

void
test_thread(void)
{
	nng_thread *   thr;
	struct add_arg aa;

	NUTS_PASS(nng_mtx_alloc(&aa.mx));
	NUTS_PASS(nng_cv_alloc(&aa.cv, aa.mx));
	aa.cnt   = 0;
	aa.delay = 0;

	NUTS_PASS(nng_thread_create(&thr, add, &aa));
	nng_thread_destroy(thr);
	NUTS_TRUE(aa.cnt == 1);

	nng_cv_free(aa.cv);
	nng_mtx_free(aa.mx);
}

void
test_cond_var(void)
{
	nng_thread *   thr;
	struct add_arg aa;

	NUTS_PASS(nng_mtx_alloc(&aa.mx));
	NUTS_PASS(nng_cv_alloc(&aa.cv, aa.mx));
	aa.cnt   = 0;
	aa.delay = 0;

	NUTS_PASS(nng_thread_create(&thr, add, &aa));

	nng_mtx_lock(aa.mx);
	while (aa.cnt == 0) {
		nng_cv_wait(aa.cv);
	}
	nng_mtx_unlock(aa.mx);
	nng_thread_destroy(thr);
	NUTS_TRUE(aa.cnt == 1);

	nng_cv_free(aa.cv);
	nng_mtx_free(aa.mx);
}

void
test_cond_wake(void)
{
	nng_thread *   thr;
	struct add_arg aa;
	nng_time       now;

	NUTS_PASS(nng_mtx_alloc(&aa.mx));
	NUTS_PASS(nng_cv_alloc(&aa.cv, aa.mx));
	aa.cnt   = 0;
	aa.delay = 200;

	now = nng_clock();

	NUTS_PASS(nng_thread_create(&thr, add, &aa));

	nng_mtx_lock(aa.mx);
	nng_cv_until(aa.cv, now + 500);
	nng_mtx_unlock(aa.mx);

	NUTS_TRUE(nng_clock() >= now + 200);
	NUTS_TRUE(nng_clock() < now + 500);

	nng_thread_destroy(thr);
	nng_cv_free(aa.cv);
	nng_mtx_free(aa.mx);
}

void
test_cond_until(void)
{
	struct add_arg aa;
	nng_time       now;

	NUTS_PASS(nng_mtx_alloc(&aa.mx));
	NUTS_PASS(nng_cv_alloc(&aa.cv, aa.mx));
	aa.cnt   = 0;
	aa.delay = 0;

	now = nng_clock();
	nng_mtx_lock(aa.mx);
	nng_cv_until(aa.cv, now + 100);
	nng_mtx_unlock(aa.mx);

	NUTS_TRUE(nng_clock() >= now);
#ifdef NO_SPRIOUS_WAKEUPS
	// Some systems (e.g. Win32) will occasionally wake a threaed
	// spuriously.  We therefore can't rely on condwait to be
	// an absolute guarantee of minimum time passage.
	NUTS_TRUE(nng_clock() >= now + 100);
#endif
	NUTS_TRUE(nng_clock() < now + 1000);

	nng_cv_free(aa.cv);
	nng_mtx_free(aa.mx);
}

void
test_random(void)
{
	int      same = 0;
	uint32_t values[1000];

	for (int i = 0; i < 1000; i++) {
		values[i] = nng_random();
	}
	for (int i = 0; i < 1000; i++) {
		for (int j = 0; j < i; j++) {
			if (values[j] == values[i]) {
				same++;
			}
		}
	}

	// 1% reproduction is *highly* unlikely.
	// There are 4 billion possible options, we are only looking at
	// 1000 of them.  In general, it would be an extreme outlier
	// to see more than 2 repeats, unless your RNG is biased.
	NUTS_TRUE(same < 5);
}

NUTS_TESTS = {
	{ "sleep", test_sleep },
	{ "clock", test_clock },
	{ "mutex", test_mutex },
	{ "thread", test_thread },
	{ "cond var", test_cond_var },
	{ "cond wake", test_cond_wake },
	{ "cond until", test_cond_until },
	{ "random", test_random },
	{ NULL, NULL },
};
