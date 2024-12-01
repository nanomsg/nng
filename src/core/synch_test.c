//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/nng.h>

#include <nuts.h>

// Notify tests for verifying condvars.
struct notifyarg {
	int          did;
	nng_duration when;
	nng_mtx     *mx;
	nng_cv      *cv;
	bool         wake;
	bool         fini;
};

void
notifyafter(void *a)
{
	struct notifyarg *na = a;

	nng_msleep(na->when);
	nng_mtx_lock(na->mx);
	na->did = 1;
	nng_cv_wake(na->cv);
	nng_mtx_unlock(na->mx);
}

static void
test_mutex_lock_unlock(void)
{
	nng_mtx *mtx;
	NUTS_PASS(nng_mtx_alloc(&mtx));
	for (int i = 1; i < 100; i++) {
		nng_mtx_lock(mtx);
		nng_mtx_unlock(mtx);
	}
	nng_mtx_free(mtx);
}

static void
test_mutex_block(void)
{
	nng_thread      *thr;
	struct notifyarg arg = { 0 };

	NUTS_PASS(nng_mtx_alloc(&arg.mx));
	NUTS_PASS(nng_cv_alloc(&arg.cv, arg.mx));
	arg.did  = 0;
	arg.when = 0;
	nng_mtx_lock(arg.mx);
	NUTS_PASS(nng_thread_create(&thr, notifyafter, &arg));
	nng_thread_set_name(thr, "notify thread");
	nng_msleep(10);
	NUTS_TRUE(arg.did == 0);
	nng_mtx_unlock(arg.mx);
	nng_msleep(10);
	nng_mtx_lock(arg.mx);
	while (!arg.did) {
		nng_cv_wait(arg.cv);
	}
	NUTS_TRUE(arg.did != 0);
	nng_mtx_unlock(arg.mx);
	nng_thread_destroy(thr);
	nng_cv_free(arg.cv);
	nng_mtx_free(arg.mx);
}

static void
test_cv_wake(void)
{
	nng_thread      *thr;
	struct notifyarg arg = { 0 };

	NUTS_PASS(nng_mtx_alloc(&arg.mx));
	NUTS_PASS(nng_cv_alloc(&arg.cv, arg.mx));
	arg.did  = 0;
	arg.when = 10;
	NUTS_PASS(nng_thread_create(&thr, notifyafter, &arg));
	nng_thread_set_name(thr, "notify thread");

	nng_mtx_lock(arg.mx);
	if (!arg.did) {
		nng_cv_wait(arg.cv);
	}
	nng_mtx_unlock(arg.mx);
	nng_thread_destroy(thr);
	NUTS_TRUE(arg.did == 1);
	nng_cv_free(arg.cv);
	nng_mtx_free(arg.mx);
}

static void
waiter(void *arg)
{
	struct notifyarg *na = arg;
	nng_mtx_lock(na->mx);
	while (!na->wake && !na->fini) {
		nng_cv_wait(na->cv);
	}
	if ((!na->fini) && na->wake) {
		na->did++;
	}
	nng_mtx_unlock(na->mx);
}

static void
test_cv_wake_only_one(void)
{
	nng_thread      *thr1;
	nng_thread      *thr2;
	struct notifyarg arg = { 0 };

	NUTS_PASS(nng_mtx_alloc(&arg.mx));
	NUTS_PASS(nng_cv_alloc(&arg.cv, arg.mx));
	arg.did  = 0;
	arg.when = 10;
	NUTS_PASS(nng_thread_create(&thr1, waiter, &arg));
	nng_thread_set_name(thr1, "one");
	NUTS_PASS(nng_thread_create(&thr2, waiter, &arg));
	nng_thread_set_name(thr2, "two");
	nng_msleep(200);

	nng_mtx_lock(arg.mx);
	arg.wake = true;
	nng_cv_wake1(arg.cv);
	nng_mtx_unlock(arg.mx);
	nng_msleep(200);

	nng_mtx_lock(arg.mx);
	NUTS_TRUE(arg.did == 1);
	NUTS_MSG("arg.did was %d", arg.did);
	arg.fini = true;
	nng_cv_wake(arg.cv);
	nng_mtx_unlock(arg.mx);

	nng_thread_destroy(thr1);
	nng_thread_destroy(thr2);
	nng_cv_free(arg.cv);
	nng_mtx_free(arg.mx);
}

static void
test_cv_timeout(void)
{
	nng_thread      *thr;
	struct notifyarg arg = { 0 };

	NUTS_PASS(nng_mtx_alloc(&arg.mx));
	NUTS_PASS(nng_cv_alloc(&arg.cv, arg.mx));
	arg.did  = 0;
	arg.when = 200;
	NUTS_PASS(nng_thread_create(&thr, notifyafter, &arg));
	nng_thread_set_name(thr, "notify thread");
	nng_mtx_lock(arg.mx);
	if (!arg.did) {
		nng_cv_until(arg.cv, nng_clock() + 10);
	}
	NUTS_TRUE(arg.did == 0);
	nng_mtx_unlock(arg.mx);
	nng_thread_destroy(thr);
	nng_cv_free(arg.cv);
	nng_mtx_free(arg.mx);
}

static void
test_cv_poll(void)
{
	struct notifyarg arg = { 0 };

	NUTS_PASS(nng_mtx_alloc(&arg.mx));
	NUTS_PASS(nng_cv_alloc(&arg.cv, arg.mx));
	nng_mtx_lock(arg.mx);
	NUTS_FAIL(nng_cv_until(arg.cv, 0), NNG_EAGAIN);
	nng_mtx_unlock(arg.mx);
	nng_cv_free(arg.cv);
	nng_mtx_free(arg.mx);
}

static void
test_cv_timeout_no_thread(void)
{
	struct notifyarg arg = { 0 };

	NUTS_PASS(nng_mtx_alloc(&arg.mx));
	NUTS_PASS(nng_cv_alloc(&arg.cv, arg.mx));
	arg.did  = 0;
	arg.when = 1;
	nng_mtx_lock(arg.mx);
	if (!arg.did) {
		nng_cv_until(arg.cv, nng_clock() + 10);
	}
	NUTS_TRUE(arg.did == 0);
	nng_mtx_unlock(arg.mx);
	nng_cv_free(arg.cv);
	nng_mtx_free(arg.mx);
}

NUTS_TESTS = {
	{ "mutex lock unlock", test_mutex_lock_unlock },
	{ "mutex lock block", test_mutex_block },
	{ "cv wake", test_cv_wake },
	{ "cv timeout", test_cv_timeout },
	{ "cv poll", test_cv_poll },
	{ "cv timeout no thread", test_cv_timeout_no_thread },
	{ "cv wake only one", test_cv_wake_only_one },
	{ NULL, NULL },
};
