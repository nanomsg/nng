//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "../core/nng_impl.h"
#include "../testing/nuts.h"

#include <stdlib.h>

nng_init_params *nng_init_get_params(void);
bool             nni_init_was_called(void);

void
test_init_param(void)
{
	nng_init_params *p;
	p = nng_init_get_params();
	NUTS_ASSERT(p != NULL);
}

void
test_init_called(void)
{
	NUTS_TRUE(nni_init_was_called());
	nng_fini();
	NUTS_TRUE(nni_init_was_called());
	NUTS_PASS(nng_init(NULL));
}

void
test_init_zero_resolvers(void)
{
	nng_init_params *pp;
	nng_init_params  p     = { 0 };
	p.num_resolver_threads = 0;
	nng_fini();
	NUTS_PASS(nng_init(&p));
	pp = nng_init_get_params();
	NUTS_ASSERT(pp->num_resolver_threads > 0);
	nng_fini();
	// Leave the NUTS fixture's initialization for TEST_FINI to release.
	NUTS_PASS(nng_init(NULL));
}

void
test_init_one_task_thread(void)
{
	nng_init_params *pp;
	nng_init_params  p = { 0 };

	nng_fini();
	p.max_task_threads = 1;
	NUTS_PASS(nng_init(&p));
	pp = nng_init_get_params();
	NUTS_ASSERT(pp->max_task_threads == 1);
}

void
test_init_too_many_task_threads(void)
{
	nng_socket       s;
	nng_init_params *pp;
	nng_init_params  p = { 0 };

	p.num_task_threads = 256;
	p.max_task_threads = 4;

	nng_fini();
	NUTS_PASS(nng_init(&p));
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	pp = nng_init_get_params();
	NUTS_TRUE(pp->num_task_threads == 4);
}

void
test_init_no_expire_thread(void)
{
	nng_socket       s;
	nng_init_params *pp;
	nng_init_params  p = { 0 };

	nng_fini();
	p.num_expire_threads = 0;
	p.max_expire_threads = 0;
	NUTS_PASS(nng_init(&p));
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	pp = nng_init_get_params();
	NUTS_TRUE(pp->num_expire_threads > 0);
	NUTS_MSG("Got %d expire threads", pp->num_expire_threads);
}

void
test_init_too_many_expire_threads(void)
{
	nng_socket       s;
	nng_init_params *pp;
	nng_init_params  p = { 0 };

	nng_fini();
	p.num_expire_threads = 256;
	p.max_expire_threads = 2;
	NUTS_PASS(nng_init(&p));
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	pp = nng_init_get_params();
	NUTS_TRUE(pp->num_expire_threads == 2);
	NUTS_MSG("Got %d expire threads", pp->num_expire_threads);
}

// poller tuning only supported on Windows right now
void
test_init_poller_no_threads(void)
{
	nng_socket       s;
	nng_init_params *pp;
	nng_init_params  p = { 0 };

	nng_fini();
	p.num_poller_threads = 0;
	p.max_poller_threads = 0;
	NUTS_PASS(nng_init(&p));
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	pp = nng_init_get_params();
	NUTS_TRUE(pp->num_poller_threads > 0);
	NUTS_MSG("Got %d poller threads", pp->num_expire_threads);
}

void
test_init_too_many_poller_threads(void)
{
	nng_socket       s;
	nng_init_params *pp;
	nng_init_params  p = { 0 };

	nng_fini();
	p.num_poller_threads = 256;
	p.max_poller_threads = 2;
	NUTS_PASS(nng_init(&p));
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	pp = nng_init_get_params();
#ifdef NNG_PLATFORM_WINDOWS
	NUTS_TRUE(pp->num_poller_threads == 2);
#else
	NUTS_TRUE(pp->num_poller_threads > 0);
#endif
	NUTS_MSG("Got %d poller threads", pp->num_expire_threads);
}

void
test_init_repeated(void)
{
	nng_init_params p = { 0 };
	NUTS_PASS(nng_init(NULL));
	NUTS_FAIL(nng_init(&p), NNG_EBUSY);
	NUTS_PASS(nng_init(NULL));
	nng_fini();
	nng_fini();
}

static void
concurrent_init(void *arg)
{
	nng_mtx *mtx = arg;

	// so everyone starts as close to the same time as we can.
	nng_mtx_lock(mtx);
	nng_mtx_unlock(mtx);
	for (int i = 0; i < 1000000; i++) {
		nng_init(NULL);
		nng_fini();
	}
}

void
test_init_concurrent(void)
{
	nng_thread *threads[4];
	nng_mtx    *m = NULL;

	NUTS_PASS(nng_init(NULL));
	NUTS_PASS(nng_mtx_alloc(&m));
	NUTS_ASSERT(m != NULL);
	nng_mtx_lock(m);

	for (int i = 0; i < 4; i++) {
		nng_thread_create(&threads[i], concurrent_init, m);
	}

	nng_mtx_unlock(m);

	for (int i = 0; i < 4; i++) {
		nng_thread_destroy(threads[i]);
	}

	nng_mtx_free(m);

	nng_fini();
}

static nni_atomic_int  init_alloc_attempts;
static nni_atomic_int  init_fail_at;
static nni_atomic_int  init_allocations;
static nni_atomic_bool init_alloc_failed;

static bool
init_should_fail_alloc(void)
{
	nni_atomic_inc(&init_alloc_attempts);
	int attempt = nni_atomic_get(&init_alloc_attempts);
	int fail_at = nni_atomic_get(&init_fail_at);

	if ((fail_at > 0) && (attempt >= fail_at)) {
		nni_atomic_set_bool(&init_alloc_failed, true);
		return (true);
	}
	return (false);
}

static void *
init_malloc(size_t size)
{
	void *ptr;
	if (init_should_fail_alloc()) {
		return (NULL);
	}
	if ((ptr = malloc(size)) != NULL) {
		nni_atomic_inc(&init_allocations);
	}
	return (ptr);
}

static void *
init_calloc(size_t count, size_t size)
{
	void *ptr;
	if (init_should_fail_alloc()) {
		return (NULL);
	}
	if ((ptr = calloc(count, size)) != NULL) {
		nni_atomic_inc(&init_allocations);
	}
	return (ptr);
}

static void
init_free(void *ptr, size_t size)
{
	(void) size;
	if (ptr != NULL) {
		nni_atomic_dec(&init_allocations);
		free(ptr);
	}
}

static void
test_init_allocation_failures(void)
{
	nng_init_params original = {
		.malloc_fn = nni_malloc_fn,
		.calloc_fn = nni_calloc_fn,
		.free_fn   = nni_free_fn,
	};
	nng_init_params params = {
		.malloc_fn            = init_malloc,
		.calloc_fn            = init_calloc,
		.free_fn              = init_free,
		.num_task_threads     = 2,
		.num_expire_threads   = 2,
		.num_poller_threads   = 1,
		.num_resolver_threads = 1,
	};
	bool complete = false;

	nng_fini();
	nni_atomic_init(&init_alloc_attempts);
	nni_atomic_init(&init_fail_at);
	nni_atomic_init(&init_allocations);
	nni_atomic_init_bool(&init_alloc_failed);
	for (int fail_at = 1; fail_at < 128; fail_at++) {
		nng_socket sock;
		nng_err    rv;

		nni_atomic_set(&init_alloc_attempts, 0);
		nni_atomic_set(&init_fail_at, fail_at);
		nni_atomic_set_bool(&init_alloc_failed, false);
		rv = nng_init(&params);
		if (rv == NNG_OK) {
			nng_fini();
		}
		nni_atomic_set(&init_fail_at, 0);
		NUTS_TRUE((rv == NNG_OK) || (rv == NNG_ENOMEM));
		NUTS_MSG("Failing initialization allocation %d returned %d",
		    fail_at, rv);
		NUTS_TRUE(nni_atomic_get(&init_allocations) == 0);
		NUTS_MSG("Allocation %d failed: %d allocations remain",
		    fail_at, nni_atomic_get(&init_allocations));
		if (rv == NNG_ENOMEM) {
			NUTS_MATCH(nng_strerror(rv), "Out of memory");
		}
		complete = !nni_atomic_get_bool(&init_alloc_failed);

		// A failed attempt must release its resources and reference
		// count.
		NUTS_PASS(nng_init(&params));
		NUTS_OPEN(sock);
		NUTS_CLOSE(sock);
		nng_fini();
		NUTS_TRUE(nni_atomic_get(&init_allocations) == 0);
		NUTS_MSG("Recovery after allocation %d: %d allocations remain",
		    fail_at, nni_atomic_get(&init_allocations));
		if (complete) {
			break;
		}
	}
	NUTS_TRUE(complete);
	NUTS_PASS(nng_init(&original));
}

NUTS_TESTS = {
	{ "init parameter", test_init_param },
	{ "init called", test_init_called },
	{ "init zero resolvers", test_init_zero_resolvers },
	{ "init one task thread", test_init_one_task_thread },
	{ "init too many task threads", test_init_too_many_task_threads },
	{ "init no expire thread", test_init_no_expire_thread },
	{ "init too many expire threads", test_init_too_many_expire_threads },
	{ "init no poller thread", test_init_poller_no_threads },
	{ "init too many poller threads", test_init_too_many_poller_threads },
	{ "init repeated", test_init_repeated },
	{ "init concurrent", test_init_concurrent },
	{ "init allocation failures", test_init_allocation_failures },

	{ NULL, NULL },
};
