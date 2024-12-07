//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#include <nuts.h>

nng_init_params *nng_init_get_params(void);

void
test_init_param(void)
{
	nng_init_params *p;
	p = nng_init_get_params();
	NUTS_ASSERT(p != NULL);
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

void
test_fini_closes_socket(void)
{
	nng_socket s;
	NUTS_OPEN(s);
	nng_fini();
	NUTS_FAIL(nng_close(s), NNG_ECLOSED);
}

NUTS_TESTS = {
	{ "init parameter", test_init_param },
	{ "init zero resolvers", test_init_zero_resolvers },
	{ "init one task thread", test_init_one_task_thread },
	{ "init too many task threads", test_init_too_many_task_threads },
	{ "init no expire thread", test_init_no_expire_thread },
	{ "init too many expire threads", test_init_too_many_expire_threads },
	{ "init no poller thread", test_init_poller_no_threads },
	{ "init too many poller threads", test_init_too_many_poller_threads },
	{ "init repeated", test_init_repeated },
	{ "init concurrent", test_init_concurrent },
	{ "fini closes socket", test_fini_closes_socket },

	{ NULL, NULL },
};
