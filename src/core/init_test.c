//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

uint64_t nni_init_get_param(
    nng_init_parameter parameter, uint64_t default_value);
uint64_t nni_init_get_effective(nng_init_parameter p);
void     nni_init_set_effective(nng_init_parameter p, uint64_t);

void
test_init_param(void)
{
	NUTS_ASSERT(nni_init_get_param(NNG_INIT_PARAMETER_NONE, 456) == 456);
	nng_init_set_parameter(NNG_INIT_PARAMETER_NONE, 123);
	NUTS_ASSERT(nni_init_get_param(NNG_INIT_PARAMETER_NONE, 567) == 123);
	nni_init_set_effective(NNG_INIT_PARAMETER_NONE, 124);
	NUTS_ASSERT(nni_init_get_effective(NNG_INIT_PARAMETER_NONE) == 124);
	NUTS_ASSERT(nni_init_get_param(NNG_INIT_PARAMETER_NONE, 567) == 123);
	nng_fini();
	NUTS_ASSERT(nni_init_get_param(NNG_INIT_PARAMETER_NONE, 567) == 567);
}

void
test_set_effective(void)
{
	nni_init_set_effective(NNG_INIT_PARAMETER_NONE, 999);
	NUTS_ASSERT(nni_init_get_param(NNG_INIT_PARAMETER_NONE, 0) == 0);
	NUTS_ASSERT(nni_init_get_effective(NNG_INIT_PARAMETER_NONE) == 999);
	nng_fini();
}

void
test_init_zero_resolvers(void)
{
	nng_socket s;
	nng_init_set_parameter(NNG_INIT_NUM_RESOLVER_THREADS, 0);
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	NUTS_ASSERT(
	    nni_init_get_effective(NNG_INIT_NUM_RESOLVER_THREADS) == 1);
	nng_fini();
}

void
test_init_one_task_thread(void)
{
	nng_socket s;
	nng_init_set_parameter(NNG_INIT_NUM_TASK_THREADS, 0);
	nng_init_set_parameter(NNG_INIT_MAX_TASK_THREADS, 1);
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	NUTS_ASSERT(nni_init_get_effective(NNG_INIT_NUM_TASK_THREADS) == 2);
	nng_fini();
}

void
test_init_too_many_task_threads(void)
{
	nng_socket s;
	nng_init_set_parameter(NNG_INIT_NUM_TASK_THREADS, 256);
	nng_init_set_parameter(NNG_INIT_MAX_TASK_THREADS, 4);
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	NUTS_ASSERT(nni_init_get_effective(NNG_INIT_NUM_TASK_THREADS) == 4);
	nng_fini();
}

void
test_init_no_expire_thread(void)
{
	nng_socket s;
	nng_init_set_parameter(NNG_INIT_NUM_EXPIRE_THREADS, 0);
	nng_init_set_parameter(NNG_INIT_MAX_EXPIRE_THREADS, 0);
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	NUTS_ASSERT(nni_init_get_effective(NNG_INIT_NUM_EXPIRE_THREADS) == 1);
	nng_fini();
}

void
test_init_too_many_expire_threads(void)
{
	nng_socket s;
	nng_init_set_parameter(NNG_INIT_NUM_EXPIRE_THREADS, 256);
	nng_init_set_parameter(NNG_INIT_MAX_EXPIRE_THREADS, 2);
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	NUTS_ASSERT(nni_init_get_effective(NNG_INIT_NUM_EXPIRE_THREADS) == 2);
	nng_fini();
}

// poller tuning only supported on Windows right now
#ifdef NNG_PLATFORM_WINDOWS
void
test_init_poller_no_threads(void)
{
	nng_socket s;
	nng_init_set_parameter(NNG_INIT_NUM_POLLER_THREADS, 0);
	nng_init_set_parameter(NNG_INIT_MAX_POLLER_THREADS, 0);
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	NUTS_ASSERT(nni_init_get_effective(NNG_INIT_NUM_POLLER_THREADS) == 1);
	nng_fini();
}

void
test_init_too_many_poller_threads(void)
{
	nng_socket s;
	nng_init_set_parameter(NNG_INIT_NUM_POLLER_THREADS, 256);
	nng_init_set_parameter(NNG_INIT_MAX_POLLER_THREADS, 2);
	NUTS_OPEN(s);
	NUTS_CLOSE(s);
	NUTS_ASSERT(nni_init_get_effective(NNG_INIT_NUM_POLLER_THREADS) == 2);
	nng_fini();
}
#endif

NUTS_TESTS = {
	{ "init parameter", test_init_param },
	{ "init set effective", test_set_effective },
	{ "init zero resolvers", test_init_zero_resolvers },
	{ "init one task thread", test_init_one_task_thread },
	{ "init too many task threads", test_init_too_many_task_threads },
	{ "init no expire thread", test_init_no_expire_thread },
	{ "init too many expire threads", test_init_too_many_expire_threads },
#ifdef NNG_PLATFORM_WINDOWS
	{ "init no poller thread", test_init_poller_no_threads },
	{ "init too many poller threads", test_init_too_many_poller_threads },
#endif

	{ NULL, NULL },
};