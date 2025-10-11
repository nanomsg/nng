//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "defs.h"
#include "nng_impl.h"
#include "platform.h"
#include "socket.h"

#include <stdio.h>
#include <stdlib.h>

extern int  nni_tls_sys_init(void);
extern void nni_tls_sys_fini(void);

#ifndef NNG_NUM_EXPIRE_THREADS
#define NNG_NUM_EXPIRE_THREADS (nni_plat_ncpu())
#endif

#ifndef NNG_NUM_TASKQ_THREADS
#define NNG_NUM_TASKQ_THREADS (nni_plat_ncpu() * 2)
#endif

#ifndef NNG_NUM_POLLER_THREADS
#define NNG_NUM_POLLER_THREADS (nni_plat_ncpu())
#endif

#ifndef NNG_MAX_POLLER_THREADS
#define NNG_MAX_POLLER_THREADS 8
#endif

#ifndef NNG_RESOLV_CONCURRENCY
#define NNG_RESOLV_CONCURRENCY 1
#endif

#ifndef NNG_MAX_TASKQ_THREADS
#define NNG_MAX_TASKQ_THREADS 16
#endif

#ifndef NNG_MAX_EXPIRE_THREADS
#define NNG_MAX_EXPIRE_THREADS 8
#endif

static nng_init_params init_params;

unsigned int    init_count;
nni_atomic_flag init_busy;

nng_err
nng_init(const nng_init_params *params)
{
	nng_init_params zero = { 0 };
	nng_err         rv;

	// cheap spin lock
	while (nni_atomic_flag_test_and_set(&init_busy)) {
		continue;
	}
	if (init_count > 0) {
		if (params != NULL) {
			nni_atomic_flag_reset(&init_busy);
			return (NNG_EBUSY);
		}
		init_count++;
		nni_atomic_flag_reset(&init_busy);
		return (0);
	}
	if (params == NULL) {
		params = &zero;
	}
	init_params.num_task_threads     = params->num_task_threads
	        ? params->num_task_threads
	        : NNG_NUM_TASKQ_THREADS;
	init_params.max_task_threads     = params->max_task_threads
	        ? params->max_task_threads
	        : NNG_MAX_TASKQ_THREADS;
	init_params.num_expire_threads   = params->num_expire_threads
	      ? params->num_expire_threads
	      : NNG_NUM_EXPIRE_THREADS;
	init_params.max_expire_threads   = params->max_expire_threads
	      ? params->max_expire_threads
	      : NNG_MAX_EXPIRE_THREADS;
	init_params.num_poller_threads   = params->num_poller_threads
	      ? params->num_poller_threads
	      : NNG_NUM_POLLER_THREADS;
	init_params.max_poller_threads   = params->max_poller_threads
	      ? params->max_poller_threads
	      : NNG_MAX_POLLER_THREADS;
	init_params.num_resolver_threads = params->num_resolver_threads
	    ? params->num_resolver_threads
	    : NNG_RESOLV_CONCURRENCY;

	if (((rv = nni_plat_init(&init_params)) != 0) ||
	    ((rv = nni_taskq_sys_init(&init_params)) != 0) ||
	    ((rv = nni_reap_sys_init()) != 0) ||
	    ((rv = nni_aio_sys_init(&init_params)) != 0) ||
	    ((rv = nni_tls_sys_init()) != 0)) {
		nni_atomic_flag_reset(&init_busy);
		nng_fini();
		return (rv);
	}

	// following never fails
	nni_sp_tran_sys_init();

	nng_log_notice(
	    "NNG-INIT", "NNG library version %s initialized", nng_version());
	init_count++;
	nni_atomic_flag_reset(&init_busy);
	return (rv);
}

// Undocumented, for test code only
#ifdef NNG_TEST_LIB
nng_init_params *
nng_init_get_params(void)
{
	return &init_params;
}
#endif

void
nng_fini(void)
{
	while (nni_atomic_flag_test_and_set(&init_busy)) {
		continue;
	}
	init_count--;
	if (init_count > 0) {
		nni_atomic_flag_reset(&init_busy);
		return;
	}
	nni_sock_closeall();
	nni_sp_tran_sys_fini();

	// Drain everything. This is important because some of
	// these subsystems can dispatch things to other ones.
	// So we need them *all* to be empty before proceeding.
	while ((nni_aio_sys_drain() || nni_taskq_sys_drain() ||
	    nni_reap_sys_drain())) {
		continue;
	}
	nni_tls_sys_fini();
	nni_taskq_sys_fini();
	nni_aio_sys_fini();
	nni_id_map_sys_fini();
	nni_reap_sys_fini(); // must be near the end
	nni_plat_fini();
	nni_atomic_flag_reset(&init_busy);
}
