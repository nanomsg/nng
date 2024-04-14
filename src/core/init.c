//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "nng/nng.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

extern int  nni_tls_sys_init(void);
extern void nni_tls_sys_fini(void);

static bool nni_inited = false;

static int
nni_init_helper(void)
{
	int rv;

#ifdef NNG_TEST_LIB
	static bool cleanup = false;
	if (!cleanup) {
		atexit(nng_fini);
		cleanup = true;
	}
#endif

	if (((rv = nni_taskq_sys_init()) != 0) ||
	    ((rv = nni_reap_sys_init()) != 0) ||
	    ((rv = nni_aio_sys_init()) != 0) ||
	    ((rv = nni_tls_sys_init()) != 0)) {
		nni_fini();
		return (rv);
	}

	// following never fail
	nni_sp_tran_sys_init();

	nni_inited = true;
	nng_log_notice(
	    "NNG-INIT", "NNG library version %s initialized", nng_version());

	return (0);
}

int
nni_init(void)
{
	int rv;
	if ((rv = nni_plat_init(nni_init_helper)) != 0) {
		nng_log_err("NNG-INIT",
		    "NNG library initialization failed: %s", nng_strerror(rv));
	}
	return (rv);
}

// accessing the list of parameters
typedef struct nni_init_param {
	nni_list_node      node;
	nng_init_parameter param;
	uint64_t           value;
#ifdef NNG_TEST_LIB
	uint64_t effective;
#endif
} nni_init_param;

static nni_list nni_init_params =
    NNI_LIST_INITIALIZER(nni_init_params, nni_init_param, node);

void
nni_init_set_param(nng_init_parameter p, uint64_t value)
{
	if (nni_inited) {
		// this is paranoia -- if some library code started already
		// then we cannot safely change parameters, and modifying the
		// list is not thread safe.
		return;
	}
	nni_init_param *item;
	NNI_LIST_FOREACH (&nni_init_params, item) {
		if (item->param == p) {
			item->value = value;
			return;
		}
	}
	if ((item = NNI_ALLOC_STRUCT(item)) != NULL) {
		item->param = p;
		item->value = value;
		nni_list_append(&nni_init_params, item);
	}
}

uint64_t
nni_init_get_param(nng_init_parameter p, uint64_t default_value)
{
	nni_init_param *item;
	NNI_LIST_FOREACH (&nni_init_params, item) {
		if (item->param == p) {
			return (item->value);
		}
	}
	return (default_value);
}

void
nni_init_set_effective(nng_init_parameter p, uint64_t value)
{
#ifdef NNG_TEST_LIB
	nni_init_param *item;
	NNI_LIST_FOREACH (&nni_init_params, item) {
		if (item->param == p) {
			item->effective = value;
			return;
		}
	}
	if ((item = NNI_ALLOC_STRUCT(item)) != NULL) {
		item->param     = p;
		item->effective = value;
		nni_list_append(&nni_init_params, item);
	}
#else
	NNI_ARG_UNUSED(p);
	NNI_ARG_UNUSED(value);
#endif
}

#ifdef NNG_TEST_LIB
uint64_t
nni_init_get_effective(nng_init_parameter p)
{
	nni_init_param *item;
	NNI_LIST_FOREACH (&nni_init_params, item) {
		if (item->param == p) {
			return (item->effective);
		}
	}
	return ((uint64_t) -1);
}
#endif

static void
nni_init_params_fini(void)
{
	nni_init_param *item;
	while ((item = nni_list_first(&nni_init_params)) != NULL) {
		nni_list_remove(&nni_init_params, item);
		NNI_FREE_STRUCT(item);
	}
}

void
nni_fini(void)
{
	if (!nni_inited) {
		// make sure we discard parameters even if we didn't startup
		nni_init_params_fini();
		return;
	}
	nni_sp_tran_sys_fini();
	nni_tls_sys_fini();
	nni_reap_drain();
	nni_aio_sys_fini();
	nni_taskq_sys_fini();
	nni_reap_sys_fini(); // must be before timer and aio (expire)
	nni_id_map_sys_fini();
	nni_init_params_fini();

	nni_plat_fini();
	nni_inited = false;
}
