//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

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
	    ((rv = nni_timer_sys_init()) != 0) ||
	    ((rv = nni_aio_sys_init()) != 0) ||
	    ((rv = nni_tls_sys_init()) != 0)) {
		nni_fini();
		return (rv);
	}

	// following never fail
	nni_sp_tran_sys_init();

	nni_inited = true;

	return (0);
}

int
nni_init(void)
{
	return (nni_plat_init(nni_init_helper));
}

void
nni_fini(void)
{
	if (!nni_inited) {
		return;
	}
	nni_sp_tran_sys_fini();
	nni_tls_sys_fini();
	nni_reap_drain();
	nni_aio_sys_fini();
	nni_timer_sys_fini();
	nni_taskq_sys_fini();
	nni_reap_sys_fini(); // must be before timer and aio (expire)
	nni_id_map_sys_fini();

	nni_plat_fini();
	nni_inited = false;
}
