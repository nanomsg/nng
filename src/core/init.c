//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include <stdlib.h>
#include <stdio.h>

nni_idhash *nni_endpoints;
nni_idhash *nni_pipes;
nni_idhash *nni_sockets;
nni_mtx *nni_idlock;

static nni_idhash nni_endpoints_x;
static nni_idhash nni_pipes_x;
static nni_idhash nni_sockets_x;
static nni_mtx nni_idlock_x;

static int
nni_init_helper(void)
{
	int rv;

	if ((rv = nni_taskq_sys_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_random_sys_init()) != 0) {
		nni_taskq_sys_fini();
		return (rv);
	}
	if ((rv = nni_mtx_init(&nni_idlock_x)) != 0) {
		nni_random_sys_fini();
		nni_taskq_sys_fini();
		return (rv);
	}
	if (((rv = nni_idhash_init(&nni_endpoints_x)) != 0) ||
	    ((rv = nni_idhash_init(&nni_pipes_x)) != 0) ||
	    ((rv = nni_idhash_init(&nni_sockets_x)) != 0)) {
		nni_mtx_fini(&nni_idlock_x);
		nni_random_sys_fini();
		nni_taskq_sys_fini();
		return (rv);
	}
	nni_idhash_set_limits(&nni_pipes_x, 1, 0x7fffffff,
	    (nni_random() & 0x7ffffffe) + 1);
	nni_idhash_set_limits(&nni_sockets_x, 1, 0x7fffffff, 1);
	nni_idhash_set_limits(&nni_endpoints_x, 1, 0xffffffff, 1);

	nni_idlock = &nni_idlock_x;
	nni_pipes = &nni_pipes_x;
	nni_endpoints = &nni_endpoints_x;
	nni_sockets = &nni_sockets_x;

	nni_tran_sys_init();
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
	nni_idhash_fini(&nni_endpoints_x);
	nni_idhash_fini(&nni_pipes_x);
	nni_idhash_fini(&nni_sockets_x);
	nni_mtx_fini(&nni_idlock_x);
	nni_tran_sys_fini();
	nni_random_sys_fini();
	nni_taskq_sys_fini();
	nni_plat_fini();
}
