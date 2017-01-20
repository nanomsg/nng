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
static nni_mtx nni_idlock_x;

static int
nni_init_helper(void)
{
	int rv;

	if ((rv = nni_random_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_mtx_init(&nni_idlock_x)) != 0) {
		return (rv);
	}
	if (((rv = nni_idhash_create(&nni_endpoints)) != 0) ||
	    ((rv = nni_idhash_create(&nni_pipes)) != 0) ||
	    ((rv = nni_idhash_create(&nni_sockets)) != 0)) {
		nni_mtx_fini(&nni_idlock_x);
		nni_random_fini();
		return (rv);
	}
	nni_idhash_set_limits(nni_pipes, 1, 0x7fffffff,
	    nni_random() & 0x7fffffff);
	nni_idhash_set_limits(nni_sockets, 1, 0xffffffff, 1);
	nni_idlock = &nni_idlock_x;
	nni_tran_init();
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
	nni_idhash_destroy(nni_endpoints);
	nni_idhash_destroy(nni_pipes);
	nni_idhash_destroy(nni_sockets);
	nni_mtx_fini(&nni_idlock_x);
	nni_tran_fini();
	nni_random_fini();
	nni_plat_fini();
}
