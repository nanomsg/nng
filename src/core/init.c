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

static int
nni_init_helper(void)
{
	int rv;

	if ((rv = nni_taskq_sys_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_timer_sys_init()) != 0) {
		nni_taskq_sys_fini();
		return (rv);
	}
	if ((rv = nni_random_sys_init()) != 0) {
		nni_timer_sys_fini();
		nni_taskq_sys_fini();
		return (rv);
	}
	if ((rv = nni_sock_sys_init()) != 0) {
		nni_random_sys_fini();
		nni_timer_sys_fini();
		nni_taskq_sys_fini();
		return (rv);
	}
	if ((rv = nni_ep_sys_init()) != 0) {
		nni_sock_sys_fini();
		nni_random_sys_fini();
		nni_timer_sys_fini();
		nni_taskq_sys_fini();
		return (rv);
	}
	if ((rv = nni_pipe_sys_init()) != 0) {
		nni_ep_sys_fini();
		nni_sock_sys_fini();
		nni_random_sys_fini();
		nni_timer_sys_fini();
		nni_taskq_sys_fini();
		return (rv);
	}
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
	// XXX: We should make sure that underlying sockets and
	// file descriptors are closed.  Details TBD.
	nni_taskq_sys_fini();
	nni_tran_sys_fini();
	nni_pipe_sys_fini();
	nni_ep_sys_fini();
	nni_sock_sys_fini();
	nni_random_sys_fini();
	nni_timer_sys_fini();
	nni_plat_fini();
}
