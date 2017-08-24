//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include <stdio.h>
#include <stdlib.h>

static int
nni_init_helper(void)
{
	int rv;

	if (((rv = nni_taskq_sys_init()) != 0) ||
	    ((rv = nni_timer_sys_init()) != 0) ||
	    ((rv = nni_aio_sys_init()) != 0) ||
	    ((rv = nni_random_sys_init()) != 0) ||
	    ((rv = nni_option_sys_init()) != 0) ||
	    ((rv = nni_sock_sys_init()) != 0) ||
	    ((rv = nni_ep_sys_init()) != 0) ||
	    ((rv = nni_pipe_sys_init()) != 0) ||
	    ((rv = nni_proto_sys_init()) != 0) ||
	    ((rv = nni_tran_sys_init()) != 0)) {
		nni_fini();
	}
	return (rv);
}

int
nni_init(void)
{
	return (nni_plat_init(nni_init_helper));
}

void
nni_fini(void)
{
	nni_tran_sys_fini();
	nni_proto_sys_fini();
	nni_pipe_sys_fini();
	nni_ep_sys_fini();
	nni_sock_sys_fini();
	nni_option_sys_fini();
	nni_random_sys_fini();
	nni_aio_sys_fini();
	nni_timer_sys_fini();
	nni_taskq_sys_fini();
	nni_plat_fini();
}
