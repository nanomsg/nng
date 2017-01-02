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
	nni_tran_fini();
	nni_plat_fini();
}
