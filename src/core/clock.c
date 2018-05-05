//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

nni_time
nni_clock(void)
{
	return (nni_plat_clock());
}

void
nni_msleep(nni_duration msec)
{
	nni_plat_sleep(msec);
}
