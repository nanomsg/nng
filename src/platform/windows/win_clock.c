//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_WINDOWS

nni_time
nni_plat_clock(void)
{
	// We are limited by the system clock, but that is ok.
	return (GetTickCount64()*1000);
}


void
nni_plat_usleep(nni_duration usec)
{
	Sleep((usec + 999) / 1000);
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_win_clock_not_used = 0;

#endif  // PLATFORM_WINDOWS
