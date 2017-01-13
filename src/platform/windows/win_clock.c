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
	LARGE_INTEGER freq;
	LARGE_INTEGER count;
	double rate;

	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&count);

	// convert to ticks per us
	rate = (double) freq.QuadPart / 1000000.0;

	return ((nni_time) (count.QuadPart / rate));
}


void
nni_plat_usleep(nni_duration usec)
{
	Sleep((usec + 999) / 1000);
}


#endif  // PLATFORM_WINDOWS
