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
nni_plat_usleep(nni_duration dur)
{
	uint64_t exp;


	// Convert duration to msec, rounding up.
	dur += 999;
	dur /= 1000;

	exp = (uint64_t) GetTickCount64() + dur;

	// Sleep() would be our preferred API, if it didn't have a nasty
	// feature where it rounds *down*.  We always want to sleep *at
	// least* the requested amount of time, and never ever less.
	// If we wind up sleeping less, then we will sleep(1) in the hope
	// of waiting until the next clock tick.

	Sleep((DWORD) dur);
	while ((uint64_t) GetTickCount64() < exp) {
		Sleep(1);
	}
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_win_clock_not_used = 0;

#endif  // PLATFORM_WINDOWS
