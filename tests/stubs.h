//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef STUBS_H
#define STUBS_H

#ifdef _WIN32
#include <windows.h>
#else
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#endif

// Stub handlers for some common things.

uint64_t
getms(void)
{
#ifdef _WIN32
	return (GetTickCount64());
#else
	static time_t  epoch;
	struct timeval tv;

	if (epoch == 0) {
		epoch = time(NULL);
	}
	gettimeofday(&tv, NULL);

	if (tv.tv_sec < epoch) {
		// Broken clock.
		// This will force all other timing tests to fail
		return (0);
	}
	tv.tv_sec -= epoch;
	return (((uint64_t)(tv.tv_sec) * 1000) + (tv.tv_usec / 1000));
#endif
}

#endif // STUBS_H
