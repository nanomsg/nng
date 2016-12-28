//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// The following adjustments to the platform may be defined.  These can
// be defined in either platform/config.h or loaded in via external
// defines using cmake.
//
// #define NNG_USE_GETTIMEOFDAY
//	This macro is defined if you lack a working clock_gettime,
//	nanosleep, or pthread_condattr_setclock.  In this case the
//	library uses the system clock for relative sleeps, timers, etc.
//	This can be dangerous if the system clock is changed, so only
//	use this if you have no other choice.  If it appears that
//	the system lacks clock_gettime, then it will choose this automatically.
//	This value may be ignored on platforms that don't use POSIX clocks.
//
// #define NNG_USE_CLOCKID
//	This macro may be defined to a different clock id (see
//	clock_gettime()).  By default we use CLOCK_MONOTONIC if it exists,
//	or CLOCK_REALTIME otherwise.  This is ignored if NNG_USE_GETTIMEOFDAY
//	is defined.  Platforms that don't use POSIX clocks will probably
//	ignore any setting here.
//
// #define NNG_HAVE_ARC4RANDOM
//	This indicates that the platform has the superior arc4random function
//	for getting entropy.
//
// #define NNG_HAVE_BACKTRACE
//	If your system has a working backtrace(), and backtrace_symbols(),
//	along with <execinfo.h>, you can define this to get richer backtrace
//	information for debugging.

#include <time.h>

// MacOS X used to lack CLOCK_MONOTONIC.  Now it has it, but its
// buggy, condition variables set to use it wake early.
#ifdef __APPLE__
#define NNG_USE_CLOCKID		CLOCK_REALTIME
#endif // __APPLE__

#define NNG_USE_CLOCKID		CLOCK_REALTIME
#ifndef CLOCK_REALTIME
#define NNG_USE_GETTIMEOFDAY
#elif !defined(NNG_USE_CLOCKID)
#define NNG_USE_CLOCKID		CLOCK_MONOTONIC
#else
#define NNG_USE_CLOCKID		CLOCK_REALTIME
#endif  // CLOCK_REALTIME
