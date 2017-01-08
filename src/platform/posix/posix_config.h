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
// #define NNG_HAVE_BACKTRACE
//	If your system has a working backtrace(), and backtrace_symbols(),
//	along with <execinfo.h>, you can define this to get richer backtrace
//	information for debugging.
//
// #define NNG_USE_GETRANDOM
// #define NNG_USE_GETENTROPY
// #define NNG_USE_ARC4RANDOM
// #define NNG_USE_DEVURANDOM
//	Thesse are options for obtaining entropy to seed the pRNG.
//	All known modern UNIX variants can support NNG_USE_DEVURANDOM,
//	but the other options are better still, but not portable.

#include <time.h>

// These are things about systems we know about.
#ifdef __APPLE__
// MacOS X used to lack CLOCK_MONOTONIC.  Now it has it, but its
// buggy, condition variables set to use it wake early.
#define NNG_USE_CLOCKID		CLOCK_REALTIME
// macOS 10.12 has getentropy(), but arc4random() is good enough
// and works on older releases.
#define NNG_USE_ARC4RANDOM	1
#endif // __APPLE__

// It should never hurt to use DEVURANDOM, since if the device does not
// exist then we won't open it.  (Provided: it would be bad if the device
// exists but has somehow very very different semantics.  We don't know
// of any such concerns.)  This won't be used if any of the other options
// are defined and work.
#define NNG_USE_DEVURANDOM	1

#define NNG_USE_CLOCKID		CLOCK_REALTIME
#ifndef CLOCK_REALTIME
#define NNG_USE_GETTIMEOFDAY
#elif !defined(NNG_USE_CLOCKID)
#define NNG_USE_CLOCKID		CLOCK_MONOTONIC
#else
#define NNG_USE_CLOCKID		CLOCK_REALTIME
#endif  // CLOCK_REALTIME
