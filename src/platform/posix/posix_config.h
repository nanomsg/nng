/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/*
 * The following adjustments to the platform may be defined.  These can
 * be defined in either platform/config.h or loaded in via external
 * defines using cmake.
 *
 * #define NNG_USE_GETTIMEOFDAY
 *	This macro is defined if you lack a working clock_gettime,
 *	nanosleep, or pthread_condattr_setclock.  In this case the
 *	library uses the system clock for relative sleeps, timers, etc.
 *	This can be dangerous if the system clock is changed, so only
 *	use this if you have no other choice.  If it appears that
 *	the system lacks clock_gettime, then it will choose this automatically.
 *	This value may be ignored on platforms that don't use POSIX clocks.
 *
 * #define NNG_USE_CLOCKID
 *	This macro may be defined to a different clock id (see 
 *	clock_gettime()).  By default we use CLOCK_MONOTONIC if it exists,
 *	or CLOCK_REALTIME otherwise.  This is ignored if NNG_USE_GETTIMEOFDAY
 *	is defined.  Platforms that don't use POSIX clocks will probably
 *	ignore any setting here.
 *
 * #define NNG_HAVE_BACKTRACE
 *	If your system has a working backtrace(), and backtrace_symbols(),
 *	along with <execinfo.h>, you can define this to get richer backtrace
 *	information for debugging.
 */

#include <time.h>

#ifndef	CLOCK_REALTIME
#define	NNG_USE_GETTIMEOFDAY
#elif !defined(NNG_USE_CLOCKID)
#ifdef	CLOCK_MONOTONIC
#define	NNG_USE_CLOCKID	CLOCK_MONOTONIC
#else
#define	NNG_USE_CLOCKID	CLOCK_REALTIME
#endif
#endif	/* CLOCK_REALTIME */
