//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX clock stuff.
#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX

#include <errno.h>
#include <string.h>
#include <time.h>

#ifndef NNG_USE_GETTIMEOFDAY

// Use POSIX realtime stuff
nni_time
nni_plat_clock(void)
{
	struct timespec ts;
	nni_time        usec;

	if (clock_gettime(NNG_USE_CLOCKID, &ts) != 0) {
		/* This should never ever occur. */
		nni_panic("clock_gettime failed: %s", strerror(errno));
	}

	usec = ts.tv_sec;
	usec *= 1000000;
	usec += (ts.tv_nsec / 1000);
	return (usec);
}

void
nni_plat_usleep(nni_duration usec)
{
	struct timespec ts;

	ts.tv_sec  = usec / 1000000;
	ts.tv_nsec = (usec % 1000000) * 1000;

	/* Do this in a loop, so that interrupts don't actually wake us. */
	while (ts.tv_sec || ts.tv_nsec) {
		if (nanosleep(&ts, &ts) == 0) {
			break;
		}
	}
}

#else // NNG_USE_GETTIMEOFDAY

// If you're here, its because you don't have a modern clock_gettime with
// monotonic clocks, or the necessary pthread_condattr_settclock().  In
// this case, you should be advised that *bad* things can happen if your
// system clock changes time while programs using this library are running.
// (Basically, timeouts can take longer or shorter, leading to either hangs
// or apparent spurious errors.  Eventually it should all sort itself out,
// but if you change the clock by a large amount you might wonder what the
// heck is happening until it does.)

#include <poll.h>
#include <pthread.h>
#include <sys/time.h>

nni_time
nni_plat_clock(void)
{
	nni_time usec;

	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0) {
		nni_panic("gettimeofday failed: %s", strerror(errno));
	}

	usec = tv.tv_sec;
	usec *= 1000000;
	usec += tv.tv_usec;
	return (usec);
}

void
nni_plat_usleep(nni_duration usec)
{
	// So probably there is no nanosleep.  We could in theory use
	// pthread condition variables, but that means doing memory
	// allocation, or forcing the use of pthreads where the platform
	// might be preferring the use of another threading package.
	// Additionally, use of pthreads means that we cannot use
	// relative times in a clock_settime safe manner.
	// So we can use poll() instead, which is rather coarse, but
	// pretty much guaranteed to work.
	struct pollfd pfd;
	nni_time      now;
	nni_time      expire;

	// Possibly we could pass NULL instead of pfd, but passing a valid
	// pointer ensures that if the system dereferences the pointer it
	// won't come back with EFAULT.
	pfd.fd     = -1;
	pfd.events = 0;

	now    = nni_clock();
	expire = now + usec;

	while (now < expire) {
		// In theory we could round up to a whole number of msec,
		// but under the covers poll already does some rounding up,
		// and the loop above guarantees that we will not bail out
		// early.  So this gives us a better chance to avoid adding
		// nearly an extra unneeded millisecond to the wait.
		(void) poll(&pfd, 0, (int) ((expire - now) / 1000));
		now = nni_clock();
	}
}

#endif // NNG_USE_GETTIMEOFDAY

#endif // NNG_PLATFORM_POSIX
