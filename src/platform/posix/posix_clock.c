//
// Copyright 2022 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX clock stuff.
#include "core/nng_impl.h"
#include "platform/posix/posix_impl.h"

#ifdef NNG_PLATFORM_POSIX

#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

int
nni_time_get(uint64_t *sec, uint32_t *nsec)
{
	int rv;
#if defined(NNG_HAVE_TIMESPEC_GET)
	struct timespec ts;
	if ((rv = timespec_get(&ts, TIME_UTC)) == TIME_UTC) {
		*sec  = ts.tv_sec;
		*nsec = ts.tv_nsec;
		return (0);
	}
#elif defined(NNG_HAVE_CLOCK_GETTIME)
	struct timespec ts;
	if ((rv = clock_gettime(CLOCK_REALTIME, &ts)) == 0) {
		*sec  = ts.tv_sec;
		*nsec = ts.tv_nsec;
		return (0);
	}
#else
	struct timeval tv;
	if ((rv = gettimeofday(&tv, NULL)) == 0) {
		*sec  = tv.tv_sec;
		*nsec = tv.tv_usec * 1000;
		return (0);
	}
#endif
	return (nni_plat_errno(errno));
}

#if defined(NNG_HAVE_CLOCK_GETTIME) && !defined(NNG_USE_GETTIMEOFDAY)

// Use POSIX realtime stuff
nni_time
nni_clock(void)
{
	struct timespec ts;
	nni_time        msec;

	if (clock_gettime(NNG_USE_CLOCKID, &ts) != 0) {
		// This should never ever occur.
		nni_panic("clock_gettime failed: %s", strerror(errno));
	}

	msec = ts.tv_sec;
	msec *= 1000;
	msec += (ts.tv_nsec / 1000000);
	return (msec);
}

void
nni_msleep(nni_duration ms)
{
	struct timespec ts;

	ts.tv_sec  = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;

	// Do this in a loop, so that interrupts don't actually wake
	// us.
	while (ts.tv_sec || ts.tv_nsec) {
		if (nanosleep(&ts, &ts) == 0) {
			break;
		}
	}
}

#else // NNG_USE_GETTIMEOFDAY

// If you're here, its because you don't have a modern clock_gettime
// with monotonic clocks, or the necessary
// pthread_condattr_settclock().  In this case, you should be advised
// that *bad* things can happen if your system clock changes time while
// programs using this library are running. (Basically, timeouts can
// take longer or shorter, leading to either hangs or apparent spurious
// errors.  Eventually it should all sort itself out, but if you change
// the clock by a large amount you might wonder what the heck is
// happening until it does.)

#include <poll.h>
#include <pthread.h>
#include <sys/time.h>

nni_time
nni_clock(void)
{
	nni_time ms;

	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0) {
		nni_panic("gettimeofday failed: %s", strerror(errno));
	}

	ms = tv.tv_sec;
	ms *= 1000;
	ms += (tv.tv_usec / 1000);
	return (ms);
}

void
nni_msleep(nni_duration ms)
{
	// So probably there is no nanosleep.  We could in theory use
	// pthread condition variables, but that means doing memory
	// allocation, or forcing the use of pthreads where the
	// platform might be preferring the use of another threading
	// package. Additionally, use of pthreads means that we cannot
	// use relative times in a clock_settime safe manner. So we can
	// use poll() instead.
	struct pollfd pfd;
	nni_time      now;
	nni_time      expire;

	// Possibly we could pass NULL instead of pfd, but passing a
	// valid pointer ensures that if the system dereferences the
	// pointer it won't come back with EFAULT.
	pfd.fd     = -1;
	pfd.events = 0;

	now    = nni_clock();
	expire = now + ms;

	while (now < expire) {
		(void) poll(&pfd, 0, (int) (expire - now));
		now = nni_clock();
	}
}

#endif // NNG_USE_GETTIMEOFDAY

#endif // NNG_PLATFORM_POSIX
