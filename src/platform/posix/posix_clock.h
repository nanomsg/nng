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
 * This is more of a direct #include of a .c rather than .h file.
 * But having it be a .h makes compiler rules work out properly.  Do
 * not include this more than once into your program, or you will
 * get multiple symbols defined.
 */

/*
 * POSIX clock stuff.
 */

#include <time.h>
#include <errno.h>
#include <string.h>

#ifndef	NNG_USE_GETTIMEOFDAY

/*
 * Use POSIX realtime stuff.
 */

uint64_t
nni_clock(void)
{
	struct timespec	ts;
	uint64_t	usec;

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
nni_usleep(uint64_t usec)
{
	struct timespec ts;

	ts.tv_sec = usec / 1000000;
	ts.tv_nsec = (usec % 1000000) * 1000;

	/* Do this in a loop, so that interrupts don't actually wake us. */
	while (ts.tv_sec || ts.tv_nsec) {
		(void) nanosleep(&ts, &ts);
	}
}

#else	/* NNG_USE_GETTIMEOFDAY */

/*
 * If you're here, its because you don't have a modern clock_gettime with
 * monotonic clocks, or the necessary pthread_condattr_settclock().  In
 * this case, you should be advised that *bad* things can happen if your
 * system clock changes time while programs using this library are running.
 * (Basically, timeouts can take longer or shorter, leading to either hangs
 * or apparent spurious errors.  Eventually it should all sort itself out,
 * but if you change the clock by a large amount you might wonder what the
 * heck is happening until it does.)
 */

#include <pthread.h>
#include <sys/time.h>

uint64_t
nni_clock(void)
{
	uint64_t usec;

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
nni_usleep(uint64_t usec)
{
	/*
	 * So probably there is no nanosleep.  We could in theory use
	 * pthread condition variables, but that means doing memory
	 * allocation, or forcing the use of pthreads where the platform
	 * might be preferring the use of another threading package.
	 * Additionally, use of pthreads means that we cannot use
	 * relative times in a clock_settime safe manner.
	 * So we can use poll() instead, which is rather coarse, but
	 * pretty much guaranteed to work.
	 */
	struct pollfd pfd;
	uint64_t now;
	uint64_t expire;

	/*
	 * Possibly we could pass NULL instead of pfd, but passing a valid
	 * pointer ensures that if the system dereferences the pointer it
	 * won't come back with EFAULT.
	 */
	pfd.fd = -1;
	pfd.events = 0;

 	now = nni_clock();
	expire = now + usec;

	while (now < expire) {
		/*
		 * In theory we could round up to a whole number of msec,
		 * but under the covers poll already does some rounding up,
		 * and the loop above guarantees that we will not bail out
		 * early.  So this gives us a better chance to avoid adding
		 * nearly an extra unneeded millisecond to the wait.
		 */
		(void) poll(&pfd, 0, (int)((expire - now) / 1000));
 		now = nni_clock();
	}
}

#endif	/* NNG_USE_GETTIMEOFDAY */
