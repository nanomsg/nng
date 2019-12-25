//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef STUBS_H
#define STUBS_H

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
// order counts
#include <mswsock.h>
#define PLATFD SOCKET
#define poll WSAPoll
#else
#include <poll.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#define PLATFD int
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
	return (
	    ((uint64_t)(tv.tv_sec) * 1000) + (uint64_t)(tv.tv_usec / 1000));
#endif
}

bool
fdready(int fd)
{
	struct pollfd pfd;
	pfd.fd      = (PLATFD) fd;
	pfd.events  = POLLRDNORM;
	pfd.revents = 0;

	switch (poll(&pfd, 1, 0)) {
	case 0:
		return (false);
	case 1:
		return (true);
	default:
#ifdef CONVEY_H
		ConveyError("BAD POLL RETURN!");
#elif defined(TEST_CHECK)
		TEST_ASSERT(0);
#endif
		return (false);
	}
}

uint16_t
test_htons(uint16_t in)
{
#ifdef NNG_LITTLE_ENDIAN
	in = ((in >> 8) & 0xff) | ((in & 0xff) << 8);
#endif
	return (in);
}

#endif // STUBS_H
