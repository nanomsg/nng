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

int
nosocket(nng_socket *s)
{
	ConveySkip("Protocol unconfigured");
	return (NNG_ENOTSUP);
}

#ifndef NNG_HAVE_REQ0
#define nng_req0_open nosocket
#endif

#ifndef NNG_HAVE_REP0
#define nng_rep0_open nosocket
#endif

#ifndef NNG_HAVE_PUB0
#define nng_pub0_open nosocket
#endif

#ifndef NNG_HAVE_SUB0
#define nng_sub0_open nosocket
#endif

#ifndef NNG_HAVE_PAIR0
#define nng_pair0_open nosocket
#endif

#ifndef NNG_HAVE_PAIR1
#define nng_pair1_open nosocket
#endif

#ifndef NNG_HAVE_PUSH0
#define nng_push0_open nosocket
#endif

#ifndef NNG_HAVE_PULL0
#define nng_pull0_open nosocket
#endif

#ifndef NNG_HAVE_SURVEYOR0
#define nng_surveyor0_open nosocket
#endif

#ifndef NNG_HAVE_RESPONDENT0
#define nng_respondent0_open nosocket
#endif

#endif // STUBS_H
