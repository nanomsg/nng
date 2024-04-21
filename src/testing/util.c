//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#define TEST_NO_MAIN

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
// order counts
#include <mswsock.h>
#define poll WSAPoll
#include <io.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(_WIN32) && !defined(CLOCK_MONOTONIC)
#include <poll.h>
#endif

#include "nuts.h"

uint64_t
nuts_clock(void)
{
#ifdef _WIN32
	return (GetTickCount64());
#elif defined(CLOCK_MONTONIC)
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t val;

	val = ts.tv_sec;
	val *= 1000;
	val += ts.tv_nsec / 1000000;
	return (val);
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
	    ((uint64_t) (tv.tv_sec) * 1000) + (uint64_t) (tv.tv_usec / 1000));
#endif

#ifdef _WIN32
#else
#include <fcntl.h>
#include <unistd.h>
#endif
}

bool
nuts_poll_fd(int fd)
{
#ifdef _WIN32
	struct pollfd pfd;
	pfd.fd      = (SOCKET) fd;
	pfd.events  = POLLRDNORM;
	pfd.revents = 0;

	switch (WSAPoll(&pfd, 1, 0)) {
	case 0:
		return (false);
	case 1:
		return (true);
	}
#else
	struct pollfd pfd;

	pfd.fd      = fd;
	pfd.events  = POLLRDNORM;
	pfd.revents = 0;

	switch (poll(&pfd, 1, 0)) {
	case 0:
		return (false);
	case 1:
		return (true);
	}
#endif
	return (false);
}

static bool
is_little_endian(void)
{
	uint16_t num = 0x1;
	uint8_t *ptr = (uint8_t *) (void *) (&num);
	return (ptr[0] == 1);
}

uint16_t
nuts_be16(uint16_t in)
{
	if (is_little_endian()) {
		in = ((in / 0x100) + ((in % 0x100) * 0x100));
	}
	return (in);
}

uint32_t
nuts_be32(uint32_t in)
{
	if (is_little_endian()) {
		in = ((in >> 24u) & 0xffu) | ((in >> 8u) & 0xff00u) |
		    ((in << 8u) & 0xff0000u) | ((in << 24u) & 0xff000000u);
	}
	return (in);
}

void
nuts_sleep(int msec)
{
#ifdef _WIN32
	Sleep(msec);
#elif defined(CLOCK_MONOTONIC)
	struct timespec ts;

	ts.tv_sec  = msec / 1000;
	ts.tv_nsec = (msec % 1000) * 1000000;

	// Do this in a loop, so that interrupts don't actually wake us.
	while (ts.tv_sec || ts.tv_nsec) {
		if (nanosleep(&ts, &ts) == 0) {
			break;
		}
	}
#else
	poll(NULL, 0, msec);
#endif
}

#define NUTS_COLOR_DEFAULT_ 0
#define NUTS_COLOR_GREEN_ 1
#define NUTS_COLOR_RED_ 2
#define NUTS_COLOR_DEFAULT_INTENSIVE_ 3
#define NUTS_COLOR_GREEN_INTENSIVE_ 4
#define NUTS_COLOR_RED_INTENSIVE_ 5

void
nuts_logger(nng_log_level level, nng_log_facility fac, const char *msgid,
    const char *msg)
{
	(void) fac;
	char *lstr;
	int   color;
	switch (level) {
	case NNG_LOG_DEBUG:
		lstr  = "DEBUG";
		color = NUTS_COLOR_DEFAULT_;
		break;
	case NNG_LOG_INFO:
		lstr  = "INFO";
		color = NUTS_COLOR_DEFAULT_;
		break;
	case NNG_LOG_NOTICE:
		lstr  = "NOTICE";
		color = NUTS_COLOR_DEFAULT_INTENSIVE_;
		break;
	case NNG_LOG_WARN:
		lstr  = "WARNING";
		color = NUTS_COLOR_RED_;
		break;
	case NNG_LOG_ERR:
		lstr  = "ERROR";
		color = NUTS_COLOR_RED_INTENSIVE_;
		break;
	default:
		lstr  = "LEVEL UNKNOWN";
		color = NUTS_COLOR_DEFAULT_;
		break;
	}
	test_message_color_(color, "%s: %s: %s", lstr, msgid, msg);
}
