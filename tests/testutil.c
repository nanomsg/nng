//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

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

#include "testutil.h"

#include <nng/supplemental/util/platform.h>

uint64_t
testutil_clock(void)
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
	    ((uint64_t)(tv.tv_sec) * 1000) + (uint64_t)(tv.tv_usec / 1000));
#endif

#ifdef _WIN32
#else
#include <fcntl.h>
#include <unistd.h>
#endif
}

bool
testutil_pollfd(int fd)
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

uint16_t
testutil_htons(uint16_t in)
{
#ifdef NNG_LITTLE_ENDIAN
	in = ((in >> 8u) & 0xffu) | ((in & 0xffu) << 8u);
#endif
	return (in);
}

uint32_t
testutil_htonl(uint32_t in)
{
#ifdef NNG_LITTLE_ENDIAN
	in = ((in >> 24u) & 0xffu) | ((in >> 8u) & 0xff00u) |
	    ((in << 8u) & 0xff0000u) | ((in << 24u) & 0xff000000u);
#endif
	return (in);
}

void
testutil_scratch_addr(const char *scheme, size_t sz, char *addr)
{
	if (strcmp(scheme, "inproc") == 0) {
		(void) snprintf(addr, sz, "%s://testutil%04x%04x%04x%04x",
		    scheme, nng_random(), nng_random(), nng_random(),
		    nng_random());
		return;
	}

	if ((strncmp(scheme, "tcp", 3) == 0) ||
	    (strncmp(scheme, "tls", 3) == 0)) {
		(void) snprintf(addr, sz, "%s://127.0.0.1:%u", scheme,
		    testutil_next_port());
		return;
	}

	if (strncmp(scheme, "ws", 2) == 0) {
		(void) snprintf(addr, sz,
		    "%s://127.0.0.1:%u/testutil%04x%04x%04x%04x", scheme,
		    testutil_next_port(), nng_random(), nng_random(),
		    nng_random(), nng_random());
		return;
	}

	if (strncmp(scheme, "ipc", 3) == 0) {
#ifdef _WIN32
		// Windows doesn't place IPC names in the filesystem.
		(void) snprintf(addr, sz, "%s://testutil%04x%04x%04x%04x",
		    scheme, nng_random(), nng_random(), nng_random(),
		    nng_random());
#else
		char *tmpdir;

		if (((tmpdir = getenv("TMPDIR")) == NULL) &&
		    ((tmpdir = getenv("TEMP")) == NULL) &&
		    ((tmpdir = getenv("TMP")) == NULL)) {
			tmpdir = "/tmp";
		}

		(void) snprintf(addr, sz, "%s://%s/testutil%04x%04x%04x%04x",
		    scheme, tmpdir, nng_random(), nng_random(), nng_random(),
		    nng_random());
		return;
#endif
	}

	// We should not be here.
	abort();
}

// testutil_next_port returns a "next" allocation port.
// Ports are chosen by starting from a random point within a
// range (normally 38000-40000, but other good places to choose
// might be 36000-37000, 42000-43000, 45000-47000, 48000-49000.
// These are non-ephemeral ports.  Successive calls to this function
// will return the next port in the range (wrapping).  This works even
// across process boundaries, as the range is tracked in a file named
// by $TEST_PORT_FILE.  The range of ports can be configured by using
// $TEST_PORT_RANGE (the range is specified as "lo:hi" where the actual
// port will be in the range [lo,hi).
uint16_t
testutil_next_port(void)
{
	char *   pfile;
	FILE *   f;
	uint16_t port;
	uint16_t base;
	uint16_t end;
	char *   str;
#ifdef _WIN32
	OVERLAPPED olp;
	HANDLE     h;
#endif

	pfile = getenv("TEST_PORT_FILE");
	if (pfile == NULL) {
		pfile = ".nng_ports";
	}
	if (((str = getenv("TEST_PORT_RANGE")) == NULL) ||
	    ((sscanf(str, "%hu:%hu", &base, &end)) != 1) ||
	    ((int) end - (int) base) < 1) {
		base = 38000;
		end  = 40000;
	}

	if (((f = fopen(pfile, "r+")) == NULL) &&
	    ((f = fopen(pfile, "w+")) == NULL)) {
		return (0);
	}
	(void) fseek(f, 0, SEEK_SET);

#ifdef _WIN32
	h = (HANDLE) _get_osfhandle(_fileno(f));

	// This contains the offset information for LockFileEx.
	ZeroMemory(&olp, sizeof(olp));

	if (LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD,
	        &olp) == FALSE) {
		fclose(f);
		return (0);
	}
#else
	if (lockf(fileno(f), 0, F_LOCK) != 0) {
		(void) fclose(f);
		return (0);
	}
#endif
	if (fscanf(f, "%hu", &port) != 1) {
		unsigned seed = (unsigned) time(NULL);

#ifdef _WIN32
		port = base + rand_s(&seed) % (end - base);
#else
		port = base + rand_r(&seed) % (end - base);
#endif
	}
	port++;
	if ((port < base) || (port >= (base + end))) {
		port = base;
	}

#ifdef _WIN32
	fseek(f, 0, SEEK_SET);
	SetEndOfFile(h);
	(void) fprintf(f, "%u", port);
	ZeroMemory(&olp, sizeof(olp));
	(void) UnlockFileEx(h, 0, MAXDWORD, MAXDWORD, &olp);
#else
	fseek(f, 0, SEEK_SET);
	(void) ftruncate(fileno(f), 0);

	(void) fprintf(f, "%u", port);
	(void) lockf(fileno(f), 0, F_ULOCK);

#endif
	(void) fclose(f);
	return (port);
}

void
testutil_sleep(int msec)
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

struct marriage_notice {
	nng_mtx *mx;
	nng_cv * cv;
	int      s1;
	int      s2;
	int      cnt1;
	int      cnt2;
	nng_pipe p1;
	nng_pipe p2;
};

static void
married(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	struct marriage_notice *notice = arg;
	(void) ev;

	nng_mtx_lock(notice->mx);
	if (nng_socket_id(nng_pipe_socket(p)) == notice->s1) {
		notice->cnt1++;
		notice->p1 = p;
	} else if (nng_socket_id(nng_pipe_socket(p)) == notice->s2) {
		notice->cnt2++;
		notice->p2 = p;
	}
	nng_cv_wake(notice->cv);
	nng_mtx_unlock(notice->mx);
}

int
testutil_marry(nng_socket s1, nng_socket s2)
{
	return (testutil_marry_ex(s1, s2, NULL, NULL, NULL));
}

int
testutil_marry_ex(
    nng_socket s1, nng_socket s2, const char *url, nng_pipe *p1, nng_pipe *p2)
{
	struct marriage_notice note;
	nng_time               timeout;
	int                    rv;
	char                   addr[32];

	if (url == NULL) {
		(void) snprintf(addr, sizeof(addr),
		    "inproc://marry%04x%04x%04x%04x", nng_random(),
		    nng_random(), nng_random(), nng_random());
		url = addr;
	}

	note.cnt1 = 0;
	note.cnt2 = 0;
	note.s1   = nng_socket_id(s1);
	note.s2   = nng_socket_id(s2);
	timeout   = nng_clock() + 1000; // 1 second

	if (((rv = nng_mtx_alloc(&note.mx)) != 0) ||
	    ((rv = nng_cv_alloc(&note.cv, note.mx)) != 0) ||
	    ((rv = nng_pipe_notify(
	          s1, NNG_PIPE_EV_ADD_POST, married, &note)) != 0) ||
	    ((rv = nng_pipe_notify(
	          s2, NNG_PIPE_EV_ADD_POST, married, &note)) != 0) ||
	    ((rv = nng_listen(s1, url, NULL, 0)) != 0) ||
	    ((rv = nng_dial(s2, url, NULL, 0)) != 0)) {
		goto done;
	}

	nng_mtx_lock(note.mx);
	while ((note.cnt1 == 0) || (note.cnt2 == 0)) {
		if ((rv = nng_cv_until(note.cv, timeout)) != 0) {
			break;
		}
	}
	nng_mtx_unlock(note.mx);
	if (p1 != NULL) {
		*p1 = note.p1;
	}
	if (p2 != NULL) {
		*p2 = note.p2;
	}

done:
	nng_pipe_notify(s1, NNG_PIPE_EV_ADD_POST, NULL, NULL);
	nng_pipe_notify(s2, NNG_PIPE_EV_ADD_POST, NULL, NULL);
	if (note.cv != NULL) {
		nng_cv_free(note.cv);
	}
	if (note.mx != NULL) {
		nng_mtx_free(note.mx);
	}
	return (rv);
}
