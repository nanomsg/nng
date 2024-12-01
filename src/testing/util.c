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
#include <stdbool.h>
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

#include <nuts.h>

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

bool
nuts_has_ipv6(void)
{
	nng_sockaddr sa = { 0 };
	nng_udp     *u;
	int          rv;

	sa.s_in6.sa_family = NNG_AF_INET6;
	sa.s_in6.sa_port   = 0;
	memset(sa.s_in6.sa_addr, 0, 16);
	sa.s_in6.sa_addr[15] = 1;

	rv = nng_udp_open(&u, &sa);
	if (rv == 0) {
		nng_udp_close(u);
	}
	return (rv == 0 ? 1 : 0);
}

void
nuts_set_logger(int level)
{
	printf("\n"); // force a new line
	nng_log_set_logger(nng_stderr_logger);
	nng_log_set_level(level);
}

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
	acutest_message_color_(color, "%s: %s: %s", lstr, msgid, msg);
}

void
nuts_tran_conn_refused(const char *scheme)
{
	nng_socket  s = NNG_SOCKET_INITIALIZER;
	nng_dialer  d = NNG_DIALER_INITIALIZER;
	const char *addr;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s);
	NUTS_FAIL(nng_dial(s, addr, &d, 0), NNG_ECONNREFUSED);
	NUTS_TRUE(nng_dialer_id(d) < 0);
	NUTS_CLOSE(s);
}

void
nuts_tran_dialer_cancel(const char *scheme)
{
	nng_socket  s = NNG_SOCKET_INITIALIZER;
	nng_dialer  d = NNG_DIALER_INITIALIZER;
	const char *addr;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s);
	NUTS_PASS(nng_dial(s, addr, &d, NNG_FLAG_NONBLOCK));
	NUTS_TRUE(nng_dialer_id(d) > 0);
	NUTS_PASS(nng_dialer_close(d));
	NUTS_CLOSE(s);
}

void
nuts_tran_dialer_closed(const char *scheme)
{
	nng_socket  s = NNG_SOCKET_INITIALIZER;
	nng_dialer  d = NNG_DIALER_INITIALIZER;
	const char *addr;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));
	NUTS_TRUE(nng_dialer_id(d) > 0);
	NUTS_PASS(nng_dialer_close(d));
	NUTS_FAIL(nng_dialer_start(d, 0), NNG_ENOENT);
	NUTS_CLOSE(s);
}

void
nuts_tran_duplicate_listen(const char *scheme)
{
	nng_socket   s  = NNG_SOCKET_INITIALIZER;
	nng_listener l1 = NNG_LISTENER_INITIALIZER;
	nng_listener l2 = NNG_LISTENER_INITIALIZER;
	const char  *addr;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s);
	NUTS_PASS(nng_listen(s, addr, &l1, 0));
	NUTS_FAIL(nng_listen(s, addr, &l2, 0), NNG_EADDRINUSE);
	NUTS_TRUE(nng_listener_id(l1) > 0);
	NUTS_TRUE(nng_listener_id(l2) < 0);
	NUTS_CLOSE(s);
}

void
nuts_tran_listener_cancel(const char *scheme)
{
	nng_socket   s = NNG_SOCKET_INITIALIZER;
	nng_listener l = NNG_LISTENER_INITIALIZER;
	const char  *addr;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s);
	NUTS_PASS(nng_listen(s, addr, &l, 0));
	NUTS_TRUE(nng_listener_id(l) > 0);
	NUTS_PASS(nng_listener_close(l));
	NUTS_CLOSE(s);
}

void
nuts_tran_listener_closed(const char *scheme)
{
	nng_socket   s = NNG_SOCKET_INITIALIZER;
	nng_listener l = NNG_LISTENER_INITIALIZER;
	const char  *addr;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s);
	NUTS_PASS(nng_listener_create(&l, s, addr));
	NUTS_TRUE(nng_listener_id(l) > 0);
	NUTS_PASS(nng_listener_close(l));
	NUTS_FAIL(nng_listener_start(l, 0), NNG_ENOENT);
	NUTS_CLOSE(s);
}

void
nuts_tran_listen_accept(const char *scheme)
{
	nng_socket   s1 = NNG_SOCKET_INITIALIZER;
	nng_socket   s2 = NNG_SOCKET_INITIALIZER;
	nng_listener l1 = NNG_LISTENER_INITIALIZER;
	nng_dialer   d1 = NNG_LISTENER_INITIALIZER;
	nng_dialer   d2 = NNG_LISTENER_INITIALIZER;
	const char  *addr;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_listen(s1, addr, &l1, 0));
	NUTS_PASS(nng_dial(s2, addr, &d1, 0));
	NUTS_PASS(nng_dial(s2, addr, &d2, 0));
	NUTS_TRUE(nng_listener_id(l1) > 0);
	NUTS_TRUE(nng_dialer_id(d1) > 0);
	NUTS_TRUE(nng_dialer_id(d2) > 0);
	NUTS_TRUE(nng_dialer_id(d1) != nng_dialer_id(d2));
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
nuts_tran_exchange(const char *scheme)
{
	nng_socket   s1 = NNG_SOCKET_INITIALIZER;
	nng_socket   s2 = NNG_SOCKET_INITIALIZER;
	nng_listener l1 = NNG_LISTENER_INITIALIZER;
	nng_dialer   d1 = NNG_LISTENER_INITIALIZER;
	const char  *addr;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_listen(s1, addr, &l1, 0));
	NUTS_PASS(nng_dial(s2, addr, &d1, 0));
	NUTS_TRUE(nng_listener_id(l1) > 0);
	NUTS_TRUE(nng_dialer_id(d1) > 0);
	for (int i = 0; i < 5; i++) {
		NUTS_SEND(s1, "ping");
		NUTS_RECV(s2, "ping");
		NUTS_SEND(s2, "acknowledge");
		NUTS_RECV(s1, "acknowledge");
	}
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
nuts_tran_pipe_id(const char *scheme)
{
	nng_socket   s1 = NNG_SOCKET_INITIALIZER;
	nng_socket   s2 = NNG_SOCKET_INITIALIZER;
	nng_listener l1 = NNG_LISTENER_INITIALIZER;
	nng_dialer   d1 = NNG_LISTENER_INITIALIZER;
	const char  *addr;
	nng_msg     *msg;
	nng_pipe     p1;
	nng_pipe     p2;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_listen(s1, addr, &l1, 0));
	NUTS_PASS(nng_dial(s2, addr, &d1, 0));
	NUTS_TRUE(nng_listener_id(l1) > 0);
	NUTS_TRUE(nng_dialer_id(d1) > 0);
	NUTS_SEND(s1, "ping");
	NUTS_PASS(nng_recvmsg(s2, &msg, 0));
	NUTS_MATCH(nng_msg_body(msg), "ping");
	p1 = nng_msg_get_pipe(msg);
	nng_msg_free(msg);
	NUTS_TRUE(nng_pipe_id(p1) > 0);
	NUTS_SEND(s2, "acknowledge");
	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	NUTS_MATCH(nng_msg_body(msg), "acknowledge");
	p2 = nng_msg_get_pipe(msg);
	NUTS_TRUE(nng_pipe_id(p2) > 0);
	nng_msg_free(msg);
	NUTS_TRUE(nng_pipe_id(p1) != nng_pipe_id(p2));
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
nuts_tran_huge_msg(const char *scheme, size_t size)
{
	nng_socket   s1 = NNG_SOCKET_INITIALIZER;
	nng_socket   s2 = NNG_SOCKET_INITIALIZER;
	nng_listener l1 = NNG_LISTENER_INITIALIZER;
	nng_dialer   d1 = NNG_LISTENER_INITIALIZER;
	const char  *addr;
	char        *buf;
	nng_msg     *msg;

	buf = nng_alloc(size);

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 5000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 5000));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 5000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 5000));
	NUTS_PASS(nng_listen(s1, addr, &l1, 0));
	NUTS_PASS(nng_dial(s2, addr, &d1, 0));
	NUTS_TRUE(nng_listener_id(l1) > 0);
	NUTS_TRUE(nng_dialer_id(d1) > 0);
	for (int i = 0; i < 5; i++) {
		for (size_t j = 0; j < size; j++) {
			buf[j] = nng_random() & 0xff;
		}
		NUTS_PASS(nng_send(s1, buf, size, 0));
		NUTS_PASS(nng_recvmsg(s2, &msg, 0));
		NUTS_TRUE(nng_msg_len(msg) == size);
		NUTS_TRUE(memcmp(nng_msg_body(msg), buf, size) == 0);
		nng_msg_free(msg);
		NUTS_PASS(nng_send(s2, buf, size, 0));
		NUTS_PASS(nng_recvmsg(s1, &msg, 0));
		NUTS_TRUE(nng_msg_len(msg) == size);
		NUTS_TRUE(memcmp(nng_msg_body(msg), buf, size) == 0);
		nng_msg_free(msg);
	}
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	nng_free(buf, size);
}

void
nuts_tran_msg_props(const char *scheme, void (*check)(nng_msg *))
{
	nng_socket   s1 = NNG_SOCKET_INITIALIZER;
	nng_socket   s2 = NNG_SOCKET_INITIALIZER;
	nng_listener l1 = NNG_LISTENER_INITIALIZER;
	nng_dialer   d1 = NNG_LISTENER_INITIALIZER;
	const char  *addr;
	nng_msg     *msg;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	NUTS_ADDR(addr, scheme);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_listen(s1, addr, &l1, 0));
	NUTS_PASS(nng_dial(s2, addr, &d1, 0));
	NUTS_TRUE(nng_listener_id(l1) > 0);
	NUTS_TRUE(nng_dialer_id(d1) > 0);
	NUTS_SEND(s1, "ping");
	NUTS_PASS(nng_recvmsg(s2, &msg, 0));
	NUTS_MATCH(nng_msg_body(msg), "ping");
	check(msg);
	nng_msg_free(msg);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
nuts_tran_perf(const char *scheme)
{
	nng_socket  s1;
	nng_socket  s2;
	const char *addr;
	nng_msg    *msg;

	NUTS_SKIP_IF_IPV6_NEEDED_AND_ABSENT(scheme);
	nuts_set_logger(NNG_LOG_NOTICE);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_ADDR(addr, scheme);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 100));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 100));
	NUTS_MARRY_EX(s1, s2, addr, NULL, NULL);
	NUTS_PASS(nng_msg_alloc(&msg, 64));
	nng_log_notice(scheme, "Exchanging 64 byte messages for 10 seconds");
	nng_time     now = nng_clock();
	nng_time     end = now + 10000; // ten seconds
	nng_duration delta;
	int          rv;
	int          num = 0;

	// count round trips for 10 seconds
	while (nng_clock() < end) {
		if ((rv = nng_sendmsg(s1, msg, 0)) != 0) {
			NUTS_PASS(rv);
			NUTS_MSG("nng_sendmsg failed");
			break;
		}
		if ((rv = nng_recvmsg(s2, &msg, 0)) != 0) {
			NUTS_PASS(rv);
			NUTS_MSG("nng_recvmsg failed");
			break;
		}
		num++;
	}
	delta = (nng_clock() - now);
	nng_msg_free(msg);

	// now count the cost of the time collection
	now = nng_clock();
	for (int i = 0; i < num; i++) {
		end = nng_clock();
		if (end < now) {
			NUTS_ASSERT(end >= now);
		}
	}
	NUTS_ASSERT(end >= now);
	NUTS_ASSERT(end - now < 10000);
	// remove the cost of timing
	delta -= (end - now);
	nng_log_notice(scheme,
	    "Did %u roundtrips in %0.2f seconds (%0.3f msg/sec)", num,
	    delta / 1000.0, (float) num / (delta / 1000.0));
	nng_log_notice(scheme, "RTT %0.3f ms", (float) delta / (float) num);
	nng_log_notice(scheme, "Timing overhead %0.3f ms, %0.3f us/msg",
	    (float) (end - now), (end - now) * 1000.0 / (float) num);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}
