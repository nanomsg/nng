//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// NUTS - NNG Unit Test Support
//
// This is the NNG testing support library.  It is used in the NNG
// project to support the various unit tests.  It should not be used
// in other projects, and no guarantees are made about interface
// stability, etc.

#ifndef NNG_TESTING_NUTS_H
#define NNG_TESTING_NUTS_H

#include <nng/nng.h>
extern void nuts_logger(
    nng_log_level, nng_log_facility, const char *, const char *);

// Call nng_fini during test finalization -- this avoids leak warnings.
extern void nng_fini(void);
#define TEST_FINI nng_fini()
#define TEST_INIT                                 \
	do {                                      \
		nng_log_set_logger(nuts_logger);  \
		nng_log_set_level(NNG_LOG_DEBUG); \
	} while (0)
#include "acutest.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// The following headers are provided for test code convenience.
#include <nng/protocol/bus0/bus.h>
#include <nng/protocol/pair0/pair.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/pubsub0/sub.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/transport/ws/websocket.h>
#include <supplemental/sha1/sha1.h>

#ifdef __cplusplus
extern "C" {
#endif

// nuts_clock returns the current time in milliseconds.
// The reference clock may be any point in the past (typically since
// the program started running.)
extern uint64_t nuts_clock(void);

// nuts_poll_fd tests if the given file descriptor polls as readable.
extern bool nuts_poll_fd(int);

// nuts_be16 converts native and big-endian words.
extern uint16_t nuts_be16(uint16_t);

// nuts_be32 converts native and big-endian double-words.
extern uint32_t nuts_be32(uint32_t);

// nuts_sleep sleeps the specified number of milliseconds.
extern void nuts_sleep(int);

// nuts_next_port returns a new port number (presumably unique)
extern uint16_t nuts_next_port(void);

// nuts_scratch_addr makes a scratch address for the given scheme.
// The address buffer must be supplied, and the size should be at least
// 64 bytes to ensure no truncation occurs.
extern void nuts_scratch_addr(const char *, size_t, char *);

// nuts_marry connects two sockets using inproc.  It uses socket
// pipe hooks to ensure that it does not return before both sockets
// are fully connected.
extern int nuts_marry(nng_socket, nng_socket);

// nuts_marry_ex is like nuts_marry, but returns the pipes that
// were connected, and includes an optional URL.  The pipe pointers and the
// URL may be NULL if not needed.  If a port number is part of the URL
// and is zero (i.e. if the URL contains :0) then listen is done first,
// and the actual bound port will be used for the client.
extern int nuts_marry_ex(
    nng_socket, nng_socket, const char *, nng_pipe *, nng_pipe *);

// nuts_stream_send_start and nuts_stream_recv_start are used
// to initiate transfers asynchronously.  They return a token which can
// be used with nuts_stream_wait, which will return the result of
// the operation (0 on success, an NNG error number otherwise.)
extern void *nuts_stream_send_start(nng_stream *, void *, size_t);
extern void *nuts_stream_recv_start(nng_stream *, void *, size_t);
extern int   nuts_stream_wait(void *);

// These are TLS certificates.  The client and server are signed with the
// root.  The server uses CN 127.0.0.1.  Other details are bogus, but
// designed to prevent accidental use elsewhere.
extern const char *nuts_server_key;
extern const char *nuts_server_crt;
extern const char *nuts_client_key;
extern const char *nuts_client_crt;
extern const char *nuts_garbled_crt;

// NUTS_SUCCESS tests for NNG success.  It reports the failure if it
// did not.
#define NUTS_PASS(cond)                                              \
	do {                                                         \
		int result_ = (cond);                                \
		TEST_CHECK_(result_ == 0, "%s succeeds", #cond);     \
		TEST_MSG("%s: expected success, got %s (%d)", #cond, \
		    nng_strerror(result_), result_);                 \
	} while (0)

// NUTS_ERROR tests for a specific NNG error code.
#define NUTS_FAIL(cond, expect)                                             \
	do {                                                                \
		int result_ = (cond);                                       \
		TEST_CHECK_(result_ == (expect), "%s fails with %s", #cond, \
		    nng_strerror(expect));                                  \
		TEST_MSG("%s: expected %s (%d), got %s (%d)", #cond,        \
		    nng_strerror(expect), expect, nng_strerror(result_),    \
		    result_);                                               \
	} while (0)

#define NUTS_SEND(sock, string) \
	NUTS_PASS(nng_send(sock, string, strlen(string) + 1, 0))

#define NUTS_RECV(sock, string)                                             \
	do {                                                                \
		char   buf_[64];                                            \
		size_t sz_ = sizeof(buf_);                                  \
		int    rv_ = nng_recv(sock, &buf_, &sz_, 0);                \
		TEST_CHECK_(                                                \
		    rv_ == 0, "nng_recv (%d %s)", rv_, nng_strerror(rv_));  \
		TEST_CHECK_(sz_ == strlen(string) + 1, "length %d want %d", \
		    (int) sz_, (int) strlen(string) + 1);                   \
		buf_[sizeof(buf_) - 1] = '\0';                              \
		TEST_CHECK_(                                                \
		    strcmp(string, buf_) == 0, "%s == %s", string, buf_);   \
	} while (0)

#define NUTS_MATCH(s1, s2)                                                \
	do {                                                              \
		TEST_CHECK_(strcmp(s1, s2) == 0, "%s == %s", (char *) s1, \
		    (char *) s2);                                         \
	} while (0)

#define NUTS_NULL(x)                                       \
	do {                                               \
		TEST_CHECK_((x) == NULL, "%p == NULL", x); \
	} while (0)

#define NUTS_ADDR(var, scheme)                                             \
	do {                                                               \
		static char nuts_addr_[64];                                \
		nuts_scratch_addr(scheme, sizeof(nuts_addr_), nuts_addr_); \
		(var) = nuts_addr_;                                        \
	} while (0)

#define NUTS_OPEN(sock) NUTS_PASS(nng_pair1_open(&(sock)))

#define NUTS_CLOSE(sock) NUTS_PASS(nng_close(sock))

#define NUTS_SLEEP(ms) nuts_sleep(ms)

#define NUTS_CLOCK(var)               \
	do {                          \
		(var) = nuts_clock(); \
	} while (0)

#define NUTS_BEFORE(when)                                                   \
	do {                                                                \
		uint64_t nuts_t0_ = (when);                                 \
		uint64_t nuts_t1_ = nuts_clock();                           \
		TEST_CHECK_(nuts_t1_ < nuts_t0_,                            \
		    "time before, deadline %lld, current %lld, delta %lld", \
		    (long long) nuts_t0_, (long long) nuts_t1_,             \
		    (long long) nuts_t0_ - (long long) nuts_t1_);           \
	} while (0)

#define NUTS_AFTER(when)                                                   \
	do {                                                               \
		uint64_t nuts_t0_ = (when);                                \
		uint64_t nuts_t1_ = nuts_clock();                          \
		TEST_CHECK_(nuts_t1_ >= nuts_t0_,                          \
		    "time after, deadline %lld, current %lld, delta %lld", \
		    (long long) nuts_t0_, (long long) nuts_t1_,            \
		    (long long) nuts_t0_ - (long long) nuts_t1_);          \
	} while (0)

#define NUTS_MARRY(s1, s2) NUTS_PASS(nuts_marry(s1, s2))
#define NUTS_MARRY_EX(s1, s2, url, p1, p2) \
	NUTS_PASS(nuts_marry_ex(s1, s2, url, p1, p2))

// Redefine some macros from acutest.h for consistency.
#define NUTS_TRUE TEST_CHECK
#define NUTS_ASSERT TEST_ASSERT
#define NUTS_CASE TEST_CASE
#define NUTS_MSG TEST_MSG

#define NUTS_TESTS TEST_LIST

#define NUTS_PROTO(x, y) (((x) << 4u) | (y))

#define NUTS_ENABLE_LOG(level)                         \
	do {                                           \
		nng_log_set_logger(nng_stderr_logger); \
		nng_log_set_level(level);              \
	} while (0)

#define NUTS_LOGGING()                            \
	do {                                      \
		nng_log_set_logger(nuts_logger);  \
		nng_log_set_level(NNG_LOG_DEBUG); \
	} while (0)
#ifdef __cplusplus
};
#endif

#endif // NNG_TEST_NUTS_H
