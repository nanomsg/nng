//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/supplemental/util/platform.h>

#include "acutest.h"
#include "testutil.h"

void
test_recv_timeout(void)
{
	nng_socket s1;
	uint64_t   now;
	nng_msg *  msg = NULL;

	TEST_CHECK(nng_pair_open(&s1) == 0);
	TEST_CHECK(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, 10) == 0);
	now = testutil_clock();
	TEST_CHECK(nng_recvmsg(s1, &msg, 0) == NNG_ETIMEDOUT);
	TEST_CHECK(msg == NULL);
	TEST_CHECK(testutil_clock() >= (now + 9));
	TEST_CHECK(testutil_clock() < (now + 500));
	TEST_CHECK(nng_close(s1) == 0);
}

void
test_recv_nonblock(void)
{
	nng_socket s1;
	uint64_t   now;
	nng_msg *  msg = NULL;

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, 10) == 0);
	now = testutil_clock();
	TEST_CHECK(nng_recvmsg(s1, &msg, NNG_FLAG_NONBLOCK) == NNG_EAGAIN);
	TEST_CHECK(msg == NULL);
	TEST_CHECK(testutil_clock() < (now + 500));
	TEST_CHECK(nng_close(s1) == 0);
}

void
test_send_timeout(void)
{
	nng_socket s1;
	uint64_t   now;
	nng_msg *  msg;

	TEST_CHECK(nng_msg_alloc(&msg, 0) == 0);
	TEST_CHECK(nng_pair_open(&s1) == 0);
	TEST_CHECK(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, 100) == 0);
	now = testutil_clock();
	TEST_CHECK(nng_sendmsg(s1, msg, 0) == NNG_ETIMEDOUT);
	TEST_CHECK(testutil_clock() >= (now + 9));
	TEST_CHECK(testutil_clock() < (now + 500));
	nng_msg_free(msg);
	TEST_CHECK(nng_close(s1) == 0);
}

void
test_send_nonblock(void)
{
	nng_socket s1;
	uint64_t   now;
	nng_msg *  msg;

	TEST_CHECK(nng_msg_alloc(&msg, 0) == 0);
	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, 500) == 0);
	now = testutil_clock();
	TEST_CHECK(nng_sendmsg(s1, msg, NNG_FLAG_NONBLOCK) == NNG_EAGAIN);
	TEST_CHECK(testutil_clock() < (now + 100));
	TEST_CHECK(nng_close(s1) == 0);
	nng_msg_free(msg);
}

void
test_readonly_options(void)
{
	nng_socket s1;
	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_setopt_int(s1, NNG_OPT_RECVFD, 0) == NNG_EREADONLY);
	TEST_CHECK(nng_setopt_int(s1, NNG_OPT_SENDFD, 0) == NNG_EREADONLY);
	TEST_CHECK(nng_setopt(s1, NNG_OPT_LOCADDR, "a", 1) == NNG_EREADONLY);
	TEST_CHECK(nng_close(s1) == 0);
}

void
test_socket_base(void)
{
	nng_socket s1 = NNG_SOCKET_INITIALIZER;

	TEST_CHECK(nng_socket_id(s1) < 0);
	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_socket_id(s1) > 0);

	// Cannot set bogus options
	TEST_CHECK(nng_setopt_bool(s1, "BAD_OPT", false) == NNG_ENOTSUP);

	TEST_CHECK(nng_close(s1) == 0);
}

void
test_socket_name(void)
{
	nng_socket s1;
	char       name[128]; // 64 is max
	char *     str;
	long       id;
	char *     end;
	size_t     sz;

	sz = sizeof(name);
	TEST_CHECK(nng_pair_open(&s1) == 0);
	TEST_CHECK(nng_getopt(s1, NNG_OPT_SOCKNAME, name, &sz) == 0);
	TEST_CHECK(sz > 0 && sz < 64);
	TEST_CHECK(sz == strlen(name) + 1);
	id = strtol(name, &end, 10);
	TEST_CHECK(id == (long) s1.id);
	TEST_CHECK(end != NULL && *end == '\0');

	TEST_CHECK(nng_setopt(s1, NNG_OPT_SOCKNAME, "hello", 6) == 0);
	sz = sizeof(name);
	TEST_CHECK(nng_getopt(s1, NNG_OPT_SOCKNAME, name, &sz) == 0);
	TEST_CHECK(sz == 6);
	TEST_CHECK(strcmp(name, "hello") == 0);

	memset(name, 'A', 64);
	name[64] = '\0';

	// strings must be NULL terminated
	TEST_CHECK(nng_setopt(s1, NNG_OPT_SOCKNAME, name, 5) == NNG_EINVAL);

	TEST_CHECK(nng_getopt_string(s1, NNG_OPT_SOCKNAME, &str) == 0);
	TEST_ASSERT(str != NULL);
	TEST_CHECK(strlen(str) == 5);
	TEST_CHECK(strcmp(str, "hello") == 0);
	nng_strfree(str);

	TEST_CHECK(nng_close(s1) == 0);
}

void
test_socket_name_oversize(void)
{
	nng_socket s1;
	char       name[256]; // 64 is max
	size_t     sz = sizeof(name);

	memset(name, 'A', sz);
	TEST_CHECK(nng_pair_open(&s1) == 0);

	TEST_CHECK(nng_setopt(s1, NNG_OPT_SOCKNAME, name, sz) == NNG_EINVAL);
	name[sz - 1] = '\0';
	TEST_CHECK(nng_setopt(s1, NNG_OPT_SOCKNAME, name, sz) == NNG_EINVAL);

	strcpy(name, "hello");
	TEST_CHECK(nng_setopt(s1, NNG_OPT_SOCKNAME, name, sz) == 0);
	sz = sizeof(name);
	memset(name, 'B', sz);
	TEST_CHECK(nng_getopt(s1, NNG_OPT_SOCKNAME, name, &sz) == 0);
	TEST_CHECK(sz == 6);
	TEST_CHECK(strcmp(name, "hello") == 0);

	TEST_CHECK(nng_close(s1) == 0);
}

void
test_send_recv(void)
{
	nng_socket   s1;
	nng_socket   s2;
	int          len;
	size_t       sz;
	nng_duration to = 3000; // 3 seconds
	char *       buf;
	char *       a = "inproc://t1";

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_pair1_open(&s2) == 0);

	TEST_CHECK(nng_setopt_int(s1, NNG_OPT_RECVBUF, 1) == 0);
	TEST_CHECK(nng_getopt_int(s1, NNG_OPT_RECVBUF, &len) == 0);
	TEST_CHECK(len == 1);

	TEST_CHECK(nng_setopt_int(s1, NNG_OPT_SENDBUF, 1) == 0);
	TEST_CHECK(nng_setopt_int(s2, NNG_OPT_SENDBUF, 1) == 0);

	TEST_CHECK(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, to) == 0);
	TEST_CHECK(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, to) == 0);
	TEST_CHECK(nng_setopt_ms(s2, NNG_OPT_SENDTIMEO, to) == 0);
	TEST_CHECK(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, to) == 0);

	TEST_CHECK(nng_listen(s1, a, NULL, 0) == 0);
	TEST_CHECK(nng_dial(s2, a, NULL, 0) == 0);

	TEST_CHECK(nng_send(s1, "abc", 4, 0) == 0);
	TEST_CHECK(nng_recv(s2, &buf, &sz, NNG_FLAG_ALLOC) == 0);
	TEST_CHECK(buf != NULL);
	TEST_CHECK(sz == 4);
	TEST_CHECK(memcmp(buf, "abc", 4) == 0);
	nng_free(buf, sz);

	TEST_CHECK(nng_close(s1) == 0);
	TEST_CHECK(nng_close(s2) == 0);
}

void
test_send_recv_zero_length(void)
{
	nng_socket   s1;
	nng_socket   s2;
	int          len;
	size_t       sz;
	nng_duration to = 3000; // 3 seconds
	char *       buf;
	char *       a = "inproc://send-recv-zero-length";

	TEST_NNG_PASS(nng_pair1_open(&s1));
	TEST_NNG_PASS(nng_pair1_open(&s2));

	TEST_NNG_PASS(nng_setopt_int(s1, NNG_OPT_RECVBUF, 1));
	TEST_NNG_PASS(nng_getopt_int(s1, NNG_OPT_RECVBUF, &len));
	TEST_CHECK(len == 1);

	TEST_NNG_PASS(nng_setopt_int(s1, NNG_OPT_SENDBUF, 1));
	TEST_NNG_PASS(nng_setopt_int(s2, NNG_OPT_SENDBUF, 1));

	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, to));
	TEST_NNG_PASS(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, to));
	TEST_NNG_PASS(nng_setopt_ms(s2, NNG_OPT_SENDTIMEO, to));
	TEST_NNG_PASS(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, to));

	TEST_NNG_PASS(nng_listen(s1, a, NULL, 0));
	TEST_NNG_PASS(nng_dial(s2, a, NULL, 0));

	TEST_NNG_PASS(nng_send(s1, "", 0, 0));
	TEST_NNG_PASS(nng_recv(s2, &buf, &sz, NNG_FLAG_ALLOC));
	TEST_CHECK(buf == NULL);
	TEST_CHECK(sz == 0);
	nng_free(buf, sz);

	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(s2));
}

void
test_connection_refused(void)
{
	nng_socket s1;

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_dial(s1, "inproc://no", NULL, 0) == NNG_ECONNREFUSED);
	TEST_CHECK(nng_close(s1) == 0);
}

void
test_late_connection(void)
{
	char *     buf;
	size_t     sz;
	nng_socket s1;
	nng_socket s2;
	char *     a = "inproc://asy";

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_pair1_open(&s2) == 0);

	TEST_CHECK(nng_setopt_ms(s1, NNG_OPT_RECONNMINT, 10) == 0);
	TEST_CHECK(nng_setopt_ms(s1, NNG_OPT_RECONNMAXT, 10) == 0);

	TEST_CHECK(nng_dial(s1, a, NULL, NNG_FLAG_NONBLOCK) == 0);
	TEST_CHECK(nng_listen(s2, a, NULL, 0) == 0);
	nng_msleep(100);
	TEST_CHECK(nng_send(s1, "abc", 4, 0) == 0);
	TEST_CHECK(nng_recv(s2, &buf, &sz, NNG_FLAG_ALLOC) == 0);
	TEST_CHECK(sz == 4);
	TEST_CHECK(memcmp(buf, "abc", 4) == 0);
	nng_free(buf, sz);

	TEST_CHECK(nng_close(s1) == 0);
	TEST_CHECK(nng_close(s2) == 0);
}

void
test_address_busy(void)
{
	char *       a = "inproc://eaddrinuse";
	nng_listener l = NNG_LISTENER_INITIALIZER;
	nng_dialer   d = NNG_DIALER_INITIALIZER;
	nng_socket   s1;
	nng_socket   s2;

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_pair1_open(&s2) == 0);

	TEST_CHECK(nng_listener_id(l) < 0);
	TEST_CHECK(nng_listen(s1, a, &l, 0) == 0);
	TEST_CHECK(nng_listener_id(l) > 0);

	// Cannot start another one.
	TEST_CHECK(nng_listen(s1, a, NULL, 0) == NNG_EADDRINUSE);

	// We can't restart it -- it's already running
	TEST_CHECK(nng_listener_start(l, 0) == NNG_ESTATE);

	// We can connect to it.
	TEST_CHECK(nng_dialer_id(d) < 0);
	TEST_CHECK(nng_dial(s2, a, &d, 0) == 0);
	TEST_CHECK(nng_dialer_id(d) > 0);

	TEST_CHECK(nng_close(s1) == 0);
	TEST_CHECK(nng_close(s2) == 0);
}

void
test_endpoint_types(void)
{
	nng_socket   s1;
	nng_dialer   d = NNG_DIALER_INITIALIZER;
	nng_listener l = NNG_LISTENER_INITIALIZER;
	nng_dialer   d2;
	nng_listener l2;
	char *       a = "inproc://mumble...";
	bool         b;

	TEST_CHECK(nng_pair1_open(&s1) == 0);

	TEST_CHECK(nng_dialer_id(d) < 0);
	TEST_CHECK(nng_dialer_create(&d, s1, a) == 0);
	TEST_CHECK(nng_dialer_id(d) > 0);

	// Forge a listener
	l2.id = nng_dialer_id(d);
	TEST_CHECK(
	    nng_listener_getopt_bool(l2, NNG_OPT_RAW, &b) == NNG_ENOENT);
	TEST_CHECK(nng_listener_close(l2) == NNG_ENOENT);
	TEST_CHECK(nng_dialer_close(d) == 0);

	TEST_CHECK(nng_listener_id(l) < 0);
	TEST_CHECK(nng_listener_create(&l, s1, a) == 0);
	TEST_CHECK(nng_listener_id(l) > 0);

	// Forge a dialer
	d2.id = nng_listener_id(l);
	TEST_CHECK(nng_dialer_getopt_bool(d2, NNG_OPT_RAW, &b) == NNG_ENOENT);
	TEST_CHECK(nng_dialer_close(d2) == NNG_ENOENT);
	TEST_CHECK(nng_listener_close(l) == 0);

	TEST_CHECK(nng_close(s1) == 0);
}

void
test_bad_url(void)
{
	nng_socket s1;

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_dial(s1, "bogus://1", NULL, 0) == NNG_ENOTSUP);
	TEST_CHECK(nng_listen(s1, "bogus://2", NULL, 0) == NNG_ENOTSUP);
	TEST_CHECK(nng_close(s1) == 0);
}

void
test_url_option(void)
{
	nng_socket   s1;
	char         url[NNG_MAXADDRLEN];
	nng_listener l;
	nng_dialer   d;
	size_t       sz;

	TEST_CHECK(nng_pair1_open(&s1) == 0);

	// Listener
	TEST_CHECK(nng_listener_create(&l, s1, "inproc://url1") == 0);
	memset(url, 0, sizeof(url));
	sz = sizeof(url);
	TEST_CHECK(nng_listener_getopt(l, NNG_OPT_URL, url, &sz) == 0);
	TEST_CHECK(strcmp(url, "inproc://url1") == 0);
	TEST_CHECK(
	    nng_listener_setopt(l, NNG_OPT_URL, url, sz) == NNG_EREADONLY);
	sz = sizeof(url);

	// Dialer
	TEST_CHECK(nng_dialer_create(&d, s1, "inproc://url2") == 0);
	TEST_CHECK(nng_dialer_getopt(d, NNG_OPT_URL, url, &sz) == 0);
	TEST_CHECK(strcmp(url, "inproc://url2") == 0);
	TEST_CHECK(
	    nng_dialer_setopt(d, NNG_OPT_URL, url, sz) == NNG_EREADONLY);

	nng_close(s1);
}

void
test_listener_options(void)
{
	nng_socket   s1;
	nng_listener l;
	size_t       sz;

	TEST_CHECK(nng_pair1_open(&s1) == 0);

	// Create a listener with the specified options
	TEST_CHECK(nng_setopt_size(s1, NNG_OPT_RECVMAXSZ, 543) == 0);
	TEST_CHECK(nng_listener_create(&l, s1, "inproc://listener_opts") == 0);
	TEST_CHECK(nng_listener_getopt_size(l, NNG_OPT_RECVMAXSZ, &sz) == 0);
	TEST_CHECK(sz == 543);

	// Verify endpoint overrides
	TEST_CHECK(nng_listener_setopt_size(l, NNG_OPT_RECVMAXSZ, 678) == 0);
	TEST_CHECK(nng_listener_getopt_size(l, NNG_OPT_RECVMAXSZ, &sz) == 0);
	TEST_CHECK(sz == 678);
	TEST_CHECK(nng_getopt_size(s1, NNG_OPT_RECVMAXSZ, &sz) == 0);
	TEST_CHECK(sz == 543);

	// And socket overrides again
	TEST_CHECK(nng_setopt_size(s1, NNG_OPT_RECVMAXSZ, 911) == 0);
	TEST_CHECK(nng_listener_getopt_size(l, NNG_OPT_RECVMAXSZ, &sz) == 0);
	TEST_CHECK(sz == 911);

	// Cannot set invalid options
	TEST_CHECK(nng_listener_setopt_size(l, "BAD_OPT", 1) == NNG_ENOTSUP);
	TEST_CHECK(nng_listener_setopt_bool(l, NNG_OPT_RECVMAXSZ, true) ==
	    NNG_EBADTYPE);
	TEST_CHECK(
	    nng_listener_setopt(l, NNG_OPT_RECVMAXSZ, &sz, 1) == NNG_EINVAL);

	// Cannot set inappropriate options
	TEST_CHECK(nng_listener_setopt_string(l, NNG_OPT_SOCKNAME, "1") ==
	    NNG_ENOTSUP);
	TEST_CHECK(
	    nng_listener_setopt_bool(l, NNG_OPT_RAW, true) == NNG_ENOTSUP);
	TEST_CHECK(
	    nng_listener_setopt_ms(l, NNG_OPT_RECONNMINT, 1) == NNG_ENOTSUP);
	TEST_CHECK(nng_listener_setopt_string(l, NNG_OPT_SOCKNAME, "bogus") ==
	    NNG_ENOTSUP);

	// Read only options
	TEST_CHECK(nng_listener_setopt_string(
	               l, NNG_OPT_URL, "inproc://junk") == NNG_EREADONLY);

	TEST_CHECK(nng_close(s1) == 0);
}

void
test_dialer_options(void)
{
	nng_socket s1;
	nng_dialer d;
	size_t     sz;

	TEST_CHECK(nng_pair1_open(&s1) == 0);

	// Create a listener with the specified options
	TEST_CHECK(nng_setopt_size(s1, NNG_OPT_RECVMAXSZ, 543) == 0);
	TEST_CHECK(nng_dialer_create(&d, s1, "inproc://dialer_opts") == 0);
	TEST_CHECK(nng_dialer_getopt_size(d, NNG_OPT_RECVMAXSZ, &sz) == 0);
	TEST_CHECK(sz == 543);

	// Verify endpoint overrides
	TEST_CHECK(nng_dialer_setopt_size(d, NNG_OPT_RECVMAXSZ, 678) == 0);
	TEST_CHECK(nng_dialer_getopt_size(d, NNG_OPT_RECVMAXSZ, &sz) == 0);
	TEST_CHECK(sz == 678);
	TEST_CHECK(nng_getopt_size(s1, NNG_OPT_RECVMAXSZ, &sz) == 0);
	TEST_CHECK(sz == 543);

	// And socket overrides again
	TEST_CHECK(nng_setopt_size(s1, NNG_OPT_RECVMAXSZ, 911) == 0);
	TEST_CHECK(nng_dialer_getopt_size(d, NNG_OPT_RECVMAXSZ, &sz) == 0);
	TEST_CHECK(sz == 911);

	// Cannot set invalid options
	TEST_CHECK(nng_dialer_setopt_size(d, "BAD_OPT", 1) == NNG_ENOTSUP);
	TEST_CHECK(nng_dialer_setopt_bool(d, NNG_OPT_RECVMAXSZ, true) ==
	    NNG_EBADTYPE);
	TEST_CHECK(
	    nng_dialer_setopt(d, NNG_OPT_RECVMAXSZ, &sz, 1) == NNG_EINVAL);

	// Cannot set inappropriate options
	TEST_CHECK(
	    nng_dialer_setopt_string(d, NNG_OPT_SOCKNAME, "1") == NNG_ENOTSUP);
	TEST_CHECK(
	    nng_dialer_setopt_bool(d, NNG_OPT_RAW, true) == NNG_ENOTSUP);
	TEST_CHECK(
	    nng_dialer_setopt_ms(d, NNG_OPT_SENDTIMEO, 1) == NNG_ENOTSUP);
	TEST_CHECK(nng_dialer_setopt_string(d, NNG_OPT_SOCKNAME, "bogus") ==
	    NNG_ENOTSUP);

	// Read only options
	TEST_CHECK(nng_dialer_setopt_string(d, NNG_OPT_URL, "inproc://junk") ==
	    NNG_EREADONLY);

	TEST_CHECK(nng_close(s1) == 0);
}

void
test_endpoint_absent_options(void)
{
	size_t       s;
	int          i;
	nng_duration t;
	bool         b;
	nng_dialer   d;
	nng_listener l;
	d.id = 1999;
	l.id = 1999;

	TEST_CHECK(
	    nng_dialer_setopt_size(d, NNG_OPT_RECVMAXSZ, 10) == NNG_ENOENT);
	TEST_CHECK(
	    nng_listener_setopt_size(l, NNG_OPT_RECVMAXSZ, 10) == NNG_ENOENT);

	TEST_CHECK(nng_dialer_getopt_bool(d, NNG_OPT_RAW, &b) == NNG_ENOENT);
	TEST_CHECK(nng_listener_getopt_bool(l, NNG_OPT_RAW, &b) == NNG_ENOENT);

	TEST_CHECK(
	    nng_dialer_getopt_size(d, NNG_OPT_RECVMAXSZ, &s) == NNG_ENOENT);
	TEST_CHECK(
	    nng_listener_getopt_size(l, NNG_OPT_RECVMAXSZ, &s) == NNG_ENOENT);

	TEST_CHECK(nng_dialer_getopt_int(d, NNG_OPT_RAW, &i) == NNG_ENOENT);
	TEST_CHECK(nng_listener_getopt_int(l, NNG_OPT_RAW, &i) == NNG_ENOENT);

	TEST_CHECK(
	    nng_dialer_getopt_ms(d, NNG_OPT_RECVTIMEO, &t) == NNG_ENOENT);
	TEST_CHECK(
	    nng_listener_getopt_ms(l, NNG_OPT_SENDTIMEO, &t) == NNG_ENOENT);
}

void
test_timeout_options(void)
{
	nng_socket   s1;
	nng_duration to;
	size_t       sz;

	char *cases[] = {
		NNG_OPT_RECVTIMEO,
		NNG_OPT_SENDTIMEO,
		NNG_OPT_RECONNMAXT,
		NNG_OPT_RECONNMINT,
		NULL,
	};

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	for (int i = 0; cases[i] != NULL; i++) {
		bool b;
		TEST_CASE(cases[i]);

		// Can't receive a duration into zero bytes.
		sz = 0;
		TEST_CHECK(nng_getopt(s1, cases[i], &to, &sz) == NNG_EINVAL);

		// Type mismatches
		TEST_CHECK(nng_getopt_bool(s1, cases[i], &b) == NNG_EBADTYPE);
		sz = 1;
		TEST_CHECK(nng_getopt(s1, cases[i], &b, &sz) == NNG_EINVAL);

		// Can set a valid duration
		TEST_CHECK(nng_setopt_ms(s1, cases[i], 1234) == 0);
		TEST_CHECK(nng_getopt_ms(s1, cases[i], &to) == 0);
		TEST_CHECK(to == 1234);

		to = 0;
		sz = sizeof(to);
		TEST_CHECK(nng_getopt(s1, cases[i], &to, &sz) == 0);
		TEST_CHECK(to == 1234);
		TEST_CHECK(sz == sizeof(to));

		// Can't set a negative duration
		TEST_CHECK(nng_setopt_ms(s1, cases[i], -5) == NNG_EINVAL);

		// Can't pass a buf too small for duration
		sz = sizeof(to) - 1;
		to = 1;
		TEST_CHECK(nng_setopt(s1, cases[i], &to, sz) == NNG_EINVAL);
	}
	TEST_CHECK(nng_close(s1) == 0);
}

void
test_size_options(void)
{
	nng_socket s1;
	size_t     val;
	size_t     sz;
	char *     opt;

	char *cases[] = {
		NNG_OPT_RECVMAXSZ,
		NULL,
	};

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	for (int i = 0; (opt = cases[i]) != NULL; i++) {
		TEST_CASE(opt);

		// Can't receive a size into zero bytes.
		sz = 0;
		TEST_CHECK(nng_getopt(s1, opt, &val, &sz) == NNG_EINVAL);

		// Can set a valid duration
		TEST_CHECK(nng_setopt_size(s1, opt, 1234) == 0);
		TEST_CHECK(nng_getopt_size(s1, opt, &val) == 0);
		TEST_CHECK(val == 1234);

		val = 0;
		sz  = sizeof(val);
		TEST_CHECK(nng_getopt(s1, opt, &val, &sz) == 0);
		TEST_CHECK(val == 1234);
		TEST_CHECK(sz == sizeof(val));

		// Can't pass a buf too small for size
		sz  = sizeof(val) - 1;
		val = 1;
		TEST_CHECK(nng_setopt(s1, opt, &val, sz) == NNG_EINVAL);

		// We limit the limit to 4GB. Clear it if you want to
		// ship more than 4GB at a time.
#if defined(_WIN64) || defined(_LP64)
		val = 0x10000u;
		val <<= 30u;
		TEST_CHECK(nng_setopt_size(s1, opt, val) == NNG_EINVAL);
		TEST_CHECK(nng_getopt_size(s1, opt, &val) == 0);
		TEST_CHECK(val == 1234);
#endif
	}
	TEST_CHECK(nng_close(s1) == 0);
}

TEST_LIST = {
	{ "recv timeout", test_recv_timeout },
	{ "recv non-block", test_recv_nonblock },
	{ "send timeout", test_send_timeout },
	{ "send non-block", test_send_nonblock },
	{ "read only options", test_readonly_options },
	{ "socket base", test_socket_base },
	{ "socket name", test_socket_name },
	{ "socket name oversize", test_socket_name_oversize },
	{ "send recv", test_send_recv },
	{ "send recv zero length", test_send_recv_zero_length },
	{ "connection refused", test_connection_refused },
	{ "late connection", test_late_connection },
	{ "address busy", test_address_busy },
	{ "bad url", test_bad_url },
	{ "url option", test_url_option },
	{ "listener options", test_listener_options },
	{ "dialer options", test_dialer_options },
	{ "timeout options", test_timeout_options },
	{ "size options", test_size_options },
	{ "endpoint absent options", test_endpoint_absent_options },
	{ "endpoint types", test_endpoint_types },

	{ NULL, NULL },
};
