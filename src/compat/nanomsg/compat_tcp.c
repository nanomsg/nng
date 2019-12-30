/*
    Copyright 2019 Garrett D'Amore <garrett@damore.org>
    Copyright (c) 2012 Martin Sustrik  All rights reserved.
    Copyright 2016 Franklin "Snaipe" Mathieu <franklinmathieu@gmail.com>

    Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom
    the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

// This test is a pretty much completely rewritten version of the
// legacy nanomsg tcp test.  The NNG test infrastructure is a bit more
// robust, and we take advantage of that.

#include <nng/compat/nanomsg/nn.h>
#include <nng/compat/nanomsg/pair.h>
#include <nng/compat/nanomsg/pubsub.h>
#include <nng/compat/nanomsg/tcp.h>

#include "compat_testutil.h"

#include <acutest.h>
#include <testutil.h>

void
test_bind_and_close(void)
{
	int      sb;
	char     addr[32];
	uint16_t port = testutil_next_port();
	(void) snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", port);

	TEST_CHECK((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK(nn_bind(sb, addr) >= 0);
	TEST_CHECK(nn_close(sb) == 0);
}

void
test_connect_and_close(void)
{
	int      sc;
	char     addr[32];
	uint16_t port = testutil_next_port();
	(void) snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", port);

	TEST_CHECK((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK(nn_connect(sc, addr) >= 0);
	TEST_CHECK(nn_close(sc) == 0);
}

void
test_bind_and_connect(void)
{
	int      sb, sc;
	char     addr[32];
	uint16_t port = testutil_next_port();
	(void) snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", port);

	TEST_CHECK((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK(sb != sc);
	TEST_CHECK(nn_bind(sb, addr) >= 0);
	TEST_CHECK(nn_connect(sc, addr) >= 0);

	testutil_sleep(200);

	TEST_CHECK(nn_close(sb) == 0);
	TEST_CHECK(nn_close(sc) == 0);
}

void
test_bad_addresses(void)
{
	int s;
	TEST_CHECK((s = nn_socket(AF_SP, NN_PAIR)) >= 0);

	TEST_NN_FAIL(nn_connect(s, "tcp://*:"), EINVAL);
	TEST_NN_FAIL(nn_connect(s, "tcp://*:1000000"), EINVAL);
	TEST_NN_FAIL(nn_connect(s, "tcp://*:some_port"), EINVAL);
	TEST_NN_FAIL(nn_connect(s, "tcp://127.0.0.1"), EINVAL);
	TEST_NN_FAIL(nn_connect(s, "tcp://:5555"), EINVAL);
	TEST_NN_FAIL(nn_connect(s, "tcp://abc.123.---.#:5555"), EINVAL);

	TEST_NN_FAIL(nn_bind(s, "tcp://127.0.0.1:1000000"), EINVAL);
	TEST_NN_PASS(nn_close(s));
}

void
test_no_delay(void)
{
	int    s;
	int    opt;
	size_t sz;
	TEST_CHECK((s = nn_socket(AF_SP, NN_PAIR)) >= 0);

	sz = sizeof(opt);
	TEST_NN_PASS(nn_getsockopt(s, NN_TCP, NN_TCP_NODELAY, &opt, &sz));
	TEST_CHECK(sz == sizeof(opt));
	TEST_CHECK(opt == 0);
	opt = 2;
	TEST_NN_FAIL(
	    nn_setsockopt(s, NN_TCP, NN_TCP_NODELAY, &opt, sz), EINVAL);

	opt = 1;
	TEST_NN_PASS(nn_setsockopt(s, NN_TCP, NN_TCP_NODELAY, &opt, sz));

	opt = 3;
	TEST_NN_PASS(nn_getsockopt(s, NN_TCP, NN_TCP_NODELAY, &opt, &sz));
	TEST_CHECK(sz == sizeof(opt));
	TEST_CHECK(opt == 1);
	TEST_NN_PASS(nn_close(s));
}

void
test_ping_pong(void)
{
	int      sb, sc;
	char     addr[32];
	uint16_t port = testutil_next_port();
	(void) snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", port);

	TEST_CHECK((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK(sb != sc);
	TEST_CHECK(nn_bind(sb, addr) >= 0);
	TEST_CHECK(nn_connect(sc, addr) >= 0);

	testutil_sleep(200);

	/*  Ping-pong test. */
	for (int i = 0; i != 100; ++i) {

		char buf[4];
		int  n;
		TEST_NN_PASS(nn_send(sc, "ABC", 3, 0));
		TEST_NN_PASS(n = nn_recv(sb, buf, 4, 0));
		TEST_CHECK(n == 3);
		TEST_CHECK(memcmp(buf, "ABC", 3) == 0);

		TEST_NN_PASS(nn_send(sb, "DEF", 3, 0));
		TEST_NN_PASS(n = nn_recv(sc, buf, 4, 0));
		TEST_CHECK(n == 3);
		TEST_CHECK(memcmp(buf, "DEF", 3) == 0);
	}

	TEST_CHECK(nn_close(sb) == 0);
	TEST_CHECK(nn_close(sc) == 0);
}

// test_batch tests sending a batch of messages.  It relies on having
// a reasonably deep buffer in the socket.
void
test_batch(void)
{
	int      sb, sc;
	char     addr[32];
	uint16_t port = testutil_next_port();
	(void) snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", port);

	TEST_CHECK((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK(sb != sc);
	TEST_CHECK(nn_bind(sb, addr) >= 0);
	TEST_CHECK(nn_connect(sc, addr) >= 0);

	testutil_sleep(200);

#define DIGITS "0123456789012345678901234567890123456789"
	for (int i = 0; i < 100; i++) {
		TEST_NN_PASS(nn_send(sc, DIGITS, strlen(DIGITS) + 1, 0));
	}

	for (int i = 0; i < 100; i++) {
		char buf[64];
		int  n;
		TEST_NN_PASS(n = nn_recv(sb, buf, sizeof(buf), 0));
		TEST_CHECK(n == (strlen(DIGITS) + 1));
		TEST_CHECK(memcmp(DIGITS, buf, n) == 0);
	}

	TEST_CHECK(nn_close(sb) == 0);
	TEST_CHECK(nn_close(sc) == 0);
}

void
test_pair_reject(void)
{
	int      sb, sc, sd;
	char     addr[32];
	uint16_t port = testutil_next_port();
	(void) snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", port);

	TEST_CHECK((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK((sd = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK(sb != sc);
	TEST_CHECK(nn_bind(sb, addr) >= 0);
	TEST_CHECK(nn_connect(sc, addr) >= 0);
	testutil_sleep(100);
	TEST_CHECK(nn_connect(sd, addr) >= 0);

	testutil_sleep(200);

	TEST_CHECK(nn_close(sb) == 0);
	TEST_CHECK(nn_close(sc) == 0);
	TEST_CHECK(nn_close(sd) == 0);
}

void
test_addr_in_use(void)
{
	int      sb, sc;
	char     addr[32];
	uint16_t port = testutil_next_port();
	(void) snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", port);

	TEST_CHECK((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK(sb != sc);
	TEST_NN_PASS(nn_bind(sb, addr));
	TEST_NN_FAIL(nn_bind(sc, addr), EADDRINUSE);

	TEST_CHECK(nn_close(sb) == 0);
	TEST_CHECK(nn_close(sc) == 0);
}

void
test_max_recv_size(void)
{
	int      sb, sc;
	int      opt;
	int      n;
	size_t   sz;
	char     addr[32];
	char     buf[64];
	uint16_t port = testutil_next_port();
	(void) snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", port);

	TEST_CHECK((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	TEST_CHECK(sb != sc);
	opt = 100;
	sz = sizeof (opt);
	TEST_NN_PASS(nn_setsockopt(sb, NN_SOL_SOCKET, NN_RCVTIMEO, &opt, sz));

	/*  Test that NN_RCVMAXSIZE can be -1, but not lower */
	sz  = sizeof(opt);
	opt = -1;
	TEST_NN_PASS(
	    nn_setsockopt(sb, NN_SOL_SOCKET, NN_RCVMAXSIZE, &opt, sz));

	opt = -2;
	TEST_NN_FAIL(
	    nn_setsockopt(sb, NN_SOL_SOCKET, NN_RCVMAXSIZE, &opt, sz), EINVAL);

	opt = 4;
	TEST_NN_PASS(
	    nn_setsockopt(sb, NN_SOL_SOCKET, NN_RCVMAXSIZE, &opt, sz));
	opt = -5;
	TEST_NN_PASS(
	    nn_getsockopt(sb, NN_SOL_SOCKET, NN_RCVMAXSIZE, &opt, &sz));
	TEST_CHECK(opt == 4);
	TEST_CHECK(sz == sizeof(opt));

	TEST_CHECK(nn_bind(sb, addr) >= 0);
	TEST_CHECK(nn_connect(sc, addr) >= 0);

	testutil_sleep(200);

	TEST_NN_PASS(nn_send(sc, "ABC", 4, 0));
	TEST_NN_PASS(nn_send(sc, "012345", 6, 0));

	TEST_NN_PASS(n = nn_recv(sb, buf, sizeof(buf), 0));
	TEST_CHECK(n == 4);
	TEST_CHECK(strcmp(buf, "ABC") == 0);

	TEST_NN_FAIL(nn_recv(sb, buf, sizeof(buf), 0), ETIMEDOUT);

	TEST_NN_PASS(nn_close(sb));
	TEST_NN_PASS(nn_close(sc));
}

TEST_LIST = {
	{ "compat tcp bind and close ", test_bind_and_close },
	{ "compat tcp connect and close ", test_connect_and_close },
	{ "compat tcp bind and connect ", test_bind_and_connect },
	{ "compat tcp invalid addresses", test_bad_addresses },
	{ "compat tcp no delay option", test_no_delay },
	{ "compat tcp ping pong", test_ping_pong },
	{ "compat tcp send recv batch", test_batch },
	{ "compat tcp pair reject", test_pair_reject },
	{ "compat tcp addr in use", test_addr_in_use },
	{ "compat tcp max recv size", test_max_recv_size },
	{ NULL, NULL },
};
