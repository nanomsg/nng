/*
    Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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
#include <nng/compat/nanomsg/tcp.h>

#include "nuts_compat.h"

#include <nuts.h>

void
test_bind_and_close(void)
{
	int   sb;
	char *addr;

	NUTS_ADDR(addr, "tcp");

	NUTS_TRUE((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE(nn_bind(sb, addr) >= 0);
	NUTS_TRUE(nn_close(sb) == 0);
}

void
test_connect_and_close(void)
{
	int   sc;
	char *addr;

	NUTS_ADDR(addr, "tcp");
	NUTS_NN_PASS((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_NN_PASS(nn_connect(sc, addr));
	NUTS_NN_PASS(nn_close(sc));
}

void
test_bind_and_connect(void)
{
	int   sb, sc, p1, p2;
	char *addr;

	NUTS_ADDR(addr, "tcp");
	NUTS_TRUE((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE(sb != sc);

	NUTS_NN_MARRY_EX(sb, sc, addr, p1, p2);

	NUTS_NN_PASS(nn_close(sb));
	NUTS_NN_PASS(nn_close(sc));
}

void
test_bad_addresses(void)
{
	int s;
	NUTS_TRUE((s = nn_socket(AF_SP, NN_PAIR)) >= 0);

	NUTS_NN_FAIL(nn_connect(s, "tcp://*:"), EINVAL);
	NUTS_NN_FAIL(nn_connect(s, "tcp://*:1000000"), EINVAL);
	NUTS_NN_FAIL(nn_connect(s, "tcp://*:some_port"), EINVAL);
	NUTS_NN_FAIL(nn_connect(s, "tcp://127.0.0.1"), EINVAL);
	NUTS_NN_FAIL(nn_connect(s, "tcp://:5555"), EINVAL);
	NUTS_NN_FAIL(nn_connect(s, "tcp://abc.123.---.#:5555"), EINVAL);

	NUTS_NN_FAIL(nn_bind(s, "tcp://127.0.0.1:1000000"), EINVAL);
	NUTS_NN_PASS(nn_close(s));
}

void
test_no_delay(void)
{
	int    s;
	int    opt;
	size_t sz;
	NUTS_TRUE((s = nn_socket(AF_SP, NN_PAIR)) >= 0);

	sz = sizeof(opt);
	NUTS_NN_PASS(nn_getsockopt(s, NN_TCP, NN_TCP_NODELAY, &opt, &sz));
	NUTS_TRUE(sz == sizeof(opt));
	NUTS_TRUE(opt == 0);
	opt = 2;
	NUTS_NN_FAIL(
	    nn_setsockopt(s, NN_TCP, NN_TCP_NODELAY, &opt, sz), EINVAL);

	opt = 1;
	NUTS_NN_PASS(nn_setsockopt(s, NN_TCP, NN_TCP_NODELAY, &opt, sz));

	opt = 3;
	NUTS_NN_PASS(nn_getsockopt(s, NN_TCP, NN_TCP_NODELAY, &opt, &sz));
	NUTS_TRUE(sz == sizeof(opt));
	NUTS_TRUE(opt == 1);
	NUTS_NN_PASS(nn_close(s));
}

void
test_ping_pong(void)
{
	int   sb, sc, p1, p2;
	char *addr;

	NUTS_ADDR(addr, "tcp");
	NUTS_NN_PASS((sb = nn_socket(AF_SP, NN_PAIR)));
	NUTS_NN_PASS((sc = nn_socket(AF_SP, NN_PAIR)));
	NUTS_TRUE(sb != sc);
	NUTS_NN_MARRY_EX(sc, sb, addr, p1, p2);
	NUTS_TRUE(p1 >= 0);
	NUTS_TRUE(p2 >= 0);

	/*  Ping-pong test. */
	for (int i = 0; i != 100; ++i) {

		char buf[4];
		int  n;
		NUTS_NN_PASS(nn_send(sc, "ABC", 3, 0));
		NUTS_NN_PASS(n = nn_recv(sb, buf, 4, 0));
		NUTS_TRUE(n == 3);
		NUTS_TRUE(memcmp(buf, "ABC", 3) == 0);

		NUTS_NN_PASS(nn_send(sb, "DEF", 3, 0));
		NUTS_NN_PASS(n = nn_recv(sc, buf, 4, 0));
		NUTS_TRUE(n == 3);
		NUTS_TRUE(memcmp(buf, "DEF", 3) == 0);
	}

	NUTS_NN_PASS(nn_close(sb));
	NUTS_NN_PASS(nn_close(sc));
}

void
test_pair_reject(void)
{
	int   sb, sc, sd, p1, p2;
	char *addr;

	NUTS_ADDR(addr, "tcp");

	NUTS_TRUE((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE((sd = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE(sb != sc);

	NUTS_NN_MARRY_EX(sc, sb, addr, p1, p2);

	NUTS_TRUE(nn_connect(sd, addr) >= 0);
	NUTS_SLEEP(200);

	NUTS_NN_PASS(nn_close(sb));
	NUTS_NN_PASS(nn_close(sc));
	NUTS_NN_PASS(nn_close(sd));
}

void
test_addr_in_use(void)
{
	int   sb, sc;
	char *addr;

	NUTS_ADDR(addr, "tcp");
	NUTS_TRUE((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE(sb != sc);
	NUTS_NN_PASS(nn_bind(sb, addr));
	NUTS_NN_FAIL(nn_bind(sc, addr), EADDRINUSE);

	NUTS_NN_PASS(nn_close(sb));
	NUTS_NN_PASS(nn_close(sc));
}

void
test_max_recv_size(void)
{
	int    sb, sc, p1, p2;
	int    opt;
	int    n;
	size_t sz;
	char   buf[64];
	char *addr;

	NUTS_ADDR(addr, "tcp");

	NUTS_TRUE((sb = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE((sc = nn_socket(AF_SP, NN_PAIR)) >= 0);
	NUTS_TRUE(sb != sc);
	opt = 100;
	sz  = sizeof(opt);
	NUTS_NN_PASS(nn_setsockopt(sb, NN_SOL_SOCKET, NN_RCVTIMEO, &opt, sz));

	/*  Test that NN_RCVMAXSIZE can be -1, but not lower */
	sz  = sizeof(opt);
	opt = -1;
	NUTS_NN_PASS(
	    nn_setsockopt(sb, NN_SOL_SOCKET, NN_RCVMAXSIZE, &opt, sz));

	opt = -2;
	NUTS_NN_FAIL(
	    nn_setsockopt(sb, NN_SOL_SOCKET, NN_RCVMAXSIZE, &opt, sz), EINVAL);

	opt = 4;
	NUTS_NN_PASS(
	    nn_setsockopt(sb, NN_SOL_SOCKET, NN_RCVMAXSIZE, &opt, sz));
	opt = -5;
	NUTS_NN_PASS(
	    nn_getsockopt(sb, NN_SOL_SOCKET, NN_RCVMAXSIZE, &opt, &sz));
	NUTS_TRUE(opt == 4);
	NUTS_TRUE(sz == sizeof(opt));

	NUTS_NN_MARRY_EX(sc, sb, addr, p1, p2);

	NUTS_NN_PASS(nn_send(sc, "ABC", 4, 0));
	NUTS_NN_PASS(nn_send(sc, "012345", 6, 0));

	NUTS_NN_PASS(n = nn_recv(sb, buf, sizeof(buf), 0));
	NUTS_TRUE(n == 4);
	NUTS_TRUE(strcmp(buf, "ABC") == 0);

	NUTS_NN_FAIL(nn_recv(sb, buf, sizeof(buf), 0), ETIMEDOUT);

	NUTS_NN_PASS(nn_close(sb));
	NUTS_NN_PASS(nn_close(sc));
}

TEST_LIST = {
	{ "compat tcp bind and close ", test_bind_and_close },
	{ "compat tcp connect and close ", test_connect_and_close },
	{ "compat tcp bind and connect ", test_bind_and_connect },
	{ "compat tcp invalid addresses", test_bad_addresses },
	{ "compat tcp no delay option", test_no_delay },
	{ "compat tcp ping pong", test_ping_pong },
	{ "compat tcp pair reject", test_pair_reject },
	{ "compat tcp addr in use", test_addr_in_use },
	{ "compat tcp max recv size", test_max_recv_size },
	{ NULL, NULL },
};
