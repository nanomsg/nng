/*
    Copyright (c) 2013 Insollo Entertainment, LLC. All rights reserved.
    Copyright 2017 Garrett D'Amore <garrett@damore.org>
    Copyright 2016 Franklin "Snaipe" Mathieu <franklinmathieu@gmail.com>
    Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
    Copyright 2018 Capitar IT Group BV <info@capitar.com>

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

// Note: This file started life in nanomsg.  We have copied it, and adjusted
// it for validating the compatibility features of nanomsg.   As much as
// possible we want to run tests from the nanomsg test suite unmodified.

#ifndef COMPAT_TESTUTIL_H_INCLUDED
#define COMPAT_TESTUTIL_H_INCLUDED

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define nn_err_strerror nn_strerror
#define nn_err_abort abort
#define nn_assert assert
#define errno_assert assert
#define wsa_assert assert
#define alloc_assert(x) assert(x != NULL)

#if defined __GNUC__ || defined __llvm__ || defined __clang__
#define NN_UNUSED __attribute__((unused))
#else
#define NN_UNUSED
#endif

extern int  test_socket_impl(char *file, int line, int family, int protocol);
extern int  test_connect_impl(char *file, int line, int sock, char *address);
extern int  test_bind_impl(char *file, int line, int sock, char *address);
extern void test_close_impl(char *file, int line, int sock);
extern void test_send_impl(char *file, int line, int sock, char *data);
extern void test_recv_impl(char *file, int line, int sock, char *data);
extern void test_drop_impl(char *file, int line, int sock, int err);
extern int  test_setsockopt_impl(char *file, int line, int sock, int level,
	int option, const void *optval, size_t optlen);
extern int get_test_port(int argc, const char *argv[]);
extern void test_addr_from(char *out, const char *proto, const char *ip,
	int port);
extern void nn_sleep(int);

#define test_socket(f, p) test_socket_impl(__FILE__, __LINE__, (f), (p))
#define test_connect(s, a) test_connect_impl(__FILE__, __LINE__, (s), (a))
#define test_bind(s, a) test_bind_impl(__FILE__, __LINE__, (s), (a))
#define test_send(s, d) test_send_impl(__FILE__, __LINE__, (s), (d))
#define test_recv(s, d) test_recv_impl(__FILE__, __LINE__, (s), (d))
#define test_drop(s, e) test_drop_impl(__FILE__, __LINE__, (s), (e))
#define test_close(s) test_close_impl(__FILE__, __LINE__, (s))
#define test_setsockopt(s, l, o, v, z) \
	test_setsockopt_impl(__FILE__, __LINE__, (s), (l), (o), (v), (z))

struct nn_thread {
	void *thr;
};

extern int nn_thread_init(struct nn_thread *, void (*)(void *), void *);
extern void nn_thread_term(struct nn_thread *);

#endif // COMPAT_TESTUTIL_H_INCLUDED
