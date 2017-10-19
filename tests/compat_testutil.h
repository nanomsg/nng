/*
    Copyright (c) 2013 Insollo Entertainment, LLC. All rights reserved.
    Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

// Note: This file started life in nanomsg.  We have copied it, and adjusted
// it for validating the compatibility features of nanomsg.   As much as
// possible we want to run tests from the nanomsg test suite unmodified.

#ifndef TESTUTIL_H_INCLUDED
#define TESTUTIL_H_INCLUDED

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define nn_err_strerror nn_strerror
#define nn_err_abort abort
#define nn_assert assert
#define errno_assert assert
#define alloc_assert(x) assert(x != NULL)

static int  test_socket_impl(char *file, int line, int family, int protocol);
static int  test_connect_impl(char *file, int line, int sock, char *address);
static int  test_bind_impl(char *file, int line, int sock, char *address);
static void test_close_impl(char *file, int line, int sock);
static void test_send_impl(char *file, int line, int sock, char *data);
static void test_recv_impl(char *file, int line, int sock, char *data);
static void test_drop_impl(char *file, int line, int sock, int err);
static int  test_setsockopt_impl(char *file, int line, int sock, int level,
     int option, const void *optval, size_t optlen);

#define test_socket(f, p) test_socket_impl(__FILE__, __LINE__, (f), (p))
#define test_connect(s, a) test_connect_impl(__FILE__, __LINE__, (s), (a))
#define test_bind(s, a) test_bind_impl(__FILE__, __LINE__, (s), (a))
#define test_send(s, d) test_send_impl(__FILE__, __LINE__, (s), (d))
#define test_recv(s, d) test_recv_impl(__FILE__, __LINE__, (s), (d))
#define test_drop(s, e) test_drop_impl(__FILE__, __LINE__, (s), (e))
#define test_close(s) test_close_impl(__FILE__, __LINE__, (s))
#define test_setsockopt(s, l, o, v, z) \
	test_setsockopt_impl(__FILE__, __LINE__, (s), (l), (o), (v), (z))

#define NN_UNUSED

static int
test_socket_impl(char *file, int line, int family, int protocol)
{
	int sock;

	sock = nn_socket(family, protocol);
	if (sock == -1) {
		fprintf(stderr, "Failed create socket: %s [%d] (%s:%d)\n",
		    nn_err_strerror(errno), (int) errno, file, line);
		nn_err_abort();
	}

	return sock;
}

static int
test_connect_impl(char *file, int line, int sock, char *address)
{
	int rc;

	rc = nn_connect(sock, address);
	if (rc < 0) {
		fprintf(stderr, "Failed connect to \"%s\": %s [%d] (%s:%d)\n",
		    address, nn_err_strerror(errno), (int) errno, file, line);
		nn_err_abort();
	}
	return rc;
}

static int
test_bind_impl(char *file, int line, int sock, char *address)
{
	int rc;

	rc = nn_bind(sock, address);
	if (rc < 0) {
		fprintf(stderr, "Failed bind to \"%s\": %s [%d] (%s:%d)\n",
		    address, nn_err_strerror(errno), (int) errno, file, line);
		nn_err_abort();
	}
	return rc;
}

static int
test_setsockopt_impl(char *file, int line, int sock, int level, int option,
    const void *optval, size_t optlen)
{
	int rc;

	rc = nn_setsockopt(sock, level, option, optval, optlen);
	if (rc < 0) {
		fprintf(stderr, "Failed set option \"%d\": %s [%d] (%s:%d)\n",
		    option, nn_err_strerror(errno), (int) errno, file, line);
		nn_err_abort();
	}
	return rc;
}

static void
test_close_impl(char *file, int line, int sock)
{
	int rc;

	rc = nn_close(sock);
	if ((rc != 0) && (errno != EBADF && errno != ETERM)) {
		fprintf(stderr, "Failed to close socket: %s [%d] (%s:%d)\n",
		    nn_err_strerror(errno), (int) errno, file, line);
		nn_err_abort();
	}
}

static void
test_send_impl(char *file, int line, int sock, char *data)
{
	size_t data_len;
	int    rc;

	data_len = strlen(data);

	rc = nn_send(sock, data, data_len, 0);
	if (rc < 0) {
		fprintf(stderr, "Failed to send: %s [%d] (%s:%d)\n",
		    nn_err_strerror(errno), (int) errno, file, line);
		nn_err_abort();
	}
	if (rc != (int) data_len) {
		fprintf(stderr,
		    "Data to send is truncated: %d != %d (%s:%d)\n", rc,
		    (int) data_len, file, line);
		nn_err_abort();
	}
}

static void
test_recv_impl(char *file, int line, int sock, char *data)
{
	size_t data_len;
	int    rc;
	char * buf;

	data_len = strlen(data);
	/*  We allocate plus one byte so that we are sure that message received
	    has correct length and not truncated  */
	buf = malloc(data_len + 1);
	alloc_assert(buf);

	rc = nn_recv(sock, buf, data_len + 1, 0);
	if (rc < 0) {
		fprintf(stderr, "Failed to recv: %s [%d] (%s:%d)\n",
		    nn_err_strerror(errno), (int) errno, file, line);
		nn_err_abort();
	}
	if (rc != (int) data_len) {
		fprintf(stderr,
		    "Received data has wrong length: %d != %d (%s:%d)\n", rc,
		    (int) data_len, file, line);
		nn_err_abort();
	}
	if (memcmp(data, buf, data_len) != 0) {
		/*  We don't print the data as it may have binary garbage  */
		fprintf(
		    stderr, "Received data is wrong (%s:%d)\n", file, line);
		nn_err_abort();
	}

	free(buf);
}

static void
test_drop_impl(char *file, int line, int sock, int err)
{
	int  rc;
	char buf[1024];

	rc = nn_recv(sock, buf, sizeof(buf), 0);
	if (rc < 0 && err != errno) {
		fprintf(stderr,
		    "Got wrong err to recv: %s [%d != %d] (%s:%d)\n",
		    nn_err_strerror(errno), (int) errno, err, file, line);
		nn_err_abort();
	} else if (rc >= 0) {
		fprintf(stderr, "Did not drop message: [%d bytes] (%s:%d)\n",
		    rc, file, line);
		nn_err_abort();
	}
}

static int
get_test_port(int argc, const char *argv[])
{
	return atoi(argc < 2 ? "5555" : argv[1]);
}

static void
test_addr_from(char *out, const char *proto, const char *ip, int port)
{
	sprintf(out, "%s://%s:%d", proto, ip, port);
}

void
nn_sleep(int32_t msec)
{
	void nng_msleep(int32_t);
	nng_msleep(msec);
}

struct nn_thread {
	void *thr;
};

int
nn_thread_init(struct nn_thread *thr, void (*func)(void *), void *arg)
{
	int nng_thread_create(void **, void (*)(void *), void *);
	return (nng_thread_create(&thr->thr, func, arg));
}

void
nn_thread_term(struct nn_thread *thr)
{
	void nng_thread_destroy(void *);
	nng_thread_destroy(thr->thr);
}

#endif // TESTUTIL_H_INCLUDED
