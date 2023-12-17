//
// Copyright 2023 Pat Maddox <pat@patmaddox.com>
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//


#include <nuts.h>
#include <sys/types.h>
#include <sys/socket.h>

int nuts_socket_pair(int *sv);

// file descriptor tests

static void
test_file_descriptor_invalid_fd_fail(void)
{
	nng_socket s;
	char       addr[NNG_MAXADDRLEN];

	printf("1\n");
	NUTS_OPEN(s);
	printf("2\n");
	(void) snprintf(addr, sizeof(addr), "file_descriptor://invalid");
	printf("3\n", addr);
	NUTS_FAIL(nng_dial(s, addr, NULL, 0), NNG_EADDRINVAL);
	printf("4\n");
	NUTS_CLOSE(s);
	printf("5\n");
}

void
test_file_descriptor_connect(void)
{
	nng_socket s1;
	nng_socket s2;
	char       addr[NNG_MAXADDRLEN];
	int        sv[2];

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nuts_socket_pair(sv));
	(void) snprintf(addr, sizeof(addr), "file_descriptor://%u", sv[0]);
	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	(void) snprintf(
	    addr, sizeof(addr), "file_descriptor://%u", sv[1]);
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
}

TEST_LIST = {
	{ "file descriptor invalid", test_file_descriptor_invalid_fd_fail },
	{ "file descriptor connect", test_file_descriptor_connect },
	{ NULL, NULL },
};

int
nuts_socket_pair(int *sv)
{
  return socketpair(PF_UNIX, SOCK_STREAM, 0, sv);
}
