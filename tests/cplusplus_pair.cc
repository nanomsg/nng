//
//  Copyright 2025 Staysail Systems, Inc.
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <cstdio>
#include <cstring>
#include <iostream>

#include <nng/nng.h>

#define SOCKET_ADDRESS "inproc://c++"

int
main(int argc, char **argv)
{

#if defined(NNG_HAVE_PAIR1)

	nng_socket s1;
	nng_socket s2;
	nng_err    rv;
	size_t     sz;
	char       buf[8];
	(void) argc;
	(void) argv;

	nng_init(NULL);
	if ((rv = (nng_err) nng_pair1_open(&s1)) != 0) {
		throw nng_strerror(rv);
	}
	if ((rv = (nng_err) nng_pair1_open(&s2)) != 0) {
		throw nng_strerror(rv);
	}
	if ((rv = (nng_err) nng_listen(s1, SOCKET_ADDRESS, NULL, 0)) != 0) {
		throw nng_strerror(rv);
	}
	if ((rv = (nng_err) nng_dial(s2, SOCKET_ADDRESS, NULL, 0)) != 0) {
		throw nng_strerror(rv);
	}
	if ((rv = (nng_err) nng_send(s2, (void *) "ABC", 4, 0)) != 0) {
		throw nng_strerror(rv);
	}
	sz = sizeof(buf);
	if ((rv = (nng_err) nng_recv(s1, buf, &sz, 0)) != 0) {
		throw nng_strerror(rv);
	}
	if ((sz != 4) || (std::strcmp(buf, "ABC") != 0)) {
		throw "Contents did not match";
	}
	if ((rv = (nng_err) nng_send(s1, (void *) "DEF", 4, 0)) != 0) {
		throw nng_strerror(rv);
	}
	sz = sizeof(buf);
	if ((rv = (nng_err) nng_recv(s2, buf, &sz, 0)) != 0) {
		throw nng_strerror(rv);
	}
	if ((sz != 4) || (std::strcmp(buf, "DEF") != 0)) {
		throw "Contents did not match";
	}
	if ((rv = (nng_err) nng_socket_close(s1)) != 0) {
		throw nng_strerror(rv);
	}
	if ((rv = (nng_err) nng_socket_close(s2)) != 0) {
		throw nng_strerror(rv);
	}

	std::cout << "Pass." << std::endl;
	nng_fini();
#else
	(void) argc;
	(void) argv;
	std::cout << "Skipped (protocol unconfigured)." << std::endl;
#endif

	return (0);
}
