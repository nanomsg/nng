//
//  Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng.h"

#include <cstring>

#define SOCKET_ADDRESS "inproc://c++"

int
main(int argc, char **argv)
{
    nng_socket s1;
    nng_socket s2;
    int rv;
    size_t sz;
    char buf[8];

    if ((rv = nng_pair0_open(&s1)) != 0) {
	throw nng_strerror(rv);
    }
    if ((rv = nng_pair0_open(&s2)) != 0) {
	throw nng_strerror(rv);
    }
    if ((rv = nng_listen(s1, SOCKET_ADDRESS, NULL, 0)) != 0) {
	throw nng_strerror(rv);
    }
    if ((rv = nng_dial(s2, SOCKET_ADDRESS, NULL, 0)) != 0) {
	throw nng_strerror(rv);
    }
    if ((rv = nng_send(s2, (void *)"ABC", 4, 0)) != 0) {
	throw nng_strerror(rv);
    }
    sz = sizeof (buf);
    if ((rv = nng_recv(s1, buf, &sz, 0)) != 0) {
        throw nng_strerror(rv);
    }
    if ((sz != 4) || (memcmp(buf, "ABC", 4) != 0)) {
        throw "Contents did not match";
    }
    if ((rv = nng_send(s1, (void *)"DEF", 4, 0)) != 0) {
	throw nng_strerror(rv);
    }
    sz = sizeof (buf);
    if ((rv = nng_recv(s2, buf, &sz, 0)) != 0) {
        throw nng_strerror(rv);
    }
    if ((sz != 4) || (memcmp(buf, "DEF", 4) != 0)) {
        throw "Contents did not match";
    }
    if ((rv = nng_close(s1)) != 0) {
        throw nng_strerror(rv);
    }
    if ((rv = nng_close(s2)) != 0) {
        throw nng_strerror(rv);
    }

    return (0);
}

