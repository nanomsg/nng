//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

#include <nng/protocol/bus0/bus.h>

void
test_bug1247(void)
{
	nng_socket bus1, bus2;
	char *     addr;

	NUTS_ADDR(addr, "tcp");

	NUTS_PASS(nng_bus0_open(&bus1));
	NUTS_PASS(nng_bus0_open(&bus2));

	NUTS_PASS(nng_listen(bus1, addr, NULL, 0));
	NUTS_FAIL(nng_listen(bus2, addr, NULL, 0), NNG_EADDRINUSE);

	NUTS_PASS(nng_close(bus2));
	NUTS_PASS(nng_close(bus1));
}

TEST_LIST = {
	{ "bug1247", test_bug1247 },
	{ NULL, NULL },
};
