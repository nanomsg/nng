//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "../testing/nuts.h"

void
test_hold_release(void)
{
	nng_socket s;
	nng_dialer d;
	char      *addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));

	NUTS_FAIL(nng_dialer_release(d), NNG_ESTATE);
	NUTS_PASS(nng_dialer_hold(d));
	NUTS_PASS(nng_dialer_release(d));
	NUTS_FAIL(nng_dialer_release(d), NNG_ESTATE);

	NUTS_CLOSE(s);
}

void
test_hold_release_balanced(void)
{
	nng_socket s;
	nng_dialer d;
	char      *addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));

	NUTS_PASS(nng_dialer_hold(d));
	NUTS_PASS(nng_dialer_hold(d));
	NUTS_PASS(nng_dialer_release(d));
	NUTS_PASS(nng_dialer_release(d));
	NUTS_FAIL(nng_dialer_release(d), NNG_ESTATE);

	NUTS_CLOSE(s);
}

void
test_hold_survives_close(void)
{
	nng_socket       s;
	nng_dialer       d;
	char            *addr;
	const nng_url   *url;

	NUTS_ADDR(addr, "inproc");

	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));
	NUTS_PASS(nng_dialer_hold(d));
	NUTS_CLOSE(s);

	NUTS_PASS(nng_dialer_get_url(d, &url));
	NUTS_PASS(nng_dialer_release(d));

	NUTS_FAIL(nng_dialer_get_url(d, &url), NNG_ENOENT);
}

void
test_hold_release_after_close(void)
{
	nng_socket  s;
	nng_dialer  d;
	char       *addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));
	NUTS_PASS(nng_dialer_hold(d));
	NUTS_CLOSE(s);

	NUTS_PASS(nng_dialer_hold(d));
	NUTS_PASS(nng_dialer_release(d));
	NUTS_PASS(nng_dialer_release(d));

	NUTS_FAIL(nng_dialer_release(d), NNG_ENOENT);
	NUTS_FAIL(nng_dialer_hold(d), NNG_ENOENT);
}

void
test_hold_release_invalid_dialer(void)
{
	nng_dialer d = NNG_DIALER_INITIALIZER;

	NUTS_FAIL(nng_dialer_hold(d), NNG_ENOENT);
	NUTS_FAIL(nng_dialer_release(d), NNG_ENOENT);
}

void
test_hold_after_close(void)
{
	nng_socket  s;
	nng_dialer  d;
	char       *addr;

	NUTS_ADDR(addr, "inproc");

	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));

	NUTS_PASS(nng_dialer_close(d));
	NUTS_FAIL(nng_dialer_hold(d), NNG_ENOENT);

	NUTS_CLOSE(s);
}

void
test_close_after_hold(void)
{
	nng_socket       s;
	nng_dialer       d;
	char            *addr;
	const nng_url   *url;

	NUTS_ADDR(addr, "inproc");

	NUTS_OPEN(s);
	NUTS_PASS(nng_dialer_create(&d, s, addr));

	NUTS_PASS(nng_dialer_hold(d));
	NUTS_PASS(nng_dialer_close(d));

	NUTS_PASS(nng_dialer_get_url(d, &url));

	NUTS_PASS(nng_dialer_release(d));
	NUTS_CLOSE(s);
}

NUTS_TESTS = {
	{ "hold and release", test_hold_release },
	{ "hold and release (balanced)", test_hold_release_balanced },
	//{ "hold survives close", test_hold_survives_close },
	//{ "hold and release after close", test_hold_release_after_close },
	{ "hold and release invalid dialer", test_hold_release_invalid_dialer },
	{ "hold after close", test_hold_after_close },
	{ "close after hold", test_close_after_hold },
	{ NULL, NULL },
};
