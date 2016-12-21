/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#include "core/nng_impl.h"

/*
 * This file provides the "public" API.  This is a thin wrapper around
 * internal API functions.  We use the public prefix instead of internal,
 * to indicate that these interfaces are intended for applications to use
 * directly.
 *
 * Anything not defined in this file, applications have no business using.
 * Pretty much every function calls the nni_platform_init to check against
 * fork related activity.
 */
int
nng_socket_create(nng_socket_t *s, uint16_t proto)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_socket_create(s, proto));
}


int
nng_socket_close(nng_socket_t s)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_socket_close(s));
}


uint16_t
nng_socket_protocol(nng_socket_t s)
{
	nni_init();
	return (nni_socket_protocol(s));
}


/*
 * Misc.
 */
const char *
nng_strerror(int num)
{
	nni_init();
	switch (num) {
	case 0:
		return ("Hunky dory");  /* what did you expect? */

	case NNG_EINTR:
		return ("Interrupted");

	case NNG_ENOMEM:
		return ("Out of memory");

	case NNG_EINVAL:
		return ("Invalid argument");

	case NNG_EBUSY:
		return ("Resource busy");

	case NNG_ETIMEDOUT:
		return ("Timed out");

	case NNG_ECONNREFUSED:
		return ("Connection refused");

	case NNG_ECLOSED:
		return ("Object closed");

	case NNG_EAGAIN:
		return ("Try again");

	case NNG_ENOTSUP:
		return ("Not supported");

	case NNG_EADDRINUSE:
		return ("Address in use");

	default:
		return ("Unknown error");
	}
}


/*
 * Message handling.
 */
int
nng_msg_alloc(nng_msg_t *msgp, size_t size)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_alloc(msgp, size));
}


void
nng_msg_free(nng_msg_t msg)
{
	nni_init();
	return (nni_msg_free(msg));
}
