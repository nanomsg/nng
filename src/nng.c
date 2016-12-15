/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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
	nni_platform_init();
	return (nni_socket_create(s, proto));
}

int
nng_socket_close(nng_socket_t s)
{
	nni_platform_init();
	return (nni_socket_close(s));
}

uint16_t
nng_socket_protocol(nng_socket_t s)
{
	nni_platform_init();
	return (nni_socket_protocol(s));
}

/*
 * Misc.
 */

const char *
nng_strerror(int num)
{
	switch (num) {
	case 0:
		return ("Hunky dory");	/* what did you expect? */
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
        nni_platform_init();
        return (nni_msg_alloc(msgp, size));
}

void
nng_msg_free(nng_msg_t msg)
{
        nni_platform_init();
        return (nni_msg_free(msg));
}