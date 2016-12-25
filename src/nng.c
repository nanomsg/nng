//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

// This file provides the "public" API.  This is a thin wrapper around
// internal API functions.  We use the public prefix instead of internal,
// to indicate that these interfaces are intended for applications to use
// directly.
//
// Anything not defined in this file, applications have no business using.
// Pretty much every function calls the nni_platform_init to check against
// fork related activity.
int
nng_open(nng_socket **s, uint16_t proto)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_socket_create(s, proto));
}


int
nng_close(nng_socket *s)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_socket_close(s));
}


uint16_t
nng_protocol(nng_socket *s)
{
	nni_init();
	return (nni_socket_proto(s));
}


int
nng_recvmsg(nng_socket *s, nng_msg **msgp, int flags)
{
	int rv;
	nni_time expire;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	if ((flags == NNG_FLAG_NONBLOCK) || (s->s_rcvtimeo == 0)) {
		expire = NNI_TIME_ZERO;
	} else if (s->s_rcvtimeo < 0) {
		expire = NNI_TIME_NEVER;
	} else {
		expire = nni_clock() + s->s_rcvtimeo;
	}

	return (nni_socket_recvmsg(s, msgp, expire));
}


int
nng_sendmsg(nng_socket *s, nng_msg *msg, int flags)
{
	int rv;
	nni_time expire;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	if ((flags == NNG_FLAG_NONBLOCK) || (s->s_sndtimeo == 0)) {
		expire = NNI_TIME_ZERO;
	} else if (s->s_sndtimeo < 0) {
		expire = NNI_TIME_NEVER;
	} else {
		expire = nni_clock() + s->s_sndtimeo;
	}

	return (nni_socket_sendmsg(s, msg, expire));
}


int
nng_setopt(nng_socket *s, int opt, const void *val, size_t sz)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_socket_setopt(s, opt, val, sz));
}


int
nng_getopt(nng_socket *s, int opt, void *val, size_t *szp)
{
	int rv;

	if ((rv == nni_init()) != 0) {
		return (rv);
	}
	return (nni_socket_getopt(s, opt, val, szp));
}


// Misc.
const char *
nng_strerror(int num)
{
	nni_init();
	switch (num) {
	case 0:
		return ("Hunky dory");  // What did you expect?

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


// Message handling.
int
nng_msg_alloc(nng_msg **msgp, size_t size)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_alloc(msgp, size));
}


void
nng_msg_free(nng_msg *msg)
{
	nni_init();
	return (nni_msg_free(msg));
}


void *
nng_msg_body(nng_msg *msg, size_t *szp)
{
	nni_init();
	return (nni_msg_body(msg, szp));
}


void *
nng_msg_header(nng_msg *msg, size_t *szp)
{
	nni_init();
	return (nni_msg_header(msg, szp));
}


int
nng_msg_append(nng_msg *msg, const void *data, size_t sz)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_append(msg, data, sz));
}


int
nng_msg_prepend(nng_msg *msg, const void *data, size_t sz)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_prepend(msg, data, sz));
}


int
nng_msg_append_header(nng_msg *msg, const void *data, size_t sz)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_append_header(msg, data, sz));
}


int
nng_msg_prepend_header(nng_msg *msg, const void *data, size_t sz)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_prepend_header(msg, data, sz));
}


int
nng_msg_trim(nng_msg *msg, size_t sz)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_trim(msg, sz));
}


int
nng_msg_trunc(nng_msg *msg, size_t sz)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_trunc(msg, sz));
}


int
nng_msg_trim_header(nng_msg *msg, size_t sz)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_trim_header(msg, sz));
}


int
nng_msg_trunc_header(nng_msg *msg, size_t sz)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_trunc_header(msg, sz));
}


int
nng_msg_getopt(nng_msg *msg, int opt, void *ptr, size_t *szp)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_msg_getopt(msg, opt, ptr, szp));
}
