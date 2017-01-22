//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng.h"
#include "nng_compat.h"

#include <string.h>
#include <stdio.h>

// This file provides the "public" API.  This is a thin wrapper around
// internal API functions.  We use the public prefix instead of internal,
// to indicate that these interfaces are intended for applications to use
// directly.
//
// Anything not defined in this file, applications have no business using.
// Pretty much every function calls the nni_platform_init to check against
// fork related activity.

static struct {
	int	perr;
	int	nerr;
}
nn_errnos[] = {
	{ NNG_EINTR,	    EINTR	  },
	{ NNG_ENOMEM,	    ENOMEM	  },
	{ NNG_EINVAL,	    EINVAL	  },
	{ NNG_EBUSY,	    EBUSY	  },
	{ NNG_ETIMEDOUT,    ETIMEDOUT	  },
	{ NNG_ECONNREFUSED, ECONNREFUSED  },
	{ NNG_ECLOSED,	    EBADF	  },
	{ NNG_EAGAIN,	    EAGAIN	  },
	{ NNG_ENOTSUP,	    ENOTSUP	  },
	{ NNG_EADDRINUSE,   EADDRINUSE	  },
	{ NNG_ESTATE,	    EFSM	  },
	{ NNG_ENOENT,	    ENOENT	  },
	{ NNG_EPROTO,	    EPROTO	  },
	{ NNG_EUNREACHABLE, EHOSTUNREACH  },
	{ NNG_EADDRINVAL,   EADDRNOTAVAIL },
	{ NNG_EPERM,	    EACCES	  },
	{ NNG_EMSGSIZE,	    EMSGSIZE	  },
	{ NNG_ECONNABORTED, ECONNABORTED  },
	{ NNG_ECONNRESET,   ECONNRESET	  },
	{		 0,		0 },
};

const char *
nn_strerror(int err)
{
	int i;
	static char msgbuf[32];

	for (i = 0; nn_errnos[i].perr != 0; i++) {
		if (nn_errnos[i].perr == err) {
			return (nng_strerror(nn_errnos[i].nerr));
		}
	}
	if (err == EIO) {
		return ("Unknown I/O error");
	}

	// Arguablye we could use strerror() here, but we should only
	// be getting errnos we understand at this point.
	(void) snprintf(msgbuf, sizeof (msgbuf), "Unknown error %d", err);
	return (msgbuf);
}


static void
nn_seterror(int err)
{
	int i;

	for (i = 0; nn_errnos[i].nerr != 0; i++) {
		if (nn_errnos[i].nerr == err) {
			errno = nn_errnos[i].perr;
			return;
		}
	}
	// No idea...
	errno = EIO;
}


int
nn_socket(int domain, int protocol)
{
	nng_socket sock;
	int rv;

	if ((domain != AF_SP) && (domain != AF_SP_RAW)) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	if ((rv = nng_open(&sock, protocol)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	if (domain == AF_SP_RAW) {
		int raw = 1;
		rv = nng_setopt(sock, NNG_OPT_RAW, &raw, sizeof (raw));
		if (rv != 0) {
			nn_seterror(rv);
			nng_close(sock);
			return (-1);
		}
	}
	return ((int) sock);
}


int
nn_close(int s)
{
	int rv;

	if ((rv = nng_close((nng_socket) s)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return (0);
}


int
nn_bind(int s, const char *addr)
{
	int rv;
	nng_endpoint ep;

	if ((rv = nng_listen((nng_socket) s, addr, &ep, NNG_FLAG_SYNCH)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int) ep);
}


int
nn_connect(int s, const char *addr)
{
	int rv;
	nng_endpoint ep;

	if ((rv = nng_dial((nng_socket) s, addr, &ep, 0)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int) ep);
}


int
nn_shutdown(int s, int ep)
{
	int rv;

	// Socket is wired into the endpoint... so passing a bad endpoint
	// ID can result in affecting the wrong socket.  But this requires
	// a buggy application, and because we don't recycle endpoints
	// until wrap, its unlikely to actually come up in practice.

	if ((rv = nng_endpoint_close((nng_endpoint) ep)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return (0);
}


int
nn_send(int s, const void *buf, size_t len, int flags)
{
	int rv;

	switch (flags) {
	case NN_DONTWAIT:
		flags = NNG_FLAG_NONBLOCK;
		break;
	case 0:
		break;
	default:
		nn_seterror(NNG_EINVAL);
		return (-1);
	}
	if (len == NN_MSG) {
		// FIX ME -- this is a message allocated another way...
		nn_seterror(NNG_ENOTSUP);
		return (-1);
	}
	rv = nng_send((nng_socket) s, (void *)buf, len, flags);
	if (rv != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int)len);
}


int
nn_recv(int s, void *buf, size_t len, int flags)
{
	int rv;
	
	switch (flags) {
	case NN_DONTWAIT:
		flags = NNG_FLAG_NONBLOCK;
		break;
	case 0:
		break;
	default:
		nn_seterror(NNG_EINVAL);
		return (-1);
	}
	if (len == NN_MSG) {
		nn_seterror(NNG_ENOTSUP);
		return (-1);
	}
	rv = nng_recv((nng_socket) s, buf, &len, flags);
	if (rv != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int)len);
}
