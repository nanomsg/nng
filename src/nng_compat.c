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


void *
nn_allocmsg(size_t size, int type)
{
	uintptr_t *ch;
	nng_msg *msg;
	int rv;

	// Validate type and non-zero size.  This also checks for overflow.
	if ((type != 0) || (size < 1) || ((size + sizeof (msg) < size))) {
		nn_seterror(NNG_EINVAL);
		return (NULL);
	}

	// So our "messages" from nn are really going to be nng messages
	// but to make this work, we use a bit of headroom in the message
	// to stash the message header.
	if ((rv = nng_msg_alloc(&msg, size + (sizeof (msg)))) != 0) {
		nn_seterror(rv);
		return (NULL);
	}

	memcpy(nng_msg_body(msg), &msg, sizeof (msg));

	// We are counting on the implementation of nn_msg_trim to not
	// reallocate the message but just to leave the prefix inplace.
	(void) nng_msg_trim(msg, sizeof (msg));

	return (nng_msg_body(msg));
}


void
nni_freemsg(void *ptr)
{
	nng_msg *msg;

	memcpy(&msg, ((char *) ptr) - sizeof (msg), sizeof (msg));
	nng_msg_free(msg);
}


void *
nni_reallocmsg(void *ptr, size_t len)
{
	nng_msg *msg;
	int rv;

	if ((len + sizeof (msg)) < len) {
		// overflowed!
		nn_seterror(NNG_EINVAL);
		return (NULL);
	}

	memcpy(&msg, ((char *) ptr) - sizeof (msg), sizeof (msg));

	// We need to realloc the requested len, plus size for our header.
	if ((rv = nng_msg_realloc(msg, len + sizeof (msg))) != 0) {
		// We don't free the old message.  Code is free to cope
		// as it sees fit.
		nn_seterror(rv);
		return (NULL);
	}
	// Stash the msg header pointer
	memcpy(nng_msg_body(msg), &msg, sizeof (msg));
	nng_msg_trim(msg, sizeof (msg));
	return (nng_msg_body(msg));
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
		nng_msg *msg;
		memcpy(&msg, ((char *) buf) - sizeof (msg), sizeof (msg));
		len = nng_msg_len(msg);
		rv = nng_sendmsg((nng_socket) s, msg, flags);
	} else {
		rv = nng_send((nng_socket) s, (void *) buf, len, flags);
	}
	if (rv != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int) len);
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
		nng_msg *msg;
		rv = nng_recvmsg((nng_socket) s, &msg, flags);
		if (rv == 0) {
			void *body;
			// prepend our header to the body...
			// Note that this *can* alter the message,
			// although for performance reasons it ought not.
			// (There should be sufficient headroom.)
			nng_msg_prepend(msg, &msg, sizeof (msg));
			// then trim it off :-)
			nng_msg_trim(msg, sizeof (msg));
			// store the pointer to the revised body
			body =  nng_msg_body(msg);

			// arguably we could do this with a pointer store,
			// but memcpy gives us extra paranoia in case the
			// the receiver is misaligned.
			memcpy(buf, &body, sizeof (body));
			len = nng_msg_len(msg);
		}
	} else {
		rv = nng_recv((nng_socket) s, buf, &len, flags);
	}
	if (rv != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int) len);
}


#if 0
int
nn_sendmsg(int s, const struct nn_msghdr *mh, int flags)
{
	void *chunk;

	switch (flags) {
	case NN_DONTWAIT:
		flags = NN_FLAG_NONBLOCK;
		break;
	case 0:
		break;
	default:
		nn_seterror(NNG_EINVAL);
		return (-1);
	}

	// Iterate over the iovecs.  The first iov may be NN_MSG,
	// in which case it must be the only iovec.

	if ((mh->msg_iovlen == 1) && (mh->msg_iov[0].iov_len == NN_MSG)) {
		// Chunk is stored at the offset...
		chunk = *(void **) mh->msg_iov[0].iov_base;
		// Chunk must be aligned
		if ((chuink & (sizeof (void *) - 1)) != 0) {
			nn_seterror(NNG_EINVAL);
			return (-1);
		}
		size = (size_t) (*(uintptr_t *) (((void **) chunk) - 1));
	}
}


#endif
