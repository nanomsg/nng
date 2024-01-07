//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_HAVE_SOCKETPAIR
// This provides an implementation of socketpair(), which is supposed
// to be present on XPG6 and newer.  This trivial implementation
// only supports SOCK_STREAM over AF_UNIX.  Which is sufficient for
// most purposes.  The fds array should point to an int[2].
#include <errno.h>
#include <sys/socket.h>

int
nni_socket_pair(int fds[2])
{
	int rv;
	rv = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
	if (rv != 0) {
		return (nni_plat_errno(errno));
	}

#ifdef SO_NOSIGPIPE
	int set = 1;
	setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
	setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
#endif

	return (0);
}
#else
int
nni_socket_pair(int fds[2])
{
	return (NNG_ENOTSUP);
}
#endif
