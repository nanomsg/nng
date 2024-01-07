//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"


#ifdef NNG_HAVE_SOCKETPAIR_TODO
// TODO: Windows lacks socketpair.  We can emulate it with an explcit
// implementation based on AF_UNIX.

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

	return (0);
}
#else
int
nni_socket_pair(int fds[2])
{
	NNI_ARG_UNUSED(fds);
	return (NNG_ENOTSUP);
}

// This is also the fdc transport.

typedef struct nni_sfd_conn nni_sfd_conn;

void
nni_sfd_close_fd(int fd)
{
	NNI_ARG_UNUSED(fd);
}

int
nni_sfd_conn_alloc(nni_sfd_conn **cp, int fd)
{
	NNI_ARG_UNUSED(cp);
	NNI_ARG_UNUSED(fd);
	return (NNG_ENOTSUP);
}

#endif
