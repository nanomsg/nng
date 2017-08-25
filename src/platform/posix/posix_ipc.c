//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX
#include "platform/posix/posix_aio.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef SOCK_CLOEXEC
#define NNI_STREAM_SOCKTYPE (SOCK_STREAM | SOCK_CLOEXEC)
#else
#define NNI_STREAM_SOCKTYPE SOCK_STREAM
#endif

// Solaris/SunOS systems define this, which collides with our symbol
// names.  Just undefine it now.
#ifdef sun
#undef sun
#endif

static int nni_plat_ipc_remove_stale(const char *path);

// We alias nni_posix_pipedesc to nni_plat_ipc_pipe.
// We alias nni_posix_epdesc to nni_plat_ipc_ep.

int
nni_plat_ipc_ep_init(nni_plat_ipc_ep **epp, const nni_sockaddr *sa, int mode)
{
	nni_posix_epdesc * ed;
	int                rv;
	struct sockaddr_un sun;

	if ((rv = nni_posix_epdesc_init(&ed)) != 0) {
		return (rv);
	}
	switch (mode) {
	case NNI_EP_MODE_DIAL:
		nni_posix_nn2sockaddr(&sun, sa);
		nni_posix_epdesc_set_remote(ed, &sun, sizeof(sun));
		break;
	case NNI_EP_MODE_LISTEN:

		if ((rv = nni_plat_ipc_remove_stale(
		         sa->s_un.s_path.sa_path)) != 0) {
			return (rv);
		}

		nni_posix_nn2sockaddr(&sun, sa);
		nni_posix_epdesc_set_local(ed, &sun, sizeof(sun));
		break;
	default:
		nni_posix_epdesc_fini(ed);
		return (NNG_EINVAL);
	}

	*epp = (void *) ed;
	return (0);
}

void
nni_plat_ipc_ep_fini(nni_plat_ipc_ep *ep)
{
	nni_posix_epdesc_fini((void *) ep);
}

void
nni_plat_ipc_ep_close(nni_plat_ipc_ep *ep)
{
	nni_posix_epdesc_close((void *) ep);
}

// UNIX DOMAIN SOCKETS -- these have names in the file namespace.
// We are going to check to see if there was a name already there.
// If there was, and nothing is listening (ECONNREFUSED), then we
// will just try to cleanup the old socket.  Note that this is not
// perfect in all scenarios, so use this with caution.
static int
nni_plat_ipc_remove_stale(const char *path)
{
	int                fd;
	int                rv;
	struct sockaddr_un sun;
	size_t             sz;

	sun.sun_family = AF_UNIX;
	sz             = sizeof(sun.sun_path);

	if (nni_strlcpy(sun.sun_path, path, sz) >= sz) {
		return (NNG_EADDRINVAL);
	}

	if ((fd = socket(AF_UNIX, NNI_STREAM_SOCKTYPE, 0)) < 0) {
		return (nni_plat_errno(errno));
	}

	// There is an assumption here that connect() returns immediately
	// (even when non-blocking) when a server is absent.  This seems
	// to be true for the platforms we've tried.  If it doesn't work,
	// then the cleanup will fail.  As this is supposed to be an
	// exceptional case, don't worry.
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);
	if (connect(fd, (void *) &sun, sizeof(sun)) < 0) {
		if (errno == ECONNREFUSED) {
			(void) unlink(path);
		}
	}
	(void) close(fd);
	return (0);
}

int
nni_plat_ipc_ep_listen(nni_plat_ipc_ep *ep)
{
	nni_posix_epdesc *ed = (void *) ep;

	return (nni_posix_epdesc_listen(ed));
}

void
nni_plat_ipc_ep_connect(nni_plat_ipc_ep *ep, nni_aio *aio)
{
	nni_posix_epdesc_connect((void *) ep, aio);
}

void
nni_plat_ipc_ep_accept(nni_plat_ipc_ep *ep, nni_aio *aio)
{
	nni_posix_epdesc_accept((void *) ep, aio);
}

void
nni_plat_ipc_pipe_fini(nni_plat_ipc_pipe *p)
{
	nni_posix_pipedesc_fini((void *) p);
}

void
nni_plat_ipc_pipe_close(nni_plat_ipc_pipe *p)
{
	nni_posix_pipedesc_close((void *) p);
}

void
nni_plat_ipc_pipe_send(nni_plat_ipc_pipe *p, nni_aio *aio)
{
	nni_posix_pipedesc_send((void *) p, aio);
}

void
nni_plat_ipc_pipe_recv(nni_plat_ipc_pipe *p, nni_aio *aio)
{
	nni_posix_pipedesc_recv((void *) p, aio);
}

#endif // NNG_PLATFORM_POSIX
