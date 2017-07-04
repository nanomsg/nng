//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_IPC
#include "platform/posix/posix_aio.h"
#include "platform/posix/posix_socket.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

// Solaris/SunOS systems define this, which collides with our symbol
// names.  Just undefine it now.
#ifdef sun
#undef sun
#endif

// We alias nni_posix_pipdedesc to nni_plat_ipcsock.

static int
nni_plat_ipc_path_resolve(nni_sockaddr *addr, const char *path)
{
	nng_sockaddr_path *spath;
	size_t len;

	memset(addr, 0, sizeof (*addr));
	spath = &addr->s_un.s_path;

	// TODO: abstract sockets, including autobind sockets.
	len = strlen(path);
	if ((len >= sizeof (spath->sa_path)) || (len < 1)) {
		return (NNG_EADDRINVAL);
	}
	(void) snprintf(spath->sa_path, sizeof (spath->sa_path), "%s", path);
	spath->sa_family = NNG_AF_IPC;
	return (0);
}


void
nni_plat_ipc_aio_send(nni_plat_ipcsock *s, nni_aio *aio)
{
	nni_posix_sock_aio_send((void *) s, aio);
}


void
nni_plat_ipc_aio_recv(nni_plat_ipcsock *s, nni_aio *aio)
{
	nni_posix_sock_aio_recv((void *) s, aio);
}


int
nni_plat_ipc_init(nni_plat_ipcsock **sp)
{
	nni_posix_sock *s;
	int rv;

	if ((rv = nni_posix_sock_init(&s)) == 0) {
		*sp = (void *) s;
	}
	return (rv);
}


void
nni_plat_ipc_fini(nni_plat_ipcsock *s)
{
	nni_posix_sock_fini((void *) s);
}


void
nni_plat_ipc_shutdown(nni_plat_ipcsock *s)
{
	nni_posix_sock_shutdown((void *) s);
}


int
nni_plat_ipc_listen(nni_plat_ipcsock *s, const char *path)
{
	int rv;
	nni_sockaddr addr;

	if ((rv = nni_plat_ipc_path_resolve(&addr, path)) != 0) {
		return (rv);
	}
	return (nni_posix_sock_listen((void *) s, &addr));
}


int
nni_plat_ipc_connect(nni_plat_ipcsock *s, const char *path)
{
	int rv;
	nni_sockaddr addr;

	if ((rv = nni_plat_ipc_path_resolve(&addr, path)) != 0) {
		return (rv);
	}
	return (nni_posix_sock_connect_sync((void *) s, &addr, NULL));
}


int
nni_plat_ipc_accept(nni_plat_ipcsock *s, nni_plat_ipcsock *server)
{
	return (nni_posix_sock_accept_sync((void *) s, (void *) server));
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_ipc_not_used = 0;

#endif // PLATFORM_POSIX_IPC
