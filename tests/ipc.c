//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifdef _WIN32
#else
#include <unistd.h>
#ifdef NNG_HAVE_GETPEERUCRED
#include <zone.h>
#endif
#endif

#include <nng/nng.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/transport/ipc/ipc.h>

#include "convey.h"
#include "trantest.h"

// IPC tests.
static int
check_props(nng_msg *msg)
{
	nng_pipe     p;
	size_t       z;
	nng_sockaddr la;
	nng_sockaddr ra;
	uint64_t     id;

	p = nng_msg_get_pipe(msg);
	So(nng_pipe_id(p) > 0);
	So(nng_pipe_get_addr(p, NNG_OPT_LOCADDR, &la) == 0);
	So(la.s_family == NNG_AF_IPC);
	// untyped
	z = sizeof(nng_sockaddr);
	So(nng_pipe_get(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_family == NNG_AF_IPC);

	So(nng_pipe_get_size(p, NNG_OPT_REMADDR, &z) == NNG_EBADTYPE);
	z = 1;
	So(nng_pipe_get(p, NNG_OPT_REMADDR, &ra, &z) == NNG_EINVAL);

#ifdef _WIN32
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_UID, &id) ==
	    NNG_ENOTSUP);
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_GID, &id) ==
	    NNG_ENOTSUP);
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_ZONEID, &id) ==
	    NNG_ENOTSUP);
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_PID, &id) == 0);
	So(id == GetCurrentProcessId());
#else
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_UID, &id) == 0);
	So(id == (uint64_t) getuid());
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_GID, &id) == 0);
	So(id == (uint64_t) getgid());

#if defined(NNG_HAVE_SOPEERCRED) || defined(NNG_HAVE_GETPEERUCRED) || \
    (defined(NNG_HAVE_LOCALPEERCRED) && defined(NNG_HAVE_LOCALPEERPID))
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_PID, &id) == 0);
	So(id == (uint64_t) getpid());
#else
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_PID, &id) ==
	    NNG_ENOTSUP);
#endif

#ifdef NNG_HAVE_GETPEERUCRED
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_ZONEID, &id) == 0);
	So(id == (uint64_t) getzoneid());
#else
	So(nng_pipe_get_uint64(p, NNG_OPT_IPC_PEER_ZONEID, &id) ==
	    NNG_ENOTSUP);
#endif
#endif
	return (0);
}

TestMain("IPC Transport", {
	trantest_test_extended("ipc:///tmp/nng_ipc_test_%u", check_props);
})
