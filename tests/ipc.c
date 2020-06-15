//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
	So(nng_pipe_getopt_sockaddr(p, NNG_OPT_LOCADDR, &la) == 0);
	So(la.s_family == NNG_AF_IPC);
	// untyped
	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_family == NNG_AF_IPC);

	So(nng_pipe_getopt_size(p, NNG_OPT_REMADDR, &z) == NNG_EBADTYPE);
	z = 1;
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == NNG_EINVAL);

#ifdef _WIN32
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_UID, &id) ==
	    NNG_ENOTSUP);
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_GID, &id) ==
	    NNG_ENOTSUP);
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_ZONEID, &id) ==
	    NNG_ENOTSUP);
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_PID, &id) == 0);
	So(id == GetCurrentProcessId());
#else
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_UID, &id) == 0);
	So(id == (uint64_t) getuid());
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_GID, &id) == 0);
	So(id == (uint64_t) getgid());

#if defined(NNG_HAVE_SOPEERCRED) || defined(NNG_HAVE_GETPEERUCRED) || \
    (defined(NNG_HAVE_LOCALPEERCRED) && defined(NNG_HAVE_LOCALPEERPID))
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_PID, &id) == 0);
	So(id == (uint64_t) getpid());
#else
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_PID, &id) ==
	    NNG_ENOTSUP);
#endif

#ifdef NNG_HAVE_GETPEERUCRED
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_ZONEID, &id) == 0);
	So(id == (uint64_t) getzoneid());
#else
	So(nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_ZONEID, &id) ==
	    NNG_ENOTSUP);
#endif
#endif
	return (0);
}

TestMain("IPC Transport", {
	trantest_test_extended("ipc:///tmp/nng_ipc_test_%u", check_props);

	Convey("IPC listener properties", {
		nng_socket   s;
		nng_listener l;
		nng_sockaddr sa2;
		size_t       z;

		So(nng_req0_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_listen(s, "ipc:///tmp/nng_ipc_addr_test", &l, 0) == 0);
		So(nng_listener_getopt_sockaddr(l, NNG_OPT_LOCADDR, &sa2) ==
		    0);
		So(sa2.s_ipc.sa_family == NNG_AF_IPC);
		So(strcmp(sa2.s_ipc.sa_path, "/tmp/nng_ipc_addr_test") == 0);

		So(nng_listener_setopt(l, NNG_OPT_LOCADDR, &sa2,
		       sizeof(sa2)) == NNG_EREADONLY);
		z = 8192;
		So(nng_listener_setopt_size(l, NNG_OPT_RECVMAXSZ, z) == 0);
		z = 0;
		So(nng_listener_getopt_size(l, NNG_OPT_RECVMAXSZ, &z) == 0);
		So(z == 8192);
		So(nng_listener_setopt_bool(l, NNG_OPT_RAW, true) ==
		    NNG_ENOTSUP);
	});
	Convey("IPC dialer properties", {
		nng_socket   s;
		nng_dialer   d;
		nng_sockaddr sa2;
		size_t       z;

		So(nng_req0_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_dial(s, "ipc:///tmp/nng_ipc_addr_test", &d,
		       NNG_FLAG_NONBLOCK) == 0);
		// Dialers don't have local addresses.
		So(nng_dialer_getopt_sockaddr(d, NNG_OPT_LOCADDR, &sa2) ==
		    NNG_ENOTSUP);

		So(nng_dialer_setopt(d, NNG_OPT_LOCADDR, &sa2, sizeof(sa2)) ==
		    NNG_ENOTSUP);
		z = 8192;
		So(nng_dialer_setopt_size(d, NNG_OPT_RECVMAXSZ, z) == 0);
		z = 0;
		So(nng_dialer_getopt_size(d, NNG_OPT_RECVMAXSZ, &z) == 0);
		So(z == 8192);
		So(nng_dialer_setopt_bool(d, NNG_OPT_RAW, true) ==
		    NNG_ENOTSUP);
	});

	nng_fini();
})
