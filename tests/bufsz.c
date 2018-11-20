//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/compat/nanomsg/nn.h>

#include <nng/nng.h>
#include <nng/protocol/pubsub0/sub.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/supplemental/util/platform.h>

#include "trantest.h"
#include "convey.h"
#include "stubs.h"

#define SECONDS(x) ((x) *1000)

TestMain("Buffer Options", {

	atexit(nng_fini);

	Convey("We are able to open a PAIR socket", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);

		Reset({ nng_close(s1); });

		Convey("Set/Get Recv Buf Option", {
			int cnt;
			So(nng_setopt_int(s1, NNG_OPT_RECVBUF, 10) == 0);
			So(nng_getopt_int(s1, NNG_OPT_RECVBUF, &cnt) == 0);
			So(cnt == 10);
			So(nng_setopt_size(s1, NNG_OPT_RECVBUF, 42) ==
			    NNG_EBADTYPE);

		});
		Convey("Set/Get Send Buf Option", {
			int cnt;
			So(nng_setopt_int(s1, NNG_OPT_SENDBUF, 10) == 0);
			So(nng_getopt_int(s1, NNG_OPT_SENDBUF, &cnt) == 0);
			So(cnt == 10);
			So(nng_setopt_size(s1, NNG_OPT_SENDBUF, 42) ==
			    NNG_EBADTYPE);

		});

		// NOTE: We are going to use the compat mode, but
		// this assumes that the socket is the same between compat
		// and current mode.  This is true, but normal applications
		// MUST NOT assume this.  We only do so for testing.
		Convey("Legacy Recv Buf Option", {
			int    cnt;
			int    os = (int) s1.id;
			size_t sz = sizeof(cnt);
			So(nng_setopt_int(s1, NNG_OPT_RECVBUF, 10) == 0);
			So(nn_getsockopt(
			       os, NN_SOL_SOCKET, NN_RCVBUF, &cnt, &sz) == 0);
			So(cnt == 10240);
			cnt = 1;
			So(nn_setsockopt(
			       os, NN_SOL_SOCKET, NN_RCVBUF, &cnt, sz) == 0);
			So(nn_getsockopt(
			       os, NN_SOL_SOCKET, NN_RCVBUF, &cnt, &sz) == 0);
			So(cnt == 1024); // round up!
			So(nng_getopt_int(s1, NNG_OPT_RECVBUF, &cnt) == 0);
			So(cnt == 1);

			So(nn_setsockopt(
			       os, NN_SOL_SOCKET, NN_RCVBUF, &cnt, 100) == -1);
			So(nn_errno() == EINVAL);
		});
		Convey("Legacy Send Buf Option", {
			int    cnt;
			int    os = (int) s1.id;
			size_t sz = sizeof(cnt);
			So(nng_setopt_int(s1, NNG_OPT_SENDBUF, 10) == 0);
			So(nn_getsockopt(
			       os, NN_SOL_SOCKET, NN_SNDBUF, &cnt, &sz) == 0);
			So(cnt == 10240);
			cnt = 1;
			So(nn_setsockopt(
			       os, NN_SOL_SOCKET, NN_SNDBUF, &cnt, sz) == 0);
			So(nn_getsockopt(
			       os, NN_SOL_SOCKET, NN_SNDBUF, &cnt, &sz) == 0);
			So(cnt == 1024); // round up!
			So(nng_getopt_int(s1, NNG_OPT_SENDBUF, &cnt) == 0);
			So(cnt == 1);

			So(nn_setsockopt(
			       os, NN_SOL_SOCKET, NN_SNDBUF, &cnt, 100) == -1);
			So(nn_errno() == EINVAL);
		});

	});
})
