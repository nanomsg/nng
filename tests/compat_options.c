//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/compat/nanomsg/nn.h>
#include <nng/compat/nanomsg/reqrep.h>

#include "convey.h"
#include "compat_testutil.h"

#include <string.h>

#define SECONDS(x) ((x) *1000)

TestMain("Compatible Options", {

	atexit(nn_term);

	Convey("Given a compat NN_REP socket", {
		int repsock;

		So((repsock = nn_socket(AF_SP, NN_REP)) != -1);
		Reset({ nn_close(repsock); });

		Convey("NN_DOMAIN works", {
			int    dom = 4321;
			size_t sz;
			sz = sizeof(dom);
			So(nn_getsockopt(repsock, NN_SOL_SOCKET, NN_DOMAIN,
			       &dom, &sz) == 0);
			So(sz == sizeof(dom));
			So(dom == AF_SP);

			So(nn_setsockopt(repsock, NN_SOL_SOCKET, NN_DOMAIN,
			       &dom, sz) == -1);
			So(nn_errno() == ENOPROTOOPT);
		});
		Convey("NN_LINGER has no effect", {
			int    l = 4321;
			size_t sz;
			sz = sizeof(l);
			So(nn_setsockopt(repsock, NN_SOL_SOCKET, NN_LINGER, &l,
			       sz) == 0);

			So(nn_getsockopt(repsock, NN_SOL_SOCKET, NN_LINGER, &l,
			       &sz) == 0);
			So(sz == sizeof(l));
			So(l == 0);
		});
	});
})
