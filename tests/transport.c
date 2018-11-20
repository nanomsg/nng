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

#include <nng/nng.h>

#include "convey.h"
#include "core/nng_impl.h"

static int ninits;
static int nfinis;
static int nbads;

static int
goodinit(void)
{
	ninits++;
	return (0);
}

static int
badinit(void)
{
	nbads++;
	return (NNG_ENOMEM);
}

static void
finish(void)
{
	nfinis++;
}

// Fake TCP transport
struct nni_tran fake_tcp = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tcp",
	.tran_dialer   = NULL,
	.tran_listener = NULL,
	.tran_pipe     = NULL,
	.tran_init     = goodinit,
	.tran_fini     = finish,
};

// Bad version transport
struct nni_tran badvers = {
	.tran_version  = NNI_TRANSPORT_VERSION + 1,
	.tran_scheme   = "badvers",
	.tran_dialer   = NULL,
	.tran_listener = NULL,
	.tran_pipe     = NULL,
	.tran_init     = goodinit,
	.tran_fini     = finish,
};

struct nni_tran badtran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "badtran",
	.tran_dialer   = NULL,
	.tran_listener = NULL,
	.tran_pipe     = NULL,
	.tran_init     = badinit,
	.tran_fini     = finish,
};

// Bogus good transport
struct nni_tran goodtran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "goodtran",
	.tran_dialer   = NULL,
	.tran_listener = NULL,
	.tran_pipe     = NULL,
	.tran_init     = goodinit,
	.tran_fini     = finish,
};

TestMain("Pluggable Transports", {
	Convey("Registering TCP again fails", {
		So(nni_tran_register(&fake_tcp) == NNG_ESTATE);
		So(ninits == 0);
		So(nfinis == 0);
		So(nbads == 0);
	});

	Convey("Registering bad version fails", {
		So(nni_tran_register(&badvers) == NNG_ENOTSUP);
		So(ninits == 0);
		So(nfinis == 0);
		So(nbads == 0);
	});

	Convey("Registering bad init fails", {
		if (nbads == 0) {
			So(nni_tran_register(&badtran) == NNG_ENOMEM);
		}
		So(ninits == 0);
		So(nfinis == 0);
		So(nbads == 1);

		Convey("Finish not called", {
			nng_fini();
			So(nbads == 1);
			So(nfinis == 0);
		});
	});

	Convey("Registering good init passes", {
		if (ninits == 0) {
			So(nni_tran_register(&goodtran) == 0);
			So(nfinis == 0);
		}
		So(ninits == 1);

		Convey("Finish called", {
			nng_fini();
			So(ninits == 1);
			So(nfinis == 1);
		});
	});
})
