//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"

#include <string.h>

Main({
	int rv;
	const char *addr = "inproc://test";

	Test("REQ/REP pattern", {
		Convey("We can create a REQ socket", {
			nng_socket *req;

			rv = nng_open(&req, NNG_PROTO_REQ);
			So(rv == 0);
			So(req != NULL);

			Reset({
				nng_close(req);
			})

			Convey("Protocols match", {
				So(nng_protocol(req) == NNG_PROTO_REQ);
				So(nng_peer(req) == NNG_PROTO_REP);
			})
		})

		Convey("We can create a REP socket", {
			nng_socket *rep;
			rv = nng_open(&rep, NNG_PROTO_REP);
			So(rv == 0);
			So(rep != NULL);

			Reset({
				nng_close(rep);
			})

			Convey("Protocols match", {
				So(nng_protocol(rep) == NNG_PROTO_REP);
				So(nng_peer(rep) == NNG_PROTO_REQ);
			})
		})

		Convey("We can create a linked REQ/REP pair", {
			nng_socket *req;
			nng_socket *rep;

			rv = nng_open(&rep, NNG_PROTO_REP);
			So(rv == 0);
			So(rep != NULL);

			rv = nng_open(&req, NNG_PROTO_REQ);
			So(rv == 0);
			So(req != NULL);

			Reset({
				nng_close(rep);
				nng_close(req);
			})

			rv = nng_listen(rep, addr, NULL, NNG_FLAG_SYNCH);
			So(rv == 0);

			rv = nng_dial(req, addr, NULL, NNG_FLAG_SYNCH);
			So(rv == 0);
		})
	})
})
