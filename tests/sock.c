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

TestMain("Socket Operations", {
	Convey("We are able to open a PAIR socket", {
		int rv;
		nng_socket *sock = NULL;

		rv = nng_socket_create(&sock, NNG_PROTO_PAIR);
		So(rv == 0);
		So(sock != NULL);

		Convey("And we can close it", {
			rv = nng_socket_close(sock);
			So(rv == 0);
		})

		Convey("It's type is still proto", {
			So(nng_socket_protocol(sock) == NNG_PROTO_PAIR);
		})
	})
})