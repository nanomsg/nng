//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "trantest.h"


// Inproc tests.

TestMain("TCP Transport", {

	trantest_test_all("tcp://127.0.0.1:4450");


	Convey("We cannot connect to wild cards", {
		nng_socket s;

		So(nng_open(&s, NNG_PROTO_PAIR) == 0);
		Reset({
			nng_close(s);
		})
		So(nng_dial(s, "tcp://*:5555", NULL, NNG_FLAG_SYNCH) == NNG_EADDRINVAL);
	})

	Convey("We can bind to wild card", {
		nng_socket s1;
		nng_socket s2;
		So(nng_open(&s1, NNG_PROTO_PAIR) == 0);
		So(nng_open(&s2, NNG_PROTO_PAIR) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		})
		So(nng_listen(s1, "tcp://*:5771", NULL, NNG_FLAG_SYNCH) == 0);
		So(nng_dial(s2, "tcp://127.0.0.1:5771", NULL, NNG_FLAG_SYNCH) == 0);
	})

	nng_fini();
})
