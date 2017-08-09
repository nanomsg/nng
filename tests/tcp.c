//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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

	trantest_test_all("tcp://127.0.0.1:%u");

	Convey("We cannot connect to wild cards", {
		nng_socket s;
		char       addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		trantest_next_address(addr, "tcp://*:%u");
		So(nng_dial(s, addr, NULL, NNG_FLAG_SYNCH) == NNG_EADDRINVAL);
	});

	Convey("We can bind to wild card", {
		nng_socket s1;
		nng_socket s2;
		char       addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tcp://*:%u");
		So(nng_listen(s1, addr, NULL, NNG_FLAG_SYNCH) == 0);
		// reset port back one
		trantest_prev_address(addr, "tcp://127.0.0.1:%u");
		So(nng_dial(s2, addr, NULL, NNG_FLAG_SYNCH) == 0);
	});

	nng_fini();
})
