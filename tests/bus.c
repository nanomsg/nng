//
// Copyright 2018 Garrett D'Amore <garrett@damore.org>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/bus0/bus.h>

#include "convey.h"
#include "stubs.h"

#define APPENDSTR(m, s) nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)                   \
	So(nng_msg_len(m) == strlen(s)); \
	So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

TestMain("BUS pattern", {
	const char *addr = "inproc://test";

	Reset({ nng_fini(); });

	Convey("We can create a BUS socket", {
		nng_socket bus;

		So(nng_bus_open(&bus) == 0);

		Reset({ nng_close(bus); });
	});

	Convey("We can create a linked BUS topology", {
		nng_socket   bus1;
		nng_socket   bus2;
		nng_socket   bus3;
		nng_duration rtimeo;

		So(nng_bus_open(&bus1) == 0);
		So(nng_bus_open(&bus2) == 0);
		So(nng_bus_open(&bus3) == 0);

		Reset({
			nng_close(bus1);
			nng_close(bus2);
			nng_close(bus3);
		});

		So(nng_listen(bus1, addr, NULL, 0) == 0);
		So(nng_dial(bus2, addr, NULL, 0) == 0);
		So(nng_dial(bus3, addr, NULL, 0) == 0);

		rtimeo = 50;
		So(nng_setopt_ms(bus1, NNG_OPT_RECVTIMEO, rtimeo) == 0);
		So(nng_setopt_ms(bus2, NNG_OPT_RECVTIMEO, rtimeo) == 0);
		So(nng_setopt_ms(bus3, NNG_OPT_RECVTIMEO, rtimeo) == 0);

		Convey("Messages delivered", {
			nng_msg *msg;

			// This is just a poor man's sleep.
			So(nng_recvmsg(bus1, &msg, 0) == NNG_ETIMEDOUT);
			So(nng_recvmsg(bus2, &msg, 0) == NNG_ETIMEDOUT);
			So(nng_recvmsg(bus3, &msg, 0) == NNG_ETIMEDOUT);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "99bits");
			So(nng_sendmsg(bus2, msg, 0) == 0);

			So(nng_recvmsg(bus1, &msg, 0) == 0);
			CHECKSTR(msg, "99bits");
			nng_msg_free(msg);
			So(nng_recvmsg(bus3, &msg, 0) == NNG_ETIMEDOUT);

			So(nng_msg_alloc(&msg, 0) == 0);
			APPENDSTR(msg, "onthe");
			So(nng_sendmsg(bus1, msg, 0) == 0);

			So(nng_recvmsg(bus2, &msg, 0) == 0);
			CHECKSTR(msg, "onthe");
			nng_msg_free(msg);

			So(nng_recvmsg(bus3, &msg, 0) == 0);
			CHECKSTR(msg, "onthe");
			nng_msg_free(msg);
		});
	});
})
