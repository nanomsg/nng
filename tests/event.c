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
#include "nng.h"
#include <assert.h>
#include <string.h>

#define APPENDSTR(m, s) nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)                   \
	So(nng_msg_len(m) == strlen(s)); \
	So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)
struct evcnt {
	nng_socket sock;
	int        readable;
	int        writeable;
	int        pipeadd;
	int        piperem;
	int        dialeradd;
	int        dialerrem;
	int        listeneradd;
	int        listenerrem;
	int        err;
};

void
bump(nng_event *ev, void *arg)
{
	struct evcnt *cnt = arg;

	assert(nng_event_socket(ev) == cnt->sock);
	switch (nng_event_type(ev)) {
	case NNG_EV_CAN_SND:
		cnt->writeable = 1;
		break;

	case NNG_EV_CAN_RCV:
		cnt->readable = 1;
		break;

#if 0 // These are not tested yet

	case NNG_EV_PIPE_ADD:
		cnt->pipeadd = 1;
		break;

	case NNG_EV_PIPE_REM:
		cnt->piperem = 1;
		break;

	case NNG_EV_DIALER_ADD:
		cnt->dialeradd = 1;
		break;

	case NNG_EV_DIALER_REM:
		cnt->dialerrem = 1;
		break;

	case NNG_EV_LISTENER_ADD:
		cnt->listeneradd = 1;
		break;

	case NNG_EV_LISTENER_REM:
		cnt->listenerrem = 1;
		break;
#endif

	default:
		break;
	}
}

TestMain("Event Handling", {
	const char *addr = "inproc://test";
	Convey("Given a connected pair of pair sockets", {
		nng_socket   sock1;
		nng_socket   sock2;
		struct evcnt evcnt1;
		struct evcnt evcnt2;
		nng_notify * notify1;
		nng_notify * notify2;

		So(nng_pair0_open(&sock1) == 0);
		So(nng_pair0_open(&sock2) == 0);

		memset(&evcnt1, 0, sizeof(evcnt1));
		memset(&evcnt2, 0, sizeof(evcnt2));
		evcnt1.sock = sock1;
		evcnt2.sock = sock2;

		Reset({
			nng_close(sock1);
			nng_close(sock2);
		});

		So(nng_listen(sock1, addr, NULL, 0) == 0);
		So(nng_dial(sock2, addr, NULL, 0) == 0);

		// Let everything connect.
		nng_msleep(100);

		Convey("We can register callbacks", {
			So((notify1 = nng_setnotify(sock1, NNG_EV_CAN_SND,
			        bump, &evcnt1)) != NULL);
			So((notify2 = nng_setnotify(sock2, NNG_EV_CAN_RCV,
			        bump, &evcnt2)) != NULL);

			Convey("They are called", {
				nng_msg *msg;

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "abc");

				So(nng_sendmsg(sock1, msg, 0) == 0);

				// XXX: The current implementation
				// is level rather than edge triggered.
				// Think through the ramifications of
				// this.  Probably the msgq needs to
				// toggle on reads.

				// nng_msleep(20);

				// So(nng_recvmsg(sock2, &msg, 0) ==
				// 0);

				// CHECKSTR(msg, "abc");
				// nng_msg_free(msg);

				// The notify runs async...
				nng_msleep(100);

				So(evcnt1.writeable == 1);
				So(evcnt2.readable == 1);
			});

			Convey("We can unregister them", {
				nng_unsetnotify(sock1, notify1);
				So(1);
				nng_unsetnotify(sock2, notify2);
				So(1);
			});
		});
	});
})
