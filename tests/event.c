//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "core/nng_impl.h"
#include <string.h>

#define	APPENDSTR(m, s)	nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)	So(nng_msg_len(m) == strlen(s));\
			So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)
struct evcnt {
	nng_socket *sock;
	int readable;
	int writeable;
	int pipeadd;
	int piperem;
	int epadd;
	int eprem;
	int err;
};

void
bump(nng_event *ev, void *arg)
{
	struct evcnt *cnt = arg;

	if (nng_event_socket(ev) != cnt->sock) {
		nni_panic("Incorrect socket! %p != %p",
		    nng_event_socket(ev), cnt->sock);
	}
	switch (nng_event_type(ev)) {
	case NNG_EV_CAN_SEND:
		cnt->writeable++;
		break;

	case NNG_EV_CAN_RECV:
		cnt->readable++;
		break;

	case NNG_EV_PIPE_ADD:
		cnt->pipeadd++;
		break;

	case NNG_EV_PIPE_REM:
		cnt->piperem++;
		break;

	case NNG_EV_ENDPT_ADD:
		cnt->epadd++;
		break;

	case NNG_EV_ENDPT_REM:
		cnt->eprem++;
		break;

	default:
		nni_panic("Invalid event type %d", nng_event_type(ev));
		break;
	}
}

Main({
	const char *addr = "inproc://test";

	nni_init();

	Test("Event Handling", {
		Convey("Given a connected pair of pair sockets", {
			nng_socket *sock1;
			nng_socket *sock2;
			struct evcnt evcnt1;
			struct evcnt evcnt2;
			nng_notify *notify1;
			nng_notify *notify2;

			So(nng_open(&sock1, NNG_PROTO_PAIR) == 0);
			So(nng_open(&sock2, NNG_PROTO_PAIR) == 0);

			memset(&evcnt1, 0, sizeof (evcnt1));
			memset(&evcnt2, 0, sizeof (evcnt2));
			evcnt1.sock = sock1;
			evcnt2.sock = sock2;

			Reset({
				nng_close(sock1);
				nng_close(sock2);
			})

			So(nng_listen(sock1, addr, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(sock2, addr, NULL, NNG_FLAG_SYNCH) == 0);

			// Let everything connect.
			nni_usleep(100000);

			Convey("We can register callbacks", {
				So((notify1 = nng_setnotify(sock1, NNG_EV_CAN_SEND, bump, &evcnt1)) != NULL);
				So((notify2 = nng_setnotify(sock2, NNG_EV_CAN_RECV, bump, &evcnt2)) != NULL);

				Convey("They are called", {
					nni_msg *msg;

					So(nni_msg_alloc(&msg, 0) == 0);
					APPENDSTR(msg, "abc");

					So(nng_sendmsg(sock1, msg, 0) == 0);
					So(nng_recvmsg(sock2, &msg, 0) == 0);

					CHECKSTR(msg, "abc");
					nni_msg_free(msg);

					// The notify runs async...
					nni_usleep(100000);

					So(evcnt1.writeable == 1);
					So(evcnt2.readable == 1);
				})

				Convey("We can unregister them", {
					nng_unsetnotify(sock1, notify1);
					So(1);
					nng_unsetnotify(sock2, notify2);
					So(1);
				})
			})
		})
	})

	nni_fini();
})
