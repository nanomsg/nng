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

Main({
	nni_init();

	Test("Socket Operations", {

	Convey("We are able to open a PAIR socket", {
		int rv;
		nng_socket sock = NULL;

		rv = nng_open(&sock, NNG_PROTO_PAIR);
		So(rv == 0);
		So(sock != NULL);

		Reset({
			nng_close(sock);
		})

		Convey("And we can shut it down", {
			rv = nng_shutdown(sock);
			So(rv == 0);
			rv = nng_shutdown(sock);
			So(rv == NNG_ECLOSED);
		})

		Convey("It's type is still proto", {
			So(nng_protocol(sock) == NNG_PROTO_PAIR);
		})

		Convey("Recv with no pipes times out correctly", {
			nng_msg *msg = NULL;
			int64_t when = 500000;
			uint64_t now;

			now = nni_clock();

			rv = nng_setopt(sock, NNG_OPT_RCVTIMEO, &when,
				sizeof (when));
			So(rv == 0);
			rv = nng_recvmsg(sock, &msg, 0);
			So(rv == NNG_ETIMEDOUT);
			So(msg == NULL);
			So(nni_clock() >= (now + when));
			So(nni_clock() < (now + (when * 2)));
		})

		Convey("Recv nonblock with no pipes gives EAGAIN", {
			nng_msg *msg = NULL;
			rv = nng_recvmsg(sock, &msg, NNG_FLAG_NONBLOCK);
			So(rv == NNG_EAGAIN);
			So(msg == NULL);
		})

		Convey("Send with no pipes times out correctly", {
			nng_msg *msg = NULL;
			int64_t when = 500000;
			uint64_t now;

			// We cheat to get access to the core's clock.
			So(nng_msg_alloc(&msg, 0) == 0);
			So(msg != NULL);
			now = nni_clock();

			rv = nng_setopt(sock, NNG_OPT_SNDTIMEO, &when,
				sizeof (when));
			So(rv == 0);
			rv = nng_sendmsg(sock, msg, 0);
			So(rv == NNG_ETIMEDOUT);
			So(nni_clock() >= (now + when));
			So(nni_clock() < (now + (when * 2)));
			nng_msg_free(msg);
		})

		Convey("We can set and get options", {
			int64_t when = 1234;
			int64_t check = 0;
			size_t sz;
			rv = nng_setopt(sock, NNG_OPT_SNDTIMEO, &when,
				sizeof (when));
			So(rv == 0);
			sz = sizeof (check);
			Convey("Short size is not copied", {
				sz = 0;
				rv = nng_getopt(sock, NNG_OPT_SNDTIMEO,
					&check, &sz);
				So(rv == 0);
				So(sz == sizeof (check));
				So(check == 0);
			})
			Convey("Correct size is copied", {
				sz = sizeof (check);
				rv = nng_getopt(sock, NNG_OPT_SNDTIMEO, &check,
					&sz);
				So(rv == 0);
				So(sz == sizeof (check));
				So(check == 1234);
			})
		})

		Convey("Bogus URLs not supported", {
			Convey("Dialing fails properly", {
				rv = nng_dial(sock, "bogus://somewhere", NULL, 0);
				So(rv == NNG_ENOTSUP);
			})
			Convey("Listening fails properly", {
				rv = nng_listen(sock, "bogus://elsewhere", NULL, 0);
				So(rv == NNG_ENOTSUP);
			})
		})

		Convey("Dialing synch can get refused", {
			rv = nng_dial(sock, "inproc://notthere", NULL, NNG_FLAG_SYNCH);
			So(rv == NNG_ECONNREFUSED);
		})

		Convey("Listening works", {
			rv = nng_listen(sock, "inproc://here", NULL, NNG_FLAG_SYNCH);
			So(rv == 0);

			Convey("Second listen fails ADDRINUSE", {
				rv = nng_listen(sock, "inproc://here", NULL, NNG_FLAG_SYNCH);
				So(rv == NNG_EADDRINUSE);
			})

			Convey("We can connect to it", {
				nng_socket *sock2 = NULL;
				rv = nng_open(&sock2, NNG_PROTO_PAIR);
				So(rv == 0);
				rv = nng_dial(sock2, "inproc://here", NULL, NNG_FLAG_SYNCH);
				So(rv == 0);
				nng_close(sock2);
			})
		})

		Convey("We can send and receive messages", {
			nng_socket sock2 = NULL;
			int len = 1;
			nng_msg *msg;
			uint64_t second = 1000000;

			rv = nng_open(&sock2, NNG_PROTO_PAIR);
			So(rv == 0);

			rv = nng_setopt(sock, NNG_OPT_RCVBUF, &len, sizeof (len));
			So(rv == 0);
			rv = nng_setopt(sock, NNG_OPT_SNDBUF, &len, sizeof (len));
			So(rv == 0);

			rv = nng_setopt(sock2, NNG_OPT_RCVBUF, &len, sizeof (len));
			So(rv == 0);
			rv = nng_setopt(sock2, NNG_OPT_SNDBUF, &len, sizeof (len));
			So(rv == 0);

			rv = nng_setopt(sock, NNG_OPT_SNDTIMEO, &second, sizeof (second));
			So(rv == 0);
			rv = nng_setopt(sock, NNG_OPT_RCVTIMEO, &second, sizeof (second));
			So(rv == 0);
			rv = nng_setopt(sock2, NNG_OPT_SNDTIMEO, &second, sizeof (second));
			So(rv == 0);
			rv = nng_setopt(sock2, NNG_OPT_RCVTIMEO, &second, sizeof (second));
			So(rv == 0);

			rv = nng_listen(sock, "inproc://test1", NULL, NNG_FLAG_SYNCH);
			So(rv == 0);
			rv = nng_dial(sock2, "inproc://test1", NULL, 0);
			So(rv == 0);

			rv = nng_msg_alloc(&msg, 3);
			So(rv == 0);
			So(nng_msg_len(msg) == 3);
			So(nng_msg_body(msg) != NULL);
			memcpy(nng_msg_body(msg), "abc", 3);

			rv = nng_sendmsg(sock, msg, 0);
			So(rv == 0);

			msg = NULL;
			rv = nng_recvmsg(sock2, &msg, 0);
			So(rv == 0);
			So(msg != NULL);
			So(nng_msg_len(msg) == 3);
			So(memcmp(nng_msg_body(msg), "abc", 3) == 0);
			nng_msg_free(msg);
			nng_close(sock2);
		})
	})
	})

	nni_fini();
})
