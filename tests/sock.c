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

#include <string.h>

TestMain("Socket Operations", {

	Reset({ nng_fini(); });

	Convey("We are able to open a PAIR socket", {
		int        rv;
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);

		Reset({ nng_close(s1); });

		Convey("And we can shut it down", {
			So(nng_shutdown(s1) == 0);
			So(nng_shutdown(s1) == NNG_ECLOSED);
		});

		Convey("It's type & peer are still PAIR", {
			So(nng_protocol(s1) == NNG_PROTO_PAIR);
			So(nng_peer(s1) == NNG_PROTO_PAIR);
		});

		Convey("Recv with no pipes times out correctly", {
			nng_msg *msg = NULL;
			int64_t  to  = 100000;
			uint64_t now;

			now = nng_clock();
			So(now > 0);
			So(nng_setopt_duration(s1, NNG_OPT_RCVTIMEO, to) == 0);
			So(nng_recvmsg(s1, &msg, 0) == NNG_ETIMEDOUT);
			So(msg == NULL);
			So(nng_clock() >= (now + to));
			So(nng_clock() < (now + (to * 2)));
		});

		Convey("Recv nonblock with no pipes gives EAGAIN", {
			nng_msg *msg = NULL;
			So(nng_recvmsg(s1, &msg, NNG_FLAG_NONBLOCK) ==
			    NNG_EAGAIN);
			So(msg == NULL);
		});

		Convey("Send with no pipes times out correctly", {
			nng_msg *msg = NULL;
			int64_t  to  = 100000;
			uint64_t now;

			// We cheat to get access to the core's clock.
			So(nng_msg_alloc(&msg, 0) == 0);
			So(msg != NULL);
			now = nng_clock();

			So(nng_setopt_duration(s1, NNG_OPT_SNDTIMEO, to) == 0);
			So(nng_sendmsg(s1, msg, 0) == NNG_ETIMEDOUT);
			So(nng_clock() >= (now + to));
			So(nng_clock() < (now + (to * 2)));
			nng_msg_free(msg);
		});

		Convey("We can set and get options", {
			int64_t to = 1234;
			int64_t v  = 0;
			size_t  sz;

			So(nng_setopt_duration(s1, NNG_OPT_SNDTIMEO, to) == 0);

			Convey("Short size is not copied", {
				sz = 0;
				So(nng_getopt(s1, NNG_OPT_SNDTIMEO, &v, &sz) ==
				    0);
				So(sz == sizeof(v));
				So(v == 0);
			});

			Convey("Correct size is copied", {
				sz = sizeof(v);
				So(nng_getopt(s1, NNG_OPT_SNDTIMEO, &v, &sz) ==
				    0);
				So(sz == sizeof(v));
				So(v == 1234);
			});

			Convey("Short size buf is not copied", {
				int l = 5;
				sz    = 0;
				So(nng_getopt(s1, NNG_OPT_RCVBUF, &l, &sz) ==
				    0);
				So(sz == sizeof(l));
				So(l == 5);
			});

			Convey("Insane buffer size fails", {
				So(nng_setopt_int(s1, NNG_OPT_RCVBUF,
				       0x100000) == NNG_EINVAL);
			});

			Convey("Negative timeout fails", {
				So(nng_setopt_duration(s1, NNG_OPT_RCVTIMEO,
				       -5) == NNG_EINVAL);
			});

			Convey("Short timeout fails", {
				to = 0;
				sz = sizeof(to) - 1;
				So(nng_setopt(s1, NNG_OPT_RCVTIMEO, &to, sz) ==
				    NNG_EINVAL);
			});

			Convey("Bogus raw fails", {
				So(nng_setopt_int(s1, NNG_OPT_RAW, 42) ==
				    NNG_EINVAL);
				So(nng_setopt_int(s1, NNG_OPT_RAW, -42) ==
				    NNG_EINVAL);
				So(nng_setopt_int(s1, NNG_OPT_RAW, 0) == 0);
			});

			Convey("Unsupported options fail", {
				char *crap = "crap";
				So(nng_setopt(s1, NNG_OPT_SUBSCRIBE, crap,
				       strlen(crap)) == NNG_ENOTSUP);
			});

			Convey("Bogus sizes fail", {
				size_t v;

				So(nng_setopt_size(
				       s1, NNG_OPT_RCVMAXSZ, 6550) == 0);
				So(nng_getopt_size(s1, NNG_OPT_RCVMAXSZ, &v) ==
				    0);
				So(v == 6550);

				v = 102400;
				So(nng_setopt(s1, NNG_OPT_RCVMAXSZ, &v, 1) ==
				    NNG_EINVAL);
				So(nng_getopt_size(s1, NNG_OPT_RCVMAXSZ, &v) ==
				    0);
				So(v == 6550);

				if (sizeof(size_t) == 8) {
					v = 0x10000;
					v <<= 30;
					So(nng_setopt_size(s1,
					       NNG_OPT_RCVMAXSZ,
					       v) == NNG_EINVAL);
					So(nng_getopt_size(
					       s1, NNG_OPT_RCVMAXSZ, &v) == 0);
					So(v == 6550);
				}
			});
		});

		Convey("Bogus URLs not supported", {
			Convey("Dialing fails properly", {
				rv = nng_dial(s1, "bogus://1", NULL, 0);
				So(rv == NNG_ENOTSUP);
			});
			Convey("Listening fails properly", {
				rv = nng_listen(s1, "bogus://2", NULL, 0);
				So(rv == NNG_ENOTSUP);
			});
		});

		Convey("Dialing synch can get refused", {
			rv = nng_dial(s1, "inproc://no", NULL, NNG_FLAG_SYNCH);
			So(rv == NNG_ECONNREFUSED);
		});

		Convey("Listening works", {
			char *a = "inproc://here";
			rv      = nng_listen(s1, a, NULL, NNG_FLAG_SYNCH);
			So(rv == 0);

			Convey("Second listen fails ADDRINUSE", {
				rv = nng_listen(s1, a, NULL, NNG_FLAG_SYNCH);
				So(rv == NNG_EADDRINUSE);
			});

			Convey("We can connect to it", {
				nng_socket s2;
				So(nng_pair_open(&s2) == 0);
				Reset({ nng_close(s2); });
				So(nng_dial(s2, a, NULL, NNG_FLAG_SYNCH) == 0);
				nng_close(s2);
			});
		});

		Convey("We can send and receive messages", {
			nng_socket s2;
			int        len;
			size_t     sz;
			uint64_t   to = 3000000;
			char *     buf;
			char *     a = "inproc://t1";

			So(nng_pair_open(&s2) == 0);
			Reset({ nng_close(s2); });

			So(nng_setopt_int(s1, NNG_OPT_RCVBUF, 1) == 0);
			So(nng_getopt_int(s1, NNG_OPT_RCVBUF, &len) == 0);
			So(len == 1);

			So(nng_setopt_int(s1, NNG_OPT_SNDBUF, 1) == 0);
			So(nng_setopt_int(s2, NNG_OPT_SNDBUF, 1) == 0);

			So(nng_setopt_duration(s1, NNG_OPT_SNDTIMEO, to) == 0);
			So(nng_setopt_duration(s1, NNG_OPT_RCVTIMEO, to) == 0);
			So(nng_setopt_duration(s2, NNG_OPT_SNDTIMEO, to) == 0);
			So(nng_setopt_duration(s2, NNG_OPT_RCVTIMEO, to) == 0);

			So(nng_listen(s1, a, NULL, NNG_FLAG_SYNCH) == 0);
			So(nng_dial(s2, a, NULL, NNG_FLAG_SYNCH) == 0);

			So(nng_send(s1, "abc", 4, 0) == 0);
			So(nng_recv(s2, &buf, &sz, NNG_FLAG_ALLOC) == 0);
			So(buf != NULL);
			So(sz == 4);
			So(memcmp(buf, "abc", 4) == 0);
			nng_free(buf, sz);
		});
	});
})
