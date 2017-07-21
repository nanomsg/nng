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
#include "trantest.h"

#include <string.h>

TestMain("Socket Operations", {

	atexit(nng_fini);
	//	Reset({ nng_fini(); });
	Reset({ nng_closeall(); });

	Convey("We are able to open a PAIR socket", {
		int        rv;
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);

		Reset({ nng_close(s1); });

		Convey("And we can shut it down", {
			char * buf;
			size_t sz;
			So(nng_shutdown(s1) == 0);
			So(nng_shutdown(s1) == NNG_ECLOSED);
			Convey("It can't receive", {
				So(nng_recv(s1, &buf, &sz, NNG_FLAG_ALLOC) ==
				    NNG_ECLOSED);
			});
			Convey("It can't send",
			    { So(nng_send(s1, "", 0, 0) == NNG_ECLOSED); });
			Convey("Cannot create endpoints", {
				nng_dialer   d;
				nng_listener l;
				char *       a = "inproc://closed";
				So(nng_dialer_create(&d, s1, a) ==
				    NNG_ECLOSED);
				So(nng_listener_create(&l, s1, a) ==
				    NNG_ECLOSED);
				So(nng_dial(s1, a, &d, 0) == NNG_ECLOSED);
				So(nng_listen(s1, a, &l, 0) == NNG_ECLOSED);
			});
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
			So(nng_setopt_usec(s1, nng_optid_recvtimeo, to) == 0);
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

			So(nng_setopt_usec(s1, nng_optid_sendtimeo, to) == 0);
			So(nng_sendmsg(s1, msg, 0) == NNG_ETIMEDOUT);
			So(nng_clock() >= (now + to));
			So(nng_clock() < (now + (to * 2)));
			nng_msg_free(msg);
		});

		Convey("We can set and get options", {
			int64_t to = 1234;
			int64_t v  = 0;
			size_t  sz;

			So(nng_setopt_usec(s1, nng_optid_sendtimeo, to) == 0);

			Convey("Read only options handled properly", {
				So(nng_setopt_int(s1, nng_optid_recvfd, 0) ==
				    NNG_EINVAL);
				So(nng_setopt_int(s1, nng_optid_sendfd, 0) ==
				    NNG_EINVAL);
				So(nng_setopt(s1, nng_optid_locaddr, "a", 1) ==
				    NNG_EINVAL);
				So(nng_setopt(s1, nng_optid_remaddr, "a", 1) ==
				    NNG_EINVAL);
			});

			Convey("URL option works", {
				char         url[NNG_MAXADDRLEN];
				nng_listener l;
				nng_dialer   d;
				size_t       sz;

				So(nng_listener_create(
				       &l, s1, "inproc://url1") == 0);
				So(nng_dialer_create(
				       &d, s1, "inproc://url2") == 0);
				memset(url, 0, sizeof(url));
				sz = sizeof(url);
				So(nng_listener_getopt(
				       l, nng_optid_url, url, &sz) == 0);
				So(strcmp(url, "inproc://url1") == 0);
				sz = sizeof(url);
				So(nng_dialer_getopt(
				       d, nng_optid_url, url, &sz) == 0);
				So(strcmp(url, "inproc://url2") == 0);

				Reset({
					nng_dialer_close(d);
					nng_listener_close(l);
				})
			});

			Convey("We can apply options before endpoint", {
				nng_listener l;
				char         addr[NNG_MAXADDRLEN];
				trantest_next_address(
				    addr, "ipc:///tmp/lopt_%u");

				So(nng_setopt_size(
				       s1, nng_optid_recvmaxsz, 543) == 0);
				So(nng_listener_create(&l, s1, addr) == 0);
				So(nng_listener_getopt_size(
				       l, nng_optid_recvmaxsz, &sz) == 0);
				So(sz == 543);

				Convey("Endpoint option can be overridden", {
					So(nng_listener_setopt_size(l,
					       nng_optid_recvmaxsz, 678) == 0);
					So(nng_listener_getopt_size(l,
					       nng_optid_recvmaxsz, &sz) == 0);
					So(sz == 678);
					So(nng_getopt_size(s1,
					       nng_optid_recvmaxsz, &sz) == 0);
					So(sz == 543);
				});

				Convey("And socket overrides again", {
					So(nng_setopt_size(s1,
					       nng_optid_recvmaxsz, 911) == 0);
					So(nng_listener_getopt_size(l,
					       nng_optid_recvmaxsz, &sz) == 0);
					So(sz == 911);
				});
			});
			Convey("Short size is not copied", {
				sz = 0;
				So(nng_getopt(
				       s1, nng_optid_sendtimeo, &v, &sz) == 0);
				So(sz == sizeof(v));
				So(v == 0);
				sz = 0;
				So(nng_getopt(s1, nng_optid_reconnmint, &v,
				       &sz) == 0);

				So(v == 0);
				sz = 0;
				So(nng_getopt(s1, nng_optid_reconnmaxt, &v,
				       &sz) == 0);
				So(v == 0);
			});

			Convey("Correct size is copied", {
				sz = sizeof(v);
				So(nng_getopt(
				       s1, nng_optid_sendtimeo, &v, &sz) == 0);
				So(sz == sizeof(v));
				So(v == 1234);
			});

			Convey("Short size buf is not copied", {
				int l = 5;
				sz    = 0;
				So(nng_getopt(
				       s1, nng_optid_recvbuf, &l, &sz) == 0);
				So(sz == sizeof(l));
				So(l == 5);
			});

			Convey("Insane buffer size fails", {
				So(nng_setopt_int(s1, nng_optid_recvbuf,
				       0x100000) == NNG_EINVAL);
				So(nng_setopt_int(s1, nng_optid_recvbuf,
				       -200) == NNG_EINVAL);
			});

			Convey("Negative timeout fails", {
				So(nng_setopt_usec(s1, nng_optid_recvtimeo,
				       -5) == NNG_EINVAL);
			});

			Convey("Short timeout fails", {
				to = 0;
				sz = sizeof(to) - 1;
				So(nng_setopt(s1, nng_optid_recvtimeo, &to,
				       sz) == NNG_EINVAL);
				So(nng_setopt(s1, nng_optid_reconnmint, &to,
				       sz) == NNG_EINVAL);
			});

			Convey("Bogus raw fails", {
				So(nng_setopt_int(s1, nng_optid_raw, 42) ==
				    NNG_EINVAL);
				So(nng_setopt_int(s1, nng_optid_raw, -42) ==
				    NNG_EINVAL);
				So(nng_setopt_int(s1, nng_optid_raw, 0) == 0);
				So(nng_setopt(s1, nng_optid_raw, "a", 1) ==
				    NNG_EINVAL);
			});

			Convey("Unsupported options fail", {
				char *crap = "crap";
				So(nng_setopt(s1, nng_optid_sub_subscribe,
				       crap, strlen(crap)) == NNG_ENOTSUP);
			});

			Convey("Bogus sizes fail", {
				size_t v;
				int    i;

				So(nng_setopt_size(
				       s1, nng_optid_recvmaxsz, 6550) == 0);
				So(nng_getopt_size(
				       s1, nng_optid_recvmaxsz, &v) == 0);
				So(v == 6550);

				v = 102400;
				So(nng_setopt(s1, nng_optid_recvmaxsz, &v,
				       1) == NNG_EINVAL);
				So(nng_getopt_size(
				       s1, nng_optid_recvmaxsz, &v) == 0);
				So(v == 6550);

				i = 42;
				So(nng_setopt(s1, nng_optid_recvbuf, &i, 1) ==
				    NNG_EINVAL);

				if (sizeof(size_t) == 8) {
					v = 0x10000;
					v <<= 30;
					So(nng_setopt_size(s1,
					       nng_optid_recvmaxsz,
					       v) == NNG_EINVAL);
					So(nng_getopt_size(s1,
					       nng_optid_recvmaxsz, &v) == 0);
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
			rv = nng_dial(s1, "inproc://no", NULL, 0);
			So(rv == NNG_ECONNREFUSED);
		});

		Convey("Dialing asynch does not get refused", {
			char *     buf;
			size_t     sz;
			nng_socket s2;
			char *     a = "inproc://asy";
			So(nng_dial(s1, a, NULL, NNG_FLAG_NONBLOCK) == 0);
			Convey("And connects late", {
				So(nng_pair_open(&s2) == 0);
				Reset({ nng_close(s2); });
				So(nng_listen(s2, a, NULL, 0) == 0);
				nng_usleep(100000);
				So(nng_send(s1, "abc", 4, 0) == 0);
				So(nng_recv(s2, &buf, &sz, NNG_FLAG_ALLOC) ==
				    0);
				So(sz == 4);
				So(memcmp(buf, "abc", 4) == 0);
				nng_free(buf, sz);
			});
		});

		Convey("Listening works", {
			char *       a = "inproc://here";
			nng_listener l;
			rv = nng_listen(s1, a, &l, 0);
			So(rv == 0);
			So(l != 0);

			Convey("Second listen fails ADDRINUSE", {
				rv = nng_listen(s1, a, NULL, 0);
				So(rv == NNG_EADDRINUSE);
			});

			Convey("We cannot try to start a listener again",
			    { So(nng_listener_start(l, 0) == NNG_ESTATE); });

			Convey("We can connect to it", {
				nng_socket s2;
				So(nng_pair_open(&s2) == 0);
				Reset({ nng_close(s2); });
				So(nng_dial(s2, a, NULL, 0) == 0);
				nng_close(s2);
			});
		});

		Convey("Dialer creation ok", {
			nng_dialer ep;
			char *     a = "tcp://127.0.0.1:2929";
			So(nng_dialer_create(&ep, s1, a) == 0);
			Convey("Options work", {
				size_t sz;
				So(nng_dialer_setopt_size(
				       ep, nng_optid_recvmaxsz, 4321) == 0);
				So(nng_dialer_getopt_size(
				       ep, nng_optid_recvmaxsz, &sz) == 0);
				So(sz == 4321);
			});
			Convey("Socket opts not for dialer", {
				// Not appropriate for dialer.
				So(nng_dialer_setopt_int(
				       ep, nng_optid_raw, 1) == NNG_ENOTSUP);
				So(nng_dialer_setopt_usec(ep,
				       nng_optid_reconnmint,
				       1) == NNG_ENOTSUP);
			});
			Convey("Bad size checks", {
				So(nng_dialer_setopt(ep, nng_optid_recvmaxsz,
				       "a", 1) == NNG_EINVAL);
			});
			Convey("Cannot listen",
			    { So(nng_listener_start(ep, 0) == NNG_ENOTSUP); });

		});

		Convey("Listener creation ok", {
			nng_listener ep;
			char *       a = "tcp://127.0.0.1:2929";
			So(nng_listener_create(&ep, s1, a) == 0);
			Convey("Options work", {
				size_t sz;
				So(nng_listener_setopt_size(
				       ep, nng_optid_recvmaxsz, 4321) == 0);
				So(nng_listener_getopt_size(
				       ep, nng_optid_recvmaxsz, &sz) == 0);
				So(sz == 4321);
			});
			Convey("Socket opts not for dialer", {
				// Not appropriate for dialer.
				So(nng_listener_setopt_int(
				       ep, nng_optid_raw, 1) == NNG_ENOTSUP);
				So(nng_listener_setopt_usec(ep,
				       nng_optid_reconnmint,
				       1) == NNG_ENOTSUP);
			});
			Convey("Bad size checks", {
				So(nng_listener_setopt(ep, nng_optid_recvmaxsz,
				       "a", 1) == NNG_EINVAL);
			});
			Convey("Cannot dial",
			    { So(nng_dialer_start(ep, 0) == NNG_ENOTSUP); });
		});

		Convey("Cannot access absent ep options", {
			size_t   s;
			int      i;
			uint64_t t;

			So(nng_dialer_setopt_size(
			       1999, nng_optid_recvmaxsz, 10) == NNG_ENOENT);
			So(nng_listener_setopt_size(
			       1999, nng_optid_recvmaxsz, 10) == NNG_ENOENT);

			s = 1;
			So(nng_dialer_getopt(1999, nng_optid_raw, &i, &s) ==
			    NNG_ENOENT);
			So(nng_listener_getopt(1999, nng_optid_raw, &i, &s) ==
			    NNG_ENOENT);

			So(nng_dialer_getopt_size(
			       1999, nng_optid_recvmaxsz, &s) == NNG_ENOENT);
			So(nng_listener_getopt_size(
			       1999, nng_optid_recvmaxsz, &s) == NNG_ENOENT);

			So(nng_dialer_getopt_int(1999, nng_optid_raw, &i) ==
			    NNG_ENOENT);
			So(nng_listener_getopt_int(1999, nng_optid_raw, &i) ==
			    NNG_ENOENT);

			So(nng_dialer_getopt_usec(
			       1999, nng_optid_linger, &t) == NNG_ENOENT);
			So(nng_listener_getopt_usec(
			       1999, nng_optid_linger, &t) == NNG_ENOENT);

		});

		Convey("Cannot set dialer opts when running", {
			nng_dialer ep;
			char       addr[NNG_MAXADDRLEN];

			trantest_next_address(addr, "ipc:///tmp/sock_test_%u");
			So(nng_dialer_create(&ep, s1, addr) == 0);
			So(nng_dialer_start(ep, NNG_FLAG_NONBLOCK) == 0);
			So(nng_dialer_setopt_size(
			       ep, nng_optid_recvmaxsz, 10) == NNG_ESTATE);
			So(nng_dialer_close(ep) == 0);
			So(nng_dialer_close(ep) == NNG_ENOENT);
		});

		Convey("Cannot set listener opts when running", {
			nng_listener ep;
			char         addr[NNG_MAXADDRLEN];

			trantest_next_address(addr, "ipc:///tmp/sock_test_%u");

			So(nng_listener_create(&ep, s1, addr) == 0);
			So(nng_listener_start(ep, 0) == 0);
			So(nng_listener_setopt_size(
			       ep, nng_optid_recvmaxsz, 10) == NNG_ESTATE);
			So(nng_listener_close(ep) == 0);
			So(nng_listener_close(ep) == NNG_ENOENT);
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

			So(nng_setopt_int(s1, nng_optid_recvbuf, 1) == 0);
			So(nng_getopt_int(s1, nng_optid_recvbuf, &len) == 0);
			So(len == 1);

			So(nng_setopt_int(s1, nng_optid_sendbuf, 1) == 0);
			So(nng_setopt_int(s2, nng_optid_sendbuf, 1) == 0);

			So(nng_setopt_usec(s1, nng_optid_sendtimeo, to) == 0);
			So(nng_setopt_usec(s1, nng_optid_recvtimeo, to) == 0);
			So(nng_setopt_usec(s2, nng_optid_sendtimeo, to) == 0);
			So(nng_setopt_usec(s2, nng_optid_recvtimeo, to) == 0);

			So(nng_listen(s1, a, NULL, 0) == 0);
			So(nng_dial(s2, a, NULL, 0) == 0);

			So(nng_send(s1, "abc", 4, 0) == 0);
			So(nng_recv(s2, &buf, &sz, NNG_FLAG_ALLOC) == 0);
			So(buf != NULL);
			So(sz == 4);
			So(memcmp(buf, "abc", 4) == 0);
			nng_free(buf, sz);
		});
	});
})
