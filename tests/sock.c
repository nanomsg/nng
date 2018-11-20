//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/protocol/pubsub0/sub.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"
#include "trantest.h"

#define SECONDS(x) ((x) *1000)

TestMain("Socket Operations", {
	atexit(nng_fini);
	//	Reset({ nng_fini(); });
	Reset({ nng_closeall(); });

	Convey("We are able to open a PAIR socket", {
		int        rv;
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);

		Reset({ nng_close(s1); });

		Convey("Recv with no pipes times out correctly", {
			nng_msg *    msg = NULL;
			nng_duration to  = 100;
			uint64_t     now;

			now = getms();
			So(now > 0);
			So(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, to) == 0);
			So(nng_recvmsg(s1, &msg, 0) == NNG_ETIMEDOUT);
			So(msg == NULL);
			So(getms() >= (now + to));
			So(getms() < (now + (to * 2)));
		});

		Convey("Recv nonblock with no pipes gives EAGAIN", {
			nng_msg *msg = NULL;
			So(nng_recvmsg(s1, &msg, NNG_FLAG_NONBLOCK) ==
			    NNG_EAGAIN);
			So(msg == NULL);
		});

		Convey("Send with no pipes times out correctly", {
			nng_msg *    msg = NULL;
			nng_duration to  = 100;
			uint64_t     now;

			// We cheat to get access to the core's clock.
			So(nng_msg_alloc(&msg, 0) == 0);
			So(msg != NULL);
			now = getms();

			So(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, to) == 0);
			So(nng_sendmsg(s1, msg, 0) == NNG_ETIMEDOUT);
			So(getms() >= (now + to));
			So(getms() < (now + (to * 2)));
			nng_msg_free(msg);
		});

		Convey("We can set and get options", {
			nng_duration to = 1234;

			So(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, to) == 0);

			Convey("Read only options handled properly", {
				So(nng_setopt_int(s1, NNG_OPT_RECVFD, 0) ==
				    NNG_EREADONLY);
				So(nng_setopt_int(s1, NNG_OPT_SENDFD, 0) ==
				    NNG_EREADONLY);
				So(nng_setopt(s1, NNG_OPT_LOCADDR, "a", 1) ==
				    NNG_EREADONLY);
			});

			Convey("Sockname option works", {
				char   name[128]; // 64 is max
				char * allocd;
				size_t sz;
				sz = sizeof(name);
				So(nng_getopt(
				       s1, NNG_OPT_SOCKNAME, name, &sz) == 0);
				So(sz > 0 && sz < 64);
				So(sz == strlen(name) + 1);
				So(atoi(name) == (int) s1.id);

				So(nng_setopt(
				       s1, NNG_OPT_SOCKNAME, "hello", 6) == 0);
				sz = sizeof(name);
				So(nng_getopt(
				       s1, NNG_OPT_SOCKNAME, name, &sz) == 0);
				So(sz == 6);
				So(strcmp(name, "hello") == 0);

				memset(name, 'A', 64);
				name[64] = '\0';

				// strings must be NULL terminated
				So(nng_setopt(s1, NNG_OPT_SOCKNAME, name, 5) ==
				    NNG_EINVAL);

				So(nng_getopt_string(
				       s1, NNG_OPT_SOCKNAME, &allocd) == 0);
				So(strlen(allocd) == 5);
				So(strcmp(allocd, "hello") == 0);
				nng_strfree(allocd);
			});

			Convey("Oversize sockname handled right", {
				char   name[256]; // 64 is max
				size_t sz = sizeof(name);
				memset(name, 'A', sz);
				So(nng_setopt(s1, NNG_OPT_SOCKNAME, name,
				       sz) == NNG_EINVAL);
				name[sz - 1] = '\0';
				So(nng_setopt(s1, NNG_OPT_SOCKNAME, name,
				       sz) == NNG_EINVAL);

				strcpy(name, "hello");
				So(nng_setopt(
				       s1, NNG_OPT_SOCKNAME, name, sz) == 0);
				sz = sizeof(name);
				memset(name, 'B', sz);
				So(nng_getopt(
				       s1, NNG_OPT_SOCKNAME, name, &sz) == 0);
				So(sz == 6);
				So(strcmp(name, "hello") == 0);
			});

			Convey("RAW option works", {
				bool raw;
				So(nng_getopt_bool(s1, NNG_OPT_RAW, &raw) ==
				    0);
				So(raw == false);
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
				       l, NNG_OPT_URL, url, &sz) == 0);
				So(strcmp(url, "inproc://url1") == 0);
				So(nng_listener_setopt(l, NNG_OPT_URL, url,
				       sz) == NNG_EREADONLY);
				sz = sizeof(url);
				So(nng_dialer_getopt(
				       d, NNG_OPT_URL, url, &sz) == 0);
				So(strcmp(url, "inproc://url2") == 0);

				So(nng_dialer_setopt(d, NNG_OPT_URL, url,
				       sz) == NNG_EREADONLY);
				Reset({
					nng_dialer_close(d);
					nng_listener_close(l);
				});
			});

			Convey("We can apply options before endpoint", {
				nng_listener l;
				char         addr[NNG_MAXADDRLEN];
				size_t       sz;

				trantest_next_address(
				    addr, "ipc:///tmp/lopt_%u");

				So(nng_setopt_size(
				       s1, NNG_OPT_RECVMAXSZ, 543) == 0);
				So(nng_listener_create(&l, s1, addr) == 0);
				So(nng_listener_getopt_size(
				       l, NNG_OPT_RECVMAXSZ, &sz) == 0);
				So(sz == 543);

				Convey("Endpoint option can be overridden", {
					So(nng_listener_setopt_size(l,
					       NNG_OPT_RECVMAXSZ, 678) == 0);
					So(nng_listener_getopt_size(l,
					       NNG_OPT_RECVMAXSZ, &sz) == 0);
					So(sz == 678);
					So(nng_getopt_size(s1,
					       NNG_OPT_RECVMAXSZ, &sz) == 0);
					So(sz == 543);
				});

				Convey("And socket overrides again", {
					So(nng_setopt_size(s1,
					       NNG_OPT_RECVMAXSZ, 911) == 0);
					So(nng_listener_getopt_size(l,
					       NNG_OPT_RECVMAXSZ, &sz) == 0);
					So(sz == 911);
				});
			});
			Convey("Short size is not copied", {
				size_t sz = 0;
				to        = 0;
				So(nng_getopt(s1, NNG_OPT_SENDTIMEO, &to,
				       &sz) == NNG_EINVAL);
				So(sz == sizeof(to));
				So(to == 0);
				sz = 0;
				So(nng_getopt(s1, NNG_OPT_RECONNMINT, &to,
				       &sz) == NNG_EINVAL);

				So(to == 0);
				sz = 0;
				So(nng_getopt(s1, NNG_OPT_RECONNMAXT, &to,
				       &sz) == NNG_EINVAL);
				So(to == 0);
			});

			Convey("Correct size is copied", {
				size_t sz = sizeof(to);
				So(nng_getopt(
				       s1, NNG_OPT_SENDTIMEO, &to, &sz) == 0);
				So(sz == sizeof(to));
				So(to == 1234);
			});

			Convey("Short size buf is not copied", {
				int    l  = 5;
				size_t sz = 0;
				So(nng_getopt(s1, NNG_OPT_RECVBUF, &l, &sz) ==
				    NNG_EINVAL);
				So(sz == sizeof(l));
				So(l == 5);
			});

			Convey("Insane buffer size fails", {
				So(nng_setopt_int(s1, NNG_OPT_RECVBUF,
				       0x100000) == NNG_EINVAL);
				So(nng_setopt_int(s1, NNG_OPT_RECVBUF, -200) ==
				    NNG_EINVAL);
			});

			Convey("Negative timeout fails", {
				So(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, -5) ==
				    NNG_EINVAL);
			});

			Convey("Short timeout fails", {
				size_t sz = sizeof(to) - 1;
				to        = 0;
				So(nng_setopt(s1, NNG_OPT_RECVTIMEO, &to,
				       sz) == NNG_EINVAL);
				So(nng_setopt(s1, NNG_OPT_RECONNMINT, &to,
				       sz) == NNG_EINVAL);
			});

			Convey("Cannot set raw", {
				So(nng_setopt_bool(s1, NNG_OPT_RAW, true) ==
				    NNG_EREADONLY);
			});

			Convey("Unsupported options fail", {
				char *crap = "crap";
				So(nng_setopt(s1, NNG_OPT_SUB_SUBSCRIBE, crap,
				       strlen(crap)) == NNG_ENOTSUP);
			});

			Convey("Bogus sizes fail", {
				size_t v;
				int    i;

				So(nng_setopt_size(
				       s1, NNG_OPT_RECVMAXSZ, 6550) == 0);
				So(nng_getopt_size(
				       s1, NNG_OPT_RECVMAXSZ, &v) == 0);
				So(v == 6550);

				v = 102400;
				So(nng_setopt(s1, NNG_OPT_RECVMAXSZ, &v, 1) ==
				    NNG_EINVAL);
				So(nng_getopt_size(
				       s1, NNG_OPT_RECVMAXSZ, &v) == 0);
				So(v == 6550);

				i = 42;
				So(nng_setopt(s1, NNG_OPT_RECVBUF, &i, 1) ==
				    NNG_EINVAL);

				if (sizeof(size_t) == 8) {
					v = 0x10000;
					v <<= 30;
					So(nng_setopt_size(s1,
					       NNG_OPT_RECVMAXSZ,
					       v) == NNG_EINVAL);
					So(nng_getopt_size(s1,
					       NNG_OPT_RECVMAXSZ, &v) == 0);
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
			So(nng_setopt_ms(s1, NNG_OPT_RECONNMINT, 10) == 0);
			So(nng_setopt_ms(s1, NNG_OPT_RECONNMAXT, 10) == 0);
			So(nng_dial(s1, a, NULL, NNG_FLAG_NONBLOCK) == 0);
			Convey("And connects late", {
				So(nng_pair_open(&s2) == 0);
				Reset({ nng_close(s2); });
				So(nng_listen(s2, a, NULL, 0) == 0);
				nng_msleep(100);
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
			nng_listener l = NNG_LISTENER_INITIALIZER;

			So(nng_listener_id(l) < 0);
			rv = nng_listen(s1, a, &l, 0);
			So(rv == 0);
			So(nng_listener_id(l) > 0);

			Convey("Second listen fails ADDRINUSE", {
				rv = nng_listen(s1, a, NULL, 0);
				So(rv == NNG_EADDRINUSE);
			});

			Convey("We cannot try to start a listener again",
			    { So(nng_listener_start(l, 0) == NNG_ESTATE); });

			Convey("We can connect to it", {
				nng_socket s2 = NNG_SOCKET_INITIALIZER;
				So(nng_socket_id(s2) < 0);
				So(nng_pair_open(&s2) == 0);
				Reset({ nng_close(s2); });
				So(nng_dial(s2, a, NULL, 0) == 0);
				nng_close(s2);
			});
		});

		Convey("Dialer creation ok", {
			nng_dialer ep = NNG_DIALER_INITIALIZER;
			char *     a  = "tcp://127.0.0.1:2929";

			So(nng_dialer_id(ep) < 0);
			So(nng_dialer_create(&ep, s1, a) == 0);
			So(nng_dialer_id(ep) > 0);

			Convey("Options work", {
				size_t sz;
				So(nng_dialer_setopt_size(
				       ep, NNG_OPT_RECVMAXSZ, 4321) == 0);
				So(nng_dialer_getopt_size(
				       ep, NNG_OPT_RECVMAXSZ, &sz) == 0);
				So(sz == 4321);
			});

			Convey("Cannot access as listener", {
				bool         b;
				nng_listener l;
				l.id = ep.id;
				So(nng_listener_getopt_bool(
				       l, NNG_OPT_RAW, &b) == NNG_ENOENT);
				So(nng_listener_close(l) == NNG_ENOENT);
			});

			Convey("Socket opts not for dialer", {
				// Not appropriate for dialer.
				So(nng_dialer_setopt_bool(
				       ep, NNG_OPT_RAW, true) == NNG_ENOTSUP);
				So(nng_dialer_setopt_ms(ep, NNG_OPT_SENDTIMEO,
				       1) == NNG_ENOTSUP);
				So(nng_dialer_setopt_string(ep,
				       NNG_OPT_SOCKNAME,
				       "bogus") == NNG_ENOTSUP);
			});

			Convey("URL is readonly", {
				So(nng_dialer_setopt_string(ep, NNG_OPT_URL,
				       "tcp://somewhere.else.com:8888") ==
				    NNG_EREADONLY);
			});
			Convey("Bad size checks", {
				So(nng_dialer_setopt(ep, NNG_OPT_RECVMAXSZ,
				       "a", 1) == NNG_EINVAL);
			});
		});

		Convey("Listener creation ok", {
			nng_listener ep;
			char *       a = "tcp://127.0.0.1:2929";
			So(nng_listener_create(&ep, s1, a) == 0);
			Convey("Options work", {
				size_t sz;
				So(nng_listener_setopt_size(
				       ep, NNG_OPT_RECVMAXSZ, 4321) == 0);
				So(nng_listener_getopt_size(
				       ep, NNG_OPT_RECVMAXSZ, &sz) == 0);
				So(sz == 4321);
			});
			Convey("Cannot access as dialer", {
				bool       b;
				nng_dialer d;
				d.id = ep.id;
				So(nng_dialer_getopt_bool(
				       d, NNG_OPT_RAW, &b) == NNG_ENOENT);
				So(nng_dialer_close(d) == NNG_ENOENT);
			});

			Convey("Socket opts not for listener", {
				// Not appropriate for dialer.
				So(nng_listener_setopt_bool(
				       ep, NNG_OPT_RAW, true) == NNG_ENOTSUP);
				So(nng_listener_setopt_ms(ep,
				       NNG_OPT_RECONNMINT, 1) == NNG_ENOTSUP);
				So(nng_listener_setopt_string(ep,
				       NNG_OPT_SOCKNAME,
				       "bogus") == NNG_ENOTSUP);
			});

			Convey("URL is readonly", {
				So(nng_listener_setopt_string(ep, NNG_OPT_URL,
				       "tcp://somewhere.else.com:8888") ==
				    NNG_EREADONLY);
			});

			Convey("Bad size checks", {
				So(nng_listener_setopt(ep, NNG_OPT_RECVMAXSZ,
				       "a", 1) == NNG_EINVAL);
			});
		});

		Convey("Cannot access absent ep options", {
			size_t       s;
			int          i;
			nng_duration t;
			bool         b;
			nng_dialer   d;
			nng_listener l;
			d.id = 1999;
			l.id = 1999;

			So(nng_dialer_setopt_size(d, NNG_OPT_RECVMAXSZ, 10) ==
			    NNG_ENOENT);
			So(nng_listener_setopt_size(
			       l, NNG_OPT_RECVMAXSZ, 10) == NNG_ENOENT);

			s = 1;
			So(nng_dialer_getopt_bool(d, NNG_OPT_RAW, &b) ==
			    NNG_ENOENT);
			So(nng_listener_getopt_bool(l, NNG_OPT_RAW, &b) ==
			    NNG_ENOENT);

			So(nng_dialer_getopt_size(d, NNG_OPT_RECVMAXSZ, &s) ==
			    NNG_ENOENT);
			So(nng_listener_getopt_size(
			       l, NNG_OPT_RECVMAXSZ, &s) == NNG_ENOENT);

			So(nng_dialer_getopt_int(d, NNG_OPT_RAW, &i) ==
			    NNG_ENOENT);
			So(nng_listener_getopt_int(l, NNG_OPT_RAW, &i) ==
			    NNG_ENOENT);

			So(nng_dialer_getopt_ms(d, NNG_OPT_RECVTIMEO, &t) ==
			    NNG_ENOENT);
			So(nng_listener_getopt_ms(l, NNG_OPT_SENDTIMEO, &t) ==
			    NNG_ENOENT);
		});

		Convey("We can send and receive messages", {
			nng_socket   s2;
			int          len;
			size_t       sz;
			nng_duration to = SECONDS(3);
			char *       buf;
			char *       a = "inproc://t1";

			So(nng_pair_open(&s2) == 0);
			Reset({ nng_close(s2); });

			So(nng_setopt_int(s1, NNG_OPT_RECVBUF, 1) == 0);
			So(nng_getopt_int(s1, NNG_OPT_RECVBUF, &len) == 0);
			So(len == 1);

			So(nng_setopt_int(s1, NNG_OPT_SENDBUF, 1) == 0);
			So(nng_setopt_int(s2, NNG_OPT_SENDBUF, 1) == 0);

			So(nng_setopt_ms(s1, NNG_OPT_SENDTIMEO, to) == 0);
			So(nng_setopt_ms(s1, NNG_OPT_RECVTIMEO, to) == 0);
			So(nng_setopt_ms(s2, NNG_OPT_SENDTIMEO, to) == 0);
			So(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, to) == 0);

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
