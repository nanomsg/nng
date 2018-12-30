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
#include <nng/supplemental/tcp/tcp.h>

#include "convey.h"
#include "stubs.h"

static uint8_t loopback[4] = { 127, 0, 0, 1 };

TestMain("Supplemental TCP", {
	atexit(nng_fini);
	Convey("We can create a dialer and listener", {
		nng_tcp_dialer *  d;
		nng_tcp_listener *l;
		So(nng_tcp_dialer_alloc(&d) == 0);
		So(nng_tcp_listener_alloc(&l) == 0);
		Reset({
			nng_tcp_listener_close(l);
			nng_tcp_dialer_close(d);
			nng_tcp_listener_free(l);
			nng_tcp_dialer_free(d);
		});
		Convey("Listener listens (wildcard)", {
			nng_sockaddr sa;
			uint32_t     ip;

			memcpy(&ip, loopback, 4);

			sa.s_in.sa_family = NNG_AF_INET;
			sa.s_in.sa_addr   = ip;
			sa.s_in.sa_port   = 0;

			So(nng_tcp_listener_listen(l, &sa) == 0);
			So(sa.s_in.sa_port != 0);
			So(sa.s_in.sa_addr == ip);

			Convey("We can dial it", {
				nng_aio *daio = NULL;
				nng_aio *laio = NULL;
				nng_aio *maio = NULL;
				nng_tcp *c1   = NULL;
				nng_tcp *c2   = NULL;

				So(nng_aio_alloc(&daio, NULL, NULL) == 0);
				So(nng_aio_alloc(&laio, NULL, NULL) == 0);
				So(nng_aio_alloc(&maio, NULL, NULL) == 0);

				Reset({
					nng_aio_free(daio);
					nng_aio_free(laio);
					if (c1 != NULL) {
						nng_tcp_close(c1);
						nng_tcp_free(c1);
					}
					if (c2 != NULL) {
						nng_tcp_close(c2);
						nng_tcp_free(c2);
					}
				});

				nng_tcp_dialer_dial(d, &sa, daio);
				nng_tcp_listener_accept(l, laio);

				nng_aio_wait(daio);
				nng_aio_wait(laio);

				So(nng_aio_result(daio) == 0);
				So(nng_aio_result(laio) == 0);

				c1 = nng_aio_get_output(daio, 0);
				c2 = nng_aio_get_output(laio, 0);
				So(c1 != NULL);
				So(c2 != NULL);

				Convey("They exchange messages", {
					nng_aio *    aio1;
					nng_aio *    aio2;
					nng_iov      iov;
					nng_sockaddr sa2;
					char         buf1[5];
					char         buf2[5];
					bool         on;
					size_t       sz;

					So(nng_aio_alloc(&aio1, NULL, NULL) ==
					    0);
					So(nng_aio_alloc(&aio2, NULL, NULL) ==
					    0);

					Reset({
						nng_aio_free(aio1);
						nng_aio_free(aio2);
					});

					on = true;
					So(nng_tcp_setopt(c1,
					       NNG_OPT_TCP_NODELAY, &on,
					       sizeof(on)) == 0);
					So(nng_tcp_setopt(c2,
					       NNG_OPT_TCP_NODELAY, &on,
					       sizeof(on)) == 0);

					So(nng_tcp_setopt(c1,
					       NNG_OPT_TCP_KEEPALIVE, &on,
					       sizeof(on)) == 0);

					on = false;
					sz = sizeof(on);
					So(nng_tcp_getopt(c1,
					       NNG_OPT_TCP_NODELAY, &on,
					       &sz) == 0);
					So(sz == sizeof(on));
					So(on == true);

					on = false;
					sz = sizeof(on);
					So(nng_tcp_getopt(c1,
					       NNG_OPT_TCP_KEEPALIVE, &on,
					       &sz) == 0);
					So(sz == sizeof(on));
					So(on == true);

					// This relies on send completing for
					// for just 5 bytes, and on recv doing
					// the same.  Technically this isn't
					// guaranteed, but it would be weird
					// to split such a small payload.
					memcpy(buf1, "TEST", 5);
					memset(buf2, 0, 5);
					iov.iov_buf = buf1;
					iov.iov_len = 5;

					nng_aio_set_iov(aio1, 1, &iov);

					iov.iov_buf = buf2;
					iov.iov_len = 5;
					nng_aio_set_iov(aio2, 1, &iov);
					nng_tcp_send(c1, aio1);
					nng_tcp_recv(c2, aio2);
					nng_aio_wait(aio1);
					nng_aio_wait(aio2);

					So(nng_aio_result(aio1) == 0);
					So(nng_aio_count(aio1) == 5);

					So(nng_aio_result(aio2) == 0);
					So(nng_aio_count(aio2) == 5);

					So(memcmp(buf1, buf2, 5) == 0);

					Convey("Socket name matches", {
						sz = sizeof(sa2);
						So(nng_tcp_getopt(c2,
						       NNG_OPT_LOCADDR, &sa2,
						       &sz) == 0);
						So(sz == sizeof(sa2));
						So(sa2.s_in.sa_family ==
						    NNG_AF_INET);
						So(sa2.s_in.sa_addr == ip);
						So(sa2.s_in.sa_port ==
						    sa.s_in.sa_port);
					});

					Convey("Peer name matches", {
						sz = sizeof(sa2);
						So(nng_tcp_getopt(c1,
						       NNG_OPT_REMADDR, &sa2,
						       &sz) == 0);
						So(sz == sizeof(sa2));
						So(sa2.s_in.sa_family ==
						    NNG_AF_INET);
						So(sa2.s_in.sa_addr == ip);
						So(sa2.s_in.sa_port ==
						    sa.s_in.sa_port);
					});
				});
			});
		});
	});
})
