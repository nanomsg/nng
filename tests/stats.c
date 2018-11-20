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

TestMain("Stats Test", {
	atexit(nng_fini);

	Convey("We are able to open a PAIR socket", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);

		Reset({ nng_close(s1); });

		Convey("We can send and receive messages", {
			nng_socket   s2;
			int          len;
			size_t       sz;
			nng_duration to = SECONDS(3);
			char *       buf;
			char *       a = "inproc://stats";
			nng_stat *   stats;

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

			Convey("We can collect stats", {
				So(nng_stats_get(&stats) == 0);
				nng_stats_dump(stats);
				nng_stats_free(stats);
			});
		});
	});
})
