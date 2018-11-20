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
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

#define APPENDSTR(m, s) nng_msg_append(m, s, strlen(s))
#define CHECKSTR(m, s)                   \
	So(nng_msg_len(m) == strlen(s)); \
	So(memcmp(nng_msg_body(m), s, strlen(s)) == 0)

struct dev_data {
	nng_socket s1;
	nng_socket s2;
};

void
dodev(void *arg)
{
	struct dev_data *d = arg;

	nng_device(d->s1, d->s2);
}

#define SECOND(x) ((x) *1000)

Main({

	Test("PAIRv1 device", {
		const char *addr1 = "inproc://dev1";
		const char *addr2 = "inproc://dev2";

		Convey("We cannot create cooked mode device", {
			nng_socket s1;
			So(nng_pair1_open(&s1) == 0);
			Reset({ nng_close(s1); });
			So(nng_device(s1, s1) == NNG_EINVAL);
		});
		Convey("We can create a PAIRv1 device", {
			nng_socket   dev1;
			nng_socket   dev2;
			nng_socket   end1;
			nng_socket   end2;
			nng_duration tmo;
			nng_msg *    msg;
			nng_thread * thr;

			So(nng_pair1_open_raw(&dev1) == 0);
			So(nng_pair1_open_raw(&dev2) == 0);

			struct dev_data ddata;
			ddata.s1 = dev1;
			ddata.s2 = dev2;

			So(nng_thread_create(&thr, dodev, &ddata) == 0);
			Reset({
				nng_close(dev1);
				nng_close(dev2);
				nng_thread_destroy(thr);
			});

			So(nng_listen(dev1, addr1, NULL, 0) == 0);
			So(nng_listen(dev2, addr2, NULL, 0) == 0);

			So(nng_pair1_open(&end1) == 0);
			So(nng_pair1_open(&end2) == 0);

			So(nng_dial(end1, addr1, NULL, 0) == 0);
			So(nng_dial(end2, addr2, NULL, 0) == 0);

			tmo = SECOND(1);
			So(nng_setopt_ms(end1, NNG_OPT_RECVTIMEO, tmo) == 0);
			So(nng_setopt_ms(end2, NNG_OPT_RECVTIMEO, tmo) == 0);

			nng_msleep(100);
			Convey("Device can send and receive", {

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "ALPHA");
				So(nng_sendmsg(end1, msg, 0) == 0);
				So(nng_recvmsg(end2, &msg, 0) == 0);
				CHECKSTR(msg, "ALPHA");
				nng_msg_free(msg);

				So(nng_msg_alloc(&msg, 0) == 0);
				APPENDSTR(msg, "OMEGA");

				So(nng_sendmsg(end2, msg, 0) == 0);
				So(nng_recvmsg(end1, &msg, 0) == 0);

				CHECKSTR(msg, "OMEGA");
				nng_msg_free(msg);
			});
		});
	});

	nng_fini();
})
