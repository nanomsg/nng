// Copyright 2018 Cody Piersall <cody.piersall@gmail.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"

#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>

#define SNDBUFSIZE 150
#define RCVBUFSIZE 200

const char *addrs[] = {
	"ipc:///tmp/ipctemp_setrecvmaxsz",
	"tcp://127.0.0.1:43895",
	"ws://127.0.0.1:43897",
};

TestMain("recvmaxsize", {
	// we don't actually care what the content of the message is.
	char         msg[SNDBUFSIZE];
	char         rcvbuf[RCVBUFSIZE];
	size_t       rcvsize = RCVBUFSIZE;
	nng_socket   s0;
	nng_socket   s1;
	nng_listener l;
	int          numproto = sizeof addrs / sizeof *addrs;
	Convey("recvmaxsize can be set after listening", {
		for (int i = 0; i < numproto; i++) {
			const char *addr = addrs[i];
			So(nng_pair1_open(&s0) == 0);
			So(nng_setopt_ms(s0, NNG_OPT_RECVTIMEO, 100) == 0);
			So(nng_setopt_size(s0, NNG_OPT_RECVMAXSZ, 200) == 0);
			So(nng_listen(s0, addr, &l, 0) == 0);
			So(nng_setopt_size(s0, NNG_OPT_RECVMAXSZ, 100) == 0);

			So(nng_pair1_open(&s1) == 0);
			So(nng_dial(s1, addr, NULL, 0) == 0);
			So(nng_send(s1, msg, 150, 0) == 0);
			So(nng_recv(s0, rcvbuf, &rcvsize, 0) == NNG_ETIMEDOUT);
			So(nng_close(s0) == 0);
			So(nng_close(s1) == 0);
		}
	});
})
