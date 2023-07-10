//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

//
// Forwarder example based on https://github.com/C-o-r-E/nng_pubsub_proxy
//
// This example shows how to use raw sockets to set up a forwarder or proxy for
// pub/sub.
//
// An example setup for running this example would involve the following:
//
//  - Run this example binary (in the background or a terminal, etc)
//  - In a new terminal, run
//      `nngcat --sub --dial "tcp://localhost:3328" --quoted`
//  - In a second terminal, run
//      `nngcat --sub --dial "tcp://localhost:3328" --quoted`
//  - In a third terminal, run
//      `for n in $(seq 0 99);`
//        `do nngcat --pub --dial "tcp://localhost:3327" --data "$n";`
//      `done`
//
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <nng/nng.h>
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/pubsub0/sub.h>

#define PROXY_FRONT_URL "tcp://localhost:3327"
#define PROXY_BACK_URL "tcp://localhost:3328"

void
panic_on_error(int should_panic, const char *format, ...)
{
	if (should_panic) {
		va_list args;
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
		exit(EXIT_FAILURE);
	}
}

int
main()
{
	nng_socket sock_front_end = NNG_SOCKET_INITIALIZER;
	nng_socket sock_back_end  = NNG_SOCKET_INITIALIZER;
	int        ret            = 0;

	//
	//  First we need some nng sockets. Not to be confused with network
	//  sockets
	//
	ret = nng_sub0_open_raw(&sock_front_end);
	panic_on_error(ret, "Failed to open front end socket\n");

	ret = nng_pub0_open_raw(&sock_back_end);
	panic_on_error(ret, "Failed to open back end socket\n");

	//
	//  Now we need to set up a listener for each socket so that they have
	//  addresses
	//

	nng_listener front_ls = NNG_LISTENER_INITIALIZER;
	nng_listener back_ls  = NNG_LISTENER_INITIALIZER;

	ret = nng_listener_create(&front_ls, sock_front_end, PROXY_FRONT_URL);
	panic_on_error(ret, "Failed to create front listener\n");

	ret = nng_listener_create(&back_ls, sock_back_end, PROXY_BACK_URL);
	panic_on_error(ret, "Failed to create back listener\n");

	ret = nng_listener_start(front_ls, 0);
	panic_on_error(ret, "Failed to start front listener\n");

	ret = nng_listener_start(back_ls, 0);
	panic_on_error(ret, "Failed to start back listener\n");

	//
	//  Finally let nng do the forwarding/proxying
	//

	ret = nng_device(sock_front_end, sock_back_end);
	panic_on_error(
	    ret, "nng_device returned %d: %s\n", ret, nng_strerror(ret));

	printf("done");
	return 0;
}