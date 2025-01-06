//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2021 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

//
// This is just a simple REQ/REP demonstration application.  It is derived
// from the legacy nanomsg demonstration program of the same name, written
// by Tim Dysinger, but updated for nng.  I've also updated it to pass simpler
// binary data rather than strings over the network.
//
// The program implements a simple RPC style service, which just returns
// the date in UNIX time (seconds since 1970).
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <nng/nng.h>

#define CLIENT "client"
#define SERVER "server"
#define DATECMD 1

void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
	exit(1);
}

void
showdate(time_t now)
{
	struct tm *info = localtime(&now);
	printf("%s", asctime(info));
}

int
server(const char *url)
{
	nng_socket   sock;
	nng_listener listener;
	int          rv;
	int          count = 0;

	if ((rv = nng_init(NULL)) != 0) {
		fatal("nng_init", rv);
	}
	if ((rv = nng_rep0_open(&sock)) != 0) {
		fatal("nng_rep0_open", rv);
	}

	if ((rv = nng_listener_create(&listener, sock, url)) != 0) {
		fatal("nng_listener_create", rv);
	}

	nng_socket_set_ms(sock, NNG_OPT_REQ_RESENDTIME, 2000);
	nng_listener_start(listener, 0);

	for (;;) {
		uint64_t val;
		nng_msg *msg;
		count++;
		if ((rv = nng_recvmsg(sock, &msg, 0)) != 0) {
			fatal("nng_recv", rv);
		}
		if ((nng_msg_trim_u64(msg, &val) == 0) && (val == DATECMD)) {
			time_t now;
			printf("SERVER: RECEIVED DATE REQUEST\n");
			now = time(&now);
			if (count == 6) {
				printf("SERVER: SKIP SENDING REPLY\n");
				nng_msg_free(msg);
				continue;
			}
			printf("SERVER: SENDING DATE: ");
			showdate(now);

			// Reuse the message.  We know it is big enough.
			nng_msg_append_u64(msg, now);
			rv = nng_sendmsg(sock, msg, 0);
			if (rv != 0) {
				fatal("nng_send", rv);
			}
		} else {
			// Unrecognized command, so toss the message.
			nng_msg_free(msg);
		}
	}
}

int
client(const char *url)
{
	nng_socket sock;
	nng_dialer dialer;
	int        rv;
	int        sleep = 0;

	if ((rv = nng_init(NULL)) != 0) {
		fatal("nng_init", rv);
	}
	if ((rv = nng_req0_open(&sock)) != 0) {
		fatal("nng_socket", rv);
	}

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
	}

	nng_socket_set_ms(sock, NNG_OPT_REQ_RESENDTIME, 2000);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	while (1) {

		nng_msg *msg;
		uint64_t now;
		if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
			fatal("nng_msg_alloc", rv);
		}
		if ((rv = nng_msg_append_u64(msg, DATECMD)) != 0) {
			fatal("nng_msg_append", rv);
		}
		printf("CLIENT: SENDING DATE REQUEST\n");
		if ((rv = nng_sendmsg(sock, msg, 0)) != 0) {
			fatal("nng_sendmsg", rv);
		}
		if ((rv = nng_recvmsg(sock, &msg, 0)) != 0) {
			fatal("nng_recvmsg", rv);
		}
		if ((rv = nng_msg_trim_u64(msg, &now)) != 0) {
			fatal("nng_msg_trim_u64", rv);
		}
		nng_msg_free(msg);
		printf("CLIENT: RECEIVED DATE: ");
		showdate((time_t) now);
		nng_msleep(sleep);
		sleep++;
		if (sleep == 4) {
			sleep = 4000;
		}
	}

	nng_socket_close(sock);
	return (0);
}

int
main(const int argc, const char **argv)
{
	if ((argc > 1) && (strcmp(CLIENT, argv[1]) == 0))
		return (client(argv[2]));

	if ((argc > 1) && (strcmp(SERVER, argv[1]) == 0))
		return (server(argv[2]));

	fprintf(stderr, "Usage: reqrep %s|%s <URL> ...\n", CLIENT, SERVER);
	return (1);
}
