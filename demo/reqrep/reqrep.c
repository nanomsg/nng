//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/transport/zerotier/zerotier.h>
#include <nng/supplemental/util/platform.h>

#define CLIENT "client"
#define SERVER "server"
#define DATECMD 1

#define PUT64(ptr, u)                                        \
	do {                                                 \
		(ptr)[0] = (uint8_t)(((uint64_t)(u)) >> 56); \
		(ptr)[1] = (uint8_t)(((uint64_t)(u)) >> 48); \
		(ptr)[2] = (uint8_t)(((uint64_t)(u)) >> 40); \
		(ptr)[3] = (uint8_t)(((uint64_t)(u)) >> 32); \
		(ptr)[4] = (uint8_t)(((uint64_t)(u)) >> 24); \
		(ptr)[5] = (uint8_t)(((uint64_t)(u)) >> 16); \
		(ptr)[6] = (uint8_t)(((uint64_t)(u)) >> 8);  \
		(ptr)[7] = (uint8_t)((uint64_t)(u));         \
	} while (0)

#define GET64(ptr, v)                                 \
	v = (((uint64_t)((uint8_t)(ptr)[0])) << 56) + \
	    (((uint64_t)((uint8_t)(ptr)[1])) << 48) + \
	    (((uint64_t)((uint8_t)(ptr)[2])) << 40) + \
	    (((uint64_t)((uint8_t)(ptr)[3])) << 32) + \
	    (((uint64_t)((uint8_t)(ptr)[4])) << 24) + \
	    (((uint64_t)((uint8_t)(ptr)[5])) << 16) + \
	    (((uint64_t)((uint8_t)(ptr)[6])) << 8) +  \
	    (((uint64_t)(uint8_t)(ptr)[7]))

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
	nng_socket sock;
	nng_listener listener;
	int        rv;
	int        count = 0;

	if ((rv = nng_rep0_open(&sock)) != 0) {
		fatal("nng_rep0_open", rv);
	}

	if ((rv = nng_listener_create(&listener, sock, url)) != 0) {
		fatal("nng_listener_create", rv);
	}

	if (strncmp(url, "zt://", 5) == 0) {
		printf("ZeroTier transport will store its keys in current working directory.\n");
		printf("The server and client instances must run in separate directories.\n");
		nng_listener_setopt_string(listener, NNG_OPT_ZT_HOME, ".");
		nng_listener_setopt_ms(listener, NNG_OPT_RECONNMINT, 1);
		nng_listener_setopt_ms(listener, NNG_OPT_RECONNMAXT, 1000);
		nng_setopt_ms(sock, NNG_OPT_REQ_RESENDTIME, 2000);
		nng_setopt_ms(sock, NNG_OPT_RECVMAXSZ, 0);
		nng_listener_setopt_ms(listener, NNG_OPT_ZT_PING_TIME, 10000);
		nng_listener_setopt_ms(listener, NNG_OPT_ZT_CONN_TIME, 1000);
	} else {
		nng_setopt_ms(sock, NNG_OPT_REQ_RESENDTIME, 2000);
	}
	nng_listener_start(listener, 0);

	for (;;) {
		char *   buf = NULL;
		size_t   sz;
		uint64_t val;
		count++;
		if ((rv = nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC)) != 0) {
			fatal("nng_recv", rv);
		}
		if ((sz == sizeof(uint64_t)) &&
		    ((GET64(buf, val)) == DATECMD)) {
			time_t now;
			printf("SERVER: RECEIVED DATE REQUEST\n");
			now = time(&now);
			if (count == 6) {
				printf("SERVER: SKIP SENDING REPLY\n");
				nng_free(buf, sz);
				continue;
			}
			printf("SERVER: SENDING DATE: ");
			showdate(now);

			// Reuse the buffer.  We know it is big enough.
			PUT64(buf, (uint64_t) now);
			rv = nng_send(sock, buf, sz, NNG_FLAG_ALLOC);
			if (rv != 0) {
				fatal("nng_send", rv);
			}
			continue;
		}
		// Unrecognized command, so toss the buffer.
		nng_free(buf, sz);
	}
}

int
client(const char *url)
{
	nng_socket sock;
	nng_dialer dialer;
	int        rv;
	size_t     sz;
	char *     buf = NULL;
	uint8_t    cmd[sizeof(uint64_t)];
	int        sleep = 0;

	PUT64(cmd, DATECMD);

	if ((rv = nng_req0_open(&sock)) != 0) {
		fatal("nng_socket", rv);
	}

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
	}

	if (strncmp(url, "zt://", 5) == 0) {
		printf("ZeroTier transport will store its keys in current working directory\n");
		printf("The server and client instances must run in separate directories.\n");
		nng_dialer_setopt_string(dialer, NNG_OPT_ZT_HOME, ".");
		nng_dialer_setopt_ms(dialer, NNG_OPT_RECONNMINT, 1);
		nng_dialer_setopt_ms(dialer, NNG_OPT_RECONNMAXT, 1000);
		nng_setopt_ms(sock, NNG_OPT_REQ_RESENDTIME, 2000);
		nng_setopt_ms(sock, NNG_OPT_RECVMAXSZ, 0);
		nng_dialer_setopt_ms(dialer, NNG_OPT_ZT_PING_TIME, 10000);
		nng_dialer_setopt_ms(dialer, NNG_OPT_ZT_CONN_TIME, 1000);
	} else {
		nng_setopt_ms(sock, NNG_OPT_REQ_RESENDTIME, 2000);
	}

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	while (1) {

		printf("CLIENT: SENDING DATE REQUEST\n");
		if ((rv = nng_send(sock, cmd, sizeof(cmd), 0)) != 0) {
			fatal("nng_send", rv);
		}
		if ((rv = nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC)) != 0) {
			fatal("nng_recv", rv);
		}

		if (sz == sizeof(uint64_t)) {
			uint64_t now;
			GET64(buf, now);
			printf("CLIENT: RECEIVED DATE: ");
			showdate((time_t) now);
		} else {
			printf("CLIENT: GOT WRONG SIZE!\n");
		}
		nng_msleep(sleep);
		sleep++;
		if (sleep == 4) {
			sleep = 4000;
		}
	}

	// This assumes that buf is ASCIIZ (zero terminated).
	nng_free(buf, sz);
	nng_close(sock);
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
