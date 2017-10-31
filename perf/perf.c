//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// We steal access to the clock and thread functions so that we can
// work on Windows too.  These functions are *not* part of nng's public
// API, so don't be lazy like this!  All nni_ symbols are subject to
// change without notice, and not part of the stable API or ABI.
#include "core/nng_impl.h"

#if defined(NNG_ENABLE_PAIR1)
#include "protocol/pair1/pair.h"

#elif defined(NNG_ENABLE_PAIR0)
#include "protocol/pair0/pair.h"

#else

static void die(const char *, ...);

static int
nng_pair_open(nng_socket *rv)
{
	die("No pair protocol enabled in this build!");
	return (NNG_ENOTSUP);
}
#endif // NNG_ENABLE_PAIR

static void latency_client(const char *, int, int);
static void latency_server(const char *, int, int);
static void throughput_client(const char *, int, int);
static void throughput_server(const char *, int, int);
static void do_remote_lat(int argc, char **argv);
static void do_local_lat(int argc, char **argv);
static void do_remote_thr(int argc, char **argv);
static void do_local_thr(int argc, char **argv);
static void do_inproc_thr(int argc, char **argv);
static void do_inproc_lat(int argc, char **argv);
static void die(const char *, ...);

// perf implements the same performance tests found in the standard
// nanomsg & mangos performance tests.  As with mangos, the decision
// about which test to run is determined by the program name (ARGV[0}])
// that it is run under.
//
// Options are:
//
// - remote_lat - remote latency side (client, aka latency_client)
// - local_lat  - local latency side (server, aka latency_server)
// - local_thr  - local throughput side
// - remote_thr - remote throughput side
// - inproc_lat - inproc latency
// - inproc_thr - inproc throughput
//

int
main(int argc, char **argv)
{
	char *prog;

	// Allow -m <remote_late> or whatever to override argv[0].
	if ((argc >= 3) && (strcmp(argv[1], "-m") == 0)) {
		prog = argv[1];
		argv += 3;
		argc -= 3;
	} else {
		if (((prog = strrchr(argv[0], '/')) != NULL) ||
		    ((prog = strrchr(argv[0], '\\')) != NULL) ||
		    ((prog = strrchr(argv[0], ':')) != NULL)) {
			prog++;
		} else {
			prog = argv[0];
		}
		argc--;
		argv++;
	}
	if ((strcmp(prog, "remote_lat") == 0) ||
	    (strcmp(prog, "latency_client") == 0)) {
		do_remote_lat(argc, argv);
	} else if ((strcmp(prog, "local_lat") == 0) ||
	    (strcmp(prog, "latency_server") == 0)) {
		do_local_lat(argc, argv);
	} else if ((strcmp(prog, "local_thr") == 0) ||
	    (strcmp(prog, "throughput_server") == 0)) {
		do_local_thr(argc, argv);
	} else if ((strcmp(prog, "remote_thr") == 0) ||
	    (strcmp(prog, "throughput_client") == 0)) {
		do_remote_thr(argc, argv);
	} else if ((strcmp(prog, "inproc_thr") == 0)) {
		do_inproc_thr(argc, argv);
	} else if ((strcmp(prog, "inproc_lat") == 0)) {
		do_inproc_lat(argc, argv);
	} else {
		die("Unknown program mode? Use -m <mode>.");
	}
}

int
nop(void)
{
	return (0);
}

static void
die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(2);
}

static int
parse_int(const char *arg, const char *what)
{
	long  val;
	char *eptr;

	val = strtol(arg, &eptr, 10);
	// Must be a postive number less than around a billion.
	if ((val < 0) || (val > (1 << 30)) || (*eptr != 0) || (eptr == arg)) {
		die("Invalid %s", what);
	}
	return ((int) val);
}

void
do_local_lat(int argc, char **argv)
{
	long int msgsize;
	long int trips;

	if (argc != 3) {
		die("Usage: local_lat <listen-addr> <msg-size> <roundtrips>");
	}

	msgsize = parse_int(argv[1], "message size");
	trips   = parse_int(argv[2], "round-trips");

	latency_server(argv[0], msgsize, trips);
}

void
do_remote_lat(int argc, char **argv)
{
	int msgsize;
	int trips;

	if (argc != 3) {
		die("Usage: remote_lat <connect-to> <msg-size> <roundtrips>");
	}

	msgsize = parse_int(argv[1], "message size");
	trips   = parse_int(argv[2], "round-trips");

	latency_client(argv[0], msgsize, trips);
}

void
do_local_thr(int argc, char **argv)
{
	int msgsize;
	int trips;

	if (argc != 3) {
		die("Usage: local_thr <listen-addr> <msg-size> <count>");
	}

	msgsize = parse_int(argv[1], "message size");
	trips   = parse_int(argv[2], "count");

	throughput_server(argv[0], msgsize, trips);
}

void
do_remote_thr(int argc, char **argv)
{
	int msgsize;
	int trips;

	if (argc != 3) {
		die("Usage: remote_thr <connect-to> <msg-size> <count>");
	}

	msgsize = parse_int(argv[1], "message size");
	trips   = parse_int(argv[2], "count");

	throughput_client(argv[0], msgsize, trips);
}

struct inproc_args {
	int         count;
	int         msgsize;
	const char *addr;
	void (*func)(const char *, int, int);
};

static void
do_inproc(void *args)
{
	struct inproc_args *ia = args;

	ia->func(ia->addr, ia->msgsize, ia->count);
}

void
do_inproc_lat(int argc, char **argv)
{
	nni_thr            thr;
	struct inproc_args ia;
	int                rv;

	nni_init();
	if (argc != 2) {
		die("Usage: inproc_lat <msg-size> <count>");
	}

	ia.addr    = "inproc://latency_test";
	ia.msgsize = parse_int(argv[0], "message size");
	ia.count   = parse_int(argv[1], "count");
	ia.func    = latency_server;

	if ((rv = nni_thr_init(&thr, do_inproc, &ia)) != 0) {
		die("Cannot create thread: %s", nng_strerror(rv));
	}
	nni_thr_run(&thr);

	// Sleep a bit.
	nng_msleep(100);

	latency_client("inproc://latency_test", ia.msgsize, ia.count);
	nni_thr_fini(&thr);
}

void
do_inproc_thr(int argc, char **argv)
{
	nni_thr            thr;
	struct inproc_args ia;
	int                rv;

	nni_init();
	if (argc != 2) {
		die("Usage: inproc_thr <msg-size> <count>");
	}

	ia.addr    = "inproc://tput_test";
	ia.msgsize = parse_int(argv[0], "message size");
	ia.count   = parse_int(argv[1], "count");
	ia.func    = throughput_client;

	if ((rv = nni_thr_init(&thr, do_inproc, &ia)) != 0) {
		die("Cannot create thread: %s", nng_strerror(rv));
	}
	nni_thr_run(&thr);
	throughput_server("inproc://tput_test", ia.msgsize, ia.count);
	nni_thr_fini(&thr);
}

void
latency_client(const char *addr, int msgsize, int trips)
{
	nng_socket s;
	nng_msg *  msg;
	nni_time   start, end;
	int        rv;
	int        i;
	float      total;
	float      latency;

	if ((rv = nng_pair_open(&s)) != 0) {
		die("nng_socket: %s", nng_strerror(rv));
	}

	// XXX: set no delay
	// XXX: other options (TLS in the future?, Linger?)

	if ((rv = nng_dial(s, addr, NULL, 0)) != 0) {
		die("nng_dial: %s", nng_strerror(rv));
	}

	if (nng_msg_alloc(&msg, msgsize) != 0) {
		die("nng_msg_alloc: %s", nng_strerror(rv));
	}

	start = nni_clock();
	for (i = 0; i < trips; i++) {
		if ((rv = nng_sendmsg(s, msg, 0)) != 0) {
			die("nng_sendmsg: %s", nng_strerror(rv));
		}

		if ((rv = nng_recvmsg(s, &msg, 0)) != 0) {
			die("nng_recvmsg: %s", nng_strerror(rv));
		}
	}
	end = nni_clock();

	nni_msg_free(msg);
	nng_close(s);

	total   = (float) ((end - start)) / 1000;
	latency = ((float) ((total * 1000000)) / (trips * 2));
	printf("total time: %.3f [s]\n", total);
	printf("message size: %d [B]\n", msgsize);
	printf("round trip count: %d\n", trips);
	printf("average latency: %.3f [us]\n", latency);
}

void
latency_server(const char *addr, int msgsize, int trips)
{
	nng_socket s;
	nng_msg *  msg;
	int        rv;
	int        i;

	if ((rv = nng_pair_open(&s)) != 0) {
		die("nng_socket: %s", nng_strerror(rv));
	}

	// XXX: set no delay
	// XXX: other options (TLS in the future?, Linger?)

	if ((rv = nng_listen(s, addr, NULL, 0)) != 0) {
		die("nng_listen: %s", nng_strerror(rv));
	}

	for (i = 0; i < trips; i++) {
		if ((rv = nng_recvmsg(s, &msg, 0)) != 0) {
			die("nng_recvmsg: %s", nng_strerror(rv));
		}
		if (nng_msg_len(msg) != msgsize) {
			die("wrong message size: %d != %d", nng_msg_len(msg),
			    msgsize);
		}
		if ((rv = nng_sendmsg(s, msg, 0)) != 0) {
			die("nng_sendmsg: %s", nng_strerror(rv));
		}
	}

	// Wait a bit for things to drain... linger should do this.
	// 100ms ought to be enough.
	nng_msleep(100);
	nng_close(s);
}

// Our throughput story is quite a mess.  Mostly I think because of the poor
// caching and message reuse.  We should probably implement a message pooling
// API somewhere.

void
throughput_server(const char *addr, int msgsize, int count)
{
	nng_socket s;
	nng_msg *  msg;
	int        rv;
	int        i;
	uint64_t   start, end;
	float      msgpersec, mbps, total;

	if ((rv = nng_pair_open(&s)) != 0) {
		die("nng_socket: %s", nng_strerror(rv));
	}
	rv = nng_setopt_int(s, NNG_OPT_RECVBUF, 128);
	if (rv != 0) {
		die("nng_setopt(nng_opt_recvbuf): %s", nng_strerror(rv));
	}

	// XXX: set no delay
	// XXX: other options (TLS in the future?, Linger?)

	if ((rv = nng_listen(s, addr, NULL, 0)) != 0) {
		die("nng_listen: %s", nng_strerror(rv));
	}

	// Receive first synchronization message.
	if ((rv = nng_recvmsg(s, &msg, 0)) != 0) {
		die("nng_recvmsg: %s", nng_strerror(rv));
	}
	nni_msg_free(msg);
	start = nni_clock();

	for (i = 0; i < count; i++) {
		if ((rv = nng_recvmsg(s, &msg, 0)) != 0) {
			die("nng_recvmsg: %s", nng_strerror(rv));
		}
		if (nng_msg_len(msg) != msgsize) {
			die("wrong message size: %d != %d", nng_msg_len(msg),
			    msgsize);
		}
		nni_msg_free(msg);
	}
	end = nni_clock();
	nng_close(s);
	total     = (float) ((end - start)) / 1000;
	msgpersec = (float) (count) / total;
	mbps      = (float) (msgpersec * 8 * msgsize) / (1024 * 1024);
	printf("total time: %.3f [s]\n", total);
	printf("message size: %d [B]\n", msgsize);
	printf("message count: %d\n", count);
	printf("throughput: %.f [msg/s]\n", msgpersec);
	printf("throughput: %.3f [Mb/s]\n", mbps);
}

void
throughput_client(const char *addr, int msgsize, int count)
{
	nng_socket s;
	nng_msg *  msg;
	int        rv;
	int        i;

	// We send one extra zero length message to start the timer.
	count++;

	if ((rv = nng_pair_open(&s)) != 0) {
		die("nng_socket: %s", nng_strerror(rv));
	}

	// XXX: set no delay
	// XXX: other options (TLS in the future?, Linger?)

	rv = nng_setopt_int(s, NNG_OPT_SENDBUF, 128);
	if (rv != 0) {
		die("nng_setopt(nng_opt_sendbuf): %s", nng_strerror(rv));
	}

	if ((rv = nng_dial(s, addr, NULL, 0)) != 0) {
		die("nng_dial: %s", nng_strerror(rv));
	}

	if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
		die("nng_msg_alloc: %s", nng_strerror(rv));
	}
	if ((rv = nng_sendmsg(s, msg, 0)) != 0) {
		die("nng_sendmsg: %s", nng_strerror(rv));
	}

	for (i = 0; i < count; i++) {
		if ((rv = nng_msg_alloc(&msg, msgsize)) != 0) {
			die("nng_msg_alloc: %s", nng_strerror(rv));
		}

		if ((rv = nng_sendmsg(s, msg, 0)) != 0) {
			die("nng_sendmsg: %s", nng_strerror(rv));
		}
	}

	// Wait 100msec for pipes to drain.
	nng_msleep(100);
	nng_close(s);
}
