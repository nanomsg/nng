//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

// pubdrop - this is a simple testing utility that lets us measure PUB/SUB
// performance, including dropped messages, delivery across multiple threads,
// etc.  It actually uses a wild card subscription for now.

#if defined(NNG_HAVE_PUB0) && defined(NNG_HAVE_SUB0)
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/pubsub0/sub.h>

#else

static void die(const char *, ...);

static int
nng_pub0_open(nng_socket *arg)
{
	(void) arg;
	die("Pub protocol enabled in this build!");
	return (NNG_ENOTSUP);
}

static int
nng_sub0_open(nng_socket *arg)
{
	(void) arg;
	die("Sub protocol enabled in this build!");
	return (NNG_ENOTSUP);
}

#endif // NNG_HAVE_PUB0....

static void         die(const char *, ...);
static void         do_pubdrop(int argc, char **argv);
static uint64_t     nperusec;
static volatile int x;

void
work(void)
{
	x = rand();
}

void
usdelay(unsigned long long nusec)
{
	nusec *= nperusec;
	while (nusec > 0) {
		work();
		nusec--;
	}
}

int
main(int argc, char **argv)
{
	argc--;
	argv++;

	// We calculate a delay factor to roughly delay 1 usec.  We don't
	// need this to be perfect, just reproducible on the same host.
	unsigned long cnt = 1000000;

	nng_time beg = nng_clock();
	for (unsigned long i = 0; i < cnt; i++) {
		work();
	}
	nng_time end = nng_clock();
	nperusec     = cnt / (1000 * (end - beg));

	do_pubdrop(argc, argv);
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

struct pubdrop_args {
	const char *       addr;
	bool               start;
	unsigned long long msgsize;
	unsigned long long count;
	unsigned long long intvl;
	unsigned long long drops;
	unsigned long long gaps;
	unsigned long long errs;
	unsigned long long recvs;
	nng_time           beg;
	nng_time           end;
	nng_mtx *          mtx;
	nng_cv *           cv;
};

static void
pub_server(void *arg)
{
	struct pubdrop_args *pa = arg;
	nng_socket           sock;
	int                  rv;
	nng_msg *            msg;
	nng_time             start;
	nng_time             end;

	if ((rv = nng_pub0_open(&sock)) != 0) {
		die("Cannot open sub: %s", nng_strerror(rv));
	}
	if ((rv = nng_listen(sock, pa->addr, NULL, 0)) != 0) {
		die("Cannot listen: %s", nng_strerror(rv));
	}

	nng_mtx_lock(pa->mtx);
	while (!pa->start) {
		nng_cv_wait(pa->cv);
	}
	nng_mtx_unlock(pa->mtx);

	start = nng_clock();
	for (uint64_t i = 0; i < pa->count; i++) {
		// Unfortunately we need to allocate messages dynamically as we
		// go. The other option would be to allocate them all up front,
		// but that could be a rather excessive amount of memory.
		if ((rv = nng_msg_alloc(&msg, (size_t) pa->msgsize)) != 0) {
			die("Message alloc failed");
		}
		memcpy(nng_msg_body(msg), &i, sizeof(i));
		if ((rv = nng_sendmsg(sock, msg, 0)) != 0) {
			die("Sendmsg: %s", nng_strerror(rv));
		}
		// It sure would be nice if we had a usec granularity option
		// here.
		if (pa->intvl > 0) {
			usdelay((unsigned long long) pa->intvl);
		}
	}

	end = nng_clock();

	nng_msleep(1000); // drain the queue
	nng_close(sock);

	nng_mtx_lock(pa->mtx);
	pa->beg = start;
	pa->end = end;
	nng_mtx_unlock(pa->mtx);
}

static void
sub_client(void *arg)
{
	struct pubdrop_args *pa = arg;
	nng_socket           sock;
	int                  rv;
	nng_msg *            msg;
	unsigned long long   recvs;
	unsigned long long   drops;
	unsigned long long   gaps;
	unsigned long long   errs;
	unsigned long long   expect;

	if ((rv = nng_sub0_open(&sock)) != 0) {
		die("Cannot open sub: %s", nng_strerror(rv));
	}
	if ((rv = nng_dial(sock, pa->addr, NULL, 0)) != 0) {
		die("Cannot listen: %s", nng_strerror(rv));
	}
	if ((rv = nng_setopt_ms(sock, NNG_OPT_RECONNMINT, 51)) != 0) {
		die("setopt: %s", nng_strerror(rv));
	}
	if ((rv = nng_setopt(sock, NNG_OPT_SUB_SUBSCRIBE, "", 0)) != 0) {
		die("setopt: %s", nng_strerror(rv));
	}
	if ((rv = nng_setopt_ms(sock, NNG_OPT_RECVTIMEO, 10000)) != 0) {
		die("setopt: %s", nng_strerror(rv));
	}

	expect = 0;
	recvs = drops = gaps = errs = 0;

	while (expect < pa->count) {
		uint64_t got;
		if ((rv = nng_recvmsg(sock, &msg, 0)) != 0) {
			if ((rv == NNG_ECLOSED) || (rv == NNG_ETIMEDOUT)) {
				// Closed without receiving the last message
				drops += (pa->count - expect);
				gaps++;
				break;
			}
			printf("ERROR: %s\n", nng_strerror(rv));
			errs++;
			break;
		}
		recvs++;
		memcpy(&got, nng_msg_body(msg), sizeof(got));
		nng_msg_free(msg);
		if (got != expect) {
			gaps++;
			if (got > expect) {
				drops += (got - expect);
			} else {
				die("Misordered delivery");
			}
		}
		expect = got + 1;
	}

	nng_mtx_lock(pa->mtx);
	pa->drops += drops;
	pa->errs += errs;
	pa->recvs += recvs;
	pa->gaps += gaps;
	nng_mtx_unlock(pa->mtx);
}

static void
do_pubdrop(int argc, char **argv)
{
	nng_thread **       thrs;
	struct pubdrop_args pa;
	int                 rv;
	int                 nsubs;

	if (argc != 5) {
		die("Usage: pubdrop <url> <msg-size> <msg-count> <num-subs> "
		    "<interval>");
	}

	memset(&pa, 0, sizeof(pa));
	pa.addr    = argv[0];
	pa.msgsize = parse_int(argv[1], "message size");
	pa.count   = parse_int(argv[2], "count");
	pa.intvl   = parse_int(argv[4], "interval");
	nsubs      = parse_int(argv[3], "#subscribers");

	if (pa.msgsize < sizeof(uint64_t)) {
		die("Message size too small.");
	}

	thrs = calloc(sizeof(nng_thread *), (size_t) pa.count + 1);
	if (((rv = nng_mtx_alloc(&pa.mtx)) != 0) ||
	    ((nng_cv_alloc(&pa.cv, pa.mtx)) != 0)) {
		die("Startup: %s\n", nng_strerror(rv));
	};

	if ((rv = nng_thread_create(&thrs[0], pub_server, &pa)) != 0) {
		die("Cannot create pub thread: %s", nng_strerror(rv));
	}

	nng_msleep(100); // give time for listener to start...

	for (int i = 0; i < nsubs; i++) {
		if ((rv = nng_thread_create(&thrs[i + 1], sub_client, &pa)) !=
		    0) {
			die("Cannot create sub thread: %s", nng_strerror(rv));
		}
	}

	// Sleep a bit for conns to establish.
	nng_msleep(2000);
	nng_mtx_lock(pa.mtx);
	pa.start = true;
	nng_cv_wake(pa.cv);
	nng_mtx_unlock(pa.mtx);

	for (int i = 0; i < nsubs + 1; i++) {
		nng_thread_destroy(thrs[i]);
	}

	nng_mtx_lock(pa.mtx);

	unsigned long long expect  = nsubs * pa.count;
	unsigned long long missing = nsubs ? expect - pa.recvs : 0;
	double             dur     = (pa.end - pa.beg) / 1000.0;

	printf("Sub Sent %llu messages in %.3f sec (%.2f msgs/sec)\n",
	    pa.count, dur, pa.count / dur);
	printf("Expected %llu messages total\n", expect);
	printf("Received %llu messages total\n", pa.recvs);
	printf("Effective rate %.2f msgs/sec\n", pa.recvs / dur);
	printf("Errors %llu total\n", pa.errs);
	printf("Reported %llu dropped messages in %llu gaps\n", pa.drops,
	    pa.gaps);
	printf("Dropped %llu messages (missing)\n", missing);
	printf("Drop rate %.2f%%\n", expect ? 100.0 * missing / expect : 0);

	nng_mtx_unlock(pa.mtx);
}
