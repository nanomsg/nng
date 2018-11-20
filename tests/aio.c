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

void
cbdone(void *p)
{
	(*(int *) p)++;
}

void
sleepdone(void *arg)
{
	*(nng_time *) arg = nng_clock();
}

void
cancelfn(nng_aio *aio, void *arg, int rv)
{
	*(int *) arg = rv;
	nng_aio_finish(aio, rv);
}

Main({
	Test("AIO operations", {
		const char *addr = "inproc://aio";

		Convey("Sleep works", {
			nng_time start = 0;
			nng_time end   = 0;
			nng_aio *saio;
			So(nng_aio_alloc(&saio, sleepdone, &end) == 0);
			start = nng_clock();
			nng_sleep_aio(200, saio);
			nng_aio_wait(saio);
			So(nng_aio_result(saio) == 0);
			So(end != 0);
			So((end - start) >= 200);
			So((end - start) <= 1000);
			So((nng_clock() - start) >= 200);
			So((nng_clock() - start) <= 1000);
			nng_aio_free(saio);
		});

		Convey("Sleep timeout works", {
			nng_time start = 0;
			nng_time end   = 0;
			nng_aio *saio;
			So(nng_aio_alloc(&saio, sleepdone, &end) == 0);
			nng_aio_set_timeout(saio, 100);
			start = nng_clock();
			nng_sleep_aio(2000, saio);
			nng_aio_wait(saio);
			So(nng_aio_result(saio) == NNG_ETIMEDOUT);
			So(end != 0);
			So((end - start) >= 100);
			So((end - start) <= 1000);
			So((nng_clock() - start) >= 100);
			So((nng_clock() - start) <= 1000);
			nng_aio_free(saio);
		});

		Convey("Given a connected pair of sockets", {
			nng_socket s1;
			nng_socket s2;
			nng_aio *  txaio;
			nng_aio *  rxaio;
			int        txdone = 0;
			int        rxdone = 0;
			nng_msg *  m;

			So(nng_pair1_open(&s1) == 0);
			So(nng_pair1_open(&s2) == 0);

			So(nng_listen(s1, addr, NULL, 0) == 0);
			So(nng_dial(s2, addr, NULL, 0) == 0);

			So(nng_aio_alloc(&rxaio, cbdone, &rxdone) == 0);
			So(nng_aio_alloc(&txaio, cbdone, &txdone) == 0);

			Reset({
				nng_aio_free(rxaio);
				nng_aio_free(txaio);
				nng_close(s1);
				nng_close(s2);
			});

			nng_aio_set_timeout(rxaio, 100);
			nng_aio_set_timeout(txaio, 100);

			So(nng_msg_alloc(&m, 0) == 0);
			APPENDSTR(m, "hello");

			nng_recv_aio(s2, rxaio);

			nng_aio_set_msg(txaio, m);
			nng_send_aio(s1, txaio);

			nng_aio_wait(txaio);
			nng_aio_wait(rxaio);

			So(nng_aio_result(rxaio) == 0);
			So(nng_aio_result(txaio) == 0);

			So((m = nng_aio_get_msg(rxaio)) != NULL);
			CHECKSTR(m, "hello");

			nng_msg_free(m);

			So(rxdone == 1);
			So(txdone == 1);
		});

		Convey("Failure modes work", {
			nng_socket s;
			nng_aio *  a;
			int        done = 0;

			So(nng_pair1_open(&s) == 0);

			So(nng_aio_alloc(&a, cbdone, &done) == 0);

			Reset({
				nng_aio_free(a);
				nng_close(s);
			});

			Convey("Explicit timeout works", {
				nng_aio_set_timeout(a, 40);
				nng_recv_aio(s, a);
				nng_aio_wait(a);
				So(done == 1);
				So(nng_aio_result(a) == NNG_ETIMEDOUT);
			});
			Convey("Default timeout works", {
				So(nng_setopt_ms(s, NNG_OPT_RECVTIMEO, 40) ==
				    0);
				nng_recv_aio(s, a);
				nng_aio_wait(a);
				So(done == 1);
				So(nng_aio_result(a) == NNG_ETIMEDOUT);
			});
			Convey("Zero timeout works", {
				nng_aio_set_timeout(a, NNG_DURATION_ZERO);
				nng_recv_aio(s, a);
				nng_aio_wait(a);
				So(done == 1);
				So(nng_aio_result(a) == NNG_ETIMEDOUT);
			});
			Convey("Cancellation works", {
				nng_aio_set_timeout(a, NNG_DURATION_INFINITE);
				nng_recv_aio(s, a);
				nng_aio_cancel(a);
				nng_aio_wait(a);
				So(done == 1);
				So(nng_aio_result(a) == NNG_ECANCELED);
			})
		});

		Convey("We cannot set insane IOVs", {
			nng_aio *aio;
			nng_iov  iov;

			So(nng_aio_alloc(&aio, NULL, NULL) == 0);
			So(nng_aio_set_iov(aio, 1024, &iov) == NNG_EINVAL);
			nng_aio_free(aio);
		});

		Convey("Provider cancellation works", {
			nng_aio *aio;
			int      rv = 0;
			// We fake an empty provider that does not do anything.
			So(nng_aio_alloc(&aio, NULL, NULL) == 0);
			So(nng_aio_begin(aio) == true);
			nng_aio_defer(aio, cancelfn, &rv);
			nng_aio_cancel(aio);
			nng_aio_wait(aio);
			So(rv == NNG_ECANCELED);
			nng_aio_free(aio);
		});
	});

	nng_fini();
})
