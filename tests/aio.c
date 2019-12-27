//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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

#include "acutest.h"
#include "testutil.h"

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

void
test_sleep(void)
{
	nng_time start = 0;
	nng_time end   = 0;
	nng_aio *saio;

	TEST_NNG_PASS(nng_aio_alloc(&saio, sleepdone, &end));
	start = nng_clock();
	nng_sleep_aio(200, saio);
	nng_aio_wait(saio);
	TEST_NNG_PASS(nng_aio_result(saio));
	TEST_CHECK(end != 0);
	TEST_CHECK((end - start) >= 200);
	TEST_CHECK((end - start) <= 1000);
	TEST_CHECK((nng_clock() - start) >= 200);
	TEST_CHECK((nng_clock() - start) <= 1000);
	nng_aio_free(saio);
}

void
test_sleep_timeout(void)
{
	nng_time start = 0;
	nng_time end   = 0;
	nng_aio *saio;

	TEST_CHECK(nng_aio_alloc(&saio, sleepdone, &end) == 0);
	nng_aio_set_timeout(saio, 100);
	start = nng_clock();
	nng_sleep_aio(2000, saio);
	nng_aio_wait(saio);
	TEST_NNG_FAIL(nng_aio_result(saio), NNG_ETIMEDOUT);
	TEST_CHECK(end != 0);
	TEST_CHECK((end - start) >= 100);
	TEST_CHECK((end - start) <= 1000);
	TEST_CHECK((nng_clock() - start) >= 100);
	TEST_CHECK((nng_clock() - start) <= 1000);
	nng_aio_free(saio);
}

void
test_insane_niov(void)
{
	nng_aio *aio;
	nng_iov  iov;

	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_NNG_FAIL(nng_aio_set_iov(aio, 1024, &iov), NNG_EINVAL);
	nng_aio_free(aio);
}

void
test_provider_cancel(void)
{
	nng_aio *aio;
	int      rv = 0;
	// We fake an empty provider that does not do anything.
	TEST_NNG_PASS(nng_aio_alloc(&aio, NULL, NULL));
	TEST_CHECK(nng_aio_begin(aio) == true);
	nng_aio_defer(aio, cancelfn, &rv);
	nng_aio_cancel(aio);
	nng_aio_wait(aio);
	TEST_CHECK(rv == NNG_ECANCELED);
	nng_aio_free(aio);
}

void
test_consumer_cancel(void)
{
	nng_aio *  a;
	nng_socket s1;
	int        done = 0;

	TEST_CHECK(nng_pair1_open(&s1) == 0);
	TEST_CHECK(nng_aio_alloc(&a, cbdone, &done) == 0);

	nng_aio_set_timeout(a, NNG_DURATION_INFINITE);
	nng_recv_aio(s1, a);
	nng_aio_cancel(a);
	nng_aio_wait(a);
	TEST_CHECK(done == 1);
	TEST_CHECK(nng_aio_result(a) == NNG_ECANCELED);

	nng_aio_free(a);
	TEST_CHECK(nng_close(s1) == 0);
}

void
test_traffic(void)
{
	nng_socket s1;
	nng_socket s2;
	nng_aio *  txaio;
	nng_aio *  rxaio;
	int        txdone = 0;
	int        rxdone = 0;
	nng_msg *  m;
	char *     addr = "inproc://traffic";

	TEST_NNG_PASS(nng_pair1_open(&s1));
	TEST_NNG_PASS(nng_pair1_open(&s2));

	TEST_NNG_PASS(nng_listen(s1, addr, NULL, 0));
	TEST_NNG_PASS(nng_dial(s2, addr, NULL, 0));

	TEST_NNG_PASS(nng_aio_alloc(&rxaio, cbdone, &rxdone));
	TEST_NNG_PASS(nng_aio_alloc(&txaio, cbdone, &txdone));

	nng_aio_set_timeout(rxaio, 1000);
	nng_aio_set_timeout(txaio, 1000);

	TEST_NNG_PASS(nng_msg_alloc(&m, 0));
	TEST_NNG_PASS(nng_msg_append(m, "hello", strlen("hello")));

	nng_recv_aio(s2, rxaio);

	nng_aio_set_msg(txaio, m);
	nng_send_aio(s1, txaio);

	nng_aio_wait(txaio);
	nng_aio_wait(rxaio);

	TEST_NNG_PASS(nng_aio_result(rxaio));
	TEST_NNG_PASS(nng_aio_result(txaio));

	TEST_CHECK((m = nng_aio_get_msg(rxaio)) != NULL);
	TEST_CHECK(nng_msg_len(m) == strlen("hello"));
	TEST_CHECK(memcmp(nng_msg_body(m), "hello", strlen("hello")) == 0);

	nng_msg_free(m);

	TEST_CHECK(rxdone == 1);
	TEST_CHECK(txdone == 1);

	nng_aio_free(rxaio);
	nng_aio_free(txaio);
	TEST_NNG_PASS(nng_close(s1));
	TEST_NNG_PASS(nng_close(s2));
}

void
test_explicit_timeout(void)
{
	nng_socket s;
	nng_aio *  a;
	int        done = 0;

	TEST_NNG_PASS(nng_pair1_open(&s));
	TEST_NNG_PASS(nng_aio_alloc(&a, cbdone, &done));
	nng_aio_set_timeout(a, 40);
	nng_recv_aio(s, a);
	nng_aio_wait(a);
	TEST_CHECK(done == 1);
	TEST_NNG_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	TEST_NNG_PASS(nng_close(s));
}

void
test_inherited_timeout(void)
{
	nng_socket s;
	nng_aio *  a;
	int        done = 0;

	TEST_NNG_PASS(nng_pair1_open(&s));
	TEST_NNG_PASS(nng_aio_alloc(&a, cbdone, &done));
	TEST_NNG_PASS(nng_setopt_ms(s, NNG_OPT_RECVTIMEO, 40));
	nng_recv_aio(s, a);
	nng_aio_wait(a);
	TEST_CHECK(done == 1);
	TEST_NNG_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	TEST_NNG_PASS(nng_close(s));
}

void
test_zero_timeout(void)
{
	nng_socket s;
	nng_aio *  a;
	int        done = 0;

	TEST_NNG_PASS(nng_pair1_open(&s));
	TEST_NNG_PASS(nng_aio_alloc(&a, cbdone, &done));
	nng_aio_set_timeout(a, NNG_DURATION_ZERO);
	nng_recv_aio(s, a);
	nng_aio_wait(a);
	TEST_CHECK(done == 1);
	TEST_NNG_FAIL(nng_aio_result(a), NNG_ETIMEDOUT);
	nng_aio_free(a);
	TEST_NNG_PASS(nng_close(s));
}

TEST_LIST = {
	{ "sleep", test_sleep },
	{ "sleep timeout", test_sleep_timeout },
	{ "insane niov", test_insane_niov },
	{ "provider cancel", test_provider_cancel },
	{ "consumer cancel", test_consumer_cancel },
	{ "traffic", test_traffic },
	{ "explicit timeout", test_explicit_timeout },
	{ "inherited timeout", test_inherited_timeout },
	{ "zero timeout", test_zero_timeout },
	{ NULL, NULL },
};