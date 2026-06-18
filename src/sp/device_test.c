//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>

#include <nuts.h>

struct dev_data {
	nng_socket s1;
	nng_socket s2;
};

#define SECOND(x) ((x) *1000)

static void
check_device_busy(nng_socket s)
{
	bool         raw;
	int          fd;
	nng_duration tmo;
	uint16_t     proto;
	const char  *name;

	NUTS_FAIL(nng_socket_close(s), NNG_EBUSY);
	NUTS_FAIL(nng_socket_set_ms(s, NNG_OPT_RECVTIMEO, SECOND(1)), NNG_EBUSY);
	NUTS_FAIL(nng_socket_get_ms(s, NNG_OPT_RECVTIMEO, &tmo), NNG_EBUSY);
	NUTS_FAIL(nng_socket_get_recv_poll_fd(s, &fd), NNG_EBUSY);
	NUTS_FAIL(nng_socket_get_send_poll_fd(s, &fd), NNG_EBUSY);
	NUTS_FAIL(nng_socket_proto_id(s, &proto), NNG_EBUSY);
	NUTS_FAIL(nng_socket_peer_id(s, &proto), NNG_EBUSY);
	NUTS_FAIL(nng_socket_proto_name(s, &name), NNG_EBUSY);
	NUTS_FAIL(nng_socket_peer_name(s, &name), NNG_EBUSY);
	NUTS_FAIL(nng_socket_raw(s, &raw), NNG_EBUSY);
}

void
test_device_not_cooked(void)
{
	nng_socket cooked;
	nng_socket raw;
	NUTS_PASS(nng_pair1_open(&cooked));
	NUTS_PASS(nng_pair1_open_raw(&raw));
	NUTS_FAIL(nng_device(cooked, cooked), NNG_EINVAL);
	NUTS_FAIL(nng_device(raw, cooked), NNG_EINVAL);
	NUTS_FAIL(nng_device(cooked, raw), NNG_EINVAL);
	NUTS_CLOSE(cooked);
	NUTS_CLOSE(raw);
}

void
test_device_incompatible(void)
{
	nng_socket s1;
	nng_socket s2;

	NUTS_PASS(nng_pair0_open_raw(&s1));
	NUTS_PASS(nng_pair1_open_raw(&s2));
	NUTS_FAIL(nng_device(s1, s2), NNG_EINVAL);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
test_device_aio_failure_keeps_sockets(void)
{
	nng_socket cooked;
	nng_socket raw;
	nng_aio   *aio;

	NUTS_PASS(nng_pair1_open(&cooked));
	NUTS_PASS(nng_pair1_open_raw(&raw));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_device_aio(aio, raw, cooked);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_EINVAL);

	NUTS_CLOSE(cooked);
	NUTS_CLOSE(raw);
	nng_aio_free(aio);
}

void
test_device_aio_duplicate_busy(void)
{
	nng_socket s1;
	nng_socket s2;
	nng_socket s3;
	nng_aio   *aio1;
	nng_aio   *aio2;

	NUTS_PASS(nng_pair1_open_raw(&s1));
	NUTS_PASS(nng_pair1_open_raw(&s2));
	NUTS_PASS(nng_pair1_open_raw(&s3));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	nng_device_aio(aio1, s1, s2);
	check_device_busy(s1);
	check_device_busy(s2);

	nng_device_aio(aio2, s1, s3);
	nng_aio_wait(aio2);
	NUTS_FAIL(nng_aio_result(aio2), NNG_EBUSY);
	NUTS_CLOSE(s3);

	nng_aio_cancel(aio1);
	nng_aio_wait(aio1);
	NUTS_FAIL(nng_aio_result(aio1), NNG_ECANCELED);
	NUTS_FAIL(nng_socket_close(s1), NNG_ECLOSED);
	NUTS_FAIL(nng_socket_close(s2), NNG_ECLOSED);

	nng_aio_free(aio1);
	nng_aio_free(aio2);
}

void
test_device_forward(void)
{
	struct dev_data d;
	nng_duration    tmo = SECOND(1);
	nng_socket      e1, e2;
	nng_aio        *aio;

	// will be a pair variant
	NUTS_PASS(nng_pair1_open_raw(&d.s1));
	NUTS_PASS(nng_pair1_open_raw(&d.s2));
	NUTS_PASS(nng_pair1_open(&e1));
	NUTS_PASS(nng_pair1_open(&e2));
	NUTS_PASS(nng_socket_set_ms(e1, NNG_OPT_RECVTIMEO, tmo));
	NUTS_PASS(nng_socket_set_ms(e2, NNG_OPT_RECVTIMEO, tmo));
	NUTS_PASS(nng_socket_set_ms(e1, NNG_OPT_SENDTIMEO, tmo));
	NUTS_PASS(nng_socket_set_ms(e2, NNG_OPT_SENDTIMEO, tmo));

	NUTS_MARRY(e1, d.s1);
	NUTS_MARRY(e2, d.s2);
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_device_aio(aio, d.s1, d.s2);

	NUTS_SEND(e1, "ping");
	NUTS_RECV(e2, "ping");
	NUTS_SEND(e2, "pong");
	NUTS_RECV(e1, "pong");

	nng_aio_cancel(aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	nng_aio_free(aio);

	NUTS_CLOSE(e1);
	NUTS_CLOSE(e2);
}

void
test_device_reflect(void)
{
	struct dev_data d;
	nng_duration    tmo = SECOND(1);
	nng_socket      e1;
	nng_aio        *aio;

	// will be a pair variant
	NUTS_PASS(nng_pair1_open_raw(&d.s1));
	d.s2 = d.s1;
	NUTS_PASS(nng_pair1_open(&e1));
	NUTS_PASS(nng_socket_set_ms(e1, NNG_OPT_RECVTIMEO, tmo));
	NUTS_PASS(nng_socket_set_ms(e1, NNG_OPT_SENDTIMEO, tmo));

	NUTS_MARRY(e1, d.s1);
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_device_aio(aio, d.s1, d.s2);

	NUTS_SEND(e1, "ping");
	NUTS_RECV(e1, "ping");
	NUTS_SEND(e1, "pong");
	NUTS_RECV(e1, "pong");

	nng_aio_cancel(aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	nng_aio_free(aio);

	NUTS_CLOSE(e1);
}

void
test_device_aio(void)
{
	struct dev_data d;
	nng_duration    tmo = SECOND(1);
	nng_socket      e1, e2;
	nng_aio        *aio;

	// will be a pair variant
	NUTS_PASS(nng_pair1_open_raw(&d.s1));
	NUTS_PASS(nng_pair1_open_raw(&d.s2));
	NUTS_PASS(nng_pair1_open(&e1));
	NUTS_PASS(nng_pair1_open(&e2));
	NUTS_PASS(nng_socket_set_ms(e1, NNG_OPT_RECVTIMEO, tmo));
	NUTS_PASS(nng_socket_set_ms(e2, NNG_OPT_RECVTIMEO, tmo));
	NUTS_PASS(nng_socket_set_ms(e1, NNG_OPT_SENDTIMEO, tmo));
	NUTS_PASS(nng_socket_set_ms(e2, NNG_OPT_SENDTIMEO, tmo));

	NUTS_MARRY(e1, d.s1);
	NUTS_MARRY(e2, d.s2);
	// cancellation of this aio is how we stop it
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_device_aio(aio, d.s1, d.s2);
	check_device_busy(d.s1);
	check_device_busy(d.s2);

	NUTS_SEND(e1, "ping");
	NUTS_RECV(e2, "ping");
	NUTS_SEND(e2, "pong");
	NUTS_RECV(e1, "pong");

	nng_aio_cancel(aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	nng_aio_free(aio);
	NUTS_FAIL(nng_socket_close(d.s1), NNG_ECLOSED);
	NUTS_FAIL(nng_socket_close(d.s2), NNG_ECLOSED);

	NUTS_CLOSE(e1);
	NUTS_CLOSE(e2);
}

NUTS_TESTS = {
	{ "device not cooked", test_device_not_cooked },
	{ "device incompatible", test_device_incompatible },
	{ "device aio failure keeps sockets", test_device_aio_failure_keeps_sockets },
	{ "device aio duplicate busy", test_device_aio_duplicate_busy },
	{ "device forward", test_device_forward },
	{ "device reflect", test_device_reflect },
	{ "device aio", test_device_aio },
	{ NULL, NULL },
};
