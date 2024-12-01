//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>

#include <nuts.h>

void
test_ipc_stream(void)
{
	nng_stream_dialer   *d = NULL;
	nng_stream_listener *l = NULL;
	char                *url;
	nng_aio             *daio = NULL;
	nng_aio             *laio = NULL;
	nng_aio             *maio = NULL;
	nng_stream          *c1   = NULL;
	nng_stream          *c2   = NULL;
	nng_aio             *aio1;
	nng_aio             *aio2;
	nng_iov              iov;
	nng_sockaddr         sa2;
	char                 buf1[5];
	char                 buf2[5];

	NUTS_ADDR(url, "ipc");
	NUTS_PASS(nng_aio_alloc(&daio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&laio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&maio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));

	NUTS_PASS(nng_stream_listener_alloc(&l, url));
	NUTS_PASS(nng_stream_listener_listen(l));

	NUTS_PASS(nng_stream_dialer_alloc(&d, url));
	nng_stream_dialer_dial(d, daio);
	nng_stream_listener_accept(l, laio);

	nng_aio_wait(daio);
	NUTS_PASS(nng_aio_result(daio));
	nng_aio_wait(laio);
	NUTS_PASS(nng_aio_result(laio));

	c1 = nng_aio_get_output(daio, 0);
	c2 = nng_aio_get_output(laio, 0);
	NUTS_TRUE(c1 != NULL);
	NUTS_TRUE(c2 != NULL);

	// This relies on send completing for
	// for just 5 bytes, and on recv doing
	// the same.  Technically this isn't
	// guaranteed, but it would be weird
	// to split such a small payload.
	memcpy(buf1, "TEST", 5);
	memset(buf2, 0, 5);
	iov.iov_buf = buf1;
	iov.iov_len = 5;

	nng_aio_set_iov(aio1, 1, &iov);

	iov.iov_buf = buf2;
	iov.iov_len = 5;
	nng_aio_set_iov(aio2, 1, &iov);
	nng_stream_send(c1, aio1);
	nng_stream_recv(c2, aio2);
	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_TRUE(nng_aio_count(aio1) == 5);

	NUTS_PASS(nng_aio_result(aio2));
	NUTS_TRUE(nng_aio_count(aio2) == 5);

	NUTS_TRUE(memcmp(buf1, buf2, 5) == 0);

	NUTS_PASS(nng_stream_get_addr(c2, NNG_OPT_LOCADDR, &sa2));
	NUTS_TRUE(sa2.s_ipc.sa_family == NNG_AF_IPC);
	NUTS_MATCH(sa2.s_ipc.sa_path, url + strlen("ipc://"));

	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_aio_free(daio);
	nng_aio_free(laio);
	nng_aio_free(maio);

	nng_stream_listener_close(l);
	nng_stream_dialer_close(d);
	nng_stream_listener_free(l);
	nng_stream_dialer_free(d);
	nng_stream_close(c1);
	nng_stream_free(c1);
	nng_stream_close(c2);
	nng_stream_free(c2);
}

NUTS_TESTS = {
	{ "ipc stream", test_ipc_stream },
	{ NULL, NULL },
};
