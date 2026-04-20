//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>

#include <nuts.h>

// Verifies the platform iov clamp handles cumulative iov totals exceeding
// INT_MAX without triggering EINVAL (macOS/XNU sendmsg).  We build an
// oversized iov cheaply by referencing a single chunk 8 times; peak memory
// stays at ~256 MiB.
void
test_ipc_stream_iov_exceeds_int_max(void)
{
	nng_stream_dialer   *d    = NULL;
	nng_stream_listener *l    = NULL;
	char                *url;
	nng_aio             *daio = NULL;
	nng_aio             *laio = NULL;
	nng_aio             *saio = NULL;
	nng_stream          *c1   = NULL;
	nng_stream          *c2   = NULL;

	NUTS_ADDR(url, "ipc");
	NUTS_PASS(nng_aio_alloc(&daio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&laio, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&saio, NULL, NULL));

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

	// 8 x (INT_MAX/8 + 1) = INT_MAX + 1: cumulative iov just clears the
	// 32-bit signed kernel cap while committing only ~256 MiB of memory.
	const size_t per = ((size_t) INT_MAX / 8) + 1;
	char        *buf = malloc(per);
	NUTS_TRUE(buf != NULL);
	memset(buf, 'A', per);

	nng_iov iov[8];
	for (int i = 0; i < 8; i++) {
		iov[i].iov_buf = buf;
		iov[i].iov_len = per;
	}
	NUTS_PASS(nng_aio_set_iov(saio, 8, iov));

	// The peer never drains, so guard against any hang in the first
	// sendmsg by bounding the wait.  Normal completion is sub-second.
	nng_aio_set_timeout(saio, 10000);
	nng_stream_send(c1, saio);
	nng_aio_wait(saio);

	// sendmsg only moves what fits in SO_SNDBUF, but it must not fail.
	// Before the fix, macOS rejected the oversized iov with EINVAL.
	NUTS_PASS(nng_aio_result(saio));
	NUTS_TRUE(nng_aio_count(saio) > 0);
	NUTS_TRUE(nng_aio_count(saio) <= (size_t) INT_MAX);

	free(buf);
	nng_aio_free(saio);
	nng_aio_free(daio);
	nng_aio_free(laio);
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
	{ "ipc stream iov exceeds INT_MAX",
	    test_ipc_stream_iov_exceeds_int_max },
	{ NULL, NULL },
};
