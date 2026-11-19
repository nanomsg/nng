//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "../testing/nuts.h"
#include "lmq.h"

static void
test_lmq_resize_full_power_of_two(void)
{
	nni_lmq  lmq;
	nng_msg *msgs[5];
	nng_msg *out;
	size_t   i;

	for (i = 0; i < 5; i++) {
		NUTS_PASS(nng_msg_alloc(&msgs[i], 0));
	}

	nni_lmq_init(&lmq, 4);
	for (i = 0; i < 4; i++) {
		NUTS_PASS(nni_lmq_put(&lmq, msgs[i]));
	}
	NUTS_ASSERT(nni_lmq_len(&lmq) == 4);
	NUTS_ASSERT(nni_lmq_full(&lmq));

	// Resize to the same power-of-two capacity while the queue is full.
	NUTS_PASS(nni_lmq_resize(&lmq, 4));
	NUTS_ASSERT(nni_lmq_len(&lmq) == 4);
	NUTS_ASSERT(nni_lmq_cap(&lmq) == 4);
	NUTS_ASSERT(nni_lmq_full(&lmq));

	// Free one slot and enqueue another message. The put index must wrap
	// to a valid slot rather than pointing one past the allocated buffer.
	NUTS_PASS(nni_lmq_get(&lmq, &out));
	NUTS_ASSERT(out == msgs[0]);
	NUTS_PASS(nni_lmq_put(&lmq, msgs[4]));

	// Draining must yield the remaining original messages followed by the
	// newly enqueued one. Before the fix the new message was written out of
	// bounds and the stale msgs[0] was returned a second time.
	for (i = 1; i < 5; i++) {
		NUTS_PASS(nni_lmq_get(&lmq, &out));
		NUTS_ASSERT(out == msgs[i]);
	}
	NUTS_ASSERT(nni_lmq_empty(&lmq));

	nni_lmq_fini(&lmq);
	for (i = 0; i < 5; i++) {
		nng_msg_free(msgs[i]);
	}
}

NUTS_TESTS = {
	{ "lmq resize full power of two", test_lmq_resize_full_power_of_two },
	{ NULL, NULL },
};
