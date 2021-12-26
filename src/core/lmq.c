//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng_impl.h"

// Light-weight message queue. These are derived from our heavy-weight
// message queues, but are less "featured", but more useful for
// performance sensitive contexts.  Locking must be done by the caller.


// Note that initialization of a queue is guaranteed to succeed.
// However, if the requested capacity is larger than 2, and memory
// cannot be allocated, then the capacity will only be 2.
void
nni_lmq_init(nni_lmq *lmq, size_t cap)
{
	lmq->lmq_len = 0;
	lmq->lmq_get = 0;
	lmq->lmq_put = 0;
	lmq->lmq_alloc = 0;
	lmq->lmq_mask = 0;
	lmq->lmq_msgs = NULL;
	lmq->lmq_msgs = lmq->lmq_buf;
	lmq->lmq_cap = 2;
	lmq->lmq_mask = 0x1; // only index 0 and 1
	if (cap > 2) {
		(void) nni_lmq_resize(lmq, cap);
	} else {
		lmq->lmq_cap = cap;
	}
}

void
nni_lmq_fini(nni_lmq *lmq)
{
	if (lmq == NULL) {
		return;
	}

	/* Free any orphaned messages. */
	while (lmq->lmq_len > 0) {
		nng_msg *msg = lmq->lmq_msgs[lmq->lmq_get++];
		lmq->lmq_get &= lmq->lmq_mask;
		lmq->lmq_len--;
		nni_msg_free(msg);
	}
	if (lmq->lmq_alloc > 0) {
		nni_free(lmq->lmq_msgs, lmq->lmq_alloc * sizeof(nng_msg *));
	}
}

void
nni_lmq_flush(nni_lmq *lmq)
{
	while (lmq->lmq_len > 0) {
		nng_msg *msg = lmq->lmq_msgs[lmq->lmq_get++];
		lmq->lmq_get &= lmq->lmq_mask;
		lmq->lmq_len--;
		nni_msg_free(msg);
	}
}

size_t
nni_lmq_len(nni_lmq *lmq)
{
	return (lmq->lmq_len);
}

size_t
nni_lmq_cap(nni_lmq *lmq)
{
	return (lmq->lmq_cap);
}

bool
nni_lmq_full(nni_lmq *lmq)
{
	return (lmq->lmq_len >= lmq->lmq_cap);
}

bool
nni_lmq_empty(nni_lmq *lmq)
{
	return (lmq->lmq_len == 0);
}

int
nni_lmq_put(nni_lmq *lmq, nng_msg *msg)
{
	if (lmq->lmq_len >= lmq->lmq_cap) {
		return (NNG_EAGAIN);
	}
	lmq->lmq_msgs[lmq->lmq_put++] = msg;
	lmq->lmq_len++;
	lmq->lmq_put &= lmq->lmq_mask;
	return (0);
}

int
nni_lmq_get(nni_lmq *lmq, nng_msg **mp)
{
	nng_msg *msg;
	if (lmq->lmq_len == 0) {
		return (NNG_EAGAIN);
	}
	msg = lmq->lmq_msgs[lmq->lmq_get++];
	lmq->lmq_get &= lmq->lmq_mask;
	lmq->lmq_len--;
	*mp = msg;
	return (0);
}

int
nni_lmq_resize(nni_lmq *lmq, size_t cap)
{
	nng_msg  *msg;
	nng_msg **new_q;
	size_t    alloc;
	size_t    len;

	alloc = 2;
	while (alloc < cap) {
		alloc *= 2;
	}

	if ((new_q = nni_alloc(sizeof(nng_msg *) * alloc)) == NULL) {
		return (NNG_ENOMEM);
	}

	len = 0;
	while ((len < cap) && (nni_lmq_get(lmq, &msg) == 0)) {
		new_q[len++] = msg;
	}

	// Flush anything left over.
	nni_lmq_flush(lmq);

	if (lmq->lmq_alloc > 0) {
		nni_free(lmq->lmq_msgs, lmq->lmq_alloc * sizeof(nng_msg *));
	}
	lmq->lmq_msgs  = new_q;
	lmq->lmq_cap   = cap;
	lmq->lmq_alloc = alloc;
	lmq->lmq_mask  = alloc - 1;
	lmq->lmq_len   = len;
	lmq->lmq_put   = len;
	lmq->lmq_get   = 0;

	return (0);
}
