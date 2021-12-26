//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_LMQ_H
#define CORE_LMQ_H

#include "nng_impl.h"

// nni_lmq is a very lightweight message queue.  Defining it this way allows
// us to share some common code.  Locking must be supplied by the caller.
// For performance reasons, this is allocated inline.
typedef struct nni_lmq {
	size_t    lmq_cap;
	size_t    lmq_alloc; // alloc is cap, rounded up to power of 2
	size_t    lmq_mask;
	size_t    lmq_len;
	size_t    lmq_get;
	size_t    lmq_put;
	nng_msg **lmq_msgs;
	nng_msg  *lmq_buf[2]; // default minimal buffer
} nni_lmq;

extern void   nni_lmq_init(nni_lmq *, size_t);
extern void   nni_lmq_fini(nni_lmq *);
extern void   nni_lmq_flush(nni_lmq *);
extern size_t nni_lmq_len(nni_lmq *);
extern size_t nni_lmq_cap(nni_lmq *);
extern int    nni_lmq_put(nni_lmq *lmq, nng_msg *msg);
extern int    nni_lmq_get(nni_lmq *lmq, nng_msg **mp);
extern int    nni_lmq_resize(nni_lmq *, size_t);
extern bool   nni_lmq_full(nni_lmq *);
extern bool   nni_lmq_empty(nni_lmq *);

#endif // CORE_LMQ_H
