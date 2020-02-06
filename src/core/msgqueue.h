//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_MSGQUEUE_H
#define CORE_MSGQUEUE_H

#include "nng_impl.h"
#include "pollable.h"

// Message queues.  Message queues work in some ways like Go channels;
// they are a thread-safe way to pass messages between subsystems.  They
// do have additional capabilities though.
//
// Message queues can be closed many times safely.
//
// Readers & writers in a message queue can be woken either by a timeout
// or by a specific signal (arranged by the caller).
typedef struct nni_msgq nni_msgq;

// nni_msgq_init creates a message queue with the given capacity.
// (If the capacity is zero, then the queue is unbuffered.)
// It returns NNG_ENOMEM if resources cannot be allocated.
extern int nni_msgq_init(nni_msgq **, unsigned);

// nni_msgq_fini destroys a message queue.  It will also free any
// messages that may be in the queue.
extern void nni_msgq_fini(nni_msgq *);


extern void nni_msgq_aio_put(nni_msgq *, nni_aio *);
extern void nni_msgq_aio_get(nni_msgq *, nni_aio *);

// nni_msgq_tryput performs a non-blocking attempt to put a message on
// the message queue.
extern int nni_msgq_tryput(nni_msgq *, nni_msg *);

// nni_msgq_close closes the queue.  After this all operates on the
// message queue will return NNG_ECLOSED.  Messages inside the queue
// are freed.  Unlike closing a go channel, this operation is idempotent.
extern void nni_msgq_close(nni_msgq *);

// nni_msgq_resize resizes the message queue; messages already in the queue
// will be preserved as long as there is room.  Messages that are dropped
// due to no room are taken from the most recent.  (Oldest messages are
// preserved.)
extern int nni_msgq_resize(nni_msgq *, int);

// nni_msgq_cap returns the "capacity" of the message queue.  This does not
// include the extra room for pushback, nor the extra slot reserved to make
// zero-length message queues possible.  As a consequence, it is possible
// for the message queue to contain up to 2 more messages than the capacity.
extern int nni_msgq_cap(nni_msgq *mq);

extern int nni_msgq_get_recvable(nni_msgq *mq, nni_pollable **);
extern int nni_msgq_get_sendable(nni_msgq *mq, nni_pollable **);

#endif // CORE_MSQUEUE_H
