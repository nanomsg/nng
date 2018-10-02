//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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

// nni_msgq_flush discards any messages that are sitting in the queue.
// It does not wake any writers that might be waiting.
extern void nni_msgq_flush(nni_msgq *);

extern void nni_msgq_aio_put(nni_msgq *, nni_aio *);
extern void nni_msgq_aio_get(nni_msgq *, nni_aio *);

// nni_msgq_tryput performs a non-blocking attempt to put a message on
// the message queue.
extern int nni_msgq_tryput(nni_msgq *, nni_msg *);

// nni_msgq_set_error sets an error condition on the message queue,
// which causes all current and future readers/writes to return the
// given error condition (if non-zero).  Threads waiting to put or get
// are woken as well, if non-zero.  If zero, then any present error
// condition is cleared, and waiters are not woken (there shouldn't be
// any waiters unless it was already zero.)
extern void nni_msgq_set_error(nni_msgq *, int);

// nni_msgq_set_put_error sets an error condition on the put side of the
// message queue, and for that side behaves like nni_msgq_set_error.
// Readers (nni_msgq_get*) are unaffected.
extern void nni_msgq_set_put_error(nni_msgq *, int);

// nni_msgq_set_get_error sets an error condition on the get side of the
// message queue, and for that side behaves like nni_msgq_set_error.
// Readers (nni_msgq_put*) are unaffected.
extern void nni_msgq_set_get_error(nni_msgq *, int);

// nni_msgq_filter is a callback function used to filter messages.
// The function is called on entry (put) or exit (get).  The void
// argument is an opaque pointer supplied with the function at registration
// time.  The primary use for these functions is to support the protocol
// socket needs.
typedef nni_msg *(*nni_msgq_filter)(void *, nni_msg *);

// nni_msgq_set_filter sets the filter on the queue.  Messages
// are filtered through this just before they are returned via the get
// functions.  If the filter returns NULL, then the message is silently
// discarded instead, and any get waiters remain waiting.
extern void nni_msgq_set_filter(nni_msgq *, nni_msgq_filter, void *);

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

// nni_msgq_len returns the number of messages currently in the queue.
extern int nni_msgq_len(nni_msgq *mq);

extern int nni_msgq_get_recvable(nni_msgq *mq, nni_pollable **);
extern int nni_msgq_get_sendable(nni_msgq *mq, nni_pollable **);

// message queues keep statistics
extern uint64_t nni_msgq_stat_get_bytes(nni_msgq *);
extern uint64_t nni_msgq_stat_put_bytes(nni_msgq *);
extern uint64_t nni_msgq_stat_get_msgs(nni_msgq *);
extern uint64_t nni_msgq_stat_put_msgs(nni_msgq *);
extern uint64_t nni_msgq_stat_get_errs(nni_msgq *);
extern uint64_t nni_msgq_stat_put_errs(nni_msgq *);
extern uint64_t nni_msgq_stat_discards(nni_msgq *);

#endif // CORE_MSQUEUE_H
