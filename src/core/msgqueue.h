//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_MSGQUEUE_H
#define CORE_MSGQUEUE_H

#include "nng_impl.h"

// Message queues.  Message queues work in some ways like Go channels;
// they are a thread-safe way to pass messages between subsystems.  They
// do have additional capabilities though.
//
// A closed message queue cannot be written to, but if there are messages
// still in it and it is draining, it can be read from.  This permits
// linger operations to work.
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
// the message queue.  It is the same as calling nng_msgq_put_until with
// a zero time.
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

// nni_msgq_set_best_effort marks the message queue best effort on send.
// What this does is treat the message queue condition as if it were
// successful, returning 0, and discarding the message.  If zero is
// passed then this mode is reset to normal.
extern void nni_msgq_set_best_effort(nni_msgq *, int);

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

// nni_msgq_cb_flags is an enumeration of flag bits used with nni_msgq_cb.
enum nni_msgq_cb_flags {
	nni_msgq_f_full    = 1,
	nni_msgq_f_empty   = 2,
	nni_msgq_f_can_get = 4,
	nni_msgq_f_can_put = 8,
	nni_msgq_f_closed  = 16,
};

// nni_msgq_cb is a callback function used by sockets to monitor
// the status of the queue.  It is called with the lock held for
// performance reasons so consumers must not re-enter the queue.
// The purpose is to enable file descriptor notifications on the socket,
// which don't need to reenter the msgq.  The integer is a mask of
// flags that are true for the given message queue.
typedef void (*nni_msgq_cb)(void *, int);

// nni_msgq_set_cb sets the callback and argument for the callback
// which will be called on state changes in the message queue.  Only
// one callback can be registered on a message queue at a time.
extern void nni_msgq_set_cb(nni_msgq *, nni_msgq_cb, void *);

// nni_msgq_close closes the queue.  After this all operates on the
// message queue will return NNG_ECLOSED.  Messages inside the queue
// are freed.  Unlike closing a go channel, this operation is idempotent.
extern void nni_msgq_close(nni_msgq *);

// nni_msgq_drain is like nng_msgq_close, except that reads
// against the queue are permitted for up to the time limit.  The
// operation blocks until either the queue is empty, or the timeout
// has expired.  Any messages still in the queue at the timeout are freed.
extern void nni_msgq_drain(nni_msgq *, nni_time);

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

#endif // CORE_MSQUEUE_H
