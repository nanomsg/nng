//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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
typedef struct nni_msgq   nni_msgq;

// nni_msgq_init creates a message queue with the given capacity,
// which must be a positive number.  It returns NNG_EINVAL if the capacity
// is invalid, or NNG_ENOMEM if resources cannot be allocated.
extern int nni_msgq_init(nni_msgq **, int);

// nni_msgq_fini destroys a message queue.  It will also free any
// messages that may be in the queue.
extern void nni_msgq_fini(nni_msgq *);

extern int nni_msgq_aio_put(nni_msgq *, nni_aio *);
extern int nni_msgq_aio_get(nni_msgq *, nni_aio *);
extern int nni_msgq_aio_notify_get(nni_msgq *, nni_aio *);
extern int nni_msgq_aio_notify_put(nni_msgq *, nni_aio *);
extern int nni_msgq_aio_cancel(nni_msgq *, nni_aio *);

// nni_msgq_put puts the message to the queue.  It blocks until it
// was able to do so, or the queue is closed, returning either 0 on
// success or NNG_ECLOSED if the queue was closed.  If NNG_ECLOSED is
// returned, the caller is responsible for freeing the message with
// nni_msg_free(), otherwise the message is "owned" by the queue, and
// the caller is not permitted to access it further.
extern int nni_msgq_put(nni_msgq *, nni_msg *);

// nni_msgq_tryput is like nni_msgq_put, except that it does not block,
// if there is no room to put the message it simply returns NNG_EAGAIN.
extern int nni_msgq_tryput(nni_msgq *, nni_msg *);

// nni_msgq_get gets the message from the queue.  It blocks until a
// message is available, or the queue is closed, returning either 0 on
// success or NNG_ECLOSED if the queue was closed.  If a message is
// provided, the caller is assumes ownership of the message and must
// call nni_msg_free() when it is finished with it.
extern int nni_msgq_get(nni_msgq *, nni_msg **);

// nni_msgq_put_until is like nni_msgq_put, except that if the
// system clock reaches the specified time without being able to place
// the message in the queue, it will return NNG_ETIMEDOUT.
extern int nni_msgq_put_until(nni_msgq *, nni_msg *, nni_time);

// nni_msgq_get_until is like nni_msgq_put, except that if the
// system clock reaches the specified time without being able to retrieve
// a message from the queue, it will return NNG_ETIMEDOUT.
extern int nni_msgq_get_until(nni_msgq *, nni_msg **, nni_time);

// nni_msgq_put_sig is an enhanced version of nni_msgq_put, but it
// can be interrupted by nni_msgqueue_signal using the same final pointer,
// which can be thought of as a turnstile.  If interrupted it returns EINTR.
// The turnstile should be initialized to zero.
extern int nni_msgq_put_sig(nni_msgq *, nni_msg *, nni_signal *);

// nni_msgq_get_sig is an enhanced version of nni_msgq_get_t, but it
// can be interrupted by nni_msgq_signal using the same final pointer,
// which can be thought of as a turnstile.  If interrupted it returns EINTR.
// The turnstile should be initialized to zero.
extern int nni_msgq_get_sig(nni_msgq *, nni_msg **, nni_signal *);

// nni_msgq_signal delivers a signal / interrupt to waiters blocked in
// the msgq, if they have registered an interest in the same turnstile.
// It modifies the turnstile's value under the lock to a non-zero value.
extern void nni_msgq_signal(nni_msgq *, nni_signal *);

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

#define NNI_MSGQ_NOTIFY_CANPUT		1
#define NNI_MSGQ_NOTIFY_CANGET		2

typedef void (*nni_msgq_notify_fn)(nni_msgq *, int, void *);

// nni_msgq_notify registers a function to be called when the message
// queue state changes.  It notifies that the queue is readable, or writeable.
// Only one function can be registered (for simplicity), and it is called
// outside of the queue's lock.
extern int nni_msgq_notify(nni_msgq *, nni_msgq_notify_fn, void *);

#endif  // CORE_MSQUEUE_H
