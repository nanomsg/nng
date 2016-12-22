//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
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
typedef struct nni_msgqueue * nni_msgqueue_t;
typedef struct nni_msgqueue nni_msgqueue;

// nni_msgqueue_create creates a message queue with the given capacity,
// which must be a positive number.  It returns NNG_EINVAL if the capacity
// is invalid, or NNG_ENOMEM if resources cannot be allocated.
extern int nni_msgqueue_create(nni_msgqueue **, int);

// nni_msgqueue_destroy destroys a message queue.  It will also free any
// messages that may be in the queue.
extern void nni_msgqueue_destroy(nni_msgqueue *);

// nni_msgqueue_put puts the message to the queue.  It blocks until it
// was able to do so, or the queue is closed, returning either 0 on
// success or NNG_ECLOSED if the queue was closed.  If NNG_ECLOSED is
// returned, the caller is responsible for freeing the message with
// nni_msg_free(), otherwise the message is "owned" by the queue, and
// the caller is not permitted to access it further.
extern int nni_msgqueue_put(nni_msgqueue *, nni_msg *);

// nni_msgqueue_get gets the message from the queue.  It blocks until a
// message is available, or the queue is closed, returning either 0 on
// success or NNG_ECLOSED if the queue was closed.  If a message is
// provided, the caller is assumes ownership of the message and must
// call nni_msg_free() when it is finished with it.
extern int nni_msgqueue_get(nni_msgqueue *, nni_msg **);

// nni_msgqueue_put_until is like nni_msgqueue_put, except that if the
// system clock reaches the specified time without being able to place
// the message in the queue, it will return NNG_ETIMEDOUT.
extern int nni_msgqueue_put_until(nni_msgqueue *, nni_msg *, nni_time);

// nni_msgqueue_get_until is like nni_msgqueue_put, except that if the
// system clock reaches the specified time without being able to retrieve
// a message from the queue, it will return NNG_ETIMEDOUT.
extern int nni_msgqueue_get_until(nni_msgqueue *, nni_msg **, nni_time);

// nni_msgqueue_put_sig is an enhanced version of nni_msgqueue_put, but it
// can be interrupted by nni_msgqueue_signal using the same final pointer,
// which can be thought of as a turnstile.  If interrupted it returns EINTR.
// The turnstile should be initialized to zero.
extern int nni_msgqueue_put_sig(nni_msgqueue *, nni_msg *, nni_signal *);

// nni_msgqueue_get_sig is an enhanced version of nni_msgqueue_get_t, but it
// can be interrupted by nni_msgqueue_signal using the same final pointer,
// which can be thought of as a turnstile.  If interrupted it returns EINTR.
// The turnstile should be initialized to zero.
extern int nni_msgqueue_get_sig(nni_msgqueue *, nni_msg **, nni_signal *);

// nni_msgqueue_signal delivers a signal / interrupt to waiters blocked in
// the msgqueue, if they have registered an interest in the same turnstile.
// It modifies the turnstile's value under the lock to a non-zero value.
extern void nni_msgqueue_signal(nni_msgqueue *, nni_signal *);

// nni_msgqueue_close closes the queue.  After this all operates on the
// message queue will return NNG_ECLOSED.  Messages inside the queue
// are freed.  Unlike closing a go channel, this operation is idempotent.
extern void nni_msgqueue_close(nni_msgqueue *);

#endif  // CORE_MSQUEUE_H
