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

// nni_msgqueue_put attempts to put a message to the queue.  It will wait
// for the timeout (us), if the value is positive.  If the value is negative
// then it will wait forever. If the value is zero, it will just check, and
// return immediately whether a message can be put or not.  Valid returns are
// NNG_ECLOSED if the queue is closed or NNG_ETIMEDOUT if the message cannot
// be placed after a time, or NNG_EAGAIN if the operation cannot succeed
// immediately and a zero timeout is specified.  Note that timeout granularity
// may be limited -- for example Windows systems have a millisecond resolution
// timeout capability.
extern int nni_msgqueue_put(nni_msgqueue *, nni_msg *, int);

// nni_msgqueue_get gets the message from the queue, using a timeout just
// like nni_msgqueue_put.
extern int nni_msgqueue_get(nni_msgqueue *, nni_msg **, int);

// nni_msgqueue_put_sig is an enhanced version of nni_msgqueue_put, but it
// can be interrupted by nni_msgqueue_signal using the same final pointer,
// which can be thought of as a turnstile.  If interrupted it returns EINTR.
// The turnstile should be initialized to zero.
extern int nni_msgqueue_put_sig(nni_msgqueue *, nni_msg *, int, int *);

// nni_msgqueue_get_sig is an enhanced version of nni_msgqueue_get_t, but it
// can be interrupted by nni_msgqueue_signal using the same final pointer,
// which can be thought of as a turnstile.  If interrupted it returns EINTR.
// The turnstile should be initialized to zero.
extern int nni_msgqueue_get_sig(nni_msgqueue *, nni_msg **, int, int *);

// nni_msgqueue_signal delivers a signal / interrupt to waiters blocked in
// the msgqueue, if they have registered an interest in the same turnstile.
// It modifies the turnstile's value under the lock to a non-zero value.
extern void nni_msgqueue_signal(nni_msgqueue *, int *);

// nni_msgqueue_close closes the queue.  After this all operates on the
// message queue will return NNG_ECLOSED.  Messages inside the queue
// are freed.  Unlike closing a go channel, this operation is idempotent.
extern void nni_msgqueue_close(nni_msgqueue *);

#endif  // CORE_MSQUEUE_H
