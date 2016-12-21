/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#ifndef CORE_MSGQUEUE_H
#define CORE_MSGQUEUE_H

#include "nng.h"

/*
 * Message queues.  Message queues work in some ways like Go channels;
 * they are a thread-safe way to pass messages between subsystems.
 */
typedef struct nni_msgqueue * nni_msgqueue_t;

/*
 * nni_msgqueue_create creates a message queue with the given capacity,
 * which must be a positive number.  It returns NNG_EINVAL if the capacity
 * is invalid, or NNG_ENOMEM if resources cannot be allocated.
 */
extern int nni_msgqueue_create(nni_msgqueue_t *, int);

/*
 * nni_msgqueue_destroy destroys a message queue.  It will also free any
 * messages that may be in the queue.
 */
extern void nni_msgqueue_destroy(nni_msgqueue_t);

/*
 * nni_msgqueue_put attempts to put a message to the queue.  It will wait
 * for the timeout (us), if the value is positive.  If the value is negative
 * then it will wait forever. If the value is zero, it will just check, and
 * return immediately whether a message can be put or not.  Valid returns are
 * NNG_ECLOSED if the queue is closed or NNG_ETIMEDOUT if the message cannot
 * be placed after a time, or NNG_EAGAIN if the operation cannot succeed
 * immediately and a zero timeout is specified.  Note that timeout granularity
 * may be limited -- for example Windows systems have a millisecond resolution
 * timeout capability.
 */
extern int nni_msgqueue_put(nni_msgqueue_t, nng_msg_t, int);

/*
 * nni_msgqueue_get gets the message from the queue, using a timeout just
 * like nni_msgqueue_put.
 */
extern int nni_msgqueue_get(nni_msgqueue_t, nng_msg_t *, int);

/*
 * The following two functions are interruptible versions of msgqueue_get
 * and msgqueue_put.  The signal argument (pointer) must be initialized
 * to zero.  Then, we can raise a signal, by calling nni_msgqueue_signal
 * on the same object.  The signal flag will remain raised until it is
 * cleared to zero.  If a routine is interrupted, it will return NNG_EINTR.
 * Note that only threads using the signal object will be interrupted;
 * this has no effect on other threads that may be waiting on the msgqueue
 * as well.
 */
extern int nni_msgqueue_put_sig(nni_msgqueue_t, nng_msg_t, int, int *);
extern int nni_msgqueue_get_sig(nni_msgqueue_t, nng_msg_t *, int, int *);
extern void nni_msgqueue_signal(nni_msgqueue_t, int *);

/*
 * nni_msgqueue_close closes the queue.  After this all operates on the
 * message queue will return NNG_ECLOSED.  Messages inside the queue
 * are freed.  Unlike closing a go channel, this operation is idempotent.
 */
extern void nni_msgqueue_close(nni_msgqueue_t);

#endif  /* CORE_MSQUEUE_H */
