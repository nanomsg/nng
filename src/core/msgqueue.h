/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef CORE_MSGQUEUE_H
#define CORE_MSGQUEUE_H

#include "nng.h"

/*
 * Message queues.  Message queues work in some ways like Go channels;
 * they are a thread-safe way to pass messages between subsystems.
 */
typedef struct nni_msgqueue *nni_msgqueue_t;

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
 * nni_msgqueue_close closes the queue.  After this all operates on the
 * message queue will return NNG_ECLOSED.  Messages inside the queue
 * are freed.  Unlike closing a go channel, this operation is idempotent.
 */
extern void nni_msgqueue_close(nni_msgqueue_t);

#endif	/* CORE_MSQUEUE_H */
