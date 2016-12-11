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

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

/*
 * These are the APIs that a platform must implement to support nng.
 */

/*
 * nni_abort crashes the system; it should do whatever is appropriate
 * for abnormal programs on the platform, such as calling abort().
 */
void nni_abort(void);

/*
 * nni_vnsprintf is exactly like its POSIX counterpart.
 * Some platforms (Windows!) need a special version of this.
 */
void nni_vsnprintf(char *, size_t, const char *, va_list);

/*
 * nni_debug_output is used to emit debug messages.  Typically this is used
 * during core debugging, or to emit panic messages.  Message content will
 * not contain newlines, but the output will add them.
 */
void nni_debug_out(const char *);

/*
 * nni_set_debug_output is used to redirect debug output; for example an
 * application could replace the default output routine with one that sends
 * it's output to syslog.  If NULL is specified, then a default handler
 * used instead.  The handler should add any newlines to the output as
 * required.  The default handler writes to standard error.
 */
void nni_set_debug_out(void (*)(const char *));

/*
 * nni_alloc allocates memory.  In most cases this can just be malloc().
 * However, you may provide a different allocator, for example it is
 * possible to use a slab allocator or somesuch.  It is permissible for this
 * to return NULL if memory cannot be allocated.
 */
void *nni_alloc(size_t);

/*
 * nni_free frees memory allocated with nni_alloc. It takes a size because
 * some allocators do not track size, or can operate more efficiently if
 * the size is provided with the free call.  Examples of this are slab
 * allocators like this found in Solaris/illumos (see libumem or kmem).
 * This routine does nothing if supplied with a NULL pointer and zero size.
 * Most implementations can just call free() here.
 */
void nni_free(void *, size_t);

typedef struct nni_mutex *nni_mutex_t;
typedef struct nni_cond *nni_cond_t;

/*
 * Mutex handling.
 */
int nni_mutex_create(nni_mutex_t *);
void nni_mutex_destroy(nni_mutex_t);
void nni_mutex_enter(nni_mutex_t);
void nni_mutex_exit(nni_mutex_t);
int nni_mutex_tryenter(nni_mutex_t);
int nni_cond_create(nni_cond_t *, nni_mutex_t);
void nni_cond_destroy(nni_cond_t);

/*
 * nni_cond_broadcast wakes all waiters on the condition.  This should be
 * called with the lock held.
 */
void nni_cond_broadcast(nni_cond_t);

/*
 * nni_cond_signal wakes a signal waiter.
 */
void nni_cond_signal(nni_cond_t);

/*
 * nni_condwait waits for a wake up on the condition variable.  The
 * associated lock is atomically released and reacquired upon wake up.
 * Callers can be spuriously woken.  The associated lock must be held.
 */
void nni_cond_wait(nni_cond_t);

/*
 * nni_cond_timedwait waits for a wakeup on the condition variable, just
 * as with nni_condwait, but it will also wake after the given number of
 * milliseconds has passed.  (This is a relative timed wait.)  Early
 * wakeups are permitted, and the caller must take care to double check any
 * conditions.  The return value is 0 on success, or an error code, which
 * can be NNG_ETIMEDOUT.
 */
int nnp_cond_timedwait(nni_cond_t, int);

#endif /* PLATFORM_H */
