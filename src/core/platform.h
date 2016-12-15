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

#ifndef CORE_PLATFORM_H
#define CORE_PLATFORM_H

/*
 * We require some standard C header files.  The only one of these that might
 * be problematic is <stdint.h>, which is required for C99.  Older versions
 * of the Windows compilers might not have this.  However, latest versions of
 * MS Studio have a functional <stdint.h>.  If this impacts you, just upgrade
 * your tool chain.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/*
 * These are the APIs that a platform must implement to support nng.
 */

/*
 * A word about fork-safety: This library is *NOT* fork safe, in that
 * functions may not be called in the child process without an intervening
 * exec().  The library attempts to detect this situation, and crashes the
 * process with an error message if it encounters it.  (See nn_platform_init
 * below.)
 *
 * Additionally, some file descriptors may leak across fork even to
 * child processes.  We make every reasonable effort to ensure that this
 * does not occur, but on some platforms there are unavoidable race
 * conditions between file creation and marking the file close-on-exec.
 *
 * Forkers should use posix_spawn() if possible, and as much as possible
 * arrange for file close on exec by posix_spawn, or close the descriptors
 * they do not need in the child.
 */

/*
 * nni_plat_abort crashes the system; it should do whatever is appropriate
 * for abnormal programs on the platform, such as calling abort().
 */
extern void nni_plat_abort(void);

/*
 * nni_plat_vnsprintf is exactly like its POSIX counterpart.
 * Some platforms (Windows!) need a special version of this.
 */
extern void nni_plat_vsnprintf(char *, size_t, const char *, va_list);

/*
 * nni_plat_println is used to emit debug messages.  Typically this is used
 * during core debugging, or to emit panic messages.  Message content will
 * not contain newlines, but the output will add them.
 */
extern void nni_plat_println(const char *);

/*
 * nni_alloc allocates memory.  In most cases this can just be malloc().
 * However, you may provide a different allocator, for example it is
 * possible to use a slab allocator or somesuch.  It is permissible for this
 * to return NULL if memory cannot be allocated.
 */
extern void *nni_alloc(size_t);

/*
 * nni_free frees memory allocated with nni_alloc. It takes a size because
 * some allocators do not track size, or can operate more efficiently if
 * the size is provided with the free call.  Examples of this are slab
 * allocators like this found in Solaris/illumos (see libumem or kmem).
 * This routine does nothing if supplied with a NULL pointer and zero size.
 * Most implementations can just call free() here.
 */
extern void nni_free(void *, size_t);

typedef struct nni_mutex *nni_mutex_t;
typedef struct nni_cond *nni_cond_t;

/*
 * Mutex handling.
 */
extern int nni_mutex_create(nni_mutex_t *);
extern void nni_mutex_destroy(nni_mutex_t);
extern void nni_mutex_enter(nni_mutex_t);
extern void nni_mutex_exit(nni_mutex_t);
extern int nni_mutex_tryenter(nni_mutex_t);

extern int nni_cond_create(nni_cond_t *, nni_mutex_t);
extern void nni_cond_destroy(nni_cond_t);

/*
 * nni_cond_broadcast wakes all waiters on the condition.  This should be
 * called with the lock held.
 */
extern void nni_cond_broadcast(nni_cond_t);

/*
 * nni_cond_signal wakes a signal waiter.
 */
extern void nni_cond_signal(nni_cond_t);

/*
 * nni_condwait waits for a wake up on the condition variable.  The
 * associated lock is atomically released and reacquired upon wake up.
 * Callers can be spuriously woken.  The associated lock must be held.
 */
extern void nni_cond_wait(nni_cond_t);

/*
 * nni_cond_timedwait waits for a wakeup on the condition variable, just
 * as with nni_condwait, but it will also wake after the given number of
 * microseconds has passed.  (This is a relative timed wait.)  Early
 * wakeups are permitted, and the caller must take care to double check any
 * conditions.  The return value is 0 on success, or an error code, which
 * can be NNG_ETIMEDOUT.  Note that it is permissible to wait for longer
 * than the timeout based on the resolution of your system clock.
 */
extern int nni_cond_timedwait(nni_cond_t, uint64_t);

typedef struct nni_thread *nni_thread_t;
/*
 * nni_thread_creates a thread that runs the given function. The thread
 * receives a single argument.
 */
extern int nni_thread_create(nni_thread_t *, void (*fn)(void *), void *);

/*
 * nni_thread_reap waits for the thread to exit, and then releases any
 * resources associated with the thread.  After this returns, it
 * is an error to reference the thread in any further way.
 */
extern void nni_thread_reap(nni_thread_t);

/*
 * nn_clock returns a number of microseconds since some arbitrary time
 * in the past.  The values returned by nni_clock may be used with
 * nni_cond_timedwait.
 */
extern uint64_t nni_clock(void);

/*
 * nni_usleep sleeps for the specified number of microseconds (at least).
 */
extern void nni_usleep(uint64_t);

/*
 * nni_platform_init is called to allow the platform the chance to
 * do any necessary initialization.  This routine MUST be idempotent,
 * and threadsafe, and will be called before any other API calls, and
 * may be called at any point thereafter.  It is permitted to return
 * an error if some critical failure inializing the platform occurs,
 * but once this succeeds, all future calls must succeed as well, unless
 * nni_plat_fini has been called.
 *
 * The function argument should be called if the platform has not initialized
 * (i.e. exactly once please), and its result passed back to the caller.
 */
extern int nni_plat_init(int (*)(void));

/*
 * nni_platform_fini is called to clean up resources.  It is intended to
 * be called as the last thing executed in the library, and no other functions
 * will be called until nni_platform_init is called.
 */
extern void nni_plat_fini(void);

/*
 * Actual platforms we support.
 */
#if defined(PLATFORM_POSIX)
#include "platform/posix/posix_impl.h"
#else
#error "unknown platform"
#endif

#endif /* CORE_PLATFORM_H */
