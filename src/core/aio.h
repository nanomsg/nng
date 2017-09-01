//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_AIO_H
#define CORE_AIO_H

#include "core/defs.h"
#include "core/list.h"
#include "core/taskq.h"
#include "core/thread.h"

typedef struct nni_aio_ops nni_aio_ops;

typedef void (*nni_aio_cancelfn)(nni_aio *, int);

// An nni_aio is an async I/O handle.
struct nni_aio {
	int      a_result; // Result code (nng_errno)
	size_t   a_count;  // Bytes transferred (I/O only)
	nni_time a_expire;

	// These fields are private to the aio framework.
	nni_cv   a_cv;
	unsigned a_init : 1;     // initialized flag
	unsigned a_fini : 1;     // shutting down (no new operations)
	unsigned a_done : 1;     // operation has completed
	unsigned a_pend : 1;     // completion routine pending
	unsigned a_active : 1;   // aio was started
	unsigned a_expiring : 1; // expiration callback in progress
	unsigned a_waiting : 1;  // a thread is waiting for this to finish
	unsigned a_synch : 1;    // run completion synchronously
	unsigned a_pad : 25;     // ensure 32-bit alignment
	nni_task a_task;

	// Read/write operations.
	nni_iov a_iov[4];
	int     a_niov;

	// Message operations.
	nni_msg *a_msg;

	// Connect/accept operations.
	void *a_endpt; // opaque endpoint handle
	void *a_pipe;  // opaque pipe handle

	// Resolver operations.
	nni_sockaddr *a_addr;

	// Extra user data.
	void *a_data;

	// Provider-use fields.
	nni_aio_cancelfn a_prov_cancel;
	void *           a_prov_data;
	nni_list_node    a_prov_node;

	// Expire node.
	nni_list_node a_expire_node;
};

// nni_aio_init initializes an aio object.  The callback is called with
// the supplied argument when the operation is complete.  If NULL is
// supplied for the callback, then nni_aio_wake is used in its place,
// and the aio is used for the argument.
extern int nni_aio_init(nni_aio **, nni_cb, void *);

// nni_aio_fini finalizes the aio, releasing resources (locks)
// associated with it.  The caller is responsible for ensuring that any
// associated I/O is unscheduled or complete.  This is safe to call
// on zero'd memory.
extern void nni_aio_fini(nni_aio *);

// nni_aio_fini_cb finalizes the aio WITHOUT waiting for it to complete.
// This is intended exclusively for finalizing an AIO from a completion
// callack for that AIO. It is important that the caller ensure that nothing
// else might be waiting for that AIO or using it.
extern void nni_aio_fini_cb(nni_aio *);

// nni_aio_stop cancels any unfinished I/O, running completion callbacks,
// but also prevents any new operations from starting (nni_aio_start will
// return NNG_ESTATE).  This should be called before nni_aio_fini().  The
// best pattern is to call nni_aio_stop on all linked aios, before calling
// nni_aio_fini on any of them.  This function will block until any
// callbacks are executed, and therefore it should never be executed
// from a callback itself.  (To abort operations without blocking
// use nni_aio_cancel instead.)
extern void nni_aio_stop(nni_aio *);

// nni_aio_set_data sets user data.  This should only be done by the
// consumer, initiating the I/O.  The intention is to be able to store
// additional data for use when the operation callback is executed.
extern void nni_aio_set_data(nni_aio *, void *);

// nni_aio_get_data returns the user data that was previously stored
// with nni_aio_set_data.
extern void *nni_aio_get_data(nni_aio *);

extern void     nni_aio_set_msg(nni_aio *, nni_msg *);
extern nni_msg *nni_aio_get_msg(nni_aio *);
extern void     nni_aio_set_pipe(nni_aio *, void *);
extern void *   nni_aio_get_pipe(nni_aio *);
extern void     nni_aio_set_ep(nni_aio *, void *);
extern void *   nni_aio_get_ep(nni_aio *);

// nni_aio_set_synch sets a synchronous completion flag on the AIO.
// When this is set, the next time the AIO is completed, the callback
// be run synchronously, from the thread calling the finish routine.
// It is important that this only be set when the provider knows that
// it is not holding any locks or resources when completing the operation,
// or when the consumer knows that the callback routine does not acquire
// any locks.  Use with caution to avoid deadlocks.  The flag is cleared
// automatically when the completion callback is executed.  Some care has
// been taken so that other aio operations like aio_wait will work,
// although it is still an error to try waiting for an aio from that aio's
// completion callback.
void nni_aio_set_synch(nni_aio *);

// nni_aio_set_timeout sets the timeout (absolute) when the AIO will
// be canceled.  The cancelation does not happen until after nni_aio_start
// is called.
extern void nni_aio_set_timeout(nni_aio *, nni_time);

// nni_aio_result returns the result code (0 on success, or an NNG errno)
// for the operation.  It is only valid to call this when the operation is
// complete (such as when the callback is executed or after nni_aio_wait
// is performed).
extern int nni_aio_result(nni_aio *);

// nni_aio_count returns the number of bytes of data transferred, if any.
// As with nni_aio_result, it is only defined if the I/O operation has
// completed.
extern size_t nni_aio_count(nni_aio *);

// nni_aio_wait blocks the caller until the operation is complete.
// The operation must have already been started.  This routine will
// block until the AIO, as well as any callback, has completed execution.
// If the callback routine reschedules the AIO, the wait may wind up
// waiting for the rescheduled operation; this is most often used in
// lieu of a callback to build synchronous constructs on top of AIOs.
extern void nni_aio_wait(nni_aio *);

// nni_aio_list_init creates a list suitable for use by providers using
// the a_prov_node member of the aio.  These operations are not locked,
// but they do have some extra checks -- remove is idempotent for example,
// and append will perform any necessary remove first.
extern void nni_aio_list_init(nni_list *);
extern void nni_aio_list_append(nni_list *, nni_aio *);
extern void nni_aio_list_remove(nni_aio *);
extern int  nni_aio_list_active(nni_aio *);

// nni_aio_finish is called by the provider when an operation is complete.
extern void nni_aio_finish(nni_aio *, int, size_t);
extern void nni_aio_finish_error(nni_aio *, int);
extern void nni_aio_finish_pipe(nni_aio *, void *);
extern void nni_aio_finish_msg(nni_aio *, nni_msg *);

// nni_aio_cancel is used to cancel an operation.  Any pending I/O or
// timeouts are canceled if possible, and the callback will be returned
// with the indicated result (NNG_ECLOSED or NNG_ECANCELED is recommended.)
extern void nni_aio_cancel(nni_aio *, int rv);

extern int nni_aio_start(nni_aio *, nni_aio_cancelfn, void *);

// nni_aio_stop is used to abort all further operations on the AIO.
// When this is executed, no further operations or callbacks will be
// executed, and if callbacks or I/O is in progress this will block
// until they are either canceled or aborted.  (Question: why not just
// nni_fini?)
// extern void nni_aio_stop(nni_aio *);

extern int  nni_aio_sys_init(void);
extern void nni_aio_sys_fini(void);
#endif // CORE_AIO_H
