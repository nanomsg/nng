//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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

typedef void (*nni_aio_cancelfn)(nni_aio *, void *, int);

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

// nni_aio_stop cancels any unfinished I/O, running completion callbacks,
// but also prevents any new operations from starting (nni_aio_start will
// return NNG_ESTATE).  This should be called before nni_aio_fini().  The
// best pattern is to call nni_aio_stop on all linked aios, before calling
// nni_aio_fini on any of them.  This function will block until any
// callbacks are executed, and therefore it should never be executed
// from a callback itself.  (To abort operations without blocking
// use nni_aio_cancel instead.)
extern void nni_aio_stop(nni_aio *);

// nni_aio_close closes the aio for further activity. It aborts any in-progress
// transaction (if it can), and future calls nni_aio_begin or nni_aio_schedule
// with both result in NNG_ECLOSED. The expectation is that protocols call this
// for all their aios in a stop routine, before calling fini on any of them.
extern void nni_aio_close(nni_aio *);

// nni_aio_set_data sets user data.  This should only be done by the
// consumer, initiating the I/O.  The intention is to be able to store
// additional data for use when the operation callback is executed.
// The index represents the "index" at which to store the data.  A maximum
// of 4 elements can be stored with the (index < 4).
extern void nni_aio_set_data(nni_aio *, unsigned, void *);

// nni_aio_get_data returns the user data that was previously stored
// with nni_aio_set_data.
extern void *nni_aio_get_data(nni_aio *, unsigned);

// nni_set_input sets input parameters on the AIO.  The semantic details
// of this will be determined by the specific AIO operation.  AIOs can
// carry up to 4 input parameters.
extern void nni_aio_set_input(nni_aio *, unsigned, void *);

// nni_get_input returns the input value stored by nni_aio_set_input.
extern void *nni_aio_get_input(nni_aio *, unsigned);

// nni_set_output sets output results on the AIO, allowing providers to
// return results to consumers.  The semantic details are determined by
// the AIO operation.  Up to 4 outputs can be carried on an AIO.
extern void nni_aio_set_output(nni_aio *, unsigned, void *);

// nni_get_output returns an output previously stored on the AIO.
extern void *nni_aio_get_output(nni_aio *, unsigned);

// XXX: These should be refactored in terms of generic inputs and outputs.
extern void     nni_aio_set_msg(nni_aio *, nni_msg *);
extern nni_msg *nni_aio_get_msg(nni_aio *);

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
extern void nni_aio_list_prepend(nni_list *, nni_aio *);
extern void nni_aio_list_remove(nni_aio *);
extern int  nni_aio_list_active(nni_aio *);

// nni_aio_finish is called by the provider when an operation is complete.
extern void nni_aio_finish(nni_aio *, int, size_t);
// nni_aio_finish_synch is to be called when a synchronous completion is
// desired.  It is very important that the caller not hold any locks when
// calling this, but it is useful for chaining completions to minimize
// context switch overhead during completions.
extern void nni_aio_finish_synch(nni_aio *, int, size_t);
extern void nni_aio_finish_error(nni_aio *, int);
extern void nni_aio_finish_msg(nni_aio *, nni_msg *);

// nni_aio_abort is used to abort an operation.  Any pending I/O or
// timeouts are canceled if possible, and the callback will be returned
// with the indicated result (NNG_ECLOSED or NNG_ECANCELED is recommended.)
extern void nni_aio_abort(nni_aio *, int rv);

// nni_aio_begin is called by a provider to indicate it is starting the
// operation, and to check that the aio has not already been marked for
// teardown.  It returns 0 on success, or NNG_ECANCELED if the aio is being
// torn down.  (In that case, no operation should be aborted without any
// call to any other functions on this AIO, most especially not the
// nng_aio_finish family of functions.)
extern int nni_aio_begin(nni_aio *);

extern void *nni_aio_get_prov_data(nni_aio *);
extern void  nni_aio_set_prov_data(nni_aio *, void *);
extern void *nni_aio_get_prov_extra(nni_aio *, unsigned);
extern void  nni_aio_set_prov_extra(nni_aio *, unsigned, void *);
// nni_aio_advance_iov moves up the iov, reflecting that some I/O as
// been performed.  It returns the amount of data remaining in the argument;
// i.e. if the count refers to more data than the iov can support, then
// the result will be left over count.
extern size_t nni_aio_iov_advance(nni_aio *, size_t);
// nni_aio_iov_count returns the number of bytes referenced by the aio's iov.
extern size_t nni_aio_iov_count(nni_aio *);

extern int nni_aio_set_iov(nni_aio *, unsigned, const nni_iov *);

extern void nni_aio_set_timeout(nni_aio *, nng_duration);
extern void nni_aio_get_iov(nni_aio *, unsigned *, nni_iov **);
extern void nni_aio_normalize_timeout(nni_aio *, nng_duration);
extern void nni_aio_bump_count(nni_aio *, size_t);

extern void nni_aio_set_sockaddr(nni_aio *aio, const nng_sockaddr *);
extern void nni_aio_get_sockaddr(nni_aio *aio, nng_sockaddr *);

// nni_aio_schedule indicates that the AIO has begun, and is scheduled for
// asychronous completion. This also starts the expiration timer. Note that
// prior to this, the aio is uncancellable.  If the operation has a zero
// timeout (NNG_FLAG_NONBLOCK) then NNG_ETIMEDOUT is returned.  If the
// operation has already been canceled, or should not be run, then an error
// is returned.  (In that case the caller should probably either return an
// error to its caller, or possibly cause an asynchronous error by calling
// nni_aio_finish_error on this aio.)
extern int nni_aio_schedule(nni_aio *, nni_aio_cancelfn, void *);

extern void nni_sleep_aio(nni_duration, nni_aio *);

extern int  nni_aio_sys_init(void);
extern void nni_aio_sys_fini(void);
#endif // CORE_AIO_H
