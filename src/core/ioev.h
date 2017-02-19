//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_IOEV_H
#define CORE_IOEV_H

#include "core/defs.h"
#include "core/thread.h"

typedef struct nni_ioev_ops	nni_ioev_ops;
typedef struct nni_ioev		nni_ioev;

// Provider specific operations on I/O events.  We only have cancellation
// at present.
struct nni_ioev_ops {
	// Cancel the I/O.  This should not callback up, but instead should
	// just do whatever is necessary to free provider specific state,
	// and unlink the I/O from any schedule.  The I/O itself will not
	// have been started if this is called.
	void (*ip_cancel)(void *);
};

// An nni_iov is an I/O event handle, used to represent asynchronous I/O.
// These take several different forms.
struct nni_ioev {
	int		ie_result;      // Result code (nng_errno)
	size_t		ie_count;       // Bytes transferred (I/O only)
	nni_cb		ie_cb;          // User specified callback.
	void *		ie_cbarg;       // Callback argument.

	// These fields are private to the io events framework.
	nni_mtx		ie_lk;
	nni_cv		ie_cv;
	unsigned	ie_flags;

	// Provider data.
	nni_ioev_ops	ie_prov_ops;
	void *		ie_prov_data;
};

// nni_ioev_init initializes an IO event.  The callback is called with
// the supplied argument when the operation is complete.  If NULL is
// supplied for the callback, then nni_ioev_wake is used in its place,
// and the ioev is used for the argument.
extern void nni_ioev_init(nni_ioev *, nni_cb, void *);

// nni_ioev_fini finalizes the IO event, releasing resources (locks)
// associated with it.  The caller is responsible for ensuring that any
// associated I/O is unscheduled or complete.
extern void nni_ioev_fini(nni_ioev *);

// nni_ioev_cancel cancels the IO event.  The result will be NNG_ECANCELED,
// unless the underlying IO has already completed.
extern void nni_ioev_cancel(nni_ioev *);

// nni_ioev_result returns the result code (0 on success, or an NNG errno)
// for the operation.  It is only valid to call this when the operation is
// complete (such as when the callback is executed or after nni_ioev_wait
// is performed).
extern int nni_ioev_result(nni_ioev *);

// nni_ioev_count returns the number of bytes of data transferred, if any.
// As with nni_ioev_result, it is only defined if the I/O operation has
// completed.
extern size_t nni_ioev_count(nni_ioev *);

// nni_ioev_wake wakes any threads blocked in nni_ioev_wait.  This is the
// default callback if no other is supplied.  If a user callback is supplied
// then that code must call this routine to wake any waiters (unless the
// user code is certain that there are no such waiters).
extern void nni_ioev_wake(nni_ioev *);

// nni_ioev_wait blocks the caller until the IO event is complete, as indicated
// by nni_ioev_wake being called.  (Recall nni_ioev_wake is the default
// callback if none is supplied.)  If a user supplied callback is provided,
// and that callback does not call nni_ioev_wake, then this routine may
// block the caller indefinitely.
extern void nni_ioev_wait(nni_ioev *);

// I/O provider related functions.
extern void nni_ioev_set_ops(nni_ioev *, nni_ioev_ops *, void *);

// nni_ioev_busy is called by the provider to begin an operation, marking
// the IO busy.  The framework will avoid calling back into the provider
// (for cancellation for example) while the ioev is busy.  It is important
// that the busy state be held for only brief periods of time, such as while
// a non-blocking I/O operation is in progress.  If the IO is canceled (or
// a cancellation is in progress), the function will return NNG_ECANCELED.
// In this case, the provider must not perform any further I/O operations,
// and must not call the completion routine.  Otherwise zero is returned.
extern int nni_ioev_busy(nni_ioev *);

// nni_ioev_unbusy clears the "busy" state set by nni_ioev_busy.
extern void nni_ioev_unbusy(nni_ioev *);

// nni_ioev_finish is called by the provider when an operation is complete.
// (This can be for any reason other than cancellation.)  The provider gives
// the result code (0 for success, an NNG errno otherwise), and the amount of
// data transferred (if any).  The ioev must have been marked busy when this
// is called.  The ioev busy state is automatically cleared by this routine.
extern void nni_ioev_finish(nni_ioev *, int, size_t);

#endif // CORE_IOEV_H
