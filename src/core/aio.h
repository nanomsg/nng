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

// An nni_aio is an async I/O handle.
struct nni_aio {
	int      a_result; // Result code (nng_errno)
	size_t   a_count;  // Bytes transferred (I/O only)
	nni_cb   a_cb;     // User specified callback.
	void *   a_cbarg;  // Callback argument.
	nni_time a_expire;

	// These fields are private to the aio framework.
	nni_mtx       a_lk;
	nni_cv        a_cv;
	unsigned      a_flags;
	int           a_refcnt; // prevent use-after-free
	nni_taskq_ent a_tqe;

	// Read/write operations.
	nni_iov a_iov[4];
	int     a_niov;

	// Message operations.
	nni_msg *a_msg;

	// Connect/accept operations.
	void *a_endpt; // opaque endpoint handle
	void *a_pipe;  // opaque pipe handle

	// Resolver operations.
	nni_sockaddr *a_addrs;
	int           a_naddrs;

	// Provider-use fields.
	void (*a_prov_cancel)(nni_aio *);
	void *        a_prov_data;
	nni_list_node a_prov_node;

	// Expire node.
	nni_list_node a_expire_node;
};

// nni_aio_init initializes an aio object.  The callback is called with
// the supplied argument when the operation is complete.  If NULL is
// supplied for the callback, then nni_aio_wake is used in its place,
// and the aio is used for the argument.
extern int nni_aio_init(nni_aio *, nni_cb, void *);

// nni_aio_fini finalizes the aio, releasing resources (locks)
// associated with it.  The caller is responsible for ensuring that any
// associated I/O is unscheduled or complete.  This is safe to call
// on zero'd memory.
extern void nni_aio_fini(nni_aio *);

// nni_aio_result returns the result code (0 on success, or an NNG errno)
// for the operation.  It is only valid to call this when the operation is
// complete (such as when the callback is executed or after nni_aio_wait
// is performed).
extern int nni_aio_result(nni_aio *);

// nni_aio_count returns the number of bytes of data transferred, if any.
// As with nni_aio_result, it is only defined if the I/O operation has
// completed.
extern size_t nni_aio_count(nni_aio *);

// nni_aio_wake wakes any threads blocked in nni_aio_wait.  This is the
// default callback if no other is supplied.  If a user callback is supplied
// then that code must call this routine to wake any waiters (unless the
// user code is certain that there are no such waiters).
extern void nni_aio_wake(nni_aio *);

// nni_aio_wait blocks the caller until the operation is complete, as indicated
// by nni_aio_wake being called.  (Recall nni_aio_wake is the default
// callback if none is supplied.)  If a user supplied callback is provided,
// and that callback does not call nni_aio_wake, then this routine may
// block the caller indefinitely.
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
// The provider gives the result code (0 for success, an NNG errno otherwise),
// and the amount of data transferred (if any).  If the return code is
// non-zero, it indicates that the operation failed (usually because the aio
// was already canceled.)  This is important for providers that need to
// prevent resources (new pipes for example) from accidentally leaking
// during close operations.
extern int nni_aio_finish(nni_aio *, int, size_t);

// nni_aio_cancel is used to cancel an operation.  Any pending I/O or
// timeouts are canceled if possible, and the callback will be returned
// with the indicated result (NNG_ECLOSED or NNG_ECANCELED is recommended.)
extern void nni_aio_cancel(nni_aio *, int rv);

extern int nni_aio_start(nni_aio *, void (*)(nni_aio *), void *);

// nni_aio_stop is used to abort all further operations on the AIO.
// When this is executed, no further operations or callbacks will be
// executed, and if callbacks or I/O is in progress this will block
// until they are either canceled or aborted.  (Question: why not just
// nni_fini?)
// extern void nni_aio_stop(nni_aio *);

extern int  nni_aio_sys_init(void);
extern void nni_aio_sys_fini(void);
#endif // CORE_AIO_H
