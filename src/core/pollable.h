//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_POLLABLE_H
#define CORE_POLLABLE_H

#include "core/defs.h"
#include "core/list.h"

typedef struct nni_pollable nni_pollable;

extern int  nni_pollable_alloc(nni_pollable **);
extern void nni_pollable_free(nni_pollable *);
extern void nni_pollable_raise(nni_pollable *);
extern void nni_pollable_clear(nni_pollable *);
extern int  nni_pollable_getfd(nni_pollable *, int *);

// nni_pollable implementation details are private.  Only here for inlining.
// We have joined to the write and read file descriptors into a a single
// atomic 64 so we can update them together (and we can use cas to be sure
// that such updates are always safe.)
struct nni_pollable {
	nni_atomic_u64  p_fds;
	nni_atomic_bool p_raised;
};

extern void nni_pollable_init(nni_pollable *);
extern void nni_pollable_fini(nni_pollable *);

#endif // CORE_POLLABLE_H
