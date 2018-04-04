//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

// For the sake of simplicity, we just maintain a single global timer thread.

typedef struct nni_pollable nni_pollable;

extern int  nni_pollable_alloc(nni_pollable **);
extern void nni_pollable_free(nni_pollable *);
extern void nni_pollable_raise(nni_pollable *);
extern void nni_pollable_clear(nni_pollable *);
extern int  nni_pollable_getfd(nni_pollable *, int *);

#endif // CORE_POLLABLE_H
