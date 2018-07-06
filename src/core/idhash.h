//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_IDHASH_H
#define CORE_IDHASH_H

#include "core/defs.h"

// We find that we often want to have a list of things listed by a
// numeric ID, which is generally monotonically increasing.  This is
// most often a pipe ID.  To help keep collections of these things
// indexed by their ID (which might start from a very large value),
// we offer a hash table.  The hash table uses open addressing, but
// we use a better probe (taken from Python) to avoid hitting the same
// positions.  Our hash algorithm is just the low order bits, and we
// use table sizes that are powers of two.  Note that hash items
// must be non-NULL.  The table is protected by an internal lock.

typedef struct nni_idhash       nni_idhash;
typedef struct nni_idhash_entry nni_idhash_entry;

extern int  nni_idhash_init(nni_idhash **);
extern void nni_idhash_fini(nni_idhash *);
extern void nni_idhash_set_limits(nni_idhash *, uint64_t, uint64_t, uint64_t);
extern int  nni_idhash_find(nni_idhash *, uint64_t, void **);
extern int  nni_idhash_remove(nni_idhash *, uint64_t);
extern int  nni_idhash_insert(nni_idhash *, uint64_t, void *);
extern int  nni_idhash_alloc(nni_idhash *, uint64_t *, void *);

// 32-bit version of idhash -- limits must have been set accordingly.
extern int nni_idhash_alloc32(nni_idhash *, uint32_t *, void *);

extern size_t nni_idhash_count(nni_idhash *);

#endif // CORE_IDHASH_H
