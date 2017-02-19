//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
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
// must be non-NULL.  The table is locked.

typedef struct nni_idhash		nni_idhash;
typedef struct nni_idhash_entry		nni_idhash_entry;

// The details of the nni_idhash are "private".  But they let us inline
// this into structures.
struct nni_idhash {
	size_t			ih_cap;
	size_t			ih_count;
	size_t			ih_load;
	size_t			ih_minload; // considers placeholders
	size_t			ih_maxload;
	uint32_t		ih_walkers;
	uint32_t		ih_minval;
	uint32_t		ih_maxval;
	uint32_t		ih_dynval;
	nni_idhash_entry *	ih_entries;
};

// nni_idhash_walkfn is called when walking a hash table.  If the
// return value is non-zero, then nni_idhash_walk will terminate further
// process and return that return value.  The function takes the generic
// opaque value for the walk as its first argument, and the next two
// arguments are the hash key and the opaque value stored with it.
// Note that the walkfn must not attempt to change the hash table.
// The user must provide any locking needed.
typedef int (*nni_idhash_walkfn)(void *, uint32_t, void *);
extern int nni_idhash_init(nni_idhash *);
extern void nni_idhash_fini(nni_idhash *);
extern void nni_idhash_reclaim(nni_idhash *);
extern void nni_idhash_set_limits(nni_idhash *, uint32_t, uint32_t, uint32_t);
extern int nni_idhash_create(nni_idhash **);
extern void nni_idhash_destroy(nni_idhash *);
extern int nni_idhash_find(nni_idhash *, uint32_t, void **);
extern int nni_idhash_remove(nni_idhash *, uint32_t);
extern int nni_idhash_insert(nni_idhash *, uint32_t, void *);
extern int nni_idhash_alloc(nni_idhash *, uint32_t *, void *);
extern size_t nni_idhash_count(nni_idhash *);
extern int nni_idhash_walk(nni_idhash *, nni_idhash_walkfn, void *);

#endif  // CORE_IDHASH_H
