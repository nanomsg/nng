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

#include "core/nng_impl.h"

// We find that we often want to have a list of things listed by a
// numeric ID, which is generally monotonically increasing.  This is
// most often a pipe ID.  To help keep collections of these things
// indexed by their ID (which might start from a very large value),
// we offer a hash table.  The hash table uses open addressing, but
// we use a better probe (taken from Python) to avoid hitting the same
// positions.  Our hash algorithm is just the low order bits, and we
// use table sizes that are powers of two.  Note that hash items
// must be non-NULL.  The caller is responsible for providing any
// locking required.

// In order to make life easy, we just define the ID hash structure
// directly, and let consumers directly inline it.
typedef struct {
	uint32_t	ihe_key;
	void *		ihe_val;
} nni_idhash_entry;

typedef struct {
	uint32_t		ih_cap;
	uint32_t		ih_count;
	uint32_t		ih_mincount;
	uint32_t		ih_maxcount;
	nni_idhash_entry *	ih_entries;
} nni_idhash;

// nni_idhash_walkfn is called when walking a hash table.  If the
// return value is non-zero, then nni_idhash_walk will terminate further
// process and return that return value.  The function takes the generic
// opaque value for the walk as its first argument, and the next two
// arguments are the hash key and the opaque value stored with it.
typedef int (*nni_idhash_walkfn)(void *, uint32_t, void *);
extern int nni_idhash_init(nni_idhash *);
extern void nni_idhash_fini(nni_idhash *);
extern int nni_idhash_find(nni_idhash *, uint32_t, void **);
extern int nni_idhash_remove(nni_idhash *, uint32_t);
extern int nni_idhash_insert(nni_idhash *, uint32_t, void *);
extern int nni_idhash_count(nni_idhash *, uint32_t *);
extern int nni_idhash_walk(nni_idhash *, nni_idhash_walkfn, void *);

#endif  // CORE_IDHASH_H
