//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef ZT_HASH_H
#define ZT_HASH_H

#include <stdint.h>

// This code is derived from id hash, but supports 64-bit IDs.

typedef struct zt_hash       zt_hash;
typedef struct zt_hash_entry zt_hash_entry;

// NB: These details are entirely private to the hash implementation.
// They are provided here to facilitate inlining in structures.
struct zt_hash {
	size_t         ih_cap;
	size_t         ih_count;
	size_t         ih_load;
	size_t         ih_minload; // considers placeholders
	size_t         ih_maxload;
	uint64_t       ih_minval;
	uint64_t       ih_maxval;
	uint64_t       ih_dynval;
	zt_hash_entry *ih_entries;
};

extern int  zt_hash_init(zt_hash **);
extern void zt_hash_fini(zt_hash *);
extern void zt_hash_limits(zt_hash *, uint64_t, uint64_t, uint64_t);
extern int  zt_hash_find(zt_hash *, uint64_t, void **);
extern int  zt_hash_remove(zt_hash *, uint64_t);
extern int  zt_hash_insert(zt_hash *, uint64_t, void *);
extern int  zt_hash_alloc(zt_hash *, uint64_t *, void *);

#endif // CORE_IDHASH_H
