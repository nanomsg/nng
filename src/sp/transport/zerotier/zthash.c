//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "zthash.h"

struct zt_hash_entry {
	uint64_t key;
	void *   val;
	uint32_t skips;
};

int
zt_hash_init(zt_hash **hp)
{
	zt_hash *h;

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	h->ih_entries = NULL;
	h->ih_count   = 0;
	h->ih_load    = 0;
	h->ih_cap     = 0;
	h->ih_maxload = 0;
	h->ih_minload = 0; // never shrink below this
	h->ih_minval  = 0;
	h->ih_maxval  = 0xffffffff;
	h->ih_dynval  = 0;

	*hp = h;
	return (0);
}

void
zt_hash_fini(zt_hash *h)
{
	if (h != NULL) {
		if (h->ih_entries != NULL) {
			NNI_FREE_STRUCTS(h->ih_entries, h->ih_cap);
			h->ih_entries = NULL;
			h->ih_cap = h->ih_count = 0;
			h->ih_load = h->ih_minload = h->ih_maxload = 0;
		}

		NNI_FREE_STRUCT(h);
	}
}

void
zt_hash_limits(zt_hash *h, uint64_t minval, uint64_t maxval, uint64_t start)
{
	if (start < minval) {
		start = minval;
	}
	if (start > maxval) {
		start = maxval;
	}

	h->ih_minval = minval;
	h->ih_maxval = maxval;
	h->ih_dynval = start;
	NNI_ASSERT(minval < maxval);
	NNI_ASSERT(start >= minval);
	NNI_ASSERT(start <= maxval);
}

// Inspired by Python dict implementation.  This probe will visit every
// cell.  We always hash consecutively assigned IDs.
#define ZT_HASH_NEXT(h, j) ((((j) *5) + 1) & (h->ih_cap - 1))
#define ZT_HASH_INDEX(h, j) ((j) & (h->ih_cap - 1))

static size_t
zt_hash_find_index(zt_hash *h, uint64_t id)
{
	size_t index;
	size_t start;
	if (h->ih_count == 0) {
		return ((size_t) -1);
	}

	index = ZT_HASH_INDEX(h, id);
	start = index;
	for (;;) {
		// The value of ihe_key is only valid if ihe_val is not NULL.
		if ((h->ih_entries[index].key == id) &&
		    (h->ih_entries[index].val != NULL)) {
			return (index);
		}
		if (h->ih_entries[index].skips == 0) {
			return ((size_t) -1);
		}
		index = ZT_HASH_NEXT(h, index);

		if (index == start) {
			break;
		}
	}

	return ((size_t) -1);
}

int
zt_hash_find(zt_hash *h, uint64_t id, void **vp)
{
	size_t index;
	if ((index = zt_hash_find_index(h, id)) == (size_t) -1) {
		return (NNG_ENOENT);
	}
	*vp = h->ih_entries[index].val;
	return (0);
}

static int
zt_hash_resize(zt_hash *h)
{
	size_t         newsize;
	size_t         oldsize;
	zt_hash_entry *newents;
	zt_hash_entry *oldents;
	uint32_t       i;

	if ((h->ih_load < h->ih_maxload) && (h->ih_load >= h->ih_minload)) {
		// No resize needed.
		return (0);
	}

	oldsize = h->ih_cap;

	newsize = 8;
	while (newsize < (h->ih_count * 2)) {
		newsize *= 2;
	}
	if (newsize == oldsize) {
		// Same size.
		return (0);
	}

	oldents = h->ih_entries;
	newents = NNI_ALLOC_STRUCTS(newents, newsize);
	if (newents == NULL) {
		return (NNG_ENOMEM);
	}

	h->ih_entries = newents;
	h->ih_cap     = newsize;
	h->ih_load    = 0;
	if (newsize > 8) {
		h->ih_minload = newsize / 8;
		h->ih_maxload = newsize * 2 / 3;
	} else {
		h->ih_minload = 0;
		h->ih_maxload = 5;
	}
	for (i = 0; i < oldsize; i++) {
		size_t index;
		if (oldents[i].val == NULL) {
			continue;
		}
		index = oldents[i].key & (newsize - 1);
		for (;;) {
			// Increment the load unconditionally.  It counts
			// once for every item stored, plus once for each
			// hashing operation we use to store the item (i.e.
			// one for the item, plus once for each rehash.)
			h->ih_load++;
			if (newents[index].val == NULL) {
				// As we are hitting this entry for the first
				// time, it won't have any skips.
				NNI_ASSERT(newents[index].skips == 0);
				newents[index].val = oldents[i].val;
				newents[index].key = oldents[i].key;
				break;
			}
			newents[index].skips++;
			index = ZT_HASH_NEXT(h, index);
		}
	}
	if (oldsize != 0) {
		NNI_FREE_STRUCTS(oldents, oldsize);
	}
	return (0);
}

int
zt_hash_remove(zt_hash *h, uint64_t id)
{
	size_t         index;
	size_t         probe;

	if ((index = zt_hash_find_index(h, id)) == (size_t) -1) {
		return (NNG_ENOENT);
	}

	// Now we have found the index where the object exists.  We are going
	// to restart the search, until the index matches, to decrement the
	// skips counter.
	probe = (int) ZT_HASH_INDEX(h, id);

	for (;;) {
                zt_hash_entry *entry;
		// The load was increased once each hashing operation we used
		// to place the the item.  Decrement it accordingly.
		h->ih_load--;
		entry = &h->ih_entries[probe];
		if (probe == index) {
			entry->val = NULL;
			entry->key = 0;
			break;
		}
		NNI_ASSERT(entry->skips > 0);
		entry->skips--;
		probe = ZT_HASH_NEXT(h, probe);
	}

	h->ih_count--;

	// Shrink -- but it's ok if we can't.
	(void) zt_hash_resize(h);

	return (0);
}

int
zt_hash_insert(zt_hash *h, uint64_t id, void *val)
{
	size_t         index;
	zt_hash_entry *ent;

	// Try to resize -- if we don't need to, this will be a no-op.
	if (zt_hash_resize(h) != 0) {
		return (NNG_ENOMEM);
	}

	// If it already exists, just overwrite the old value.
	if ((index = zt_hash_find_index(h, id)) != (size_t) -1) {
		ent      = &h->ih_entries[index];
		ent->val = val;
		return (0);
	}

	index = ZT_HASH_INDEX(h, id);
	for (;;) {
		ent = &h->ih_entries[index];

		// Increment the load count.  We do this each time time we
		// rehash.  This may over-count items that collide on the
		// same rehashing, but this should just cause a table to
		// grow sooner, which is probably a good thing.
		h->ih_load++;
		if (ent->val == NULL) {
			h->ih_count++;
			ent->key = id;
			ent->val = val;
			return (0);
		}
		// Record the skip count.  This being non-zero informs
		// that a rehash will be necessary.  Without this we
		// would need to scan the entire hash for the match.
		ent->skips++;
		index = ZT_HASH_NEXT(h, index);
	}
}

int
zt_hash_alloc(zt_hash *h, uint64_t *idp, void *val)
{
	uint64_t id;
	int      rv;

	NNI_ASSERT(val != NULL);

	if (h->ih_count > (h->ih_maxval - h->ih_minval)) {
		// Really more like ENOSPC.. the table is filled to max.
		return (NNG_ENOMEM);
	}

	for (;;) {
		id = h->ih_dynval;
		h->ih_dynval++;
		if (h->ih_dynval > h->ih_maxval) {
			h->ih_dynval = h->ih_minval;
		}

		if (zt_hash_find_index(h, id) == (size_t) -1) {
			break;
		}
	}

	rv = zt_hash_insert(h, id, val);
	if (rv == 0) {
		*idp = id;
	}
	return (rv);
}
