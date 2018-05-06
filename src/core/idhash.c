//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <string.h>

struct nni_idhash_entry {
	uint64_t ihe_key;
	void *   ihe_val;
	uint32_t ihe_skips;
};

struct nni_idhash {
	size_t            ih_cap;
	size_t            ih_count;
	size_t            ih_load;
	size_t            ih_minload; // considers placeholders
	size_t            ih_maxload;
	uint64_t          ih_minval;
	uint64_t          ih_maxval;
	uint64_t          ih_dynval;
	nni_idhash_entry *ih_entries;
	nni_mtx           ih_mtx;
};

int
nni_idhash_init(nni_idhash **hp)
{
	nni_idhash *h;

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&h->ih_mtx);
	h->ih_entries = NULL;
	h->ih_count   = 0;
	h->ih_load    = 0;
	h->ih_cap     = 0;
	h->ih_maxload = 0;
	h->ih_minload = 0; // never shrink below this
	h->ih_minval  = 0;
	h->ih_maxval  = 0xffffffff;
	h->ih_dynval  = 0;
	*hp           = h;
	return (0);
}

void
nni_idhash_fini(nni_idhash *h)
{
	if (h != NULL) {
		if (h->ih_entries != NULL) {
			NNI_FREE_STRUCTS(h->ih_entries, h->ih_cap);
			h->ih_entries = NULL;
			h->ih_cap = h->ih_count = 0;
			h->ih_load = h->ih_minload = h->ih_maxload = 0;
		}
		nni_mtx_fini(&h->ih_mtx);
		NNI_FREE_STRUCT(h);
	}
}

void
nni_idhash_set_limits(
    nni_idhash *h, uint64_t minval, uint64_t maxval, uint64_t start)
{
	if (start < minval) {
		start = minval;
	}
	if (start > maxval) {
		start = maxval;
	}

	nni_mtx_lock(&h->ih_mtx);
	h->ih_minval = minval;
	h->ih_maxval = maxval;
	h->ih_dynval = start;
	NNI_ASSERT(minval < maxval);
	NNI_ASSERT(start >= minval);
	NNI_ASSERT(start <= maxval);
	nni_mtx_unlock(&h->ih_mtx);
}

// Inspired by Python dict implementation.  This probe will visit every
// cell.  We always hash consecutively assigned IDs.
#define NNI_IDHASH_NEXTPROBE(h, j) ((((j) *5) + 1) & (h->ih_cap - 1))
#define NNI_IDHASH_INDEX(h, j) \
	(((j & 0xffffffff) ^ (j >> 32)) & (h->ih_cap - 1))

static int
nni_hash_find(nni_idhash *h, uint64_t id, void **valp)
{
	uint32_t index = NNI_IDHASH_INDEX(h, id);

	if (h->ih_count == 0) {
		return (NNG_ENOENT);
	}

	for (;;) {
		if ((h->ih_entries[index].ihe_val == NULL) &&
		    (h->ih_entries[index].ihe_skips == 0)) {
			return (NNG_ENOENT);
		}
		if (h->ih_entries[index].ihe_key == id) {
			*valp = h->ih_entries[index].ihe_val;
			return (0);
		}
		index = NNI_IDHASH_NEXTPROBE(h, index);
	}
}

int
nni_idhash_find(nni_idhash *h, uint64_t id, void **valp)
{
	int rv;

	nni_mtx_lock(&h->ih_mtx);
	rv = nni_hash_find(h, id, valp);
	nni_mtx_unlock(&h->ih_mtx);
	return (rv);
}

static int
nni_hash_resize(nni_idhash *h)
{
	size_t            newsize;
	size_t            oldsize;
	nni_idhash_entry *newents;
	nni_idhash_entry *oldents;
	uint32_t          i;

	if ((h->ih_load < h->ih_maxload) && (h->ih_load >= h->ih_minload)) {
		// No resize needed.
		return (0);
	}

	oldsize = h->ih_cap;

	newsize = 8;
	while (newsize < (h->ih_count * 2)) {
		newsize *= 2;
	}

	oldents = h->ih_entries;
	newents = NNI_ALLOC_STRUCTS(newents, newsize);
	if (newents == NULL) {
		return (NNG_ENOMEM);
	}
	memset(newents, 0, sizeof(nni_idhash_entry) * newsize);

	h->ih_entries = newents;
	h->ih_cap     = newsize;
	if (newsize > 8) {
		h->ih_minload = newsize / 8;
		h->ih_maxload = newsize * 2 / 3;
	} else {
		h->ih_minload = 0;
		h->ih_maxload = 5;
	}
	for (i = 0; i < oldsize; i++) {
		size_t index;
		if (oldents[i].ihe_val == NULL) {
			continue;
		}
		index = oldents[i].ihe_key & (newsize - 1);
		for (;;) {
			if (newents[index].ihe_val == NULL) {
				h->ih_load++;
				newents[index].ihe_val = oldents[i].ihe_val;
				newents[index].ihe_key = oldents[i].ihe_key;
				break;
			}
			newents[index].ihe_skips++;
			index = NNI_IDHASH_NEXTPROBE(h, index);
		}
	}
	if (oldsize != 0) {
		NNI_FREE_STRUCTS(oldents, oldsize);
	}
	return (0);
}

int
nni_idhash_remove(nni_idhash *h, uint64_t id)
{
	int    rv;
	void * val;
	size_t index;

	nni_mtx_lock(&h->ih_mtx);
	// First check that it is in the table.  This may double the
	// lookup time, but it means that if we get past this then we KNOW
	// we are going to delete an element.
	if ((rv = nni_hash_find(h, id, &val)) != 0) {
		nni_mtx_unlock(&h->ih_mtx);
		return (rv);
	}

	index = NNI_IDHASH_INDEX(h, id);

	for (;;) {
		nni_idhash_entry *ent = &h->ih_entries[index];
		if (ent->ihe_key == id) {
			ent->ihe_val = NULL;
			if (ent->ihe_skips == 0) {
				h->ih_load--;
			}
			h->ih_count--;
			break;
		}
		if (ent->ihe_skips < 1) {
			nni_panic("Skips should be nonzero!");
		}
		ent->ihe_skips--;
		if ((ent->ihe_skips == 0) && (ent->ihe_val == NULL)) {
			h->ih_load--;
		}
		index = NNI_IDHASH_NEXTPROBE(h, index);
	}

	// Shrink -- but it's ok if we can't.
	(void) nni_hash_resize(h);
	nni_mtx_unlock(&h->ih_mtx);

	return (0);
}

static int
nni_hash_insert(nni_idhash *h, uint64_t id, void *val)
{
	size_t index;

	// Try to resize.  If we can't, but we still have room, go ahead
	// and store it.
	if ((nni_hash_resize(h) != 0) && (h->ih_count >= (h->ih_cap - 1))) {
		return (NNG_ENOMEM);
	}
	index = NNI_IDHASH_INDEX(h, id);
	for (;;) {
		nni_idhash_entry *ent = &h->ih_entries[index];
		if ((ent->ihe_val == NULL) || (ent->ihe_key == id)) {
			if (ent->ihe_val == NULL) {
				h->ih_count++;
				h->ih_load++;
			}
			ent->ihe_key = id;
			ent->ihe_val = val;
			return (0);
		}
		ent->ihe_skips++;
		index = NNI_IDHASH_NEXTPROBE(h, index);
	}
}

int
nni_idhash_insert(nni_idhash *h, uint64_t id, void *val)
{
	int rv;

	nni_mtx_lock(&h->ih_mtx);
	rv = nni_hash_insert(h, id, val);
	nni_mtx_unlock(&h->ih_mtx);
	return (rv);
}

int
nni_idhash_alloc(nni_idhash *h, uint64_t *idp, void *val)
{
	uint64_t id;
	void *   scrap;
	int      rv;
	nni_mtx_lock(&h->ih_mtx);

	if (h->ih_count > (h->ih_maxval - h->ih_minval)) {
		// Really more like ENOSPC.. the table is filled to max.
		nni_mtx_unlock(&h->ih_mtx);

		return (NNG_ENOMEM);
	}

	for (;;) {
		id = h->ih_dynval;
		h->ih_dynval++;
		if (h->ih_dynval > h->ih_maxval) {
			h->ih_dynval = h->ih_minval;
		}

		if (nni_hash_find(h, id, &scrap) == NNG_ENOENT) {
			break;
		}
	}

	rv = nni_hash_insert(h, id, val);
	if (rv == 0) {
		*idp = id;
	}
	nni_mtx_unlock(&h->ih_mtx);

	return (rv);
}
