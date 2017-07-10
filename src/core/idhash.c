//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <string.h>

struct nni_idhash_entry {
	uint32_t ihe_key;
	uint32_t ihe_skips;
	void *   ihe_val;
};

int
nni_idhash_init(nni_idhash *h)
{
	h->ih_entries = NULL;
	h->ih_count   = 0;
	h->ih_load    = 0;
	h->ih_cap     = 0;
	h->ih_maxload = 0;
	h->ih_minload = 0; // never shrink below this
	h->ih_walkers = 0;
	h->ih_minval  = 0;
	h->ih_maxval  = 0xffffffff;
	h->ih_dynval  = 0;
	return (0);
}

void
nni_idhash_fini(nni_idhash *h)
{
	NNI_ASSERT(h->ih_walkers == 0);
	if (h->ih_entries != NULL) {
		nni_free(h->ih_entries, h->ih_cap * sizeof(nni_idhash_entry));
		h->ih_entries = NULL;
		h->ih_cap = h->ih_count = 0;
		h->ih_load = h->ih_minload = h->ih_maxload = 0;
	}
}

void
nni_idhash_reclaim(nni_idhash *h)
{
	// Reclaim the buffer if we want, but preserve the limits.
	if ((h->ih_count == 0) && (h->ih_cap != 0) && (h->ih_walkers == 0)) {
		nni_free(h->ih_entries, h->ih_cap * sizeof(nni_idhash_entry));
		h->ih_cap     = 0;
		h->ih_entries = NULL;
		h->ih_minload = 0;
		h->ih_maxload = 0;
	}
}

void
nni_idhash_set_limits(
    nni_idhash *h, uint32_t minval, uint32_t maxval, uint32_t start)
{
	h->ih_minval = minval;
	h->ih_maxval = maxval;
	h->ih_dynval = start;
	NNI_ASSERT(minval < maxval);
	NNI_ASSERT(start >= minval);
	NNI_ASSERT(start <= maxval);
}

// Inspired by Python dict implementation.  This probe will visit every
// cell.  We always hash consecutively assigned IDs.
#define NNI_IDHASH_NEXTPROBE(h, j) ((((j) *5) + 1) & (h->ih_cap - 1))

int
nni_idhash_find(nni_idhash *h, uint32_t id, void **valp)
{
	uint32_t index = id & (h->ih_cap - 1);

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
	if (h->ih_walkers && (h->ih_load < (h->ih_cap - 1))) {
		// Don't resize when walkers are running.  This way
		// walk functions can remove hash nodes.
		return (0);
	}

	oldsize = h->ih_cap;
	newsize = h->ih_cap;

	newsize = 8;
	while (newsize < (h->ih_count * 2)) {
		newsize *= 2;
	}

	oldents = h->ih_entries;
	newents = nni_alloc(sizeof(nni_idhash_entry) * newsize);
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
		uint32_t index;
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
		nni_free(oldents, sizeof(nni_idhash_entry) * oldsize);
	}
	return (0);
}

int
nni_idhash_remove(nni_idhash *h, uint32_t id)
{
	int      rv;
	void *   val;
	uint32_t index;

	// First check that it is in the table.  This may double the
	// lookup time, but it means that if we get past this then we KNOW
	// we are going to delete an element.
	if ((rv = nni_idhash_find(h, id, &val)) != 0) {
		return (rv);
	}

	index = id & (h->ih_cap - 1);

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

	return (0);
}

int
nni_idhash_insert(nni_idhash *h, uint32_t id, void *val)
{
	uint32_t index;

	if ((id < h->ih_minval) || (id > h->ih_maxval)) {
		return (NNG_EINVAL);
	}

	// Try to resize.  If we can't, but we still have room, go ahead
	// and store it.
	if ((nni_hash_resize(h) != 0) && (h->ih_count >= (h->ih_cap - 1))) {
		return (NNG_ENOMEM);
	}
	index = id & (h->ih_cap - 1);
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

	// If this was the old dynamic value, just bump it.
	if (h->ih_dynval == id) {
		h->ih_dynval++;
		// Roll over...
		if (h->ih_dynval == h->ih_maxval) {
			h->ih_dynval = h->ih_minval;
		}
	}
}

int
nni_idhash_alloc(nni_idhash *h, uint32_t *idp, void *val)
{
	uint32_t id;
	void *   scrap;
	int      rv;

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

		if (nni_idhash_find(h, id, &scrap) == NNG_ENOENT) {
			break;
		}
	}

	rv = nni_idhash_insert(h, id, val);
	if (rv == 0) {
		*idp = id;
	}
	return (rv);
}

size_t
nni_idhash_count(nni_idhash *h)
{
	return (h->ih_count);
}

int
nni_idhash_walk(nni_idhash *h, nni_idhash_walkfn fn, void *arg)
{
	uint32_t i, rv;

	for (i = 0; i < h->ih_cap; i++) {
		nni_idhash_entry *ent = &h->ih_entries[i];

		if (ent->ihe_val == NULL) {
			continue;
		}
		rv = fn(arg, ent->ihe_key, ent->ihe_val);
		if (rv != 0) {
			return (rv);
		}
	}
	return (0);
}
