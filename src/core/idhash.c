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

int
nni_idhash_init(nni_idhash *h)
{
	h->ih_entries = nni_alloc(8 * sizeof (nni_idhash_entry));
	if (h->ih_entries == NULL) {
		return (NNG_ENOMEM);
	}
	(void) memset(h->ih_entries, 0, (8 * sizeof (nni_idhash_entry)));
	h->ih_count = 0;
	h->ih_cap = 8;
	h->ih_maxcount = 5;
	h->ih_mincount = 0; // never shrink below this
	return (0);
}


void
nni_idhash_fini(nni_idhash *h)
{
	nni_free(h->ih_entries, h->ih_cap * sizeof (nni_idhash_entry));
}


// Inspired by Python dict implementation.  This probe will visit every
// cell.  We always hash consecutively assigned IDs.
#define NNI_IDHASH_NEXTPROBE(h, j) \
	((((j) * 5) + 1) & ~(h->ih_cap))

int
nni_idhash_find(nni_idhash *h, uint32_t id, void **valp)
{
	uint32_t index = id & (h->ih_cap - 1);

	for (;;) {
		if (h->ih_entries[index].ihe_val == NULL) {
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
	uint32_t newsize;
	uint32_t oldsize;
	nni_idhash_entry *newents;
	nni_idhash_entry *oldents;

	if ((h->ih_count < h->ih_maxcount) && (h->ih_count >= h->ih_mincount)) {
		// No resize needed.
		return (0);
	}

	oldsize = h->ih_cap;
	newsize = h->ih_cap;

	newsize = 8;
	while (newsize < (h->ih_count * 2)) {
		newsize *= 2;
	}

	oldents = h->ih_entries;
	newents = nni_alloc(sizeof (nni_idhash_entry) * newsize);
	if (newents == NULL) {
		return (NNG_ENOMEM);
	}
	h->ih_entries = newents;
	h->ih_cap = newsize;
	if (newsize > 8) {
		h->ih_mincount = newsize / 8;
		h->ih_maxcount = newsize * 2 / 3;
	} else {
		h->ih_mincount = 0;
		h->ih_maxcount = 5;
	}
	for (int i = 0; i < oldsize; i++) {
		uint32_t index;
		if (oldents[i].ihe_val == NULL) {
			continue;
		}
		index = oldents[i].ihe_key & (newsize - 1);
		for (;;) {
			if (newents[index].ihe_val == NULL) {
				newents[index].ihe_val = oldents[i].ihe_val;
				newents[index].ihe_key = oldents[i].ihe_key;
				break;
			}
			index = NNI_IDHASH_NEXTPROBE(h, index);
		}
	}
	nni_free(oldents, sizeof (nni_idhash_entry) * oldsize);
	return (0);
}


int
nni_hash_remove(nni_idhash *h, uint32_t id)
{
	uint32_t index = id & (h->ih_cap - 1);

	for (;;) {
		if (h->ih_entries[index].ihe_val == NULL) {
			return (NNG_ENOENT);
		}
		if (h->ih_entries[index].ihe_key == id) {
			h->ih_entries[index].ihe_val = NULL;
			h->ih_entries[index].ihe_key = 0;
			h->ih_count--;
			break;
		}
		index = NNI_IDHASH_NEXTPROBE(h, index);
	}

	// Shrink -- but it's ok if we can't.
	(void) nni_hash_resize(h);

	return (0);
}


int
nni_hash_insert(nni_idhash *h, uint32_t id, void *val)
{
	uint32_t index;

	// Try to resize.  If we can't, but we still have room, go ahead
	// and store it.
	if ((nni_hash_resize(h) != 0) && (h->ih_count >= (h->ih_cap - 1))) {
		return (NNG_ENOMEM);
	}
	index = id & (h->ih_cap - 1);
	for (;;) {
		if (h->ih_entries[index].ihe_val == NULL) {
			h->ih_entries[index].ihe_key = id;
			h->ih_entries[index].ihe_val = val;
			h->ih_count++;
			return (0);
		}
		index = NNI_IDHASH_NEXTPROBE(h, index);
	}
}


int
nni_idhash_count(nni_idhash *h, uint32_t *countp)
{
	*countp = h->ih_count;
	return (0);
}


int
nni_idhash_walk(nni_idhash *h, nni_idhash_walkfn fn, void *arg)
{
	int i, rv;

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
