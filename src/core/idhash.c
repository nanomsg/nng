//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng_impl.h"

#include <string.h>

struct nni_id_entry {
	uint64_t key;
	uint32_t skips;
	void    *val;
};

static int          id_reg_len = 0;
static int          id_reg_num = 0;
static nni_id_map **id_reg_map = NULL;
static nni_mtx      id_reg_mtx = NNI_MTX_INITIALIZER;

void
nni_id_map_init(nni_id_map *m, uint64_t lo, uint64_t hi, bool randomize)
{
	if (lo == 0) {
		lo = 1;
	}
	if (hi == 0) {
		hi = 0xffffffffu;
	}
	NNI_ASSERT(lo != 0);
	NNI_ASSERT(hi > lo);
	m->id_entries  = NULL;
	m->id_count    = 0;
	m->id_load     = 0;
	m->id_cap      = 0;
	m->id_dyn_val  = 0;
	m->id_max_load = 0;
	m->id_min_load = 0; // never shrink below this
	m->id_min_val  = lo;
	m->id_max_val  = hi;
	if (randomize) {
		m->id_flags = NNI_ID_FLAG_RANDOM;
	} else {
		m->id_flags = 0;
	}
}

void
nni_id_map_fini(nni_id_map *m)
{
	if (m->id_entries != NULL) {
		NNI_FREE_STRUCTS(m->id_entries, m->id_cap);
		m->id_entries = NULL;
		m->id_cap = m->id_count = 0;
		m->id_load = m->id_min_load = m->id_max_load = 0;
	}
}

// Inspired by Python dict implementation.  This probe will visit every
// cell.  We always hash consecutively assigned IDs.  This requires that
// the capacity is always a power of two.
#define ID_NEXT(m, j) ((((j) *5) + 1) & (m->id_cap - 1))
#define ID_INDEX(m, j) ((j) & (m->id_cap - 1))

static size_t
id_find(nni_id_map *m, uint64_t id)
{
	size_t index;
	size_t start;
	if (m->id_count == 0) {
		return ((size_t) -1);
	}

	index = ID_INDEX(m, id);
	start = index;
	for (;;) {
		// The value of ihe_key is only valid if ihe_val is not NULL.
		if ((m->id_entries[index].key == id) &&
		    (m->id_entries[index].val != NULL)) {
			return (index);
		}
		if (m->id_entries[index].skips == 0) {
			return ((size_t) -1);
		}
		index = ID_NEXT(m, index);

		if (index == start) {
			break;
		}
	}

	return ((size_t) -1);
}

void *
nni_id_get(nni_id_map *m, uint64_t id)
{
	size_t index;
	if ((index = id_find(m, id)) == (size_t) -1) {
		return (NULL);
	}
	return (m->id_entries[index].val);
}

static int
id_map_register(nni_id_map *m)
{
	if ((m->id_flags & (NNI_ID_FLAG_STATIC | NNI_ID_FLAG_REGISTER)) !=
	    NNI_ID_FLAG_STATIC) {
		return (0);
	}
	nni_mtx_lock(&id_reg_mtx);
	if (id_reg_len <= id_reg_num) {
		nni_id_map **mr;
		int          len = id_reg_len;
		if (len < 10) {
			len = 10;
		} else {
			len *= 2;
		}
		mr = nni_zalloc(sizeof(nni_id_map *) * len);
		if (mr == NULL) {
			nni_mtx_unlock(&id_reg_mtx);
			return (NNG_ENOMEM);
		}
		id_reg_len = len;
		if (id_reg_map != NULL)
			memcpy(
			    mr, id_reg_map, id_reg_num * sizeof(nni_id_map *));
		id_reg_map = mr;
	}
	id_reg_map[id_reg_num++] = m;
	m->id_flags |= NNI_ID_FLAG_REGISTER;
	nni_mtx_unlock(&id_reg_mtx);
	return (0);
}

void
nni_id_map_sys_fini(void)
{
	nni_mtx_lock(&id_reg_mtx);
	for (int i = 0; i < id_reg_num; i++) {
		if (id_reg_map[i] != NULL) {
			nni_id_map_fini(id_reg_map[i]);
		}
	}
	nni_free(id_reg_map, sizeof(nni_id_map *) * id_reg_len);
	id_reg_map = NULL;
	id_reg_len = 0;
	id_reg_num = 0;
	nni_mtx_unlock(&id_reg_mtx);
}

static int
id_resize(nni_id_map *m)
{
	nni_id_entry *new_entries;
	nni_id_entry *old_entries;
	uint32_t      new_cap;
	uint32_t      old_cap;
	uint32_t      i;
	int           rv;

	if ((m->id_load < m->id_max_load) && (m->id_load >= m->id_min_load)) {
		// No resize needed.
		return (0);
	}

	// if it is a statically declared map, register it so that we
	// will free it at finalization time
	if ((rv = id_map_register(m)) != 0) {
		return (rv);
	}

	old_cap = m->id_cap;
	new_cap = 8;
	while (new_cap < (m->id_count * 2)) {
		new_cap *= 2;
	}
	if (new_cap == old_cap) {
		// Same size.
		return (0);
	}

	old_entries = m->id_entries;
	new_entries = NNI_ALLOC_STRUCTS(new_entries, new_cap);
	if (new_entries == NULL) {
		return (NNG_ENOMEM);
	}

	m->id_entries = new_entries;
	m->id_cap     = new_cap;
	m->id_load    = 0;
	if (new_cap > 8) {
		m->id_min_load = new_cap / 8;
		m->id_max_load = new_cap * 2 / 3;
	} else {
		m->id_min_load = 0;
		m->id_max_load = 5;
	}
	for (i = 0; i < old_cap; i++) {
		size_t index;
		if (old_entries[i].val == NULL) {
			continue;
		}
		index = old_entries[i].key & (new_cap - 1);
		for (;;) {
			// Increment the load unconditionally.  It counts
			// once for every item stored, plus once for each
			// hashing operation we use to store the item (i.e.
			// one for the item, plus once for each rehash.)
			m->id_load++;
			if (new_entries[index].val == NULL) {
				// As we are hitting this entry for the first
				// time, it won't have any skips.
				NNI_ASSERT(new_entries[index].skips == 0);
				new_entries[index].val = old_entries[i].val;
				new_entries[index].key = old_entries[i].key;
				break;
			}
			new_entries[index].skips++;
			index = ID_NEXT(m, index);
		}
	}
	if (old_cap != 0) {
		NNI_FREE_STRUCTS(old_entries, old_cap);
	}
	return (0);
}

int
nni_id_remove(nni_id_map *m, uint64_t id)
{
	size_t index;
	size_t probe;

	if ((index = id_find(m, id)) == (size_t) -1) {
		return (NNG_ENOENT);
	}

	// Now we have found the index where the object exists.  We are going
	// to restart the search, until the index matches, to decrement the
	// skips counter.
	probe = ID_INDEX(m, id);

	for (;;) {
		nni_id_entry *entry;

		// The load was increased once each hashing operation we used
		// to place the item.  Decrement it accordingly.
		m->id_load--;
		entry = &m->id_entries[probe];
		if (probe == index) {
			entry->val = NULL;
			entry->key = 0; // invalid key
			break;
		}
		NNI_ASSERT(entry->skips > 0);
		entry->skips--;
		probe = ID_NEXT(m, probe);
	}

	m->id_count--;

	// Shrink -- but it's ok if we can't.
	(void) id_resize(m);

	return (0);
}

int
nni_id_set(nni_id_map *m, uint64_t id, void *val)
{
	size_t        index;
	nni_id_entry *ent;

	// Try to resize -- if we don't need to, this will be a no-op.
	if (id_resize(m) != 0) {
		return (NNG_ENOMEM);
	}

	// If it already exists, just overwrite the old value.
	if ((index = id_find(m, id)) != (size_t) -1) {
		ent      = &m->id_entries[index];
		ent->val = val;
		return (0);
	}

	index = ID_INDEX(m, id);
	for (;;) {
		ent = &m->id_entries[index];

		// Increment the load count.  We do this each time time we
		// rehash.  This may over-count items that collide on the
		// same rehashing, but this should just cause a table to
		// grow sooner, which is probably a good thing.
		m->id_load++;
		if (ent->val == NULL) {
			m->id_count++;
			ent->key = id;
			ent->val = val;
			return (0);
		}
		// Record the skip count.  This being non-zero informs
		// that a rehash will be necessary.  Without this we
		// would need to scan the entire hash for the match.
		ent->skips++;
		index = ID_NEXT(m, index);
	}
}

int
nni_id_alloc(nni_id_map *m, uint64_t *idp, void *val)
{
	uint64_t id;
	int      rv;

	NNI_ASSERT(val != NULL);

	// range is inclusive, so > to get +1 effect.
	if (m->id_count > (m->id_max_val - m->id_min_val)) {
		// Really more like ENOSPC.. the table is filled to max.
		return (NNG_ENOMEM);
	}
	if (m->id_dyn_val == 0) {
		if (m->id_flags & NNI_ID_FLAG_RANDOM) {
			// NB: The range is inclusive.
			m->id_dyn_val = nni_random() %
			        (m->id_max_val - m->id_min_val + 1) +
			    m->id_min_val;
		} else {
			m->id_dyn_val = m->id_min_val;
		}
	}

	for (;;) {
		id = m->id_dyn_val;
		m->id_dyn_val++;
		if (m->id_dyn_val > m->id_max_val) {
			m->id_dyn_val = m->id_min_val;
		}

		if (id_find(m, id) == (size_t) -1) {
			break;
		}
	}

	rv = nni_id_set(m, id, val);
	if (rv == 0) {
		*idp = id;
	}
	return (rv);
}

int
nni_id_alloc32(nni_id_map *m, uint32_t *idp, void *val)
{
	uint64_t id;
	int      rv;
	rv = nni_id_alloc(m, &id, val);
	NNI_ASSERT(id < (1ULL << 32));
	*idp = (uint32_t) id;
	return (rv);
}

bool
nni_id_visit(nni_id_map *m, uint64_t *keyp, void **valp, uint32_t *cursor)
{
	// cursor is just a cursor into the table
	uint32_t index = *cursor;
	while (index < m->id_cap) {
		if (m->id_entries[index].val != NULL) {
			if (valp != NULL) {
				*valp = m->id_entries[index].val;
			}
			if (keyp != NULL) {
				*keyp = m->id_entries[index].key;
			}
			*cursor = index + 1;
			return true;
		}
		index++;
	}
	*cursor = index;
	return (false);
}

uint32_t
nni_id_count(const nni_id_map *m)
{
	return (m->id_count);
}
