//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/nng.h>
#include <nng/supplemental/util/idhash.h>

#include "core/nng_impl.h"

struct nng_id_map_s {
	nni_id_map m;
};

int
nng_id_map_alloc(nng_id_map **map, uint64_t lo, uint64_t hi, int flags)
{
	nng_id_map *m;

	if ((m = NNI_ALLOC_STRUCT(m)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_id_map_init(
	    &m->m, lo, hi, (flags & NNG_MAP_RANDOM) ? true : false);
	*map = m;
	return (0);
}

void
nng_id_map_free(nng_id_map *map)
{
	nni_id_map_fini(&map->m);
	NNI_FREE_STRUCT(map);
}

void *
nng_id_get(nng_id_map *map, uint64_t id)
{
	return (nni_id_get(&map->m, id));
}

int
nng_id_set(nng_id_map *map, uint64_t id, void *val)
{
	return (nni_id_set(&map->m, id, val));
}

int
nng_id_remove(nng_id_map *map, uint64_t id)
{
	return (nni_id_remove(&map->m, id));
}

int
nng_id_alloc(nng_id_map *map, uint64_t *id, void *val)
{
	return (nni_id_alloc(&map->m, id, val));
}

bool
nng_id_visit(nng_id_map *map, uint64_t *id, void **valp, uint32_t *cursor)
{
	return (nni_id_visit(&map->m, id, valp, cursor));
}
