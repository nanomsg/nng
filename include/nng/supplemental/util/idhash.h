//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_UTIL_IDHASH_H
#define NNG_SUPPLEMENTAL_UTIL_IDHASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <nng/nng.h>

typedef struct nng_id_map_s nng_id_map;

#define NNG_MAP_RANDOM 1

NNG_DECL int nng_id_map_alloc(
    nng_id_map **map, uint64_t lo, uint64_t hi, int flags);
NNG_DECL void  nng_id_map_free(nng_id_map *map);
NNG_DECL void *nng_id_get(nng_id_map *, uint64_t);
NNG_DECL int   nng_id_set(nng_id_map *, uint64_t, void *);
NNG_DECL int   nng_id_alloc(nng_id_map *, uint64_t *, void *);
NNG_DECL int   nng_id_remove(nng_id_map *, uint64_t);
NNG_DECL bool  nng_id_visit(nng_id_map *, uint64_t *, void **, uint32_t *);

#ifdef __cplusplus
}
#endif

#endif // NNG_SUPPLEMENTAL_IDHASH_IDHASH_H
