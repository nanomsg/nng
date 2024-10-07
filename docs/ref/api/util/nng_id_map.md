# nng_id_map

## NAME

nng_id_map - identifier based mapping table

## SYNOPSIS

```c
#include <nng/nng.h>
#include <nng/supplemental/util/idhash.h>

typedef struct nng_id_map_s nng_id_map;

#define NNG_MAP_RANDOM 1

int   nng_id_map_alloc(nng_id_map **map_p, uint64_t lo, uint64_t hi, int flags);
void  nng_id_map_free(nng_id_map *map);
void *nng_id_get(nng_id_map *map, uint64_t id);
int   nng_id_set(nng_id_map *map, uint64_t, void *value);
int   nng_id_alloc(nng_id_map *map, uint64_t *id_p, void *value);
int   nng_id_remove(nng_id_map *map, uint64_t id);
bool  nng_id_visit(nng_id_map *map, uint64_t *id_p, void **value_p, uint32_t *cursor);
```

## DESCRIPTION

These functions provide support for managing tables of data based on
{{i:identifiers}}, ensuring that identifiers are allocated uniquely and within
specified range limits.

The table stores data pointers (which must not be `NULL`) at a logical numeric index.
It does so efficiently, even if large gaps exist, and it provides a means to efficiently
allocate a numeric identifier from a pool of unused identifiers.

Identifiers are allocated in increasing order, without reusing old identifiers until the
largest possible identifier is allocated. After wrapping, only identifiers that are no longer
in use will be considered.
No effort is made to order the availability of identifiers based on
when they were freed.{{footnote: The concern about possibly reusing a
recently released identifier comes into consideration after the range has wrapped.
Given a sufficiently large range, this is unlikely to be a concern.}}

> [!IMPORTANT]
> These functions are _not_ thread-safe.
> Callers should use a [mutex][mutex] or similar approach when thread-safety is needed.

The {{i:`nng_id_map_free`}} function deallocates one of these tables, and should be called
when it is no longer neeeded.

### Initialization

An initial table is allocated with {{i:`nng_id_map_alloc`}}, which takes the lowest legal identifier in _lo_,
and the largest legal identifier in _hi_.
The new table is returned in _map_p_, and should be used as the _map_ argument to the rest of these functions.

If these are specified as zero, then a full range of 32-bit identifiers is assumed.
If identifiers beyond 32-bits are required,
then both _lo_ and _hi_ must be specified with the exact values desired.
{{footnote: These functions are limited to storing at most 2<sup>32</sup> identifiers, even though the identifers may
themselves be larger than this.}}

The _flags_ argument is a bit mask of flags for the table.
If {{i:`NNG_MAP_RANDOM`}} is specified, then the starting point for allocations is randomized, but subsequent allocations will then be monotonically increasing.
This is useful to reduce the odds of different instances of an application using the same identifiers at the same time.

### Accessors

The {{i:`nng_id_get`}} function returns the value previously stored with the given identifier.
If no value is currently associated with the identifer, it returns `NULL`.

The {{i:`nng_id_set`}} function sets the value with the associated identifier.
This can be used to replace a previously allocated identifier.
If the identifier was not previously allocated, then it is allocated as part of the call.
This function does not necessarily honor the identifier range limits set for the map when it was allocated.

The {{:`nng_id_alloc`}} function allocates a new identifier from the range for the map, and associates it with
the supplied _value_.

The {{:`nng_id_remove`}} function removes the identifier and its associated value from the table.

### Iteration

The {{i:`nng_id_visit`}} function is used to iterate over all items in the table.
The caller starts the iteration by setting the _cursor_ to 0 before calling it.
For each call, the associated key and value of the next item will be returned in _id_p_,
and _value_p_ and the _cursor_ will be updated.
When all items have been iterated, the function returns `false`.
The order of items returned is not guaranteed to be sequential.
The caller must not attempt to derive any value of the _cursor_ as it refers to internal table indices.

## RETURN VALUES

The `nng_id_map_alloc`, `nng_id_set`, `nng_id_alloc`, and `nng_id_remove` functions
return 0 on success, or -1 on failure.

The `nng_id_map_get` function returns the requested data pointer, or `NULL` if the identifier was not found.

## ERRORS

- `NNG_ENOENT`: The _id_ does not exist in the table.
- `NNG_ENOMEM`: Insufficient memory is available, or the table is full.

[mutex]: ../thr/nng_mtx.md
