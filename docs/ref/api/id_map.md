# ID Map

Internally, _NNG_ uses a map of numeric identifiers to data structures.
This feature is also exposed for application use, as a "supplemental" feature.

When using these functions, it is necessary to add the `#include <nng/supplemental/util/idhash.h>`
include file to list of includes.

## ID Map Structure

```c
#include <nng/nng.h>
#include <nng/supplemental/util/idhash.h>

typedef struct nng_id_map_s nng_id_map;
```

The ID map structure, {{i:`nng_id_map`}} provides a table of identifiers mapping
to user-supplied pointers (which must not be `NULL`). The identifiers can be
thought of as indices into the table, with the pointers providing the reference
for the user supplied data.

The values of identifiers can be supplied by the user, or can be allocated automatically
by `nng_id_map` from a predefined range. The starting point for allocations
can also be randomly within the range.

The identifiers are 64-bit unsigned integers and can be sparse; the structure
will use space efficiently even if identifiers are very far apart.
{{footnote: The ID map is capable of storing at most 2<sup>32</sup> identifiers, even though the identifers may
themselves be much larger than this.}}

> [!IMPORTANT]
> The function available for `nng_id_map` are _not_ thread-safe.
> Callers should use a [mutex][nng_mutex] or similar approach when thread-safety is needed.

## Create ID Map

```c
#define NNG_MAP_RANDOM 1

int nng_id_map_alloc(nng_id_map **map_p, uint64_t lo, uint64_t hi, int flags);
```

The {{i:`nng_id_map_alloc`}} function allocates a map without any data in it,
and returns a pointer to it in _map_p_. When allocating identifiers dynamically,
the values will be chosen from the range defined by _lo_ and _hi_, inclusive.

The _flags_ argument is a bit mask of flags that can adjust behavior of the map.
The only flag defined at present
is `NNG_MAP_RANDOM`, which causes the first identifier allocation to start at a random
point within the range.
This is useful to reduce the odds of different instances of an application using
the same identifiers at the same time.

If both _lo_ and _hi_ are zero, then the values `0` and `0xffffffff` are substituted
in their place, giving a full range of 32-bit identifiers.

This function can return `NNG_ENOMEM` if it is unable to allocate resources, otherwise
it returns zero on success.

## Destroy Map

```c
void nng_id_map_free(nng_id_map *map);
```

The {{i:`nng_id_map_free`}} function destroys _map_, releasing any resources associated
with it.

> [!NOTE]
> The `nng_id_map_free` frees the map itself, but will not free memory associated with
> any strctures contained within it.

## Store a Value

```c
int nng_id_set(nng_id_map *map, uint64_t id, void *value);
```

The {{i:`nng_id_map_set`}} function is used to store the _value_ in the _map_ at
index _id_.

If another value is already stored at that same location, then it is overwritten with
_value_.

> [!NOTE]
> The _value_ must not be `NULL`.

If the table has to grow to accommodate this value, it may fail if insufficient
memory is available, returning `NNG_ENOMEM`. OtherwiseG it returns zero.

## Lookup a Value

```c
void *nng_id_get(nng_id_map *map, uint64_t id);
```

The {{i:`nng_id_get`}} function looks up the entry for _id_ in _map_, returning the
associated value if present, or `NULL` if no such entry exists.

## Allocate an ID

```c
int nng_id_alloc(nng_id_map *map, uint64_t *id_p, void *value);
```

The {{i:`nng_id_alloc`}} stores the _value_ in the _map_, at a newly allocated index,
and returns the index in _id_p_.

Identifiers are allocated in increasing order, without reusing old identifiers until the
largest possible identifier is allocated. After wrapping, only identifiers that are no longer
in use will be considered.
No effort is made to order the availability of identifiers based on
when they were freed.{{footnote: The concern about possibly reusing a
recently released identifier comes into consideration after the range has wrapped.
Given a sufficiently large range, this is unlikely to be a concern.}}

As with [`nng_id_set`][nng_id_set], this may need to allocate memory and can thus
fail with `NNG_ENOMEM`.

Additionally, if there are no more free identifiers within the range specified
when _map_ was created, then it will return `NNG_ENOSPC`.

Otherwise it returns zero, indicating success.

## Remove an ID

```c
int nng_id_remove(nng_id_map *map, uint64_t id);
```

The {{i:`nng_id_remove`}} removes the entry at index _id_ from _map_.

If no such entry exist, it will return `NNG_ENOENT`. Otherwise it returns zero.

## Iterating IDs

```c
bool nng_id_visit(nng_id_map *map, uint64_t *id_p, void **value_p, uint32_t *cursor);
```

The {{i:`nng_id_visit`}} function is used to iterate over all items in the table.
The caller starts the iteration by setting the _cursor_ to 0 before calling it.
For each call, the associated key and value of the next item will be returned in _id_p_,
and _value_p_ and the _cursor_ will be updated.
When all items have been iterated, the function returns `false`.
The order of items returned is not guaranteed to be sequential.
The caller must not attempt to derive any value of the _cursor_ as it refers to internal table indices.

Entries may be safely removed from _map_ while iterating.

However, if new entries are added to the table while iterating, the result of
iteration is undefined; entries may be repeated or omitted during such an iteration.

The caller must not attempt to derive any value of the _cursor_ as it refers to internal
table indices.

[nng_id_set]: #store-a-value
[nng_mutex]: synch.md#mutual-exclusion-lock
