# nng_stats

## NAME

nng_stats --- statistics snapshot

## SYNOPSIS

```c
#include <nng/nng.h>

typedef struct nng_stat nng_stat;

int nng_stats_get(nng_stat **statsp);
void nng_stats_free(nng_stat *stats);
nng_stat *nng_stat_next(nng_stat *stat);
nng_stat *nng_stat_find(nng_stat *stat, const char *name);
nng_stat *nng_stat_find_dialer(nng_stat *stat, nng_dialer dialer);
nng_stat *nng_stat_find_listener(nng_stat *stat, nng_dialer listener);
nng_stat *nng_stat_find_socket(nng_stat *stat, nng_dialer socket);
```

## DESCRIPTION

Statistics maintained by the system are organized in a tree, and
a snapshot of all statistics can be taken, and then traversed
and searched.

### Statistics Snapshot Collection

The {{i:`nng_stats_get`}} function attempts to obtain a snapshot of all the
various diagnostic statistics that are present in the system.
On success, a pointer to the statistics tree snapshot is returned in _statsp_.

> [!NOTE]
> The process of collecting statistics is designed to have minimal
> impact on the system, but there is still some impact.

The statistics are organized as a tree, rooted with a parent
statistic of type `NNG_STAT_SCOPE` that carries no value, and which
has an empty name.
This parent statistic is returned through the _statsp_ pointer.

When no longer needed, the statistics snapshot can be freed with the
{{i:`nng_stats_free`}} function.

> [!IMPORTANT]
> The `nng_stats_free` function must be called only with the root statistic that is
> returned through the _statsp_ pointer.

> [!NOTE]
> The values of individual statistics are guaranteed to be atomic,
> but due the way statistics are collected there can be discrepancies between
> them at certain times.
> For example, statistics counting bytes and messages received may not
> reflect the same number of messages, depending on when the snapshot is taken.
> This potential inconsistency arises as a result of optimizations to minimize
> the impact of statistics on actual operations.

### Traversing the Statistics Tree

Traversing the tree of statistics is done using the `nng_stat_child` and
`nng_stat_next` functions.

The `nng_stat_child` function returns either the first child of _stat_,
or `NULL` if the _stat_ has no children.

The `nng_stat_next` function returns the nearest sibling to the right of _stat_,
or `NULL` if _stat_ has no more siblings to the right.

### Finding a Statistic

Sometimes it is easiest to search for a specific statistic, matching by name,
or possibly to find the tree of statistics associated iwth a specific [socket][nng_socket],
[dialer][nng_dialer], or [listener][nng_listener].

The `nng_stat_find` functions are provided for this purpose.

The `nng_stat_find` function returns the first statistic within the subtree of
statistics _stat_, with the given _name_. If no such statistic can be found, `NULL`
is returned.

The `nng_stat_find_dialer`, `nng_stat_find_listener`, and `nng_stat_find_socket` return
the statistics subtree for the given dialer, listener, or socket object. Note that
these functions should be provided the root of the statistic tree, in order to ensure
that they can find the desired object.

## RETURN VALUES

The `nng_stats_get` function returns zero on success, or a non-zero error value on failure.

Aside from `nng_stats_free`, which has no return, the remaining functions return a pointer to
the desired statistic object, or `NULL` if such a statistic cannot be found.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory to collect statistics.
- `NNG_ENOTSUP`: Statistics are not supported (compile time option).

## SEE ALSO

[nng_stat][nng_stat]

[nng_stat]: ./nng_stat.md
[nng_socket]: TODO.md
[nng_dialer]: TODO.md
[nng_listener]: TODO.md
