# Statistics

To facilitate debugging and support situations, the _NNG_ library
provides for collection and reporting of numerous {{i:statistics}}.

These statistics are organized in a tree, and include both values,
and metadata describing the statistics. In order to be efficient and
minimize the impact of maintaining statistics, an explicit snapshot
of statistics must be taken, and that snapshot can then be processed.

> [!NOTE]
> Statistics may be disabled by build-time configuration options,
> in order to reduce program size and run-time overheads.

## Statistic Structure

```c
typedef struct nng_stat nng_stat;
```

The {{i:`nng_stat`}} structure represents a statistic, which is a single value
collected at a specific point in time.

This structure has meta-data describing the value, the value itself, and links
to any sibling or child statistics.

> [!NOTE]
> The presence, name, and semantics of any given statistic are
> subject to change at any time and without notice.

## Collecting a Snapshot

```c
int nng_stats_get(nng_stat **statsp);
```

The {{i:`nng_stats_get`}} function takes a snapshot of the statistics for
the system and returns it through the pointer _statsp_.
This function may return `NNG_ENOMEM` if memory is exhausted, or `NNG_ENOTSUP` if the statistics
support is not enabled in the build, but is otherwise expected to return zero.

## Freeing a Snapshot

```c
void nng_stats_free(nng_stat *stat);
```

The {{i:`nng_stats_free`}} function deallocates the snapshot referenced by _stat_.

> [!IMPORTANT]
> The _stat_ must be root of the statistics tree, i.e. the value that was returned
> through _statsp_ using the function `nng_stats_get`.

## Traversing the Tree

```c
const nng_stat *nng_stat_child(const nng_stat *stat);
const nng_stat *nng_stat_next(const nng_stat *stat);
```

Traversing the tree of statistics is done using the {{i:`nng_stat_child`}} and
{{i:`nng_stat_next`}} functions.

The `nng_stat_child` function returns either the first child of _stat_,
or `NULL` if the _stat_ has no children.

The `nng_stat_next` function returns the nearest sibling to the right of _stat_,
or `NULL` if _stat_ has no more siblings to the right.

## Finding a Statistic

```c
const nng_stat *nng_stat_find(const nng_stat *stat, const char *name);
const nng_stat *nng_stat_find_dialer(const nng_stat *stat, nng_dialer dialer);
const nng_stat *nng_stat_find_listener(const nng_stat *stat, nng_dialer listener);
const nng_stat *nng_stat_find_socket(const nng_stat *stat, nng_dialer socket);
```

Sometimes it is easiest to search for a specific statistic, matching by name,
or possibly to find the tree of statistics associated iwth a specific [socket][nng_socket],
[dialer][nng_dialer], or [listener][nng_listener].

The `nng_stat_find` functions are provided for this purpose.

The {{i:`nng_stat_find`}} function returns the first statistic within the subtree of
statistics _stat_, with the given _name_. If no such statistic can be found, `NULL`
is returned.

The {{i:`nng_stat_find_dialer`}}, {{i:`nng_stat_find_listener`}}, and {{i:`nng_stat_find_socket`}}
return the statistics subtree for the given dialer, listener, or socket object. If no such
statistic can be found, then they return `NULL`.
These functions should be provided the root of the statistic tree, in order to ensure
that they can find the desired object.

## Statistic Identification

```c
const char *nng_stat_name(const nng_stat *stat);
const char *nng_stat_desc(const nng_stat *stat);
```

Every statistic has a name, returned by {{i:`nng_stat_name`}}, and a description, returned by
{{i:`nng_stat_desc`}}. Descriptions are human-readable text, which might be useful for display.

## Statistic Type

```c
int nng_stat_type(const nng_stat *stat);
```

The function {{i:`nng_stat_type`}} returns the type of the statistic.
The type of a statistic determines the nature of the value, and which
function can be used to obtain that value.

- {{i:`NNG_STAT_SCOPE`}}: <a name="NNG_STAT_SCOPE"></a>
  The statistic does not carry any real value, but is
  used for grouping related statistics together. This is a nexus in the
  statistics tree.

- {{i:`NNG_STAT_COUNTER`}}: <a name="NNG_STAT_COUNTER"></a>
  The statistic is a counter that only increments.
  Usually the change in the value of the statistic is more interesting
  (as a rate) than the absolute value at any given time. The value should
  be obtained using [`nng_stat_value`][nng_stat_value].
  The units will be given by the value returned from [`nng_stat_unit`][nng_stat_unit].

- {{i:`NNG_STAT_LEVEL`}}: <a name="NNG_STAT_LEVEL"></a>
  The statistic represnts a measured value which corresponds
  to a specific value at a specific time. For example, this may represent the
  number of messages currently queued for some operation, or the link speed
  of a network interface. Most often the absolute value is more interesting
  than the change in the value over time. Again the value can be obtained with
  [`nng_stat_value`][nng_stat_value], and any appropriate unit of measurement
  with [`nng_stat_unit`][nng_stat_unit].

- {{i:`NNG_STAT_STRING`}}: <a name="NNG_STAT_STRING"></a>
  The statistic is a string, such as a name. The value
  of the string can be obtained with [`nng_stat_string`][nng_stat_string].
  The value of this string
  will remain valid until the snapshot is deallocated with [`nng_stats_free`][nng_stats_free].

- {{i:`NNG_STAT_BOOLEAN`}}: <a name="NNG_STAT_BOOLEAN"></a>
  The value of the statistic is a truth value (either `true`
  or `false`) and can be obtained with [`nng_stat_bool`][nng_stat_bool].

- {{i:`NNG_STAT_ID`}}: <a name="NNG_STAT_ID"></a>
  The value of the statistic is a numeric identifier, such as a socket
  identifier. The value can be obtained with [`nng_stat_value`][nng_stat_value],
  and will be fixed for the life of the statistic.

## Statistic Value

```c
uint64_t nng_stat_value(const nng_stat *stat);
const char *nng_stat_string(const nng_stat *stat);
bool nng_stat_bool(const nng_stat *stat);
```

These functions return the value associated with the statistic.

The {{i:`nng_stat_value`}} function returns the the numeric value for the statistic _stat_
of type [`NNG_STAT_COUNTER`][NNG_STAT_COUNTER], [`NNG_STAT_LEVEL`][NNG_STAT_LEVEL], or [`NNG_STAT_ID`][NNG_STAT_ID].
If _stat_ is not one of these types, then it returns zero.

The {{i:`nng_stat_bool`}} function returns the Boolean value (either `true` or `false`) for the statistic _stat_ of
type [`NNG_STAT_BOOLEAN`][NNG_STAT_BOOLEAN]. If the statistics is not of this type, then it returns `false`.

The {{i:`nng_stat_string`}} function returns a pointer to a string value for the statistic _stat_,
of type [`NNG_STAT_STRING`][NNG_STAT_STRING]. This string will remain valud until the snapshot that
_stat_ was collected with is deallocated with [`nng_stats_free`][nng_stats_free]. If the statistic
is not of type `NNG_STAT_STRING`, then `NULL` is returned.

## Statistic Units

```c
int nng_stat_unit(const nng_stat *stat);
```

For statistics of type [`NNG_STAT_COUNTER`][NNG_STAT_COUNTER] or [`NNG_STAT_LEVEL`][NNG_STAT_LEVEL],
it is often useful to know what that quantity being reported measures.
The following units may be returned from {{i:`nng_stat_unit`}} for such a statistic:

- {{i:`NNG_UNIT_NONE`}}: No unit is known or applies.
- {{i:`NNG_UNIT_BYTES`}}: A count of bytes.
- {{i:`NNG_UNIT_MESSAGES`}}: A count of messages.
- {{i:`NNG_UNIT_MILLIS`}}: A count of milliseconds.
- {{i:`NNG_UNIT_EVENTS`}}: A count of events of some type.

## Statistic Timestamp

```c
uint64_t nng_stat_timestamp(const nng_stat *stat);
```

Statistics have a timestamp indicating when the value was sampled,
obtained via {{i:`nng_stat_timestamp`}}. The timestamp is given in
in milliseconds since a reference time, and the reference time used
here is the same reference time used for [`nng_clock`][nng_clock].

## See Also

[`nng_clock`][nng_clock]

[nng_stat_type]: #statistic-type
[nng_stats_free]: #freeing-a-snapshot
[nng_stat_value]: #statistic-value
[nng_stat_bool]: #statistic-value
[nng_stat_string]: #statistic-value
[nng_stat_unit]: #statistic-units
[NNG_STAT_ID]: #NNG_STAT_ID
[NNG_STAT_COUNTER]: #NNG_STAT_COUNTER
[NNG_STAT_LEVEL]: #NNG_STAT_LEVEL
[NNG_STAT_SCOPE]: #NNG_STAT_SCOPE
[NNG_STAT_STRING]: #NNG_STAT_STRING
[NNG_STAT_BOOLEAN]: #NNG_STAT_BOOLEAN
[nng_clock]: ./time.md#getting-the-current-time
[nng_socket]: TODO.md
[nng_dialer]: TODO.md
[nng_listener]: TODO.md
