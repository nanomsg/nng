# nng_stat

## NAME

nng_stat --- statistic

## SYNOPSIS

```c
#include <nng/nng.h>

typedef struct nng_stat nng_stat;

enum {
	NNG_STAT_SCOPE,
	NNG_STAT_LEVEL,
	NNG_STAT_COUNTER,
	NNG_STAT_STRING,
	NNG_STAT_BOOLEAN,
	NNG_STAT_ID
};

enum {
	NNG_UNIT_NONE,
	NNG_UNIT_BYTES,
	NNG_UNIT_MESSAGES,
	NNG_UNIT_MILLIS,
	NNG_UNIT_EVENTS
};

int nng_stat_unit(nng_stat *stat);

const char *nng_stat_name(nng_stat *stat);
const char *nng_stat_desc(nng_stat *stat);
int nng_stat_type(nng_stat *stat);
int nng_stat_unit(nng_stat *stat);
uint64_t nng_stat_value(nng_stat *stat);
const char *nng_stat_string(nng_stat *stat);
bool nng_stat_bool(nng_stat *stat);
uint64_t nng_stat_timestamp(nng_stat *stat);
```

## DESCRIPTION

An {{i:`nng_stat`}} represents a {{i:statistic}}.
All statistics have names (retrievable with {{i:`nng_stat_name`}}) and
descriptions (retrievable with {{i:`nng_stat_desc`}}), and a
type (retrievable with {{i:`nng_stat_type`}}).

Statistics also have a timestamp indicating when the value was sampled,
obtained via {{i:`nng_stat_timestamp}}`. The timestamp is given in
in milliseconds since a reference time, and the reference time used
here is the same reference time used for [`nng_clock`][nng_clock].

> [!NOTE]
> The presence, name, and semantics of any given statistic are
> subject to change at any time and without notice.

### Statistic Values

The type of a statistic determines the nature of the value, and which
function can be used to obtain that value.

- {{i:`NNG_STAT_SCOPE`}}: The statistic does not carry any real value, but is
  used for grouping related statistics together. This is a nexus in the
  statistics tree.

- {{i:`NNG_STAT_COUNTER`}}: The statistic is a counter that only increments.
  Usually the change in the value of the statistic is more interesting
  (as a rate) than the absolute value at any given time. The value should
  be obtained using `nng_stat_value`. The units will be given by the value
  returned from `nng_stat_unit`.

- {{i:`NNG_STAT_LEVEL`}}: The statistic represnts a measured value which corresponds
  to a specific value at a specific time. For example, this may represent the
  number of messages currently queued for some operation, or the link speed
  of a network interface. Most often the absolute value is more interesting
  than the change in the value over time. Again the value can be obtained with
  `nng_stat_value`, and any appropriate unit of measurement with `nng_stat_unit`.

- {{i:`NNG_STAT_STRING`}}: The statistic is a string, such as a human. The value
  of the string can be obtained with `nng_stat_string`. The value of this string
  will remain valid until the snapshot is deallocated with [`nng_stats_free`][nng_stats].

- {{i:`NNG_STAT_BOOLEAN`}}: The value of the statistic is a truth value (either `true`
  or `false`) and can be obtained with `nng_stat_bool`.

- {{i:`NNG_STAT_ID`}}: The value of the statistic is a numeric identifier, such as a socket
  identifier. The value can be obtained with `nng_stat_value`, and will generally not
  change over time for a given statistic.

### Statistic Units

For statistics of type `NNG_STAT_COUNTER` or `NNG_STAT_LEVEL`, it is often
useful to know what that quantity being reported actually measures.
The following units may be returned from `nng_stat_unit` for such a statistic:

- `NNG_UNIT_NONE`: No unit is known or applies.
- `NNG_UNIT_BYTES`: A count of bytes.
- `NNG_UNIT_MESSAGES`: A count of messages.
- `NNG_UNIT_MILLIS`: A count of milliseconds.
- `NNG_UNIT_EVENTS`: A count of events of some type.

## SEE ALSO

[nng_clock][nng_clock],
[nng_stats][nng_stats],

[nng_clock]: ../util/nng_clock.md
[nng_stats]: ./nng_stats.md
