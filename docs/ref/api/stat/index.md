# Statistics

To facilitate debugging and support situations, the _NNG_ library
supports collection and reporting of numerous statistics.

These statistics are organized in a tree, and include both values,
and metadata describing the statistics. In order to be efficient and
minimize the impact of maintaining statistics, an explicit snapshot
of statistics must be taken, and that snapshot can then be processed.

The following documentation will be useful:

- [nng_stat](./nng_stat.md) - Single statistic
- [nng_stats](./nng_stats.md) - Statistics snapshot

> [!NOTE]
> The presence, name, and semantics of any given statistic are
> subject to change at any time and without notice.
> Programmatic use is therefore discouraged.

> [!NOTE]
> Statistics may be disabled by build-time configuration options,
> in order to reduce program size and run-time overheads.
