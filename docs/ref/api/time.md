# Time

_NNG_ supports has support for time in the form of access to a
system clock, and supporting timeouts for certain operations.

## Time Type

```c
typedef uint64_t nng_time;
```

The {{i:`nng_time`}} type is used to represent a clock offset from a common base time,
measured in milliseconds.

The reference, or zero value, is some arbitrary point in time, most often sytem boot, but can
be process start time or any other convenient reference.

All threads within a process will use the same reference time, but be aware that different processes
may use a different reference time.

## Duration Type

```c
typedef int64_t nng_duration;

#define NNG_DURATION_INFINITE (-1)
#define NNG_DURATION_DEFAULT  (-2)
#define NNG_DURATION_ZERO     (0)
```

The {{i:`nng_duration`}} time measures a time {{i:duration}} in milliseconds.
Normally durations are positive, but some specific negative values are reserved.

- {{i:`NNG_DURATION_INFINITE`}}: The duration essentially means forever.
  This is most often used with a timeout to indicate that there is no timeout, the
  operation should wait until it is complete, even forever.

- {{i:`NNG_DURATION_DEFAULT`}}: This special value is used in some circumstances to
  prevent overriding a default timeout. Some operations have a default maximum time,
  and this value means that the previously established default should be used.
  The precise meaning is context-specific.

- {{i:`NNG_DURATION_ZERO`}}: A zero length duration is used to performan an immediate
  poll.

## Getting the Current Time

```c
nng_time nng_clock(void);
```

The {{i:`nng_clock`}}{{hi:clock}} function returns the number of elapsed
milliseconds since some arbitrary time in the past.
The resolution of the clock depends on the underlying timing facilities of the system.
This function may be used for timing, but applications should not expect
very fine-grained values.

## Waiting for Duration

```c
void nng_msleep(nng_duration msec);
```

The {{i:`nng_msleep`}} function blocks the calling thread for at least the specified
number of milliseconds.

> [!TIP]
> This function may block for longer than requested.
> The actual wait time is determined by the capabilities of the
> underlying system.

## See Also

[`nng_cv_until`][nng_cv_until],
[`nng_sleep_aio`][nng_sleep_aio]

[nng_cv_until]: ./synch.md#waiting-for-the-condition
[nng_sleep_aio]: TODO.md
