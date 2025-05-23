# Time

_NNG_ supports has support for time in the form of access to a
system clock, and supporting timeouts for certain operations.

## Time Type

```c
typedef uint64_t nng_time;
```

The {{i:`nng_time`}} type is used to represent a clock offset from a common base time,
measured in milliseconds.

The reference, or zero value, is some arbitrary point in time, most often system boot, but can
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

## Get the Current Time

```c
nng_time nng_clock(void);
```

The {{i:`nng_clock`}}{{hi:clock}} function returns the number of elapsed
milliseconds since some arbitrary time in the past.
The resolution of the clock depends on the underlying timing facilities of the system.
This function may be used for timing, but applications should not expect
very fine-grained values.

## Wait for Duration

```c
void nng_msleep(nng_duration msec);
```

The {{i:`nng_msleep`}} function blocks the calling thread for at least the specified
number of milliseconds.

> [!TIP]
> This function may block for longer than requested.
> The actual wait time is determined by the capabilities of the
> underlying system.

## Wait Asynchronously

```c
void nng_sleep_aio(nng_duration msec, nng_aio *aio);
```

It is possible to wait as the action on an [`nng_aio`], which in effect
acts like {{i:scheduling}} a callback to run after a specified period of time.

The {{i:`nng_sleep_aio`}} function provides this capability.
After _msec_ milliseconds have passed, then _aio_'s callback will be executed.
If this sleep waits without interruption, and then completes, the result from
[`nng_aio_result`] will be zero.

> [!NOTE]
> If a timeout shorter than _msec_ is set on _aio_ using [`nng_aio_set_timeout`],
> then the sleep will wake up early, with a result code of [`NNG_ETIMEDOUT`].

## See Also

[Asynchronous Operations][aio],
[Synchronization][synchronization]

{{#include ../xref.md}}
