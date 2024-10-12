# nng_duration

## NAME

nng_duration --- relative time in milliseconds

## SYNOPSIS

```c
#include <nng/nng.h>

typedef int32_t nng_duration;

#define NNG_DURATION_INFINITE (-1)
#define NNG_DURATION_DEFAULT  (-2)
#define NNG_DURATION_ZERO     (0)
```

## DESCRIPTION

An {{i:`nng_duration`}}{{hi:duration}} is a relative time, measured in {{i:milliseconds}}.
This type is most often used in conjunction with timers and timeouts.

A couple of special values have been set aside, and carry special meanings.

- {{i:`NNG_DURATION_DEFAULT`}}:
  Indicates a context-specific default value should be used.

- {{i:`NNG_DURATION_INFINITE`}}:
  Effectively an infinite duration; used most often to disable timeouts.

- {{i:`NNG_DURATION_ZERO`}}:
  Zero length duration; used to perform an immediate poll.
