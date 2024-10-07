# nng_random

## NAME

nng_random --- get random number

## SYNOPSIS

```c
#include <nng/nng.h>

uint32_t nng_random(void);
```

## DESCRIPTION

The {{i:`nng_random`}} returns a {{i:random number}}.
The value returned is suitable for use with cryptographic functions such as
key generation.
The value is obtained using platform-specific cryptographically strong random
number facilities when available.

## RETURN VALUES

Returns a random 32-bit value.
