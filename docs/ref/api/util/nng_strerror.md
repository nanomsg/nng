# nng_strerror

## NAME

nng_strerror --- return an error description

## SYNOPSIS

```c
#include <nng/nng.h>

const char *nng_strerror(int err);
```

## DESCRIPTION

The `nng_strerror` returns the human-readable description of the
given error in `err`.

The returned error message is provided in US English, but in the
future locale-specific strings may be presented instead.

> [!NOTE]
> The specific strings associated with specific error messages are
> subject to change.
> Therefore applications must not depend on the message,
> but may use them verbatim when supplying information to end-users, such
> as in diagnostic messages or log entries.

## RETURN VALUES

This function returns the human-readable error message, terminated
by a `NUL` byte.
