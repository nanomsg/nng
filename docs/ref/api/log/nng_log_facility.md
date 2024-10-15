# nng_log_facility

## NAME

nng_log_facility --- facility or category for log messages

## SYNOPSIS

```c
#include <nng/nng.h>

typedef enum nng_log_facility {
	NNG_LOG_USER   = 1,
	NNG_LOG_DAEMON = 3,
	NNG_LOG_AUTH   = 10,
	NNG_LOG_LOCAL0 = 16,
	NNG_LOG_LOCAL1 = 17,
	NNG_LOG_LOCAL2 = 18,
	NNG_LOG_LOCAL3 = 19,
	NNG_LOG_LOCAL4 = 20,
	NNG_LOG_LOCAL5 = 21,
	NNG_LOG_LOCAL6 = 22,
	NNG_LOG_LOCAL7 = 23,
} nng_log_facility;

void nng_log_set_facility(nng_log_facility facility);
```

## DESCRIPTION

An {{i:`nng_log_facility`}} object represents a facility, which can be thought of as
a category, for log message. Normally these are used to identify the source of the
message. The facility values here correspond to those typical used with the UNIX
`syslog` logging system.

The `nng_log_set_facility` is used to set the _facility_ of the application posting logs,
so that messages that are submitted by the application can be correctly attributed to
the application itself. It may also help in message routing.

Note that while the log levels used here overlap with common levels used by the
`syslog` system found on POSIX systems, applications should not the numeric values
being the same.

## SEE ALSO

[nng_log](./nng_log.md),
[nng_log_level](./nng_log_level.md)
