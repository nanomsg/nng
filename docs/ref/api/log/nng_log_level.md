# nng_log_level

## NAME

nng_log_level --- severity level for logging messages

## SYNOPSIS

```c
#include <nng/nng.h>

typedef enum nng_log_level {
	NNG_LOG_NONE   = 0, // used for filters only, NNG suppresses these
	NNG_LOG_ERR    = 3,
	NNG_LOG_WARN   = 4,
	NNG_LOG_NOTICE = 5,
	NNG_LOG_INFO   = 6,
	NNG_LOG_DEBUG  = 7
} nng_log_level;

void nng_log_set_level(nng_log_level level);
nng_log_level nng_log_get_level(void);
```

## DESCRIPTION

The `nng_log_level` type represents a severity for logged messages.
These levels correspond to those found in the UNIX `syslog` subsystem,
although applications should not depend upon the values being identical.

The `nng_log_set_level` function is used to set the minimum severity to _level_ for processing log messages.
Any messages with a less severe rating are not processed and simply are discarded.
Use `NNG_LOG_NONE` to suppress all log messages.
Use `NNG_LOG_DEBUG` to receive all log messages.

The `nng_log_get_level` function returns the current log level, which can be useful
to elide processing to create log content that will simply be discarded anyway.

## RETURN VALUES

The `nng_log_get_level` functions returns the current log level.

## SEE ALSO

[nng_log](./nng_log.md),
[nng_log_facility](./nng_log_facility.md),
[nng_log_logger](./nng_log_logger.md)
