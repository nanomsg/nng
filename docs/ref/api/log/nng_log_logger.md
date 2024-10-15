# nng_log_logger

## NAME

nng_log_logger --- logging handler

## SYNOPSIS

```c
#include <nng/nng.h>

typedef void (*nng_logger)(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg);

void nng_null_logger(nng_log_level, nng_log_facility, const char *, const char *);
void nng_stderr_logger(nng_log_level, nng_log_facility, const char *, const char *);
void nng_system_logger(nng_log_level, nng_log_facility, const char *, const char *);

void nng_log_set_logger(nng_logger logger);
```

## DESCRIPTION

An {{i:`nng_logger`}}{{hi:logger}} is a function used as a handler to process logged messages.
This is responsible for the final disposition of the logged messages.

The {{i:`nng_log_set_logger`}} function is used to set the base logging function to _logger_.
The _logger_ may be a user defined function to process log messages.
Only a single logger may be registered at a time.
If needed, the logger should make copies of either _msgid_ or _msg_, as they will not be valid after the logger returns.

The {{i:`nng_null_logger`}} function is an implementation of `nng_logger` that simply discards the content.
This is the default logger, so logging is disabled by default.

The {{i:`nng_stderr_logger`}} function is an implementation that logs messages to the standard error stream.
It will attempt to colorize messages by the severity, if the standard error is a terminal device.
This can be supressed by setting either the `NO_COLOR` or `NNG_LOG_NO_COLOR` environment variables.

The {{i:`nng_system_logger`}} attempts to use an appropriate system facility to log messages.
For POSIX systems, this means using `syslog` to process the messages.
For other systems the defauilt behavior may be the same as `nng_stderr_logger`.

## SEE ALSO

[nng_log](./nng_log.md),
[nng_log_facility](./nng_log_facility.md),
[nng_log_level](./nng_log_level.md)
