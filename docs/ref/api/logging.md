# Logging

This chapter describes the support for message logs.
Both applications and _NNG_ itself can emit logs, which can be useful
for application field support and debugging. Additionally applications
can customize the handling of this logging as needed.

Note that logging is disabled by default unless an application
configures a suitable logger with [`nng_log_set_logger`][log_logger].

## Submitting Logs

```c
void nng_log_err(const char *msgid, const char *msg, ...);
void nng_log_warn(const char *msgid, const char *msg, ...);
void nng_log_notice(const char *msgid, const char *msg, ...);
void nng_log_info(const char *msgid, const char *msg, ...);
void nng_log_debug(const char *msgid, const char *msg, ...);
```

These {{hi:`nng_log`}} functions inject a a message into the
logging system, where it will be processed and potentially go to
system logs, standard output, or procssed further.

The _msgid_ is a short prefix that should uniquely identify the message,
possibly also with some kind of category. It is recommended that
strings between 8 and 16 charactes be used. As this may, but will not necessarily
be displayed to the user, the content of the message should not appear
solely in this field. A `NULL` value is permitted here, but that may
make filtering the message or other automatic processing more difficult.

The _msg_ is a `printf`-style format string, which is used to format the
message content. The following arguments are consumed in the
same manner as `printf`.

> [!TIP]
> Applications should take care to limit the use of higher severity levels, as message logs
> are potentially expensive, increase stress for end users and administrators, and further may
> mask real problems if incorrectly over used.
>
> Warnings and error messages should be concise and actionable, and notices should only
> really be those things that are worthy of attention.
>
> Informational and debug messages used during development should be removed when no longer
> needed, as these messages can overwhelm logging subsystems and can reduce the
> signal-to-noise value for the message logs, impairing the diagnostic value of the logs.

## Auth Logs

```c
void nng_log_auth(nng_log_level level, const char *msgid, const char *msg, ...);
```

The {{i:`nng_log_auth`}} function formats and injects a security related log message.
("Auth" can indicate either "authentication" or "authorization".)
The _level_ is a [log level][log_level].
The _msgid_, _msg_, and any remaining arguments are processed in a fashion
similar to the other [logging functions][submitting_logs], except that the
logs may be are logged using the `NNG_LOG_AUTH` [facility][log_facility], and thus may be
redirected or receive other special treatment.

## Log Levels

```c
typedef enum nng_log_level nng_log_level;

void nng_log_set_level(nng_log_level level);
nng_log_level nng_log_get_level(void);
```

The {{i:`nng_log_level`}} type represents a severity for logged messages.
These levels correspond to those found in the UNIX syslog subsystem,
although applications should not depend upon the values being identical.

The {{i:`nng_log_set_level`}} function sets the log level.
Messages with a severity that is numerically greater than this (less-severe)
will be discarded.

The {{i:`nng_log_get_level`}} function returns the log level most recently
set by `nng_log_set_level` or the default
if that function has not been called.

The log levels are defined as follows:

```c
typedef enum nng_log_level {
    NNG_LOG_NONE   = 0, // used for filters only, NNG suppresses these
    NNG_LOG_ERR    = 3,
    NNG_LOG_WARN   = 4,
    NNG_LOG_NOTICE = 5,
    NNG_LOG_INFO   = 6,
    NNG_LOG_DEBUG  = 7
} nng_log_level;
```

The value `NNG_LOG_NONE` may be useful to suppress message logs altogether.

The default level is typically `NNG_LOG_NOTICE`, but applications should
select a value rather than relying upon the default.

## Log Facilities

```c
typedef enum nng_log_facility

void nng_log_set_facility(nng_log_facility facility);
```

Logging facilities are used to indicate the source of a log message,
and may be useful in routing and processing these logs.
Traditionally these are used with the UNIX `syslog` system, and
the values here represent some (but not all) of the values found there.

The following values are defined:

```c
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
```

The {{i:`nng_log_set_facility`}} function can be used to
set the facility that the application will use when emitting log
messages. This should be called as part of initialization of the
application, if logging is to be used.

The default facility is typically `NNG_LOG_USER`, but applications should
select a value rather than relying upon the default.

## Log Handlers

```c
typedef void (*nng_logger)(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg);

void nng_null_logger(nng_log_level, nng_log_facility, const char *, const char *);
void nng_stderr_logger(nng_log_level, nng_log_facility, const char *, const char *);
void nng_system_logger(nng_log_level, nng_log_facility, const char *, const char *);

void nng_log_set_logger(nng_logger logger);
```

{{i:Log handlers}} are responsible for actually processing the logged messages.

The {{i:`nng_log_set_logger`}} function installs the named _logger_, of type {{i:`nng_logger`}},
as the log handler. The function _logger_ will be called when any message is meant to
be processed. (Messages are first filtered by [severity][log_level], then formatted,
before calling the logger.)

Any previously installed logger is replaced by _logger_.

The {{i:`nng_null_logger`}} function is an implementation of `nng_logger` that simply discards the content.
This is the default logger, so logging is disabled by default.

The {{i:`nng_stderr_logger`}} function is an implementation that logs messages to the standard error stream.
It will attempt to colorize messages by the severity, if the standard error is a terminal device.
This can be suppressed by setting either the `NO_COLOR` or `NNG_LOG_NO_COLOR` environment variables.

The {{i:`nng_system_logger`}} attempts to use an appropriate system facility to log messages.
For POSIX systems, this means using `syslog` to process the messages.
For other systems the defauilt behavior may be the same as `nng_stderr_logger`.

## See Also

The Syslog Protocol upon which this is based is documented in the following two IETF
RFCS,

- R. Gerhards, [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424), _The Syslog Protocol_,
  March 2009
- C. Lonvick, [RFC 3164](https://datatracker.ietf.org/doc/html/rfc3164), _The BSD syslog Protocol_,
  August 2001

[log_level]: #log-levels
[log_facility]: #log-facilities
[log_logger]: #log-handlers
[submitting_logs]: #submitting-logs
