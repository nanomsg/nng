# nng_log

## NAME

# nng_log --- log messages

## SYNOPSIS

```c
#include <nng/nng.h>

void nng_log_err(const char *msgid, const char *msg, ...);
void nng_log_warn(const char *msgid, const char *msg, ...);
void nng_log_notice(const char *msgid, const char *msg, ...);
void nng_log_info(const char *msgid, const char *msg, ...);
void nng_log_debug(const char *msgid, const char *msg, ...);

void nng_log_auth(nng_log_level level, const char *msgid, const char *msg, ...);
```

## DESCRIPTION

The {{i:`nng_log`}} functions are used to post a message to system or application {{i:logs}}.

The first five forms all post a message at the severity indicated by the function name.
The _msgid_ should be a short message identifier that should indicate the message in question.
A `NULL` value for _msgid_ can be used as well.

Message identifiers can be used to assist in filtering and classifying logged messages.
These should uniquely identify the nature of the problem, whe possible, to assist in trouble-shooting.
They should also be short.
Eight characters or less is ideal, and more than sixteen is strongly discouraged.
Message identifiers may not be displayed to human readers, or may not be displayed by default.
Therefore, any information in the message identifier should also be in the log content.

The message is formatted as if by `sprintf`, using `msg` as the format, and remaining arguments as arguments to the format.

The final function, {{i:`nng_log_auth`}}, is used for posting authentication related messages which might be treated specially,
such as be storing them in a separate (and presumably more secure) log file.
It takes the severity as a level in _level_.
The severity can be one of the following values:

- `NNG_LOG_ERR`
- `NNG_LOG_WARN`
- `NNG_LOG_NOTICE`
- `NNG_LOG_INFO`
- `NNG_LOG_DEBUG`

The message itself is handled according to the logging facility set up with [`nng_log_set_logger`][log_logger].
Message delivery is best effort, and messages may be suppressed based on the priority set with [`nng_log_set_level`][log_level].

Note that in order to get log messages, a suitable logger must be set using {{i:`nng_log_set_logger`}}.
The default logger, {{i:`nng_null_logger`}} simply discards logged content.

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

## SEE ALSO

[nng_log_facility][log_facility],
[nng_log_level][log_level],
[nng_log_logger][log_logger]

[log_facility]: ./nng_log_facility.md
[log_level]: ./nng_log_level.md
[log_logger]: ./nng_log_logger.md
