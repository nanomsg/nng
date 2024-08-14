
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#include "nng_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef NNG_PLATFORM_WINDOWS
#include <io.h>
#endif
#ifdef NNG_PLATFORM_POSIX
#include <syslog.h>
#include <unistd.h>
#endif
#include <time.h>

static nng_log_level    log_level    = NNG_LOG_NOTICE;
static nng_log_facility log_facility = NNG_LOG_USER;
static nng_logger       log_logger   = nng_null_logger;

void
nng_log_set_facility(nng_log_facility facility)
{
	log_facility = facility;
}

void
nng_log_set_level(nng_log_level level)
{
	log_level = level;
}

nng_log_level
nng_log_get_level(void)
{
	return (log_level);
}

void
nng_log_set_logger(nng_logger logger)
{
	if (logger == NULL) {
		logger = nng_null_logger;
	}
	log_logger = logger;
}

void
nng_null_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg)
{
	NNI_ARG_UNUSED(level);
	NNI_ARG_UNUSED(facility);
	NNI_ARG_UNUSED(msgid);
	NNI_ARG_UNUSED(msg);
}

void
stderr_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg, bool timechk)
{
	const char *sgr, *sgr0;
	// Initial implementation.
	bool             colors = false;
	const char      *level_str;
	char             when[64];
	struct tm       *tm;
	static struct tm last_log = { 0 };
	time_t           now;
	uint64_t         sec;
	uint32_t         nsec;

	NNI_ARG_UNUSED(facility);

	if (nni_time_get(&sec, &nsec) != 0) {
		// default to the epoch if we can't get a clock for some reason
		sec  = 0;
		nsec = 0;
	}
	now = (time_t) sec;

#ifdef NNG_PLATFORM_WINDOWS
	// NB: We are blithely assuming the user has a modern console.
	colors = _isatty(_fileno(stderr));
#elif defined(NNG_PLATFORM_POSIX)
	// Only assuming we can use colors (and attributes) if stderr is a tty
	// and $TERM is reasonable. We assume the terminal supports ECMA-48,
	// which is true on every reasonable system these days.
	colors = isatty(fileno(stderr)) && (getenv("TERM") != NULL) &&
	    (getenv("TERM")[0] != 0);
#else
	colors = false;
#endif

	// Escape hatch to prevent colorizing logs if we have to.  Users on
	// legacy Windows can set this, or on ancient HP terminals or
	// something.  Also in the same way that no-color.org proposes.
	// The reason for both is to allow suppression *only* for NNG.  There
	// is no good reason to enable it to override the presence of NO_COLOR.
	if ((getenv("NNG_LOG_NO_COLOR") != NULL) ||
	    (getenv("NO_COLOR") != NULL)) {
		colors = false;
	}
#ifdef NNG_HAVE_LOCALTIME_R
	struct tm tm_buf;
	// No timezone offset, not strictly ISO8601 compliant
	tm = localtime_r(&now, &tm_buf);
#else
	tm = localtime(&now);
#endif
	switch (level) {
	case NNG_LOG_ERR:
		sgr       = "\x1b[31m"; // red
		sgr0      = "\x1b[0m";
		level_str = "ERROR";
		break;
	case NNG_LOG_WARN:
		sgr       = "\x1b[33m"; // yellow
		sgr0      = "\x1b[0m";
		level_str = "WARN";
		break;
	case NNG_LOG_NOTICE:
		sgr       = "\x1b[1m"; // bold
		sgr0      = "\x1b[0m";
		level_str = "NOTICE";
		break;
	case NNG_LOG_DEBUG:
		sgr       = "\x1b[36m"; // cyan
		sgr0      = "\x1b[0m";
		level_str = "DEBUG";
		break;
	case NNG_LOG_INFO:
		sgr       = "";
		sgr0      = "";
		level_str = "INFO";
		break;
	default:
		sgr       = "";
		sgr0      = "";
		level_str = "NONE";
		break;
	}

	if (!colors) {
		sgr  = "";
		sgr0 = "";
	}

	if (timechk &&
	    ((last_log.tm_mday != tm->tm_mday) ||
	        (last_log.tm_mon != tm->tm_mon) ||
	        (last_log.tm_year != tm->tm_year))) {
		char new_day[64];
		strftime(new_day, sizeof(new_day),
		    "Date changed to %Y-%m-%d, TZ is %z", tm);
		stderr_logger(
		    NNG_LOG_DEBUG, facility, "NNG-DATE", new_day, false);
		last_log = *tm;
	}

	strftime(when, sizeof(when), "%H:%M:%S", tm);
	// we print with millisecond resolution
	bool trailing_nl =
	    ((strlen(msg) != 0) && msg[strlen(msg) - 1] == '\n');
	(void) fprintf(stderr, "%s[%-6s]: %s.%03d: %s%s%s%s%s", sgr, level_str,
	    when, nsec / 1000000, msgid ? msgid : "", msgid ? ": " : "", msg,
	    sgr0, trailing_nl ? "" : "\n");
}

void
nng_stderr_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg)
{
	stderr_logger(level, facility, msgid, msg, true);
}

void
nng_system_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg)
{
#ifdef NNG_PLATFORM_POSIX
	int pri;
	switch (level) {
	case NNG_LOG_ERR:
		pri = LOG_ERR;
		break;
	case NNG_LOG_WARN:
		pri = LOG_WARNING;
		break;
	case NNG_LOG_NOTICE:
		pri = LOG_NOTICE;
		break;
	case NNG_LOG_INFO:
		pri = LOG_INFO;
		break;
	case NNG_LOG_DEBUG:
		pri = LOG_DEBUG;
		break;
	default:
		pri = LOG_INFO;
		break;
	}
	switch (facility) {
	case NNG_LOG_DAEMON:
		pri |= LOG_DAEMON;
		break;
	case NNG_LOG_USER:
		pri |= LOG_USER;
		break;
	case NNG_LOG_AUTH:
		pri |= LOG_AUTHPRIV;
		break;
	case NNG_LOG_LOCAL0:
		pri |= LOG_LOCAL0;
		break;
	case NNG_LOG_LOCAL1:
		pri |= LOG_LOCAL1;
		break;
	case NNG_LOG_LOCAL2:
		pri |= LOG_LOCAL2;
		break;
	case NNG_LOG_LOCAL3:
		pri |= LOG_LOCAL3;
		break;
	case NNG_LOG_LOCAL4:
		pri |= LOG_LOCAL4;
		break;
	case NNG_LOG_LOCAL5:
		pri |= LOG_LOCAL5;
		break;
	case NNG_LOG_LOCAL6:
		pri |= LOG_LOCAL6;
		break;
	case NNG_LOG_LOCAL7:
		pri |= LOG_LOCAL7;
		break;
	}

	if (msgid) {
		syslog(pri, "%s: %s", msgid, msg);
	} else {
		syslog(pri, "%s", msg);
	}
#else
	// everyone else just goes to stderr for now
	nng_stderr_logger(level, facility, msgid, msg);
#endif
}

static void
nni_vlog(nng_log_level level, nng_log_facility facility, const char *msgid,
    const char *msg, va_list ap)
{
	// nobody allowed to log at LOG_EMERG or using LOG_KERN
	if (level > log_level || log_level == 0 || facility == 0) {
		return;
	}
	char formatted[512];
	vsnprintf(formatted, sizeof(formatted), msg, ap);
	log_logger(level, facility, msgid, formatted);
}

void
nng_log_debug(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_DEBUG, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_info(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_INFO, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_notice(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_NOTICE, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_warn(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_WARN, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_err(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_ERR, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_auth(nng_log_level level, const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(level, NNG_LOG_AUTH, msgid, msg, ap);
	va_end(ap);
}
