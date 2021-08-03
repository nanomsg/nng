
#ifndef __NNG_NANO_H__
#define __NNG_NANO_H__

#include <stdint.h>
#include <stdio.h>

#define DEBUG_FILE_PATH "/tmp/debug_dash.log"

#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

// later expose on makefile

#if defined(NOLOG)
#undef DEBUG_CONSOLE
#undef DEBUG_FILE
#undef DEBUG_SYSLOG
#else
#define DEBUG_CONSOLE
#define DEBUG_FILE
#define DEBUG_SYSLOG
#endif

#undef DASH_DEBUG
#if defined(DEBUG_CONSOLE) || defined(DEBUG_FILE) || defined(DEBUG_SYSLOG)
#define DASH_DEBUG 1

static inline char *
nanomq_time_str()
{
	char * buffer;
	time_t now;

	now    = time(NULL);
	buffer = ctime(&now);
	if (!buffer)
		return NULL;

	if (buffer[strlen(buffer) - 1] == '\n')
		buffer[strlen(buffer) - 1] = '\0';

	return buffer;
}

#endif

#if defined(DEBUG_CONSOLE)
#define debug_console(fmt, arg...)                                            \
	do {                                                                  \
		char *_t = nanomq_time_str();                                 \
		fprintf(stderr, "%s %s: " fmt "\n", _t, __FUNCTION__, ##arg); \
	} while (0)
#else
#define debug_console(fmt, arg...) \
	do {                       \
	} while (0)
#endif

#if defined(DEBUG_FILE)
#define debug_file(fmt, arg...)                                      \
	do {                                                         \
		char *_t   = nanomq_time_str();                      \
		FILE *file = fopen(DEBUG_FILE_PATH, "a");            \
		fprintf(file, "%s [%i] %s: " fmt "\n", _t, getpid(), \
		    __FUNCTION__, ##arg);                            \
		fclose(file);                                        \
	} while (0)
#else
#define debug_file(fmt, arg...) \
	do {                    \
	} while (0)
#endif

#if defined(DEBUG_SYSLOG)
#define debug_syslog(fmt, arg...)                                       \
	do {                                                            \
		openlog("nng-nanomq", LOG_PID, LOG_DAEMON | LOG_EMERG); \
		syslog(0, "%s: " fmt, __FUNCTION__, ##arg);             \
		closelog();                                             \
	} while (0)
#else
#define debug_syslog(fmt, arg...) \
	do {                      \
	} while (0)
#endif

#if defined(DASH_DEBUG)
#define debug_msg(fmt, arg...)             \
	do {                               \
		debug_console(fmt, ##arg); \
		debug_file(fmt, ##arg);    \
		debug_syslog(fmt, ##arg);  \
	} while (0)
#else
#define debug_msg(fmt, arg...) \
	do {                   \
	} while (0)
#endif

#define DASH_UNUSED(x) (x) __attribute__((unused))

#endif /* __NNG_NANO_H__ */
