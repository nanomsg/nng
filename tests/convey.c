/*
 * Copyright 2018 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

/*
 * This contains some of the guts of the testing framework.  It is in a single
 * file in order to simplify use and minimize external dependencies.
 *
 * If you use this with threads, you need to either have pthreads (and link
 * your test program against the threading library), or you need Windows.
 * Support for C11 threading is not implemented yet.
 *
 * For timing, this code needs a decent timer.  It will use clock_gettime
 * if it appears to be present, or the Win32 QueryPerformanceCounter, or
 * gettimeofday() if neither of those are available.
 *
 * This code is unlikely to function at all on anything that isn't a UNIX
 * or Windows system.  As we think its unlikely that you'd want to use this
 * to run testing inside an embedded device or something, we think this is a
 * reasonable limitation.
 *
 * Note that we expect that on Windows, you have a reasonably current
 * version of MSVC.  (Specifically we need a few C99-isms that Microsoft
 * only added late -- like in 2010.  Specifically uint32_t and uint64_t).
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

#else

#if NNG_HAVE_LANGINFO
#include <langinfo.h>
#include <locale.h>
#endif

#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef CONVEY_NO_THREADS
#include <pthread.h>
#endif

#endif

#include "convey.h"

/*
 * About symbol naming.  We use Go-like conventions to help set expectations,
 * even though we cannot necessarily count on the linker to prevent
 * access.  We have to accept that we may be inlined directly into the
 * user's program, so we try not to pollute their namespace.  (Convenience
 * pollution may be enabled in convey.h.)
 *
 * Symbols exposed to users directly are named ConveyXXX using CamelCase
 * (just like Go).
 *
 * Symbols used internally, but which must be exposed for external linkage
 * will be named using conveyXXX (camelCase with the leading "c" lower.)
 *
 * Symbols used internally, and kept entirely within the the .c file, are
 * named convey_xxx (using underscores).
 *
 * When symbols can reasonably be expected not to collide and are local to
 * a scope not expressed to user code, these rules are relaxed.
 */

static const char *convey_sym_pass = ".";
static const char *convey_sym_skip = "?";
static const char *convey_sym_fail = "X";
static const char *convey_nocolor  = "";
static const char *convey_green    = "";
static const char *convey_red      = "";
static const char *convey_yellow   = "";

static int         convey_debug        = 0;
static int         convey_verbose      = 0;
static int         convey_nassert      = 0;
static int         convey_nskip        = 0;
static const char *convey_assert_color = "";

#if defined(_WIN32)
static WORD   convey_defattr;
static HANDLE convey_console;
#endif

#define CONVEY_EXIT_OK 0
#define CONVEY_EXIT_FAIL 2
#define CONVEY_EXIT_FATAL 3
#define CONVEY_EXIT_NOMEM 4

struct convey_timer {
	uint64_t timer_base;
	uint64_t timer_count;
	uint64_t timer_rate;
	int      timer_running;
};

struct convey_log {
	char * log_buf;
	size_t log_size;
	size_t log_length;
};

struct convey_ctx {
	char                ctx_name[256];
	struct convey_ctx * ctx_parent;
	struct convey_ctx * ctx_root; /* the root node on the list */
	struct convey_ctx * ctx_next; /* root list only, cleanup */
	int                 ctx_level;
	int                 ctx_done;
	int                 ctx_started;
	jmp_buf *           ctx_jmp;
	int                 ctx_fatal;
	int                 ctx_fail;
	int                 ctx_skip;
	int                 ctx_printed;
	struct convey_timer ctx_timer;
	struct convey_log * ctx_errlog;
	struct convey_log * ctx_faillog;
	struct convey_log * ctx_dbglog;
};

static void  convey_print_result(struct convey_ctx *);
static void  convey_init_timer(struct convey_timer *);
static void  convey_start_timer(struct convey_timer *);
static void  convey_stop_timer(struct convey_timer *);
static void  convey_read_timer(struct convey_timer *, int *, int *);
static void  convey_init_term(void);
static int   convey_tls_init(void);
static void *convey_tls_get(void);
static int   convey_tls_set(void *);
static struct convey_ctx *convey_get_ctx(void);
static void convey_vlogf(struct convey_log *, const char *, va_list, int);
static void convey_logf(struct convey_log *, const char *, ...);
static void convey_log_emit(struct convey_log *, const char *, const char *);
static void convey_log_free(struct convey_log *);
static struct convey_log *convey_log_alloc(void);
static char *             convey_nextline(char **);
static void               convey_emit_color(const char *);

/*
 * convey_emit_color just changes the output text to the color
 * requested.  It is Windows console aware.
 */
static void
convey_emit_color(const char *color)
{
#if defined(_WIN32)

	if (convey_console != INVALID_HANDLE_VALUE) {
		WORD attr;

		attr = convey_defattr &
		    ~(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED |
		        FOREGROUND_INTENSITY);

		if (color == convey_nocolor) {
			attr = convey_defattr;
		} else if (color == convey_yellow) {
			attr |= FOREGROUND_GREEN | FOREGROUND_RED |
			    FOREGROUND_INTENSITY;
		} else if (color == convey_green) {
			attr |= FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		} else if (color == convey_red) {
			attr |= FOREGROUND_RED | FOREGROUND_INTENSITY;
		} else {
			return;
		}
		(void) fflush(stdout);
		SetConsoleTextAttribute(convey_console, attr);
	} else {
		(void) fputs(color, stdout);
	}
#else
	(void) fputs(color, stdout);
#endif
}

/*
 * convey_print_result prints the test results.  It prints more information
 * in convey_verbose mode.  Note that its possible for assertion checks done at
 * a given block to be recorded in a deeper block, since we can't easily
 * go back up to the old line and print it.
 *
 * We also leverage this point to detect completion of a root context, and
 * deallocate the child contexts.  The root context should never be reentered
 * here.
 */
static void
convey_print_result(struct convey_ctx *t)
{
	int secs, usecs;

	if (t->ctx_root == t) {
		convey_stop_timer(&t->ctx_timer); /* This is idempotent */

		convey_read_timer(&t->ctx_timer, &secs, &usecs);

		(void) convey_logf(t->ctx_dbglog, "Test %s: %s (%d.%02ds)\n",
		    t->ctx_fatal ? "FATAL"
		                 : t->ctx_fail
		            ? "FAIL"
		            : t->ctx_skip ? "PASS (with SKIPs)" : "PASS",
		    t->ctx_name, secs, usecs / 10000);

		if (convey_verbose) {
			(void) puts("");
		}
		convey_log_emit(t->ctx_errlog, "Errors:", convey_red);
		convey_log_emit(t->ctx_faillog, "Failures:", convey_yellow);
		if (convey_debug) {
			convey_log_emit(t->ctx_dbglog, "Log:", convey_nocolor);
		}
		if (convey_verbose) {
			(void) puts("");
			(void) puts("");
			convey_emit_color(convey_assert_color);
			(void) printf(
			    "%d assertions thus far", convey_nassert);
			convey_emit_color(convey_nocolor);

			if (convey_nskip) {
				(void) fputs(" ", stdout);
				convey_emit_color(convey_yellow);
				(void) fputs(
				    "(one or more sections skipped)", stdout);
				convey_emit_color(convey_nocolor);
			}
			(void) printf("\n\n--- %s: %s (%d.%02ds)\n",
			    t->ctx_fatal ? "FATAL"
			                 : t->ctx_fail ? "FAIL" : "PASS",
			    t->ctx_name, secs, usecs / 10000);
		}

		/* Remove the context, because we cannot reenter here */
		convey_tls_set(NULL);

		while (t != NULL) {
			struct convey_ctx *freeit = t;
			if (t->ctx_root == t) {
				convey_log_free(t->ctx_dbglog);
				convey_log_free(t->ctx_faillog);
				convey_log_free(t->ctx_errlog);
			}
			t = t->ctx_next;
			memset(freeit, 0, sizeof(*freeit));
			free(freeit);
		}
	}
}

/*
 * conveyStart is called when the context starts, before any call to
 * setjmp is made.  If the context isn't initialized already, that is
 * done.  Note that this code gets called multiple times when the
 * context is reentered, which is why the context used must be statically
 * allocated -- a record that it has already done is checked.  If
 * the return value is zero, then this block has already been executed,
 * and it should be skipped.  Otherwise, it needs to be done.
 */
int
conveyStart(conveyScope *scope, const char *name)
{
	struct convey_ctx *t, *parent;

	parent = convey_get_ctx();

	if ((t = scope->cs_data) != NULL) {
		if (t->ctx_done) {
			convey_print_result(t);
			return (1); /* all done, skip */
		}
		return (0); /* continue onward */
	}
	scope->cs_data = (t = calloc(1, sizeof(struct convey_ctx)));
	if (t == NULL) {
		goto allocfail;
	}
	t->ctx_jmp = &scope->cs_jmp;

	(void) snprintf(t->ctx_name, sizeof(t->ctx_name) - 1, "%s", name);

	if (parent != NULL) {
		t->ctx_parent = parent;
		t->ctx_root   = t->ctx_parent->ctx_root;
		t->ctx_level  = t->ctx_parent->ctx_level + 1;
		/* unified logging against the root context */
		t->ctx_dbglog         = t->ctx_root->ctx_dbglog;
		t->ctx_faillog        = t->ctx_root->ctx_faillog;
		t->ctx_errlog         = t->ctx_root->ctx_errlog;
		t->ctx_next           = t->ctx_root->ctx_next;
		t->ctx_root->ctx_next = t;
	} else {
		t->ctx_parent = t;
		t->ctx_root   = t;
		if (((t->ctx_errlog = convey_log_alloc()) == NULL) ||
		    ((t->ctx_faillog = convey_log_alloc()) == NULL) ||
		    ((t->ctx_dbglog = convey_log_alloc()) == NULL)) {
			goto allocfail;
		}
		convey_logf(t->ctx_dbglog, "Test Started: %s\n", t->ctx_name);
	}
	return (0);

allocfail:
	if (t != NULL) {
		convey_log_free(t->ctx_errlog);
		convey_log_free(t->ctx_dbglog);
		convey_log_free(t->ctx_faillog);
		free(t);
		scope->cs_data = NULL;
	}
	if (parent != NULL) {
		ConveyError("Unable to allocate context");
	}
	return (1);
}

/*
 * conveyLoop is called right after setjmp.  If unwind is true it indicates
 * that setjmp returned true, and we are unwinding the stack.  In that case
 * we perform a local cleanup and keep popping back up the stack.  We
 * always come through this, even if the test finishes successfully, so
 * that we can do this stack unwind.  If we are unwinding, and we are
 * at the root context, then we pritn the results and return non-zero
 * so that our caller knows to stop further processing.
 */
int
conveyLoop(conveyScope *scope, int unwind)
{
	struct convey_ctx *t;
	int                i;

	if ((t = scope->cs_data) == NULL) {
		return (1);
	}
	if (unwind) {
		if ((t->ctx_parent != t) && (t->ctx_parent != NULL)) {
			longjmp(*t->ctx_parent->ctx_jmp, 1);
		}
		if (t->ctx_done) {
			convey_print_result(t);
			return (1);
		}
	}
	if (!t->ctx_started) {
		t->ctx_started = 1;

		if (convey_verbose) {
			if (t->ctx_root == t) {
				(void) printf("=== RUN: %s\n", t->ctx_name);
			} else {
				(void) puts("");
				for (i = 0; i < t->ctx_level; i++) {
					(void) fputs("  ", stdout);
				}
				(void) printf("%s ", t->ctx_name);
				(void) fflush(stdout);
			}
		}

		convey_init_timer(&t->ctx_timer);
		convey_start_timer(&t->ctx_timer);
	}
	/* Reset TC for the following code. */
	convey_tls_set(t);
	return (0);
}

void
conveyFinish(conveyScope *scope, int *rvp)
{
	struct convey_ctx *t;

	if ((t = scope->cs_data) == NULL) {
		/* allocation failure */
		*rvp = CONVEY_EXIT_NOMEM;
		return;
	}
	t->ctx_done = 1;
	if (rvp != NULL) {
		/* exit code 1 is reserved for usage errors */
		if (t->ctx_fatal) {
			*rvp = CONVEY_EXIT_FATAL;
		} else if (t->ctx_fail) {
			*rvp = CONVEY_EXIT_FAIL;
		} else {
			*rvp = CONVEY_EXIT_OK;
		}
	}
	longjmp(*t->ctx_jmp, 1);
}

void
conveySkip(const char *file, int line, const char *fmt, ...)
{
	va_list            ap;
	struct convey_ctx *t    = convey_get_ctx();
	struct convey_log *dlog = t->ctx_dbglog;

	if (convey_verbose) {
		convey_emit_color(convey_yellow);
		(void) fputs(convey_sym_skip, stdout);
		convey_emit_color(convey_nocolor);
	}
	convey_logf(dlog, "* %s (%s:%d) (Skip): ", t->ctx_name, file, line);
	va_start(ap, fmt);
	convey_vlogf(dlog, fmt, ap, 1);
	va_end(ap);
	t->ctx_done = 1; /* This forces an end */
	convey_nskip++;
	longjmp(*t->ctx_jmp, 1);
}

void
conveyAssertFail(const char *cond, const char *file, int line)
{
	struct convey_ctx *t = convey_get_ctx();

	convey_nassert++;
	if (convey_verbose) {
		convey_emit_color(convey_yellow);
		(void) fputs(convey_sym_fail, stdout);
		convey_emit_color(convey_nocolor);
		(void) fflush(stdout);
	}
	if (t->ctx_root != t) {
		t->ctx_root->ctx_fail++;
	}
	convey_assert_color = convey_yellow;
	t->ctx_fail++;
	t->ctx_done = 1; /* This forces an end */
	convey_logf(t->ctx_faillog, "* Assertion Failed (%s)\n", t->ctx_name);
	convey_logf(t->ctx_faillog, "File: %s\n", file);
	convey_logf(t->ctx_faillog, "Line: %d\n", line);
	convey_logf(t->ctx_faillog, "Test: %s\n\n", cond);
	convey_logf(t->ctx_dbglog, "* %s (%s:%d) (FAILED): %s\n", t->ctx_name,
	    file, line, cond);
	longjmp(*t->ctx_jmp, 1);
}

void
conveyAssertPass(const char *cond, const char *file, int line)
{
	struct convey_ctx *t = convey_get_ctx();

	convey_nassert++;
	if (convey_verbose) {
		convey_emit_color(convey_green);
		(void) fputs(convey_sym_pass, stdout);
		convey_emit_color(convey_nocolor);
		(void) fflush(stdout);
	}
	convey_logf(t->ctx_dbglog, "* %s (%s:%d) (Passed): %s\n", t->ctx_name,
	    file, line, cond);
}

void
conveyAssertSkip(const char *cond, const char *file, int line)
{
	struct convey_ctx *t = convey_get_ctx();

	convey_nskip++;
	if (convey_verbose) {
		convey_emit_color(convey_yellow);
		(void) fputs(convey_sym_pass, stdout);
		convey_emit_color(convey_nocolor);
		(void) fflush(stdout);
	}
	convey_logf(t->ctx_dbglog, "* %s (%s:%d) (Skip): %s\n", t->ctx_name,
	    file, line, cond);
}

/*
 * Performance counters.  Really we just want to start and stop timers, to
 * measure elapsed time in usec.
 */
static void
convey_init_timer(struct convey_timer *pc)
{
	memset(pc, 0, sizeof(*pc));
}

static void
convey_start_timer(struct convey_timer *pc)
{
	if (pc->timer_running) {
		return;
	}
#if defined(_WIN32)
	LARGE_INTEGER pcnt, pfreq;
	QueryPerformanceCounter(&pcnt);
	QueryPerformanceFrequency(&pfreq);
	pc->timer_base = pcnt.QuadPart;
	pc->timer_rate = pfreq.QuadPart;
#elif defined(CLOCK_MONOTONIC) && !defined(CONVEY_USE_GETTIMEOFDAY)
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	pc->timer_base = ts.tv_sec;
	pc->timer_base *= 1000000000;
	pc->timer_base += ts.tv_nsec;
	pc->timer_rate = 1000000000;
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	pc->timer_base = tv.tv_sec;
	pc->timer_base *= 1000000;
	pc->timer_base += tv.tv_usec;
	pc->timer_rate = 1000000;
#endif
	pc->timer_running = 1;
}

static void
convey_stop_timer(struct convey_timer *pc)
{
	if (!pc->timer_running) {
		return;
	}
	do {
#if defined(_WIN32)
		LARGE_INTEGER pcnt;
		QueryPerformanceCounter(&pcnt);
		pc->timer_count += (pcnt.QuadPart - pc->timer_base);
#elif defined(CLOCK_MONOTONIC) && !defined(CONVEY_USE_GETTIMEOFDAY)
		uint64_t        ns;
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		ns = ts.tv_sec;
		ns *= 1000000000;
		ns += (uint64_t) ts.tv_nsec;
		pc->timer_count += (ns - pc->timer_base);
#else
		uint64_t       us;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		us = tv.tv_sec;
		us *= 1000000;
		us += tv.tv_usec;
		pc->timer_count += (us - pc->timer_base);
#endif
	} while (0);
}

static void
convey_read_timer(struct convey_timer *pc, int *secp, int *usecp)
{
	uint64_t delta, rate, sec, usec;

	delta = pc->timer_count;
	rate  = pc->timer_rate;

	sec = delta / rate;
	delta -= (sec * rate);

	/*
	 * done this way we avoid dividing rate by 1M -- and the above
	 * ensures we don't wrap.
	 */
	usec = (delta * 1000000) / rate;

	if (secp) {
		*secp = (int) sec;
	}
	if (usecp) {
		*usecp = (int) usec;
	}
}

/*
 * Thread-specific data.  Pthreads uses one way, Win32 another.  If you
 * lack threads, just #define CONVEY_NO_THREADS.  C11 thread support is
 * pending.
 */

#ifdef CONVEY_NO_THREADS
static void *convey_tls_key;

static int
convey_tls_init(void)
{
	return (0);
}

static int
convey_tls_set(void *v)
{
	convey_tls_key = v;
	return (0);
}

static void *
convey_tls_get(void)
{
	return (convey_tls_key);
}

#elif defined(_WIN32)

static DWORD convey_tls_key;

static int
convey_tls_init(void)
{
	if ((convey_tls_key = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
		return (-1);
	}
	return (0);
}

static int
convey_tls_set(void *v)
{
	if (!TlsSetValue(convey_tls_key, v)) {
		return (-1);
	}
	return (0);
}

static void *
convey_tls_get(void)
{
	return ((void *) TlsGetValue(convey_tls_key));
}

#else

static pthread_key_t convey_tls_key;

static int
convey_tls_init(void)
{
	if (pthread_key_create(&convey_tls_key, NULL) != 0) {
		return (-1);
	}
	return (0);
}

static int
convey_tls_set(void *v)
{
	if (pthread_setspecific(convey_tls_key, v) != 0) {
		return (-1);
	}
	return (0);
}

static void *
convey_tls_get(void)
{
	return (pthread_getspecific(convey_tls_key));
}

#endif

static struct convey_ctx *
convey_get_ctx(void)
{
	return (convey_tls_get());
}

/*
 * Log stuff.
 */
static void
convey_vlogf(struct convey_log *log, const char *fmt, va_list va, int addnl)
{
	/* Grow the log buffer if we need to */
	while ((log->log_size - log->log_length) < 256) {
		size_t newsz = log->log_size + 2000;
		char * ptr   = malloc(newsz);
		if (ptr == NULL) {
			return;
		}
		memcpy(ptr, log->log_buf, log->log_length);
		memset(ptr + log->log_length, 0, newsz - log->log_length);
		free(log->log_buf);
		log->log_buf  = ptr;
		log->log_size = newsz;
	}

	/* 2 allows space for NULL, and newline */
	(void) vsnprintf(log->log_buf + log->log_length,
	    log->log_size - (log->log_length + 2), fmt, va);
	log->log_length += strlen(log->log_buf + log->log_length);
	if (addnl && (log->log_buf[log->log_length - 1] != '\n')) {
		log->log_buf[log->log_length++] = '\n';
	}
}

static void
convey_logf(struct convey_log *log, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	convey_vlogf(log, fmt, va, 0);
	va_end(va);
}

static void
convey_log_emit(struct convey_log *log, const char *header, const char *color)
{
	char *s;
	char *last = log->log_buf;

	if (log->log_length == 0) {
		return;
	}

	(void) fputs("\n\n", stdout);
	convey_emit_color(color);
	(void) fputs(header, stdout);
	convey_emit_color(convey_nocolor);
	(void) fputs("\n\n", stdout);
	while ((s = convey_nextline(&last)) != NULL) {
		(void) fputs("  ", stdout);
		convey_emit_color(color);
		(void) fputs(s, stdout);
		convey_emit_color(convey_nocolor);
		(void) fputs("\n", stdout);
	}
}

static void
convey_log_free(struct convey_log *log)
{
	if (log != NULL) {
		if (log->log_size != 0) {
			free(log->log_buf);
		}
		free(log);
	}
}

static struct convey_log *
convey_log_alloc(void)
{
	return (calloc(1, sizeof(struct convey_log)));
}

/*
 * ConveyInit initializes some common global stuff.   Call it from main(),
 * if you don't use the framework provided main.
 */
int
ConveyInit(void)
{
	static int inited;

	if (!inited) {
		if (convey_tls_init() != 0) {
			return (-1);
		}
		convey_init_term();
		inited = 1;
	}
	return (0);
}

void
ConveySetVerbose(void)
{
	convey_verbose = 1;
}

void
conveyFail(const char *file, int line, const char *fmt, ...)
{
	struct convey_ctx *t    = convey_get_ctx();
	struct convey_log *flog = t->ctx_faillog;
	struct convey_log *dlog = t->ctx_dbglog;
	va_list            ap;

	convey_logf(dlog, "* %s (%s:%d) (Failed): ", t->ctx_name, file, line);
	va_start(ap, fmt);
	convey_vlogf(dlog, fmt, ap, 1);
	va_end(ap);

	convey_logf(flog, "* %s\n", t->ctx_root->ctx_name);
	convey_logf(flog, "File: %s\n", file);
	convey_logf(flog, "Line: %d\n", line);
	convey_logf(flog, "Reason: ");
	va_start(ap, fmt);
	convey_vlogf(flog, fmt, ap, 1);
	va_end(ap);

	if (t->ctx_root != t) {
		t->ctx_root->ctx_fail++;
	}
	convey_assert_color = convey_yellow;
	t->ctx_fail++;
	t->ctx_done = 1; /* This forces an end */
	longjmp(*t->ctx_jmp, 1);
}

void
conveyError(const char *file, int line, const char *fmt, ...)
{
	struct convey_ctx *t    = convey_get_ctx();
	struct convey_log *flog = t->ctx_errlog;
	struct convey_log *dlog = t->ctx_dbglog;
	va_list            ap;

	convey_logf(dlog, "* %s (%s:%d) (Error): ", t->ctx_name, file, line);
	va_start(ap, fmt);
	convey_vlogf(dlog, fmt, ap, 1);
	va_end(ap);

	convey_logf(flog, "* %s\n", t->ctx_root->ctx_name);
	convey_logf(flog, "File: %s\n", file);
	convey_logf(flog, "Line: %d\n", line);
	convey_logf(flog, "Reason: ");
	va_start(ap, fmt);
	convey_vlogf(flog, fmt, ap, 1);
	va_end(ap);

	if (t->ctx_root != t) {
		t->ctx_root->ctx_fail++;
	}
	convey_assert_color = convey_red;
	t->ctx_fail++;
	t->ctx_done = 1; /* This forces an end */
	longjmp(*t->ctx_jmp, 1);
}

void
conveyPrintf(const char *file, int line, const char *fmt, ...)
{
	va_list            ap;
	struct convey_ctx *t    = convey_get_ctx();
	struct convey_log *dlog = t->ctx_dbglog;

	convey_logf(dlog, "* %s (%s:%d) (Debug): ", t->ctx_name, file, line);
	va_start(ap, fmt);
	convey_vlogf(dlog, fmt, ap, 1);
	va_end(ap);
}

static void
convey_init_term(void)
{
	const char *term;

#ifndef _WIN32
	/* Windows console doesn't do Unicode (consistently). */

#if NNG_HAVE_LANGINFO
	const char *codeset;

	(void) setlocale(LC_ALL, "");
	codeset = nl_langinfo(CODESET);
	if ((codeset != NULL) && (strcmp(codeset, "UTF-8") == 0)) {
		convey_sym_pass = "✔";
		convey_sym_fail = "✘";
		convey_sym_skip = "⚠";
	}
#endif
	term = getenv("TERM");
	if (!isatty(fileno(stdin))) {
		term = NULL;
	}

#else
	CONSOLE_SCREEN_BUFFER_INFO info;

	convey_console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!GetConsoleScreenBufferInfo(convey_console, &info)) {
		convey_console = INVALID_HANDLE_VALUE;
	} else {
		convey_defattr = info.wAttributes;
		// Values probably don't matter, just need to be
		// different!
		convey_nocolor = "\033[0m";
		convey_green = "\033[32m";
		convey_yellow = "\033[33m";
		convey_red = "\033[31m";
	}
	term = getenv("TERM");
#endif

	if (term != NULL) {
		if ((strstr(term, "xterm") != NULL) ||
		    (strstr(term, "ansi") != NULL) ||
		    (strstr(term, "color") != NULL)) {
			convey_nocolor = "\033[0m";
			convey_green   = "\033[32m";
			convey_yellow  = "\033[33m";
			convey_red     = "\033[31m";
		}
	}
	convey_assert_color = convey_green;
}

/*
 * This function exists because strtok isn't safe, and strtok_r and
 * strsep are not universally available.  Its like strsep, but only does
 * newlines.  Could be implemented using strpbrk, but this is probably
 * faster since we are only looking for a single character.
 */
static char *
convey_nextline(char **next)
{
	char *line = *next;
	char *nl;
	char  c;

	if (line == NULL) {
		return (NULL);
	}
	for (nl = line; (c = (*nl)) != '\0'; nl++) {
		if (c == '\n') {
			*nl   = '\0';
			*next = nl + 1;
			return (line);
		}
	}

	/*
	 * If the last character in the file is a newline, treat it as
	 * the end.  (This will appear as a blank last line.)
	 */
	if (*line == '\0') {
		line = NULL;
	}
	*next = NULL;
	return (line);
}

static struct convey_env {
	struct convey_env *next;
	const char *       name;
	char *             value;
} * convey_environment;

static struct convey_env *
conveyFindEnv(const char *name)
{
	struct convey_env *ev;
	for (ev = convey_environment; ev != NULL; ev = ev->next) {
		if (strcmp(name, ev->name) == 0) {
			return (ev);
		}
	}
	return (NULL);
}

char *
conveyGetEnv(const char *name)
{
	struct convey_env *ev;

	if ((ev = conveyFindEnv(name)) != NULL) {
		return (ev->value);
	}
	return (getenv(name));
}

int
conveyPutEnv(const char *name, char *value)
{
	struct convey_env *env;

	if ((env = conveyFindEnv(name)) == NULL) {
		env = malloc(sizeof(*env));
		if (env == NULL) {
			return (-1);
		}
		env->next          = convey_environment;
		convey_environment = env;
	}
	env->name  = name;
	env->value = value;
	return (0);
}

int
conveyMain(int argc, char **argv)
{
	int                 i;
	const char *        status;
	const char *        prog = "<unknown>";
	struct convey_timer pc;
	int                 secs, usecs;
	struct convey_env * env;

	if ((argc > 0) && (argv[0] != NULL)) {
		prog = argv[0];
	}

	/*
	 * Poor man's getopt.  Very poor. We should add a way for tests
	 * to retrieve additional test specific options.
	 */
	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-') {
			break;
		}
		if (strcmp(argv[i], "-v") == 0) {
			ConveySetVerbose();
			continue;
		}
		if (strcmp(argv[i], "-d") == 0) {
			convey_debug++;
			continue;
		}
		if ((strcmp(argv[i], "-p") == 0) && ((i + 1) < argc)) {
			char *delim;
			if ((delim = strchr(argv[i + 1], '=')) != NULL) {
				*delim = '\0';
				conveyPutEnv(argv[i + 1], delim + 1);
			} else {
				conveyPutEnv(argv[i + 1], "");
			}
			i++;
			continue;
		}
	}
	if (ConveyInit() != 0) {
		(void) fputs("Cannot initialize test framework\n", stderr);
		exit(CONVEY_EXIT_NOMEM);
	}

	convey_init_timer(&pc);
	convey_start_timer(&pc);
	i = conveyMainImpl();
	convey_stop_timer(&pc);

	switch (i) {
	case CONVEY_EXIT_NOMEM:
		(void) fputs("Cannot initialize root test context\n", stderr);
		exit(CONVEY_EXIT_NOMEM);
	case CONVEY_EXIT_OK:
		if (convey_verbose) {
			(void) puts("PASS");
		}
		status = "ok";
		break;
	case CONVEY_EXIT_FAIL:
		status = "FAIL";
		if (convey_verbose) {
			(void) puts("FAIL");
		}
		break;
	default:
		status = "FATAL";
		if (convey_verbose) {
			(void) puts("FATAL");
		}
		break;
	}

	convey_read_timer(&pc, &secs, &usecs);
	(void) printf(
	    "%-8s%-52s%4d.%03ds\n", status, prog, secs, usecs / 1000);
	while ((env = convey_environment) != NULL) {
		convey_environment = env->next;
		free(env);
	}
	convey_read_timer(&pc, &secs, &usecs);
	exit(i);
}
