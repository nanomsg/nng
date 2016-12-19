/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

#else

#include <time.h>
#include <locale.h>
#include <langinfo.h>
#include <unistd.h>

#ifndef NO_THREADS
#include <pthread.h>
#endif

#endif

#include "test.h"

static const char *sym_pass = ".";
static const char *sym_skip = "?";
static const char *sym_fail = "X";
static const char *sym_fatal = "!";
static const char *color_none = "";
static const char *color_green = "";
static const char *color_red = "";
static const char *color_yellow = "";

static int debug = 0;
static int verbose = 0;
static int nasserts = 0;
static int nskips = 0;
static const char *color_asserts = "";

#define	TEXIT_OK	0
#define	TEXIT_USAGE	1
#define	TEXIT_FAIL	2
#define	TEXIT_FATAL	3
#define	TEXIT_NOMEM	4

typedef struct tperfcnt {
	uint64_t	pc_base;
	uint64_t	pc_count;
	uint64_t	pc_rate;
	int		pc_running;
} tperfcnt_t;

typedef struct tlog {
	char		*l_buf;
	size_t		l_size;
	size_t		l_length;
} tlog_t;

typedef struct tctx {
	char		t_name[256];
	struct tctx	*t_parent;
	struct tctx	*t_root;	/* the root node on the list */
	struct tctx	*t_next;	/* root list only, for cleanup */
	int		t_level;
	int		t_done;
	int		t_started;
	jmp_buf		*t_jmp;
	int		t_fatal;
	int		t_fail;
	int		t_skip;
	int		t_printed;
	tperfcnt_t	t_perfcnt;
	tlog_t		*t_fatallog;
	tlog_t		*t_faillog;
	tlog_t		*t_debuglog;
} tctx_t;

#define		PARENT(t)	((t_ctx_t *)(t->t_parent->t_data))

/*
 * Symbol naming:
 *
 * functions exposed to users (public) are named test_xxx
 * functions exposed in the ABI, but not part of the public API, are test_i_xxx
 * functions local (static) to this file -- no prefix
 */

static void print_result(tctx_t *);
static void init_perfcnt(tperfcnt_t *);
static void start_perfcnt(tperfcnt_t *);
static void stop_perfcnt(tperfcnt_t *);
static void read_perfcnt(tperfcnt_t *, int *, int *);
static void init_terminal(void);
static int init_specific(void);
static void *get_specific(void);
static int set_specific(void *);
static tctx_t *get_ctx(void);
static void log_vprintf(tlog_t *, const char *, va_list);
static void log_printf(tlog_t *, const char *, ...);
static void log_dump(tlog_t *, const char *, const char *);
static void log_free(tlog_t *);
static tlog_t *log_alloc(void);

/*
 * print_result prints the test results.  It prints more verbose information
 * in verbose mode.  Note that its possible for assertion checks done at
 * a given block to be recorded in a deeper block, since we can't easily
 * go back up to the old line and print it.
 *
 * We also leverage this point to detect completion of a root context, and
 * deallocate the child contexts.  The root context should never be reentered
 * here.
 */
static void
print_result(tctx_t *t)
{
	int secs, usecs;

	if (t->t_root == t) {
		stop_perfcnt(&t->t_perfcnt);	/* This is idempotent */

		read_perfcnt(&t->t_perfcnt, &secs, &usecs);

		log_dump(t->t_fatallog, "Errors:", color_red);
		log_dump(t->t_faillog, "Failures:", color_yellow);
		if (debug) {
			log_dump(t->t_debuglog, "Log:", color_none);
		}
		if (verbose) {
			(void) printf("\n\n%s%d assertions thus far%s",
				color_asserts, nasserts, color_none);
			if (nskips) {
				(void) printf(" %s%s%s",
					color_yellow,
					"(one or more sections skipped)",
					color_none);
			}
			(void) printf("\n\n--- %s: %s (%d.%02d)\n",
				t->t_fatal ? "FATAL" :
				t->t_fail ? "FAIL" :
				"PASS", t->t_name, secs, usecs / 10000);
		}

		/* Remove the context, because we cannot reenter here */
		set_specific(NULL);

		while (t != NULL) {
			tctx_t *freeit = t;
			if (t->t_root == t) {
				log_free(t->t_debuglog);
				log_free(t->t_faillog);
				log_free(t->t_fatallog);
			}
			t = t->t_next;
			memset(freeit, 0, sizeof (*freeit));
			free(freeit);
		}
	}
}

/*
 * test_i_start is called when the context starts, before any call to
 * setjmp is made.  If the context isn't initialized already, that is
 * done.  Note that this code gets called multiple times when the
 * context is reentered, which is why the context used must be statically
 * allocated -- a record that it has already done is checked.  If
 * the return value is zero, then this block has already been executed,
 * and it should be skipped.  Otherwise, it needs to be done.
 */
int
test_i_start(test_ctx_t *ctx, const char *name)
{
	tctx_t *t, *parent;

	parent = get_ctx();

	if ((t = ctx->T_data) != NULL) {
		if (t->t_done) {
			print_result(t);
			return (1);	/* all done, skip */
		}
		return (0);	/* continue onward */
	}
	ctx->T_data = (t = calloc(1, sizeof (tctx_t)));
	if (t == NULL) {
		goto allocfail;
	}
	t->t_jmp = &ctx->T_jmp;

	(void) snprintf(t->t_name, sizeof(t->t_name)-1, "%s", name);
	if (parent != NULL) {
		t->t_parent = parent;
		t->t_root = t->t_parent->t_root;
		t->t_level = t->t_parent->t_level + 1;
		/* unified logging against the root context */
		t->t_debuglog = t->t_root->t_debuglog;
		t->t_faillog = t->t_root->t_faillog;
		t->t_fatallog = t->t_root->t_fatallog;
		t->t_next = t->t_root->t_next;
		t->t_root->t_next = t;
	} else {
		t->t_parent = t;
		t->t_root = t;
		if (((t->t_fatallog = log_alloc()) == NULL) ||
		    ((t->t_faillog = log_alloc()) == NULL) ||
		    ((t->t_debuglog = log_alloc()) == NULL)) {
			goto allocfail;
		}
	}
	return (0);
allocfail:
	if (t != NULL) {
		log_free(t->t_fatallog);
		log_free(t->t_debuglog);
		log_free(t->t_faillog);
		free(t);
		ctx->T_data = NULL;
		return (1);
	}
	if (parent != NULL) {
		test_fatal("Unable to allocate context");
	}
	return (1);
}

/*
 * This is called right after setjmp.  The jumped being true indicates
 * that setjmp returned true, and we are popping the stack.  In that case
 * we perform a local cleanup and keep popping back up the stack.  We
 * always come through this, even if the test finishes successfully, so
 * that we can do this stack unwind.  If we are unwinding, and we are
 * at the root context, then we pritn the results and return non-zero
 * so that our caller knows to stop further processing.
 */
int
test_i_loop(test_ctx_t *ctx, int unwind)
{
	tctx_t *t;
	int i;
	if ((t = ctx->T_data) == NULL) {
		return (1);
	}
	if (unwind) {
		if ((t->t_parent != t) && (t->t_parent != NULL)) {
			longjmp(*t->t_parent->t_jmp, 1);
		}
		if (t->t_done) {
			print_result(t);
			return (1);
		}
	}
	if (!t->t_started) {
		t->t_started = 1;

		if (verbose) {
			if (t->t_root == t) {
				(void) printf("=== RUN: %s\n", t->t_name);
			} else {
				(void) printf("\n");
				for (i = 0; i < t->t_level; i++) {
					(void) printf("  ");
				}
				(void) printf("%s ", t->t_name);
				(void) fflush(stdout);
			}
		}

		init_perfcnt(&t->t_perfcnt);
		start_perfcnt(&t->t_perfcnt);
	}
	/* Reset TC for the following code. */
	set_specific(t);
	return (0);
}

void
test_i_finish(test_ctx_t *ctx, int *rvp)
{
	tctx_t *t;
	if ((t = ctx->T_data) == NULL) {
		/* allocation failure */
		*rvp = 4;
		return;
	}
	t->t_done = 1;
	if (rvp != NULL) {
		/* exit code 1 is reserved for usage errors */
		if (t->t_fatal) {
			*rvp = 3;
		} else if (t->t_fail) {
			*rvp = 2;
		} else {
			*rvp = 0;
		}
	}
	longjmp(*t->t_jmp, 1);
}

void
test_i_skip(const char *file, int line, const char *reason)
{
	tctx_t *t = get_ctx();
	if (verbose) {
		(void) printf("%s%s%s", color_yellow, sym_skip, color_none);
	}
	log_printf(t->t_debuglog, "* Skipping rest of %s: %s: %d: %s",
		t->t_name, file, line, reason);
	t->t_done = 1;	/* This forces an end */
	nskips++;
	longjmp(*t->t_jmp, 1);
}

void
test_i_assert_fail(const char *cond, const char *file, int line)
{
	tctx_t *t = get_ctx();
	nasserts++;
	if (verbose) {
		(void) printf("%s%s%s", color_yellow, sym_fail, color_none);
	}
	if (t->t_root != t) {
		t->t_root->t_fail++;
	}
	color_asserts = color_yellow;
	t->t_fail++;
	t->t_done = 1;	/* This forces an end */
	log_printf(t->t_faillog, "* %s (Assertion Failed)\n", t->t_name);
	log_printf(t->t_faillog, "File: %s\n", file);
	log_printf(t->t_faillog, "Line: %d\n", line);
	log_printf(t->t_faillog, "Test: %s\n\n", cond);
	log_printf(t->t_debuglog, "* %s (%s:%d) (FAILED)\n",
		t->t_name, file, line);
	longjmp(*t->t_jmp, 1);
}

void
test_i_assert_pass(const char *cond, const char *file, int line)
{
	tctx_t *t = get_ctx();
	nasserts++;
	if (verbose) {
		(void) printf("%s%s%s", color_green, sym_pass, color_none);
	}
	log_printf(t->t_debuglog, "* %s (%s:%d) (Passed)\n",
		t->t_name, file, line);
}

void
test_i_assert_skip(const char *cond, const char *file, int line)
{
	tctx_t *t = get_ctx();
	nskips++;
	if (verbose) {
		(void) printf("%s%s%s", color_yellow, sym_pass, color_none);
	}
	log_printf(t->t_debuglog, "* %s (%s:%d) (SKIPPED)\n",
		t->t_name, file, line);
}

/*
 * Performance counters.  Really we just want to start and stop timers, to
 * measure elapsed time in usec.
 */

static void
init_perfcnt(tperfcnt_t *pc)
{
	memset(pc, 0, sizeof (*pc));
}

static void
start_perfcnt(tperfcnt_t *pc)
{
	if (pc->pc_running) {
		return;
	}
#if defined(_WIN32)
	LARGE_INTEGER pcnt, pfreq;
	QueryPerformanceCounter(&pcnt);
	QueryPerformanceFrequency(&pfreq);
	pc->pc_base = pcnt.QuadPart;
	pc->pc_rate = pfreq.QuadPart;
#elif defined(CLOCK_MONOTONIC)
	uint64_t usecs;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	pc->pc_base = ts.tv_sec * 1000000000;
	pc->pc_base += ts.tv_nsec;
	pc->pc_rate = 1000000000;
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	pc->pc_base = tv.tv_secs * 1000000;
	pc->pc_base += tv.tv_usec;
	pc->pc_rate = 1000000;
#endif
	pc->pc_running = 1;
}

static void
stop_perfcnt(tperfcnt_t *pc)
{
	if (!pc->pc_running) {
		return;
	}
	do {
#if defined(_WIN32)
		LARGE_INTEGER pcnt;
		QueryPerformanceCounter(&pcnt);
		pc->pc_count += (pcnt.QuadPart - pc->pc_base);
#elif defined(CLOCK_MONOTONIC)
		uint64_t ns;
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		ns = (ts.tv_sec * 1000000000);
		ns += ts.tv_nsec;
		pc->pc_count += (ns - pc->pc_base);
#else
		uint64_t us;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		us = (ts.tv_sec * 1000000);
		us += ts.tv_usec;
		pc->pc_count += (us - pc->pc_base);
#endif
	} while (0);
}

static void
read_perfcnt(tperfcnt_t *pc, int *secp, int *usecp)
{
	uint64_t delta, rate, sec, usec;

	delta = pc->pc_count;
	rate = pc->pc_rate;

	sec = delta / rate;
	delta -= (sec * rate);

	/*
	 * done this way we avoid dividing rate by 1M -- and the above
	 * ensures we don't wrap.
	 */
	usec = (delta * 1000000) / rate;

	if (secp) {
		*secp = (int)sec;
	}
	if (usecp) {
		*usecp = (int)usec;
	}
}

/*
 * Thread-specific data.  Pthreads uses one way, Win32 another.  If you
 * lack threads, just #define NO_THREADS.  C11 thread support is pending.
 */

#ifdef NO_THREADS
static void *specific_val;

static int
init_specific(void)
{
	return (0);
}

static int
set_specific(void *v)
{
	specific_val = v;
	return (0);
}

static void *
get_specific(void)
{
	return (specific_val);
}
#elif defined(_WIN32)

static DWORD keyctx;

static int
init_specific(void)
{
	if ((keyctx = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
		return (-1);
	}
	return (0):
}

static int
set_specific(void *v)
{
	if (!TlsSetValue(keyctx, v)) {
		return (-1);
	}
	return (0);
}

static void *
get_specific(void)
{
	return ((void *)TlsGetValue(keyctx));
}

#else

pthread_key_t keyctx;

static int
init_specific(void)
{
	if (pthread_key_create(&keyctx, NULL) != 0) {
		return (-1);
	}
	return (0);
}

static int
set_specific(void *v)
{
	if (pthread_setspecific(keyctx, v) != 0) {
		return (-1);
	}
	return (0);
}

static void *
get_specific(void)
{
	return (pthread_getspecific(keyctx));
}
#endif

static tctx_t *
get_ctx(void)
{
	return (get_specific());
}

/*
 * Log stuff.
 */
#define	LOG_MAXL	200
#define	LOG_CHUNK	2000
static void
log_vprintf(tlog_t *log, const char *fmt, va_list va)
{
	while ((log->l_size - log->l_length) < LOG_MAXL) {
		int newsz = log->l_size + LOG_CHUNK;
		char *ptr = malloc(newsz);
		if (ptr == NULL) {
			return;
		}
		memcpy(ptr, log->l_buf, log->l_length);
		memset(ptr + log->l_length, 0, newsz - log->l_length);
		free(log->l_buf);
		log->l_buf = ptr;
		log->l_size = newsz;
	}
	(void) vsnprintf(log->l_buf + log->l_length,
		log->l_size - (log->l_length + 3), fmt, va);
	log->l_length += strlen(log->l_buf + log->l_length);
	if (log->l_buf[log->l_length-1] != '\n') {
		log->l_buf[log->l_length++] = '\n';
	}
}

static void
log_printf(tlog_t *log, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	log_vprintf(log, fmt, va);
	va_end(va);
}

static void
log_dump(tlog_t *log, const char *header, const char *color)
{
	char *s;
#ifdef NO_THREADS
#define STRTOK(base, sep)		strtok(base, sep)
#else
	char *last = NULL;
#define	STRTOK(base, sep)		strtok_r(base, sep, &last)
#endif
	if (log->l_length == 0) {
		return;
	}

	(void) printf("\n\n%s%s%s\n\n", color, header, color_none);
	for (s = STRTOK(log->l_buf, "\n"); s != NULL; s = STRTOK(NULL, "\n")) {
		(void) printf("  %s%s%s\n", color, s, color_none);
	}
}

static void
log_free(tlog_t *log)
{
	if (log != NULL) {
		if (log->l_size != 0) {
			free(log->l_buf);
		}
		free(log);
	}
}

static tlog_t *
log_alloc(void)
{
	return (calloc(1, sizeof (tlog_t)));
}

/*
 * test_init initializes some common global stuff.   Call it from main(),
 * if you don't use the framework provided main.
 */
int
test_init(void)
{
	static int inited;

	if (!inited) {
		if (init_specific() != 0) {
			return (-1);
		}
		init_terminal();
		inited = 1;
	}
	return (0);
}

void
test_set_verbose(void)
{
	verbose = 1;
}

void
test_debugf(const char *fmt, ...)
{
	va_list va;
	tctx_t *ctx = get_ctx()->t_root;

	va_start(va, fmt);
	log_vprintf(ctx->t_debuglog, fmt, va);
	va_end(va);
}

void
test_i_fail(const char *file, int line, const char *reason)
{
	tctx_t *t = get_ctx()->t_root;
	tlog_t *faillog = t->t_faillog;
	tlog_t *debuglog = t->t_debuglog;

	log_printf(debuglog, "* %s (%s:%d) (Failed): %s\n",
		t->t_name, file, line, reason);
	log_printf(faillog, "* %s\n", t->t_name);
	log_printf(faillog, "File: %s\n", file);
	log_printf(faillog, "Line: %d\n", line);
	log_printf(faillog, "Reason: %s\n", reason);

	if (t->t_root != t) {
		t->t_root->t_fail++;
	}
	color_asserts = color_yellow;
	t->t_fail++;
	t->t_done = 1;	/* This forces an end */
	longjmp(*t->t_jmp, 1);
}

void
test_i_fatal(const char *file, int line, const char *reason)
{
	tctx_t *t = get_ctx()->t_root;
	tlog_t *faillog = t->t_fatallog;
	tlog_t *debuglog = t->t_debuglog;

	log_printf(debuglog, "* %s (%s:%d) (Error): %s\n",
		t->t_name, file, line, reason);
	log_printf(faillog, "* %s\n", t->t_name);
	log_printf(faillog, "File: %s\n", file);
	log_printf(faillog, "Line: %d\n", line);
	log_printf(faillog, "Reason: %s\n", reason);

	if (t->t_root != t) {
		t->t_root->t_fail++;
	}
	color_asserts = color_red;
	t->t_fail++;
	t->t_done = 1;	/* This forces an end */
	longjmp(*t->t_jmp, 1);
}

extern int test_main_impl(void);

static void
init_terminal(void)
{
#ifndef _WIN32
	/* Windows console doesn't do Unicode (consistently). */
	const char *codeset;
	const char *term;

	(void) setlocale(LC_ALL, "");
	codeset = nl_langinfo(CODESET);
	if ((codeset != NULL) && (strcmp(codeset, "UTF-8") == 0)) {
		sym_pass = "✔";
		sym_fail = "✘";
		sym_fatal = "🔥";
		sym_skip = "⚠";
	}

	term = getenv("TERM");
	if (isatty(1) && (term != NULL)) {
		if ((strstr(term, "xterm") != NULL) ||
		    (strstr(term, "ansi") != NULL) ||
		    (strstr(term, "color") != NULL)) {
		    	color_none = "\e[0m";
		    	color_green = "\e[32m";
		    	color_yellow = "\e[33m";
		    	color_red = "\e[31m";
		    	color_asserts = color_green;
		}
	}
#endif
}

int
test_i_main(int argc, char **argv)
{
	int i;
	const char *status;
	const char *prog;
	tperfcnt_t pc;
	int secs, usecs;

	if ((argc > 0) && (argv[0] != NULL)) {
		prog = argv[0];
	} else {
		prog = "<unknown>";
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
			verbose = 1;
		}
		if (strcmp(argv[i], "-d") == 0) {
			debug++;
		}
	}
	if (test_init() != 0) {
		(void) fprintf(stderr, "Cannot initialize test framework\n");
		exit(TEXIT_NOMEM);
	}

	init_perfcnt(&pc);
	start_perfcnt(&pc);
	i = test_main_impl();
	stop_perfcnt(&pc);

	switch (i) {
	case TEXIT_NOMEM:
		(void) fprintf(stderr, "Cannot initialize root test context\n");
		exit(TEXIT_NOMEM);
	case TEXIT_OK:
		if (verbose) {
			(void) printf("PASS\n");
		}
		status = "ok";
		break;
	case TEXIT_FAIL:
		status = "FAIL";
		if (verbose) {
			(void) printf("FAIL\n");
		}
		break;
	default:
		status = "FATAL";
		if (verbose) {
			(void) printf("FATAL\n");
		}
		break;
	}

	read_perfcnt(&pc, &secs, &usecs);
	(void) printf("%-8s%-52s%4d.%03ds\n", status, prog, secs, usecs / 1000);
	exit(i);
}