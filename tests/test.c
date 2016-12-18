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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>
#include <locale.h>
#include <langinfo.h>
#include <unistd.h>
#include <time.h>

#include "test.h"

test_ctx_t *T_C = NULL;

static const char *sym_pass = ".";
static const char *sym_skip = "?";
static const char *sym_fail = "X";
static const char *sym_fatal = "!";
static const char *color_none = "";
static const char *color_green = "";
static const char *color_red = "";
static const char *color_yellow = "";

static int verbose = 0;
static int nasserts = 0;
static int nskips = 0;
static const char *color_asserts = "";

typedef struct tperfcnt {
	uint64_t	pc_count;
	uint64_t	pc_rate;
} tperfcnt_t;

typedef struct tlog {
	const char	*l_buf;
	size_t		l_size;
	size_t		l_length;
} tlog_t;

typedef struct tctx {
	char		t_name[256];
	struct tctx	*t_parent;
	struct tctx	*t_root;
	int		t_level;
	int		t_done;
	int		t_started;
	jmp_buf		*t_jmp;

	void		(*t_cleanup)(void *);
	void		*t_cleanup_arg;

	int		t_nloops;

	int		t_fatal;
	int		t_fail;
	int		t_skip;
	int		t_printed;
	tperfcnt_t	t_starttime;
	tperfcnt_t	t_endtime;
	tlog_t		t_fatallog;
	tlog_t		t_faillog;
	tlog_t		t_debuglog;
} tctx_t;

#define		PARENT(t)	((t_ctx_t *)(t->t_parent->t_data))

static void test_print_result(tctx_t *);
static void test_getperfcnt(tperfcnt_t *);
static uint64_t test_perfdelta(tperfcnt_t *, tperfcnt_t *, int *, int *);

void 
test_print_result(tctx_t *t)
{
	int secs, usecs;

	if ((t->t_root == t) && !t->t_printed) {

		t->t_printed = 1;

		test_getperfcnt(&t->t_endtime);
		test_perfdelta(&t->t_starttime, &t->t_endtime, &secs, &usecs);

		if (!verbose) {
			(void) printf("%-8s%-52s%4d.%03ds\n",
				t->t_fatal ? "fatal" :
				t->t_fail ? "fail" : "ok",
				t->t_name, secs, usecs / 1000);
		} else {
			printf("\n\n%s%d assertions thus far%s",
				color_asserts, nasserts, color_none);
			if (nskips) {
				printf(" %s(one or more sections skipped)%s",
					color_yellow, color_none);
			}
			printf("\n\n--- %s: %s (%d.%02d)\n",
				t->t_fatal ? "FATAL" :
				t->t_fail ? "FAIL" :
				"PASS", t->t_name, secs, usecs / 10000);
		}

		/* XXX: EMIT LOGS */
	}
}

int
test_ctx_init(test_ctx_t *ctx, test_ctx_t *parent, const char *name)
{
	tctx_t *t;

	if ((t = ctx->T_data) != NULL) {
		if (t->t_done) {
			test_print_result(t);
			return (1);	/* all done, skip */
		}
		return (0);	/* continue onward */
	}
	ctx->T_data = (t = calloc(1, sizeof (tctx_t)));
	if (t == NULL) {
		/* PANIC */
		return (1);
	}
	t->t_jmp = &ctx->T_jmp;

	(void) snprintf(t->t_name, sizeof(t->t_name)-1, "%s", name);
	if (parent != NULL) {
		t->t_parent = parent->T_data;
		t->t_root = t->t_parent->t_root;
		t->t_level = t->t_parent->t_level + 1;
	} else {
		t->t_parent = t;
		t->t_root = t;
	}
	return (0);
}

/*
 * This is called right after setjmp.  The jumped being true indicates
 * that setjmp returned true, and we are popping the stack.
 */
int
test_ctx_loop(test_ctx_t *ctx, int jumped)
{
	tctx_t *t;
	int i;
	if ((t = ctx->T_data) == NULL) {
		return (1);
	}
	if (jumped != 0) {
		if (t->t_cleanup != NULL) {
			t->t_cleanup(t->t_cleanup_arg);
		}
		if ((t->t_parent != t) && (t->t_parent != NULL)) {
			longjmp(*t->t_parent->t_jmp, 1);
		}
		if (t->t_done) {
			test_print_result(t);
			return (1);
		}
	}

	if (!t->t_started) {
		t->t_started = 1;

		if (verbose) {
			if (t->t_root == t) {
				printf("\n=== RUN: %s\n", t->t_name);
			} else {
				printf("\n");
				for (i = 0; i < t->t_level; i++) {
					printf("  ");
				}
				printf("%s ", t->t_name);
				fflush(stdout);
			}
		}

		test_getperfcnt(&t->t_starttime);
	}
	/* Reset TC for the following code. */
	T_C = ctx;
	return (0);
}

void
test_ctx_fini(test_ctx_t *ctx, int *rvp)
{
	tctx_t *t;
	if ((t = ctx->T_data) == NULL) {
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
test_ctx_skip(test_ctx_t *ctx)
{
	tctx_t *t = ctx->T_data;
	if (verbose) {
		(void) printf("%s%s%s", color_none, sym_skip, color_none);
	}
	t->t_done = 1;	/* This forces an end */
	nskips++;
	longjmp(*t->t_jmp, 1);
}

void
test_assert_fail(test_ctx_t *ctx, const char *cond, const char *file, int line)
{
	tctx_t *t;
	if ((t = ctx->T_data) == NULL) {
		/* PANIC? */
		/* XXX: */
	}
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
	longjmp(*t->t_jmp, 1);
}

void
test_assert_pass(test_ctx_t *ctx, const char *cond, const char *file, int line)
{
	tctx_t *t;
	if ((t = ctx->T_data) == NULL) {
		/* PANIC? */
	}
	nasserts++;
	if (verbose) {
		(void) printf("%s%s%s", color_green, sym_pass, color_none);
	}
}

void
test_assert_skip(test_ctx_t *ctx, const char *cond, const char *file, int line)
{
	tctx_t *t;
	if ((t = ctx->T_data) == NULL) {
		/* PANIC? */
	}
	nskips++;
	if (verbose) {
		(void) printf("%s%s%s", color_none, sym_pass, color_none);
	}
}

void
test_assert_fatal(test_ctx_t *ctx, const char *cond, const char *file, int line)
{
	tctx_t *t;
	if ((t = ctx->T_data) == NULL) {
		/* PANIC? */
		/* XXX: */
	}
	nasserts++;
	if (verbose) {
		(void) printf("%s%s%s", color_red, sym_fail, color_none);
	}
	if (t->t_root != t) {
		t->t_root->t_fatal++;
	}
	color_asserts = color_red;
	t->t_fail++;
	t->t_done = 1;	/* This forces an end */
	longjmp(*t->t_jmp, 1);
}

static void
test_getperfcnt(tperfcnt_t *pc)
{
#if defined(_WIN32)
	LARGE_INTEGER pcnt, pfreq;
	QueryPerformanceCounter(&pcnt);
	QueryPerformanceFrequency(&pfreq);
	pc->pc_count = pcnt.QuadPart;
	pc->pc_rate = pfreq.QuadPart;
#elif defined(CLOCK_MONOTONIC)
	uint64_t usecs;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	pc->pc_count = ts.tv_sec * 1000000000;
	pc->pc_count += ts.tv_nsec;
	pc->pc_rate = 1000000000;
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	pc->pc_count = tv.tv_secs * 1000000;
	pc->pc_count += tv.tv_usec;
	pc->pc_rate = 1000000;
#endif
}

/*
 * Calculates the seconds and usecs between two values.  Returns the
 * entire usecs as a 64-bit integer.
 */
uint64_t
test_perfdelta(tperfcnt_t *start, tperfcnt_t *end, int *secp, int *usecp)
{
	uint64_t delta, rate, sec, usec;

	delta = end->pc_count - start->pc_count;
	rate = start->pc_rate;

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
	return ((sec * 1000000) + usec);
}

void
test_ctx_log(test_ctx_t *ctx, const char *fmt, ...)
{
}

void
test_ctx_vlog(test_ctx_t *ctx, const char *fmt, va_list va)
{
}

void
test_ctx_fatal(test_ctx_t *ctx, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	printf("FATALITY: ");
	vprintf(fmt, va);
	printf("\n");
}

#if 0
void
test_ctx_emit_pass(test_ctx_t *ctx)
{
	nasserts++;
	if (verbose) {
		(void) printf("%s%s%s", color_green, sym_pass, color_none);
	}
}

void
test_ctx_emit_fail(test_ctx_t *ctx)
{
	nasserts++;
	if (verbose) {
		(void) printf("%s%s%s", color_yellow, sym_fail, color_none);
	}
	while (!ctx->T_root) {
		ctx = ctx->T_parent;
	}
	color_asserts = color_yellow;
	ctx->T_fail++;
}

void
test_ctx_emit_fatal(test_ctx_t *ctx)
{
	if (verbose) {
		(void) printf("%s%s%s", color_red, sym_fatal, color_none);
	}
	nasserts++;
	while (!ctx->T_root) {
		ctx = ctx->T_parent;
	}
	ctx->T_fatal++;
	color_asserts = color_red;
}

void
test_ctx_emit_skipped(test_ctx_t *ctx)
{
	if (verbose) {
		(void) printf("%s%s%s", color_none, sym_skip, color_none);
	}
	nskips++;
}
#endif

extern int test_main_impl(void);

static void
pretty(void)
{
#ifndef _WIN32
	/* Windows console doesn't do Unicode (consistently). */
	const char *codeset;
	const char *term;

	(void) setlocale(LC_ALL, "");
	codeset = nl_langinfo(CODESET);
	if ((codeset == NULL) || (strcmp(codeset, "UTF-8") != 0)) {
		return;
	}
	sym_pass = "✔";
	sym_fail = "✘";
	sym_fatal = "🔥";
	sym_skip = "⚠";

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
main(int argc, char **argv)
{
	int i;

	/* Poor man's getopt.  Very poor. */
	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-') {
			break;
		}
		if (strcmp(argv[i], "-v") == 0) {
			verbose = 1;
		}
	}
	pretty();
	test_main_impl();
}