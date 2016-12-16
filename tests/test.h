
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

#ifndef TESTS_TEST_H

#define TESTS_TEST_H

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>

/*
 * This test framework allows one to write tests as a form of assertion,
 * giving simpler and more readable test logic.
 *
 * The test framework provides a main() function.
 *
 * To use this call the test_main() macro, and embed test_convey() references.
 * These can be nested, and after each convey the entire stack is popped so
 * that execution can continue from the beginning, giving each test section
 * the same environment.
 *
 * There are assertion macros too, which don't roll back the stack, but which
 * do update the test state.
 *
 * Here's a sample file:
 *
 * test_main("Integer Tests", {
 *	int x = 1; int y = 2;
 *	test_convey("Addition works", func() {
 *		test_so(y == 2);
 *		test_so(y + x == 3);
 *		test_so(x + y == 3);
 *		test_convey("Even big numbers", func() {
 *			y = 100;
 *			test_so(x + y == 101);
 *		});
 *		test_convey("Notice y is still 2 in this context", func() {
 *			test_so(y == 2);
 *		});
 * 	});
 * })
 * 
 * There are other macros, but this is a work in progress.  The inspiration
 * for this is from GoConvey -- github.com/smartystreets/goconvey - but this
 * is a version for C programs.
 */

typedef struct test_ctx {
	const char *T_name;
	jmp_buf T_jmp;
	void (*T_cleanup_fn)(void *);
	void *T_cleanup_arg;
	int T_fail;
	int T_fatal;
	int T_skip;
	int T_asserts;
	int T_good;
	int T_bad;
	int T_done;
	int T_root;
	int T_level;
	int T_printed;
	struct test_ctx *T_parent;
} test_ctx_t;

extern test_ctx_t *T_C;

#define test_ctx_do(T_xparent, T_xname, T_xcode)			\
do {									\
	static test_ctx_t T_ctx;					\
	T_ctx.T_name = T_xname;						\
	T_ctx.T_parent = T_xparent;					\
	if (T_xparent != NULL) {					\
		T_ctx.T_level = T_xparent->T_level + 1;			\
		T_ctx.T_root = 0;					\
	} else {							\
		T_ctx.T_root = 1;					\
		T_ctx.T_level = 0;					\
	}								\
	if (T_ctx.T_done) {						\
		test_ctx_print_result(&T_ctx);				\
		break;							\
	}								\
	if (setjmp(T_ctx.T_jmp) != 0) {					\
		if (T_ctx.T_cleanup_fn != NULL) {			\
			T_ctx.T_cleanup_fn(T_ctx.T_cleanup_arg);	\
		}							\
		if (!T_ctx.T_root) {					\
			longjmp(T_ctx.T_parent->T_jmp, 1);		\
		}							\
		if (T_ctx.T_done) {					\
			test_ctx_print_result(&T_ctx);			\
			break;						\
		}							\
	}								\
	test_ctx_print_start(&T_ctx);					\
	do {								\
		T_C = &T_ctx;						\
		{ T_xcode }						\
		T_ctx.T_done = 1;					\
	} while (0);							\
	longjmp(T_ctx.T_jmp, 1);					\
} while (0);

#define test_main(name, code)						\
int test_main_impl(void) {						\
	static test_ctx_t ctx;						\
	test_ctx_t *T_null = NULL;					\
	ctx.T_root = 1;							\
	test_ctx_t *T_xctx = &ctx;					\
	test_ctx_do(T_null, name, code);				\
	return (ctx.T_fatal ? 2 : ctx.T_fail ? 1 : 0);			\
}

#define test_ctx_convey(T_xparent, T_xname, T_xcode)			\
{									\
	test_ctx_do( T_xparent, T_xname, T_xcode); 		\
}

#define	test_convey(T_xname, T_xcode)	test_ctx_convey(T_C, T_xname, T_xcode)


#define	test_ctx_assert(T_xctx, T_cond)					\
	if (!(T_cond)) {						\
		T_xctx->T_bad++;					\
		test_ctx_fatal(T_xctx, "%s: %d: Assertion failed: %s",	\
			__FILE__, __LINE__, #T_cond);			\
	} else {							\
		printf(".");						\
		T_xctx->T_good++;					\
	}

#define	test_assert(T_cond)	test_ctx_assert(T_C, T_cond)

#define test_ctx_so(T_xctx, T_cond)					\
	if (!(T_cond)) {						\
		printf("X");						\
		T_xctx->T_bad++;					\
	} else {							\
		printf(".");						\
		T_xctx->T_good++;					\
	}

#define test_so(T_cond)	test_ctx_so(T_C, T_cond)

#define	test_assert(T_cond)	test_ctx_assert(T_C, T_cond)

extern void test_ctx_print_start(test_ctx_t *);
extern void test_ctx_print_result(test_ctx_t *);
extern void test_ctx_fatal(test_ctx_t *ctx, const char *fmt, ...);
extern int test_main_impl(void);

#endif	/* TEST_TEST_H */
