
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
#include <sys/time.h>

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

/*
 * This structure has to be exposed in order to expose the buffer used for
 * setjmp.  It's members should never be accessed directly.  These should be
 * allocated statically in the routine(s) that need custom contexts.  The
 * framework creates a context automatically for each convey scope.
 */
typedef struct test_ctx {
	jmp_buf T_jmp;
	void 	*T_data;
} test_ctx_t;

extern test_ctx_t *T_C;

/* These functions are not for use by tests -- they are used internally. */
extern int test_ctx_init(test_ctx_t *, test_ctx_t *, const char *);
extern int test_ctx_loop(test_ctx_t *, int);
extern void test_ctx_fini(test_ctx_t *, int *);
extern void test_assert_pass(test_ctx_t *, const char *, const char *, int);
extern void test_assert_skip(test_ctx_t *, const char *, const char *, int);
extern void test_assert_fail(test_ctx_t *, const char *, const char *, int);
extern void test_assert_fatal(test_ctx_t *, const char *, const char *, int);


/*
 * test_ctx_do is a helper function not to be called directly by user
 * code.  It has to be here exposed, in order for setjmp() to work.  Do
 * not call it directly, instead use one of the other macros.
 */
#define test_ctx_do(T_xparent, T_xname, T_xcode, T_rvp)			\
do {									\
	static test_ctx_t T_ctx;					\
	int T_jumped;							\
	if (test_ctx_init(&T_ctx, T_xparent, T_xname) != 0) {		\
		break;							\
	}								\
	T_jumped = setjmp(T_ctx.T_jmp);					\
	if (test_ctx_loop(&T_ctx, T_jumped) != 0) {			\
		break;							\
	}								\
	do {								\
		T_xcode							\
	} while (0);							\
	test_ctx_fini(&T_ctx, T_rvp);					\
} while (0)

/*
 * test_ctx_convey creates a "convey" using a custom parent context.
 * The idea is that this new context creates a new "root" context,
 * which can be useful for running tests in separate threads, or for
 * passing context around explicitly.  It should rarely be needed.
 */
#define test_ctx_convey(T_xparent, T_xname, T_xcode)			\
	test_ctx_do(T_xparent, T_xname, T_xcode, NULL)

/*
 * test_main is used to wrap the top-level of your test suite, and is
 * used in lieu of a normal main() function.
 */
#define test_main(name, code)						\
int test_main_impl(void) {						\
	static test_ctx_t ctx;						\
	int rv;								\
	test_ctx_do(NULL, name, code, &rv);				\
	return (rv);							\
}

/*
 * test_ctx_assert and test_ctx_so allow you to run assertions against
 * an explicit context.  You shouldn't need these.
 */
#define	test_ctx_assert(T_xctx, T_cond)					\
	if (!(T_cond)) {						\
		test_assert_fatal(T_xctx, #T_cond, __FILE__, __LINE__);	\
	} else {							\
		test_assert_pass(T_xctx, #T_cond, __FILE__, __LINE__);	\
	}

#define test_ctx_so(T_xctx, T_cond)					\
	if (!(T_cond)) {						\
		test_assert_fail(T_xctx, #T_cond, __FILE__, __LINE__);	\
	} else {							\
		test_assert_pass(T_xctx, #T_cond, __FILE__, __LINE__);	\
	}

/*
 * test_ctx_skip can be used to skip further processing in the context.
 */
extern void test_ctx_skip(test_ctx_t *);

/*
 * These are convenience versions that use the "global" context.
 * Note that normally convey() will create its own contexts.  These
 * are the macros you should use.
 */

/*
 * test_convey(name, <code>) starts a convey context, with <code> as
 * the body.  The <code> is its scope, and may be called repeatedly
 * within the body of a loop.
 */
#define	test_convey(T_xn, T_xc)	test_ctx_convey(T_C, T_xn, T_xc)

/*
 * test_assert is just like assert(3), but applies to the context.
 * Failures in these are treated as "fatal" failures; and get higher
 * alerting than other other kinds of failures.  The entire test run
 * all the way to the root context is aborted.  (Other root contexts
 * can run, however.)
 */
#define	test_assert(T_cond)	test_ctx_assert(T_C, T_cond)

/*
 * test_so() is like test_assert, but failures here only abort the current
 * test.
 */
#define test_so(T_cond)		test_ctx_so(T_C, T_cond)

/*
 * test_skip() just stops processing of the rest of the current context,
 * and records that processing was skipped.
 */
#define	test_skip()		test_ctx_skip(T_C)

/*
 * test_skip_assert() is used to skip processing of a single assertion.
 * Further processing in the same context continues.
 */
#define	test_skip_assert(T_cnd)	test_assert_skip(T_C, T_cnd)

/*
 * test_skip_convey() is used to skip a convey context.  This is intended
 * to permit changing "test_convey", to "test_skip_convey".  This is logged,
 * and the current convey context continues processing.
 */
#define	test_skip_convey(X_n, X_c)	/* TBD */


#endif	/* TEST_TEST_H */
