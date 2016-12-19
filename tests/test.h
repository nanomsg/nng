
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

/* These functions are not for use by tests -- they are used internally. */
extern int test_i_start(test_ctx_t *, const char *);
extern int test_i_loop(test_ctx_t *, int);
extern void test_i_finish(test_ctx_t *, int *);
extern int test_i_main(int, char **);

extern void test_i_assert_pass(const char *, const char *, int);
extern void test_i_assert_skip(const char *, const char *, int);
extern void test_i_assert_fail(const char *, const char *, int);
extern void test_i_skip(const char *, int, const char *);
extern void test_i_fail(const char *, int, const char *);
extern void test_i_fatal(const char *, int, const char *);


/*
 * test_i_run is a helper function not to be called directly by user
 * code.  It has to be here exposed, in order for setjmp() to work.
 * and for the code block to be inlined.
 */
#define test_i_run(T_name, T_code, T_rvp)				\
	do {								\
		static test_ctx_t T_ctx;				\
		int T_unwind;						\
		int T_break = 0;					\
		if (test_i_start(&T_ctx, T_name) != 0) {		\
			break;						\
		}							\
		T_unwind = setjmp(T_ctx.T_jmp);				\
		if (test_i_loop(&T_ctx, T_unwind) != 0) {		\
			break;						\
		}							\
		do {							\
			T_code						\
		} while (0);						\
		if (T_break) {						\
			break;						\
		}							\
		test_i_finish(&T_ctx, T_rvp);				\
	} while (0)

/*
 * If you want multiple top-level tests in your test suite, the test
 * code should create a test_main_group(), with multiple calls to
 * test_group() in the intervening section.  This will cause a new main
 * to be emitted that runs all the main groups.
 */
#define	test_main_group(T_code)						\
	static int test_main_rv;					\
	int test_main_impl(void) {					\
		do {							\
			T_code						\
		} while (0);						\
		return (test_main_rv);					\
	}								\
	int main(int argc, char **argv) {				\
		return (test_i_main(argc, argv));			\
	}

#define	test_group(T_name, T_code)					\
	do {								\
		int T_rv;						\
		test_i_run(T_name, T_code, &T_rv);			\
		if (T_rv > test_main_rv) {				\
			test_main_rv = T_rv;				\
		};							\
	} while (0)

/*
 * test_main is used to wrap the top-level of your test suite, and is
 * used in lieu of a normal main() function.  This is the usual case where
 * the executable only contains a single top level test group.
 */
#define test_main(T_name, T_code)					\
	test_main_group({						\
		test_group(T_name, T_code);				\
	})


/*
 * If you don't want to use the test framework's main routine, but
 * prefer (or need, because of threading for example) to have your
 * test code driven separately, you can use inject test_block() in
 * your function.  It works like test_main().  These must not be
 * nested within test_main, test_main_group, or test_block itself:
 * results are undefined if you try that.  The final T_rvp pointer may
 * be NULL, or is a pointer to an integer to receive the an integer
 * result from the test. (0 is success, 4 indicates a failure to allocate
 * memory in the test framework, and anything else indicates a
 * an error or failure in the code being tested.
 */
#define test_block(T_name, T_code, T_rvp)	\
	test_i_run(T_name, T_code, T_rvp)

/*
 * test_assert and test_so allow you to run assertions.
 */
#define	test_assert(T_cond)						\
	do {								\
		if (!(T_cond)) {					\
			test_i_assert_fail(#T_cond, __FILE__, __LINE__);\
		} else {						\
			test_i_assert_pass(#T_cond, __FILE__, __LINE__);\
		}							\
	} while (0)

#define test_so(T_cond)		test_assert(T_cond)

/*
 * test_convey(name, <code>) starts a convey context, with <code> as
 * the body.  The <code> is its scope, and may be called repeatedly
 * within the body of a loop.
 */
#define	test_convey(T_name, T_code)	test_i_run(T_name, T_code, NULL)


/*
 * test_skip() just stops processing of the rest of the current context,
 * and records that processing was skipped.
 */
#define	test_skip(reason)	test_i_skip(__FILE__, __LINE__, reason)
#define test_fail(reason)	test_i_fail(__FILE__, __LINE__, reason)
#define test_fatal(reason)	test_i_fatal(__FILE__, __LINE__, reason)

/*
 * test_skip_so() is used to skip processing of a single assertion.
 * Further processing in the same context continues.
 */
#define	test_skip_so(T_cnd)	\
	test_i_assert_skip(T_cnd, __FILE__, __LINE__)

/*
 * test_skip_convey() is used to skip a convey context.  This is intended
 * to permit changing "test_convey", to "test_skip_convey".  This is logged,
 * and the current convey context continues processing.
 */
#define	test_skip_convey(T_name, T_code)	\
	test_convey(T_name, test_skip("Skipped"))

/*
 * test_reset establishes a reset for the current block.  This code will
 * be executed every time the current block is unwinding.  This means that
 * the code will be executed each time a child convey exits.  It is also
 * going to be executed once more, for the final pass, which doesn't actually
 * execute any convey blocks.  (This final pass is required in order to
 * learn that all convey's, as well as any code beyond them, are complete.)
 *
 * The way this works is by overriding the existing block's jump buffer.
 *
 * Unlike with GoConvey, this must be registered before any children
 * convey blocks; the logic only affects convey blocks that follow this
 * one, within the same scope.
 *
 * It is possible to have a subsequent reset at the same convey scope
 * override a prior reset.  Normally you should avoid this, and just
 * use lower level convey blocks.
 */
#define	test_reset(T_reset_code)					\
	T_unwind = setjmp(T_ctx.T_jmp);					\
	if (T_unwind) {							\
		do {							\
			T_reset_code					\
		} while (0);						\
	}								\
	if (test_i_loop(&T_ctx, T_unwind) != 0) {			\
		T_break = 1;						\
		break;							\
	}


/*
 * test_init sets up initial things required for testing.  If you don't
 * use test_main(), then you need to call this somewhere early in your
 * main routine.  If it returns non-zero, then you can't use the framework.
 */
extern int test_init(void);

/*
 * test_set_verbose sets verbose mode.  You shouldn't set this normally,
 * as the main() wrapper looks at argv, and does if -v is supplied.
 */
extern void test_set_verbose(void);

/*
 * test_debugf() is like printf, but it goes to a test-specific debug log.
 */
extern void test_debugf(const char *, ...);

#endif	/* TEST_TEST_H */
