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

#ifndef TESTS_CONVEY_H

#define TESTS_CONVEY_H

#include "test.h"

/*
 * This header file provides a friendlier API to the test-convey framework.
 * It basically provides some "friendly" names for symbols to use instead of
 * the test_xxx symbols.  Basically we pollute your namespace, for your
 * benefit.  Don't like the pollution?  Use test.h instead.
 */



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
 * TestMain("Integer Tests", {
 *	int x = 1; int y = 2;
 *	Convey("Addition works", func() {
 *		So(y == 2);
 *		So(y + x == 3);
 *		So(x + y == 3);
 *		Convey("Even big numbers", func() {
 *			y = 100;
 *			So(x + y == 101);
 *		});
 *		Convey("Notice y is still 2 in this context", func() {
 *			So(y == 2);
 *		});
 * 	});
 * })
 * 
 * There are other macros, but this is a work in progress.  The inspiration
 * for this is from GoConvey -- github.com/smartystreets/goconvey - but this
 * is a version for C programs.
 *
 * In addition to the names listed here, your test code should avoid using
 * names beginning with "test_" or "T_" as we use those names internally
 * in macros, which may collide or do other bad things with your names.
 */

/*
 * TestMain is used to generate a main() function that runs your code,
 * and is appropriate when your entire program consists of one test.
 * This is equivalent to doing Main() with just a single Test(), but it
 * may spare you a level of indentation.
 */
#define	TestMain(name, code)	test_main(name, code)

/*
 * Main() wraps zero or more Tests, which will then contain Convey
 * scopes.  This emits a main function, and can only be used once.
 * It also cannot be used with TestMain.
 */
#define Main(code)		test_main_group(code)

/*
 * Test creates a top-level test scope.
 */
#define	Test(name, code)	test_group(name, code)

/*
 * Convey starts a new test scope.  These can be nested.  The code is
 * executed, including new scopes, but each time a new scope is encountered,
 * the stack is unwound to give the code a fresh start to work with.
 */
#define	Convey(name, code)	test_convey(name, code)

/*
 * So is to be used like assert(), except that it always is checked,
 * and records results in the current scope.  If the assertion fails,
 * then no further processing in the same scope (other than possible
 * reset logic) is performed.  Additional tests at higher scopes, or
 * in sibling scopes, may be executed.
 */
#define So(condition)		test_so(condition)

/*
 * Skip ceases further processing the current scope (Convey).  The
 * reason is a string that will be emitted to the log.
 */
#define Skip(reason)		test_skip(reason)

/*
 * Fail records a test failure, and is much like So, except that
 * no condition is recorded, and instead you may supply your own
 * reason.
 */
#define Fail(reason)		test_fail(reason)


/*
 * SkipSo is a way to skip a check.  The fact that it was skipped
 * will be noted.
 */
#define SkipSo(condition)	test_skip_so(condition)

/*
 * SkipConvey is a way to skip an entire Convey scope.  The fact
 * will be noted.
 */
#define	SkipConvey(name, code)	test_skip_convey(name, code)


/*
 * Reset is establishes a block of code to be reset when exiting from
 * Convey blocks, or even when finishing the current scope.  It only
 * affects the following code, and it is possible to override a prior
 * Reset block with a new one in the same scope.  Unlike with GoConvey,
 * you must put this *before* other Convey blocks you wish to cover.
 */
#define	Reset(code)		test_reset(code)

/*
 * Printf is like printf, but it sends its output to the test debug
 * log, which is emitted only after the test is finished.  The system
 * injects events in the debug log as well, which makes this useful for
 * debugging flow of execution.
 *
 * NB: We avoid variadic macros since some systems don't support them.
 */
#define	Printf			test_debugf


#endif	/* TEST_CONVEY_H */
