/*
 * Copyright 2017 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#ifndef CONVEY_H

#define CONVEY_H

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * This test framework allows one to write tests as a form of assertion,
 * giving simpler and more readable test logic.
 *
 * The test framework provides a main() function.
 *
 * To use this call the Main() macro, and embed Test() and Convey() blocks.
 * These can be nested, and after each convey the entire stack is popped so
 * that execution can continue from the beginning, giving each test section
 * the same environment.
 *
 * There are assertion macros too, which don't roll back the stack, but which
 * do update the test state.
 *
 * Here's a sample file:
 *
 * Main({
 *	Test({"Integer Tests", {
 *		int x = 1; int y = 2;
 *		Convey("Addition works", func() {
 *			So(y == 2);
 *			So(y + x == 3);
 *			So(x + y == 3);
 *			Convey("Even big numbers", {
 *				y = 100;
 *				So(x + y == 101);
 *			});
 *			Convey("Notice y is still 2 in this context", {
 *				So(y == 2);
 *			});
 * 		});
 *	});
 * })
 *
 * This was inspired by GoConvey -- github.com/smartystreets/goconvey - but
 * there are differences of course -- C is not Go!
 *
 * Pleaes note that we abuse the C preprocessor and setjmp fairly heavily,
 * and as a result of the magic we have to do, a lot of these guts must be
 * exposed in this header file.  HOWEVER, only symbols beginning with a
 * capital letter are intended for consumers.  All others are for internal
 * use only.  Otherwise, welcome to the sausage factory.
 *
 * Please see the documentation at github.com/gdamore/c-convey for more
 * details about how to use this.
 */

/*
 * This structure has to be exposed in order to expose the buffer used for
 * setjmp.  It's members should never be accessed directly.  These should be
 * allocated statically in the routine(s) that need custom contexts.  The
 * framework creates a context automatically for each convey scope.
 */
typedef struct {
	void *  cs_data;
	jmp_buf cs_jmp;
} conveyScope;

/* These functions are not for use by tests -- they are used internally. */
extern int   conveyStart(conveyScope *, const char *);
extern int   conveyLoop(conveyScope *, int);
extern void  conveyFinish(conveyScope *, int *);
extern int   conveyMain(int, char **);
extern char *conveyGetEnv(const char *);
extern int   conveyPutEnv(const char *, char *);

extern void conveyAssertPass(const char *, const char *, int);
extern void conveyAssertSkip(const char *, const char *, int);
extern void conveyAssertFail(const char *, const char *, int);
extern void conveySkip(const char *, int, const char *, ...);
extern void conveyFail(const char *, int, const char *, ...);
extern void conveyError(const char *, int, const char *, ...);
extern void conveyPrintf(const char *, int, const char *, ...);
extern int  conveyMainImpl(void);

/*
 * conveyRun is a helper macro not to be called directly by user
 * code.  It has to be here exposed, in order for setjmp() to work.
 * and for the code block to be inlined.  Becuase this inlines user
 * code, we have to be *very* careful with symbol names.
 */
#define conveyRun(convey_name, convey_code, convey_resultp)          \
	do {                                                         \
		static conveyScope convey_scope;                     \
		int                convey_unwind;                    \
		int                convey_break = 0;                 \
		if (conveyStart(&convey_scope, convey_name) != 0) {  \
			break;                                       \
		}                                                    \
		convey_unwind = setjmp(convey_scope.cs_jmp);         \
		if (conveyLoop(&convey_scope, convey_unwind) != 0) { \
			break;                                       \
		}                                                    \
		do {                                                 \
			convey_code                                  \
		} while (0);                                         \
		if (convey_break) {                                  \
			break;                                       \
		}                                                    \
		conveyFinish(&convey_scope, convey_resultp);         \
	} while (0);

/*
 * ConveyReset establishes a reset for the current scope.  This code will
 * be executed every time the current scope is unwinding.  This means that
 * the code will be executed each time a child convey exits.  It is also
 * going to be executed once more, for the final pass, which doesn't actually
 * execute any convey blocks.  (This final pass is required in order to
 * learn that all convey's, as well as any code beyond them, are complete.)
 *
 * The way this works is by overriding the existing scope's jump buffer.
 *
 * Unlike with GoConvey, this must be registered before any children
 * convey blocks; the logic only affects convey blocks that follow this
 * one, within the same scope.
 *
 * This must be in a conveyRun scope (i.e. part of a Convey() or a
 * top level Test() or it will not compile.
 *
 * It is possible to have a subsequent reset at the same convey scope
 * override a prior reset.  Normally you should avoid this, and just
 * use lower level convey blocks.
 */
#define ConveyReset(convey_reset_code)                       \
	convey_unwind = setjmp(convey_scope.cs_jmp);         \
	if (convey_unwind) {                                 \
		do {                                         \
			convey_reset_code                    \
		} while (0);                                 \
	}                                                    \
	if (conveyLoop(&convey_scope, convey_unwind) != 0) { \
		convey_break = 1;                            \
		break;                                       \
	}

/*
 * ConveyMain is the outer most scope that most test programs use, unless they
 * use the short-cut ConveyTestMain.  This creates a main() routine that
 * sets up the program, parses options, and then executes the tests nested
 * within it.
 */
#define ConveyMain(code)                 \
	static int convey_main_rv;       \
	int        conveyMainImpl(void)  \
	{                                \
		do {                     \
			code             \
		} while (0);             \
		return (convey_main_rv); \
	}                                \
	int main(int argc, char **argv) { return (conveyMain(argc, argv)); }

/*
 * ConveyGetEnv is used to get environment variables, which can be
 * overridden with -p <name>=<value> on the command line.
 */
#define ConveyGetEnv(name) conveyGetEnv(name)

/*
 * ConveyPutEnv is used to change environment variables.  This is not
 * thread safe!
 */
#define ConveyPutEnv(name, value) conveyPutEnv(name, value)
/*
 * ConveyTest creates a top-level test instance, which can contain multiple
 * Convey blocks.
 */
#define ConveyTest(name, code)                      \
	do {                                        \
		int convey_rv = 0;                  \
		conveyRun(name, code, &convey_rv);  \
		if (convey_rv > convey_main_rv) {   \
			convey_main_rv = convey_rv; \
		};                                  \
	} while (0);

/*
 * ConveyTestMain is used to wrap the top-level of your test suite, and is
 * used in lieu of a normal main() function.  This is the usual case where
 * the executable only contains a single top level test group.  It
 * is the same as using Main with just a single Test embedded, but saves
 * some typing and probably a level of indentation.
 */
#define ConveyTestMain(name, code) ConveyMain(ConveyTest(name, code))

/*
 * EXPERIMENTAL:
 * If you don't want to use the test framework's main routine, but
 * prefer (or need, because of threading for example) to have your
 * test code driven separately, you can use inject ConveyBlock() in
 * your function.  It works like ConveyMain().  These must not be
 * nested within other Conveys, Tests, or Blocks (or Main).  The
 * results are undefined if you try that.  The final result pointer may
 * be NULL, or a pointer to an integer to receive the an integer
 * result from the test. (0 is success, 4 indicates a failure to allocate
 * memory in the test framework, and anything else indicates a
 * an error or failure in the code being tested.
 *
 * Blocks do not contain Tests, rather they contain Conveys only.  The
 * Block takes the place of both Main() and Test().  It is to be hoped
 * that you will not need this.
 */
#define ConveyBlock(name, code, resultp) conveyRun(name, code, resultp)

/*
 * ConveyAssert and ConveySo allow you to run assertions.
 */
#define ConveyAssert(truth)                                           \
	do {                                                          \
		if (!(truth)) {                                       \
			conveyAssertFail(#truth, __FILE__, __LINE__); \
		} else {                                              \
			conveyAssertPass(#truth, __FILE__, __LINE__); \
		}                                                     \
	} while (0)

#define ConveySo(truth) ConveyAssert(truth)

/*
 * Convey(name, <code>) starts a convey context, with <code> as
 * the body.  The <code> is its scope, and may be called repeatedly
 * within the body of a loop.
 */
#define Convey(name, code) conveyRun(name, code, NULL)

/*
 * ConveySkip() just stops processing of the rest of the current context,
 * and records that processing was skipped.
 */

/*
 * If your preprocessor doesn't understand C99 variadics, indicate it
 * with CONVEY_NO_VARIADICS.  In that case you lose support for printf-style
 * format specifiers.
 */
#ifdef CONVEY_NO_VARIADICS
#define ConveySkip(reason) conveySkip(__FILE__, __LINE__, reason)
#define ConveyFail(reason) conveyFail(__FILE__, __LINE__, reason)
#define ConveyError(reason) conveyError(__FILE__, __LINE__, reason)
#define ConveyPrintf(reason) conveyPrintf(__FILE__, __LINE__, reason)
#else
#define ConveySkip(...) conveySkip(__FILE__, __LINE__, __VA_ARGS__)
#define ConveyFail(...) conveyFail(__FILE__, __LINE__, __VA_ARGS__)
#define ConveyError(...) conveyError(__FILE__, __LINE__, __VA_ARGS__)
#define ConveyPrintf(...) conveyPrintf(__FILE__, __LINE__, __VA_ARGS__)
#endif

/*
 * ConveySkipSo() is used to skip processing of a single assertion.
 * Further processing in the same context continues.
 */
#define ConveySkipAssert(truth) conveyAssertSkip(#truth, __FILE__, __LINE__)
#define ConveySkipSo(truth) ConveySkipAssert(truth)

/*
 * ConveySkipConvey() is used to skip a convey context.  This is intended
 * to permit changing "Convey", to "SkipConvey".  This is logged,
 * and the current convey context continues processing.
 */
#define ConveySkipConvey(name, code) \
	conveyRun(name, ConveySkip("Skipped");, NULL)

/*
 * ConveyInit sets up initial things required for testing.  If you don't
 * use ConveyMain(), then you need to call this somewhere early in your
 * main routine.  If it returns non-zero, then you can't use the framework.
 */
extern int ConveyInit(void);

/*
 * ConveySetVerbose sets verbose mode.  You shouldn't set this normally,
 * as the main() wrapper looks at argv, and does if -v is supplied.
 */
extern void ConveySetVerbose(void);

/*
 * These are some public macros intended to make the API more friendly.
 * The user is welcome to #undefine any of these he wishes not to
 * use, or he can simply avoid the pollution altogether by defining
 * CONVEY_NAMESPACE_CLEAN before including this header file.  Any
 * of these names are already defined using the Convey prefix, with
 * the sole exception of Convey() itself, which you cannot undefine.
 * (We don't define a ConveyConvey()... that's just silly.)  Most of the
 * time you won't need this, because its test code that you control, and
 * you're writing to Convey(), so you can trivially avoid the conflicts and
 * benefit from the friendlier names.  This is why this is the default.
 *
 * There are some other less often used functions that we haven't aliased,
 * like ConveyBlock() and ConveySetVerbose().  Aliases for those offer
 * little benefit for the extra pollution they would create.
 */
#ifndef CONVEY_NAMESPACE_CLEAN

#define TestMain ConveyTestMain
#define Test ConveyTest
#define Main ConveyMain
#define So ConveySo
#define Skip ConveySkip
#define Fail ConveyFail
#define Error ConveyError
#define SkipConvey ConveySkipConvey
#define SkipSo ConveySkipSo
#define Reset ConveyReset
#define Printf ConveyPrintf

#endif /* CONVEY_NAMESPACE_CLEAN */

#endif /* CONVEY_H */
