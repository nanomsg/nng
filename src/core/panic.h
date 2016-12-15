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

#ifndef CORE_PANIC_H
#define CORE_PANIC_H

/*
 * nni_panic is used to terminate the process with prejudice, and
 * should only be called in the face of a critical programming error,
 * or other situation where it would be unsafe to attempt to continue.
 * As this crashes the program, it should never be used when factors outside
 * the program can cause it, such as receiving protocol errors, or running
 * out of memory.  Its better in those cases to return an error to the
 * program and let the caller handle the error situation.
 */
extern void nni_panic(const char *, ...);

/*
 * nni_println is used to print output to a debug console.  This should only
 * be used in the most dire of circumstances -- such as during an assertion
 * failure that is going to cause the program to crash.  After the string is
 * emitted, a new line character is emitted, so the string should not
 * include one.
 */
extern void nni_println(const char *);

#endif	/* CORE_PANIC_H */
