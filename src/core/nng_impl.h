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

#ifndef NNG_IMPL_H
#define NNG_IMPL_H

#include "nng.h"
#include "platform/platform.h"

/*
 * Internal implementation things for NNG, common definitions, etc.
 *
 * Hopefully it should be clear by the name that this file and its contents
 * are *NOT* for use outside of this library.
 *
 * Symbols that are private to the library begin with the nni_ prefix, whereas
 * those starting with nng_ are intended for external consumption.
 */

/*
 * C compilers may get unhappy when named arguments are not used.  While
 * there are things like __attribute__((unused)) which are arguably
 * superior, support for such are not universal.
 */
#define	NNI_ARG_UNUSED(x)	((void)x);

/*
 * We have our own snprintf, because some platforms lack this, while
 * others need special handling.  Ours just calls the vsnprintf version
 * from the platform.
 */
extern void nni_snprintf(char *, size_t, const char *, ...);

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

#endif	/* NNG_IMPL_H */
