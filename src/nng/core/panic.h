//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_PANIC_H
#define CORE_PANIC_H

// nni_panic is used to terminate the process with prejudice, and
// should only be called in the face of a critical programming error,
// or other situation where it would be unsafe to attempt to continue.
// As this crashes the program, it should never be used when factors outside
// the program can cause it, such as receiving protocol errors, or running
// out of memory.  Its better in those cases to return an error to the
// program and let the caller handle the error situation.
extern void nni_panic(const char *, ...);

// nni_println is used to print output to a debug console.  This should only
// be used in the most dire of circumstances -- such as during an assertion
// failure that is going to cause the program to crash.  After the string is
// emitted, a new line character is emitted, so the string should not
// include one.
extern void nni_println(const char *);

#endif // CORE_PANIC_H
