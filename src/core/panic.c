//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef NNG_HAVE_BACKTRACE
#include <execinfo.h>
#endif

#include "core/nng_impl.h"

// Panic handling.
void
nni_show_backtrace(void)
{
#if NNG_HAVE_BACKTRACE
	void *frames[50];
	int   nframes;

	nframes = backtrace(frames, sizeof(frames) / sizeof(frames[0]));
	if (nframes > 1) {
		char **lines = backtrace_symbols(frames, nframes);
		if (lines == NULL) {
			return;
		}
		for (int i = 1; i < nframes; i++) {
			nni_println(lines[i]);
		}
	}
#endif
}

// nni_panic shows a panic message, a possible stack bracktrace, then aborts
// the process/program.  This should only be called when a condition arises
// that should not be possible, e.g. a programming assertion failure. It should
// not be called in situations such as ENOMEM, as nni_panic is fairly rude
// to any application it may be called from within.
void
nni_panic(const char *fmt, ...)
{
	char    buf[100];
	char    fbuf[93]; // 7 bytes of "panic: "
	va_list va;

	va_start(va, fmt);
	(void) vsnprintf(fbuf, sizeof(fbuf), fmt, va);
	va_end(va);

	(void) snprintf(buf, sizeof(buf), "panic: %s", fbuf);

	nni_println(buf);
	nni_println("This message is indicative of a BUG.");
	nni_println("Report this at https://github.com/nanomsg/nng/issues");

	nni_show_backtrace();
	nni_plat_abort();
}

void
nni_println(const char *msg)
{
	// TODO: support redirection of this later.
	nni_plat_println(msg);
}
