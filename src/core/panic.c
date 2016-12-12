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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifdef	NNG_HAVE_BACKTRACE
#include <execinfo.h>
#endif

#include "core/nng_impl.h"

/*
 * Panic handling.
 */

static void
show_backtrace(void)
{
#if NNG_HAVE_BACKTRACE
	void *frames[50];
	int nframes;
	char **lines;
	int i;

	nframes = backtrace(frames, sizeof (frames) / sizeof (frames[0]));
	if (nframes > 1) {
		lines = backtrace_symbols(frames, nframes);
		if (lines == NULL) {
			return;
		}
		for (i = 1; i < nframes; i++) {
			nni_debug_out(lines[i]);
		}
	}
#endif
}

/*
 * nni_panic shows a panic message, a possible stack bracktrace, then aborts
 * the process/program.  This should only be called when a condition arises
 * that should not be possible, e.g. a programming assertion failure. It should
 * not be called in situations such as ENOMEM, as nni_panic is fairly rude
 * to any application it may be called from within.
 */
void
nni_panic(const char *fmt, ...)
{
	char buf[128];
	char fbuf[128];
	va_list	va;

	va_start(va, fmt);
	(void) nni_snprintf(fbuf, sizeof (buf), "panic: %s", fmt);
	(void) nni_vsnprintf(buf, sizeof (buf), fbuf, va);
	va_end(va);

	nni_debug_out(buf);
	nni_debug_out("This message is indicative of a BUG.");
	nni_debug_out("Report this at http://github.com/nanomsg/nanomsg");

	show_backtrace();
	nni_abort();
}
