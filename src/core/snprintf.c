/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>

#include "core/nng_impl.h"

void
nni_snprintf(char *dst, size_t sz, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	nni_vsnprintf(dst, sz, fmt, va);
	va_end(va);
}


void
nni_vsnprintf(char *dst, size_t sz, const char *fmt, va_list va)
{
	nni_plat_vsnprintf(dst, sz, fmt, va);
}
