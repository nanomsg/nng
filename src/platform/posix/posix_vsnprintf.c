/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_VSNPRINTF

#include <stdarg.h>
#include <stdio.h>

void
nni_plat_vsnprintf(char *dst, size_t sz, const char *fmt, va_list va)
{
	(void) vsnprintf(dst, sz, fmt, va);
}


#endif
