/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#ifndef CORE_SNPRINTF_H
#define CORE_SNPRINTF_H

#include <stddef.h>
#include <stdarg.h>

/*
 * We have our own snprintf, because some platforms lack this, while
 * others need special handling.  Ours just calls the vsnprintf version
 * from the platform.
 */
extern void nni_snprintf(char *, size_t, const char *, ...);
extern void nni_vsnprintf(char *, size_t, const char *, va_list);

#endif  /* CORE_SNPRINTF_H */
