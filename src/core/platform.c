/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

/*
 * This file pulls in the correct platform implementation.
 */

#include "core/nng_impl.h"

#if 0
#if defined(PLATFORM_POSIX)
#include "platform/posix/posix_impl.h"
#else
#error "unknown platform"
#endif
#endif
