/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

/*
 * This is more of a direct #include of a .c rather than .h file.
 * But having it be a .h makes compiler rules work out properly.  Do
 * not include this more than once into your program, or you will
 * get multiple symbols defined.
 *
 * The file itself pulls in POSIX implementations for platform specific
 * functionality.
 */

#ifdef  PLATFORM_POSIX
#define PLATFORM_POSIX_ALLOC
#define PLATFORM_POSIX_DEBUG
#define PLATFORM_POSIX_CLOCK
#define PLATFORM_POSIX_SYNCH
#define PLATFORM_POSIX_THREAD
#define PLATFORM_POSIX_VSNPRINTF

#include "platform/posix/posix_config.h"
#endif
