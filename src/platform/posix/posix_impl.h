//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_IMPL_H
#define PLATFORM_POSIX_IMPL_H

#ifdef  PLATFORM_POSIX
#define PLATFORM_POSIX_ALLOC
#define PLATFORM_POSIX_DEBUG
#define PLATFORM_POSIX_CLOCK
#define PLATFORM_POSIX_SYNCH
#define PLATFORM_POSIX_THREAD

#include "platform/posix/posix_config.h"
#endif

// Define types that this platform uses.
#ifdef PLATFORM_POSIX_SYNCH
struct nni_mutex {
	pthread_mutex_t mx;
}

struct nni_condvar {
	pthread_cond_t		cv;
	pthread_mutex_t *	mx;
}
#endif

#endif // PLATFORM_POSIX_IMPL_H