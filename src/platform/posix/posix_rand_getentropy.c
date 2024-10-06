//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// getrandom is not as nice as arc4random, but on platforms where it
// exists and arc4random does not, we should use it.
//
// getrandom will block only if the urandom device is not seeded yet.
// That can only happen during very early boot (earlier than we should
// normally be running.  This is the only time it can fail with correct
// arguments, and then only if it is interrupted with a signal.

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#ifdef NNG_HAVE_SYS_RANDOM
#include <sys/random.h>
#endif

#include "core/panic.h"

#ifdef NNG_HAVE_GETENTROPY

uint32_t
nni_random(void)
{
	uint32_t val;
	if (getentropy(&val, sizeof(val)) != 0) {
		nni_panic("getentropy failed");
	}
	return (val);
}

#endif
