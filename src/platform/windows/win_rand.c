//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <stdlib.h>

void
nni_plat_seed_prng(void *buf, size_t bufsz)
{
	unsigned val;

	// The rand_s routine uses RtlGenRandom to get high quality
	// pseudo random numbers (i.e. numbers that should be good enough
	// for use with crypto keying.)
	while (bufsz > sizeof(val)) {
		rand_s(&val);
		memcpy(buf, &val, sizeof(val));
		buf = (((char *) buf) + sizeof(val));
		bufsz -= sizeof(val);
	}
}

#endif // NNG_PLATFORM_WINDOWS
