//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#ifndef _CRT_RAND_S
#define _CRT_RAND_S
#endif

#include <stdlib.h>

uint32_t
nni_random(void)
{
	unsigned val;

	// rand_s is claimed by Microsoft to generate cryptographically
	// secure numbers.  It also is claimed that this will only fail
	// for EINVAL if val is NULL (not the case here).  Other error
	// conditions might be possible, but we have no way to tell.
	// For now we just ignore that possibility.
	rand_s(&val);
	return ((uint32_t)val);
}

#endif // NNG_PLATFORM_WINDOWS