//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// arc4random is the preferred source of cryptographic random numbers
// on any platform where it is found.
#include <stdlib.h>

#include "core/nng_impl.h"

#ifdef NNG_HAVE_ARC4RANDOM

uint32_t
nni_random(void)
{
	return (arc4random());
}

#endif