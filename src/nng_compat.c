//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng.h"
#include "nn_compat.h"

// This file provides the "public" API.  This is a thin wrapper around
// internal API functions.  We use the public prefix instead of internal,
// to indicate that these interfaces are intended for applications to use
// directly.
//
// Anything not defined in this file, applications have no business using.
// Pretty much every function calls the nni_platform_init to check against
// fork related activity.

int
nn_socket(int domain, int protocol)
{
}