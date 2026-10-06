//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_INIT_H
#define CORE_INIT_H

#include "defs.h"

// subsystems can call this to obtain a parameter value.
nng_init_params *nni_init_get_params(void);

// This is a one-way sanity check for public entry points.  It deliberately
// remains true after nng_fini(), which does not make further use safe.
bool nni_init_was_called(void);

#endif // CORE_INIT_H
