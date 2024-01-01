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

#include "core/nng_impl.h"

// nni_init is called each time the user enters the library.  It ensures that
// the library is initialized properly, and also deals with checks such as
// whether the process has forked since last initialization.
int nni_init(void);

// nni_fini tears everything down.  In the future it may be used to ensure
// that all resources used by the library are released back to the system.
void nni_fini(void);

// nni_init_param is used by applications (via nng_init_param) to configure
// some tunable settings at runtime.  It must be called before any other NNG
// functions are called, in order to have any effect at all.
void nni_init_set_param(nng_init_parameter, uint64_t value);

// subsystems can call this to obtain a parameter value.
uint64_t nni_init_get_param(nng_init_parameter parameter, uint64_t default_value);

// subsystems can set this to facilitate tests (only used in test code)
void nni_init_set_effective(nng_init_parameter p, uint64_t value);

#endif // CORE_INIT_H
