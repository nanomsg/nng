//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
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
// the library is initlialized properly, and also deals with checks such as
// whether the process has forked since last initialization.
int nni_init(void);

// nni_fini tears everything down.  In the future it may be used to ensure
// that all resources used by the library are released back to the system.
void nni_fini(void);

typedef struct nni_initializer {
	int (*i_init)(void);  // i_init is called exactly once
	void (*i_fini)(void); // i_fini is called on shutdown
	int           i_once; // private -- initialize to zero
	nni_list_node i_node; // private -- initialize to zero
} nni_initializer;

// nni_initialize will call the initialization routine exactly once.  This is
// done efficiently, so that if the caller has initialized already, then
// subsequent calls are "cheap" (no synchronization cost).  The initialization
// function must not itself cause any further calls to nni_initialize; the
// function should limit itself to initialization of locks and static data
// structures.  When shutting down, the finalizer will be called.  The
// order in which finalizers are called is unspecified.
//
// An initializer may fail (due to resource exhaustion), in which case the
// return value of nni_initialize will be non-zero.
int nni_initialize(nni_initializer *);

#endif // CORE_INIT_H
