// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_REFCNT_H
#define CORE_REFCNT_H

#include <nng/nng.h>

#include <core/nng_impl.h>
#include <core/platform.h>

typedef struct {
	nni_atomic_int rc_cnt;
	void (*rc_fini)(void *);
	void *rc_data;
} nni_refcnt;

extern void nni_refcnt_init(
    nni_refcnt *rc, unsigned value, void *v, void (*fini)(void *));
extern void nni_refcnt_hold(nni_refcnt *rc);
extern void nni_refcnt_rele(nni_refcnt *rc);

#endif // CORE_REFCNT_H
