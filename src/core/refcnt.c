// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <core/refcnt.h>

void
nni_refcnt_init(
    nni_refcnt *rc, unsigned value, void *data, void (*fini)(void *))
{
	nni_atomic_set(&rc->rc_cnt, value);
	rc->rc_data = data;
	rc->rc_fini = fini;
}

void
nni_refcnt_hold(nni_refcnt *rc)
{
	nni_atomic_inc(&rc->rc_cnt);
}

void
nni_refcnt_rele(nni_refcnt *rc)
{
	if (nni_atomic_dec_nv(&rc->rc_cnt) == 0) {
		rc->rc_fini(rc->rc_data);
	}
}
