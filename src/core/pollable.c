//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

struct nni_pollable {
	int     p_rfd;
	int     p_wfd;
	nni_mtx p_lock;
	bool    p_raised;
	bool    p_open;
};

int
nni_pollable_alloc(nni_pollable **pp)
{
	nni_pollable *p;
	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	p->p_open   = false;
	p->p_raised = false;
	nni_mtx_init(&p->p_lock);
	*pp = p;
	return (0);
}

void
nni_pollable_free(nni_pollable *p)
{
	if (p == NULL) {
		return;
	}
	if (p->p_open) {
		nni_plat_pipe_close(p->p_rfd, p->p_wfd);
	}
	nni_mtx_fini(&p->p_lock);
	NNI_FREE_STRUCT(p);
}

void
nni_pollable_raise(nni_pollable *p)
{
	if (p == NULL) {
		return;
	}
	nni_mtx_lock(&p->p_lock);
	if (!p->p_raised) {
		p->p_raised = true;
		if (p->p_open) {
			nni_mtx_unlock(&p->p_lock);
			nni_plat_pipe_raise(p->p_wfd);
			return;
		}
	}
	nni_mtx_unlock(&p->p_lock);
}

void
nni_pollable_clear(nni_pollable *p)
{
	if (p == NULL) {
		return;
	}
	nni_mtx_lock(&p->p_lock);
	if (p->p_raised) {
		p->p_raised = false;
		if (p->p_open) {
			nni_mtx_unlock(&p->p_lock);
			nni_plat_pipe_clear(p->p_rfd);
			return;
		}
	}
	nni_mtx_unlock(&p->p_lock);
}

int
nni_pollable_getfd(nni_pollable *p, int *fdp)
{
	if (p == NULL) {
		return (NNG_EINVAL);
	}
	nni_mtx_lock(&p->p_lock);
	if (!p->p_open) {
		int rv;
		if ((rv = nni_plat_pipe_open(&p->p_wfd, &p->p_rfd)) != 0) {
			nni_mtx_unlock(&p->p_lock);
			return (rv);
		}
		p->p_open = true;
		if (p->p_raised) {
			nni_plat_pipe_raise(p->p_wfd);
		}
	}
	nni_mtx_unlock(&p->p_lock);
	*fdp = p->p_rfd;
	return (0);
}
