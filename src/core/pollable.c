//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

// We pack the wfd and rfd into a uint64_t so that we can update the pair
// atomically and use nni_atomic_cas64, to be lock free.
#define WFD(fds) ((int) ((fds) &0xffffffffu))
#define RFD(fds) ((int) (((fds) >> 32u) & 0xffffffffu))
#define FD_JOIN(wfd, rfd) ((uint64_t)(wfd) + ((uint64_t)(rfd) << 32u))

void
nni_pollable_init(nni_pollable *p)
{
	nni_atomic_init_bool(&p->p_raised);
	nni_atomic_set64(&p->p_fds, (uint64_t) -1);
}

void
nni_pollable_fini(nni_pollable *p)
{
	uint64_t fds;

	fds = nni_atomic_get64(&p->p_fds);
	if (fds != (uint64_t) -1) {
		int rfd, wfd;
		// Read in the high order, write in the low order.
		rfd = RFD(fds);
		wfd = WFD(fds);
		nni_plat_pipe_close(rfd, wfd);
	}
}

int
nni_pollable_alloc(nni_pollable **pp)
{
	nni_pollable *p;
	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_pollable_init(p);
	*pp = p;
	return (0);
}

void
nni_pollable_free(nni_pollable *p)
{
	if (p == NULL) {
		return;
	}
	nni_pollable_fini(p);
	NNI_FREE_STRUCT(p);
}

void
nni_pollable_raise(nni_pollable *p)
{
	if (p == NULL) {
		return;
	}
	if (!nni_atomic_swap_bool(&p->p_raised, true)) {
		uint64_t fds;
		if ((fds = nni_atomic_get64(&p->p_fds)) != (uint64_t) -1) {
			nni_plat_pipe_raise(WFD(fds));
		}
	}
}

void
nni_pollable_clear(nni_pollable *p)
{
	if (p == NULL) {
		return;
	}
	if (nni_atomic_swap_bool(&p->p_raised, false)) {
		uint64_t fds;
		if ((fds = nni_atomic_get64(&p->p_fds)) != (uint64_t) -1) {
			nni_plat_pipe_clear(RFD(fds));
		}
	}
}

int
nni_pollable_getfd(nni_pollable *p, int *fdp)
{
	if (p == NULL) {
		return (NNG_EINVAL);
	}

	for (;;) {
		int      rfd;
		int      wfd;
		int      rv;
		uint64_t fds;

		if ((fds = nni_atomic_get64(&p->p_fds)) != (uint64_t) -1) {
			*fdp = RFD(fds);
			return (0);
		}
		if ((rv = nni_plat_pipe_open(&wfd, &rfd)) != 0) {
			return (rv);
		}
		fds = FD_JOIN(wfd, rfd);

		if (nni_atomic_cas64(&p->p_fds, (uint64_t) -1, fds)) {
			if (nni_atomic_get_bool(&p->p_raised)) {
				nni_plat_pipe_raise(wfd);
			}
			*fdp = rfd;
			return (0);
		}

		// Someone beat us.  Close ours, and try again.
		nni_plat_pipe_close(wfd, rfd);
	}
}
