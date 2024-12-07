//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include "reap.h"

#include <stdbool.h>

// New stuff.
static nni_reap_list *reap_list = NULL;
static nni_thr        reap_thr;
static bool           reap_exit = false;
static nni_mtx        reap_mtx  = NNI_MTX_INITIALIZER;
static bool           reap_empty;
static nni_cv         reap_work_cv  = NNI_CV_INITIALIZER(&reap_mtx);
static nni_cv         reap_empty_cv = NNI_CV_INITIALIZER(&reap_mtx);

static void
reap_worker(void *unused)
{
	NNI_ARG_UNUSED(unused);
	nni_thr_set_name(NULL, "nng:reap2");

	nni_mtx_lock(&reap_mtx);
	for (;;) {
		nni_reap_list *list;
		bool           reaped = false;

		for (list = reap_list; list != NULL; list = list->rl_next) {
			nni_reap_node *node;
			size_t         offset;
			nni_cb         func;

			if ((node = list->rl_nodes) == NULL) {
				continue;
			}

			reaped         = true;
			offset         = list->rl_offset;
			func           = list->rl_func;
			list->rl_nodes = NULL;

			// We process our list of nodes while not holding
			// the lock.
			nni_mtx_unlock(&reap_mtx);
			while (node != NULL) {
				void *ptr;
				ptr  = ((char *) node) - offset;
				node = node->rn_next;
				func(ptr);
			}
			nni_mtx_lock(&reap_mtx);
		}
		if (!reaped) {
			reap_empty = true;
			nni_cv_wake(&reap_empty_cv);
			if (reap_exit) {
				nni_mtx_unlock(&reap_mtx);
				return;
			}
			nni_cv_wait(&reap_work_cv);
		}
	}
}

void
nni_reap(nni_reap_list *rl, void *item)
{
	nni_reap_node *node;

	nni_mtx_lock(&reap_mtx);
	if (!rl->rl_inited) {
		rl->rl_inited = true;
		rl->rl_next   = reap_list;
		reap_list     = rl;
	}
	reap_empty    = false;
	node          = (void *) ((char *) item + rl->rl_offset);
	node->rn_next = rl->rl_nodes;
	rl->rl_nodes  = node;
	nni_cv_wake1(&reap_work_cv);
	nni_mtx_unlock(&reap_mtx);
}

void
nni_reap_drain(void)
{
	nni_mtx_lock(&reap_mtx);
	while (!reap_empty) {
		nni_cv_wait(&reap_empty_cv);
	}
	nni_mtx_unlock(&reap_mtx);
}

int
nni_reap_sys_init(void)
{
	int rv;

	reap_exit = false;
	// If this fails, we don't fail init, instead we will try to
	// start up at reap time.
	if ((rv = nni_thr_init(&reap_thr, reap_worker, NULL)) != 0) {
		return (rv);
	}
	nni_thr_run(&reap_thr);
	return (0);
}

void
nni_reap_sys_fini(void)
{
	nni_mtx_lock(&reap_mtx);
	reap_exit = true;
	nni_cv_wake1(&reap_work_cv);
	nni_mtx_unlock(&reap_mtx);
	nni_thr_fini(&reap_thr);

	// NB: The subsystem linkages remain in place.  We don't need
	// to reinitialize them across future initializations.
}
