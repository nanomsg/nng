//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

static nni_list nni_reap_list;
static nni_mtx  nni_reap_mtx;
static nni_cv   nni_reap_cv;
static bool     nni_reap_exit = false;
static nni_thr  nni_reap_thr;

static void
nni_reap_stuff(void *notused)
{
	NNI_ARG_UNUSED(notused);

	nni_mtx_lock(&nni_reap_mtx);
	for (;;) {
		nni_reap_item *item;
		if ((item = nni_list_first(&nni_reap_list)) != NULL) {
			nni_list_remove(&nni_reap_list, item);
			nni_mtx_unlock(&nni_reap_mtx);

			item->r_func(item->r_ptr);
			nni_mtx_lock(&nni_reap_mtx);
			continue;
		}

		if (nni_reap_exit) {
			break;
		}

		nni_cv_wait(&nni_reap_cv);
	}
	nni_mtx_unlock(&nni_reap_mtx);
}

void
nni_reap(nni_reap_item *item, nni_cb func, void *ptr)
{
	nni_mtx_lock(&nni_reap_mtx);
	item->r_func = func;
	item->r_ptr  = ptr;
	nni_list_append(&nni_reap_list, item);
	nni_cv_wake(&nni_reap_cv);
	nni_mtx_unlock(&nni_reap_mtx);
}

int
nni_reap_sys_init(void)
{
	int rv;

	NNI_LIST_INIT(&nni_reap_list, nni_reap_item, r_link);
	nni_mtx_init(&nni_reap_mtx);
	nni_cv_init(&nni_reap_cv, &nni_reap_mtx);
	nni_reap_exit = false;

	// If this fails, we don't fail init, instead we will try to
	// start up at reap time.
	if ((rv = nni_thr_init(&nni_reap_thr, nni_reap_stuff, NULL)) != 0) {
		nni_cv_fini(&nni_reap_cv);
		nni_mtx_fini(&nni_reap_mtx);
		return (rv);
	}
	nni_thr_run(&nni_reap_thr);
	return (0);
}

void
nni_reap_sys_fini(void)
{
	nni_mtx_lock(&nni_reap_mtx);
	nni_reap_exit = true;
	nni_cv_wake(&nni_reap_cv);
	nni_mtx_unlock(&nni_reap_mtx);
	nni_thr_fini(&nni_reap_thr);
}
