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

static nni_list reap_list;
static nni_mtx  reap_mtx;
static nni_cv   reap_cv;
static nni_cv   reap_empty_cv;
static bool     reap_exit  = false;
static bool     reap_empty = false;
static nni_thr  reap_thr;

static void
reap_worker(void *notused)
{
	NNI_ARG_UNUSED(notused);

	nni_mtx_lock(&reap_mtx);
	for (;;) {
		nni_reap_item *item;
		while ((item = nni_list_first(&reap_list)) != NULL) {
			nni_list_remove(&reap_list, item);
			nni_mtx_unlock(&reap_mtx);

			item->r_func(item->r_ptr);
			nni_mtx_lock(&reap_mtx);
		}

		reap_empty = true;
		nni_cv_wake(&reap_empty_cv);

		if (reap_exit) {
			break;
		}

		nni_cv_wait(&reap_cv);
	}
	nni_mtx_unlock(&reap_mtx);
}

void
nni_reap(nni_reap_item *item, nni_cb func, void *ptr)
{
	nni_mtx_lock(&reap_mtx);
	item->r_func = func;
	item->r_ptr  = ptr;
	nni_list_append(&reap_list, item);
	reap_empty = false;
	nni_cv_wake(&reap_cv);
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

	NNI_LIST_INIT(&reap_list, nni_reap_item, r_link);
	nni_mtx_init(&reap_mtx);
	nni_cv_init(&reap_cv, &reap_mtx);
	nni_cv_init(&reap_empty_cv, &reap_mtx);
	reap_exit = false;

	// If this fails, we don't fail init, instead we will try to
	// start up at reap time.
	if ((rv = nni_thr_init(&reap_thr, reap_worker, NULL)) != 0) {
		nni_cv_fini(&reap_cv);
		nni_cv_fini(&reap_empty_cv);
		nni_mtx_fini(&reap_mtx);
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
	nni_cv_wake(&reap_cv);
	nni_mtx_unlock(&reap_mtx);
	nni_thr_fini(&reap_thr);
}
