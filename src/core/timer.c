//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdlib.h>
#include <string.h>

static void nni_timer_loop(void *);

struct nni_timer {
	// We use two mutexes.  One protects the list, and the other ensures
	// that cancel is blocked if we are running a timeout calllback.
	// The callback(s) are allowed to reschedule a timeout.  The list
	// mutex is *always* acquired before the run mutex.
	nni_mtx		t_list_mx;
	nni_mtx		t_run_mx;
	nni_cv		t_cv;
	nni_list	t_entries;
	nni_thr		t_thr;
	int		t_close;
};

typedef struct nni_timer   nni_timer;

static nni_timer nni_global_timer;


int
nni_timer_sys_init(void)
{
	int rv;
	nni_timer *timer = &nni_global_timer;

	memset(timer, 0, sizeof (*timer));
	NNI_LIST_INIT(&timer->t_entries, nni_timer_node, t_node);
	timer->t_close = 0;

	if (((rv = nni_mtx_init(&timer->t_list_mx)) != 0) ||
	    ((rv = nni_mtx_init(&timer->t_run_mx)) != 0) ||
	    ((rv = nni_cv_init(&timer->t_cv, &timer->t_list_mx)) != 0) ||
	    ((rv = nni_thr_init(&timer->t_thr, nni_timer_loop, timer)) != 0)) {
		nni_timer_sys_fini();
		return (rv);
	}
	nni_thr_run(&timer->t_thr);
	return (0);
}


void
nni_timer_sys_fini(void)
{
	nni_timer *timer = &nni_global_timer;

	nni_mtx_lock(&timer->t_list_mx);
	timer->t_close = 1;
	nni_cv_wake(&timer->t_cv);
	nni_mtx_unlock(&timer->t_list_mx);

	nni_thr_fini(&timer->t_thr);
	nni_cv_fini(&timer->t_cv);
	nni_mtx_fini(&timer->t_list_mx);
	nni_mtx_fini(&timer->t_run_mx);
}


void
nni_timer_init(nni_timer_node *node, nni_cb cb, void *arg)
{
	node->t_cb = cb;
	node->t_arg = arg;
}


void
nni_timer_fini(nni_timer_node *node)
{
	NNI_ARG_UNUSED(node);
}


void
nni_timer_cancel(nni_timer_node *node)
{
	nni_timer *timer = &nni_global_timer;

	nni_mtx_lock(&timer->t_list_mx);
	nni_mtx_lock(&timer->t_run_mx);
	if (node->t_sched) {
		nni_list_remove(&timer->t_entries, node);
		node->t_sched = 0;
	}
	nni_mtx_unlock(&timer->t_run_mx);
	nni_mtx_unlock(&timer->t_list_mx);
}


void
nni_timer_schedule(nni_timer_node *node, nni_time when)
{
	nni_timer *timer = &nni_global_timer;
	nni_timer_node *srch;
	int wake = 1;

	node->t_expire = when;

	nni_mtx_lock(&timer->t_list_mx);

	if (nni_list_active(&timer->t_entries, node)) {
		nni_list_remove(&timer->t_entries, node);
	}

	srch = nni_list_first(&timer->t_entries);
	while ((srch != NULL) && (srch->t_expire < node->t_expire)) {
		srch = nni_list_next(&timer->t_entries, srch);
		wake = 0;
	}
	if (srch != NULL) {
		nni_list_insert_before(&timer->t_entries, node, srch);
	} else {
		nni_list_append(&timer->t_entries, node);
	}
	node->t_sched = 1;
	if (wake) {
		nni_cv_wake(&timer->t_cv);
	}
	nni_mtx_unlock(&timer->t_list_mx);
}


static void
nni_timer_loop(void *arg)
{
	nni_timer *timer = arg;
	nni_time now;
	nni_time expire;
	nni_timer_node *node;

	for (;;) {
		nni_mtx_lock(&timer->t_list_mx);
		if (timer->t_close) {
			nni_mtx_unlock(&timer->t_list_mx);
			break;
		}

		now = nni_clock();
		if ((node = nni_list_first(&timer->t_entries)) == NULL) {
			nni_cv_wait(&timer->t_cv);
			nni_mtx_unlock(&timer->t_list_mx);
			continue;
		}
		if (now < node->t_expire) {
			// End of run, we have to wait for next.
			nni_cv_until(&timer->t_cv, node->t_expire);
			nni_mtx_unlock(&timer->t_list_mx);
			continue;
		}

		nni_list_remove(&timer->t_entries, node);
		node->t_sched = 0;

		// The lock ordering here is important.  We acquire the run
		// lock before dropping the list lock.  One the run is done,
		// we can drop the run lock too.  The reason for the second
		// lock is so that the callback can reschedule itself.
		nni_mtx_lock(&timer->t_run_mx);
		nni_mtx_unlock(&timer->t_list_mx);
		node->t_cb(node->t_arg);
		nni_mtx_unlock(&timer->t_run_mx);
	}
}
