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

#include <stdlib.h>
#include <string.h>

static void nni_timer_loop(void *);

// XXX: replace this timer list with a minHeap based priority queue.
struct nni_timer {
	nni_mtx         t_mx;
	nni_cv          t_wait_cv;
	nni_cv          t_sched_cv;
	nni_list        t_entries;
	nni_thr         t_thr;
	int             t_run;
	int             t_waiting;
	nni_timer_node *t_active; // Must never ever be dereferenced!
};

typedef struct nni_timer nni_timer;

static nni_timer nni_global_timer;

int
nni_timer_sys_init(void)
{
	int        rv;
	nni_timer *timer = &nni_global_timer;

	memset(timer, 0, sizeof(*timer));
	NNI_LIST_INIT(&timer->t_entries, nni_timer_node, t_node);

	nni_mtx_init(&timer->t_mx);
	nni_cv_init(&timer->t_sched_cv, &timer->t_mx);
	nni_cv_init(&timer->t_wait_cv, &timer->t_mx);

	if ((rv = nni_thr_init(&timer->t_thr, nni_timer_loop, timer)) != 0) {
		nni_timer_sys_fini();
		return (rv);
	}
	timer->t_run = 1;
	nni_thr_run(&timer->t_thr);
	return (0);
}

void
nni_timer_sys_fini(void)
{
	nni_timer *timer = &nni_global_timer;

	if (timer->t_run) {
		nni_mtx_lock(&timer->t_mx);
		timer->t_run = 0;
		nni_cv_wake(&timer->t_sched_cv);
		nni_mtx_unlock(&timer->t_mx);
	}

	nni_thr_fini(&timer->t_thr);
	nni_cv_fini(&timer->t_wait_cv);
	nni_cv_fini(&timer->t_sched_cv);
	nni_mtx_fini(&timer->t_mx);
}

void
nni_timer_init(nni_timer_node *node, nni_cb cb, void *arg)
{
	node->t_cb  = cb;
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

	nni_mtx_lock(&timer->t_mx);
	while (timer->t_active == node) {
		timer->t_waiting = 1;
		nni_cv_wait(&timer->t_wait_cv);
	}
	if (nni_list_active(&timer->t_entries, node)) {
		nni_list_remove(&timer->t_entries, node);
	}
	nni_mtx_unlock(&timer->t_mx);
}

void
nni_timer_schedule(nni_timer_node *node, nni_time when)
{
	nni_timer *timer = &nni_global_timer;

	nni_mtx_lock(&timer->t_mx);
	node->t_expire = when;

	if (nni_list_active(&timer->t_entries, node)) {
		nni_list_remove(&timer->t_entries, node);
	}

	if (when != NNI_TIME_NEVER) {
		nni_timer_node *srch = nni_list_first(&timer->t_entries);
		while ((srch != NULL) && (srch->t_expire < node->t_expire)) {
			srch = nni_list_next(&timer->t_entries, srch);
		}
		if (srch != NULL) {
			nni_list_insert_before(&timer->t_entries, node, srch);
		} else {
			nni_list_append(&timer->t_entries, node);
		}
		if (nni_list_first(&timer->t_entries) == node) {
			nni_cv_wake1(&timer->t_sched_cv);
		}
	}
	nni_mtx_unlock(&timer->t_mx);
}

static void
nni_timer_loop(void *arg)
{
	nni_timer *     timer = arg;
	nni_time        now;
	nni_timer_node *node;

	for (;;) {
		nni_mtx_lock(&timer->t_mx);
		timer->t_active = NULL;
		if (timer->t_waiting) {
			timer->t_waiting = 0;
			nni_cv_wake(&timer->t_wait_cv);
		}
		if (!timer->t_run) {
			nni_mtx_unlock(&timer->t_mx);
			break;
		}

		now = nni_clock();
		if ((node = nni_list_first(&timer->t_entries)) == NULL) {
			nni_cv_wait(&timer->t_sched_cv);
			nni_mtx_unlock(&timer->t_mx);
			continue;
		}
		if (now < node->t_expire) {
			// End of run, we have to wait for next.
			nni_cv_until(&timer->t_sched_cv, node->t_expire);
			nni_mtx_unlock(&timer->t_mx);
			continue;
		}

		nni_list_remove(&timer->t_entries, node);

		// Save the active node.  Note that the timer callback can
		// free this memory or do something else with it, so it is
		// important that we never dereference this pointer, but
		// just compare the value of the pointer itself.
		timer->t_active = node;
		nni_mtx_unlock(&timer->t_mx);

		node->t_cb(node->t_arg);
	}
}
