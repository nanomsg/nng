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

typedef struct nni_taskq_thr nni_taskq_thr;
struct nni_taskq_thr {
	nni_taskq *tqt_tq;
	nni_thr    tqt_thread;
	nni_task * tqt_running;
	int        tqt_wait;
};
struct nni_taskq {
	nni_list       tq_tasks;
	nni_mtx        tq_mtx;
	nni_cv         tq_sched_cv;
	nni_cv         tq_wait_cv;
	nni_taskq_thr *tq_threads;
	int            tq_nthreads;
	int            tq_run;
	int            tq_waiting;
};

static nni_taskq *nni_taskq_systq = NULL;

static void
nni_taskq_thread(void *self)
{
	nni_taskq_thr *thr = self;
	nni_taskq *    tq  = thr->tqt_tq;
	nni_task *     task;

	nni_mtx_lock(&tq->tq_mtx);
	for (;;) {
		if ((task = nni_list_first(&tq->tq_tasks)) != NULL) {
			nni_list_remove(&tq->tq_tasks, task);
			thr->tqt_running = task;
			nni_mtx_unlock(&tq->tq_mtx);
			task->task_cb(task->task_arg);
			nni_mtx_lock(&tq->tq_mtx);
			thr->tqt_running = NULL;
			if (thr->tqt_wait || tq->tq_waiting) {
				thr->tqt_wait  = 0;
				tq->tq_waiting = 0;
				nni_cv_wake(&tq->tq_wait_cv);
			}

			continue;
		}

		if (tq->tq_waiting) {
			tq->tq_waiting = 0;
			nni_cv_wake(&tq->tq_wait_cv);
		}
		if (!tq->tq_run) {
			break;
		}
		nni_cv_wait(&tq->tq_sched_cv);
	}
	nni_mtx_unlock(&tq->tq_mtx);
}

int
nni_taskq_init(nni_taskq **tqp, int nthr)
{
	nni_taskq *tq;

	if ((tq = NNI_ALLOC_STRUCT(tq)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((tq->tq_threads = NNI_ALLOC_STRUCTS(tq->tq_threads, nthr)) ==
	    NULL) {
		NNI_FREE_STRUCT(tq);
		return (NNG_ENOMEM);
	}
	tq->tq_nthreads = nthr;
	NNI_LIST_INIT(&tq->tq_tasks, nni_task, task_node);

	nni_mtx_init(&tq->tq_mtx);
	nni_cv_init(&tq->tq_sched_cv, &tq->tq_mtx);
	nni_cv_init(&tq->tq_wait_cv, &tq->tq_mtx);

	for (int i = 0; i < nthr; i++) {
		int rv;
		tq->tq_threads[i].tqt_tq      = tq;
		tq->tq_threads[i].tqt_running = NULL;
		rv = nni_thr_init(&tq->tq_threads[i].tqt_thread,
		    nni_taskq_thread, &tq->tq_threads[i]);
		if (rv != 0) {
			nni_taskq_fini(tq);
			return (rv);
		}
	}
	tq->tq_run = 1;
	for (int i = 0; i < tq->tq_nthreads; i++) {
		nni_thr_run(&tq->tq_threads[i].tqt_thread);
	}
	*tqp = tq;
	return (0);
}

static void
nni_taskq_drain_locked(nni_taskq *tq)
{
	// We need to first let the taskq completely drain.
	for (;;) {
		int busy = 0;
		if (!nni_list_empty(&tq->tq_tasks)) {
			busy = 1;
		} else {
			int i;
			for (i = 0; i < tq->tq_nthreads; i++) {
				if (tq->tq_threads[i].tqt_running != 0) {
					busy = 1;
					break;
				}
			}
		}
		if (!busy) {
			break;
		}
		tq->tq_waiting++;
		nni_cv_wait(&tq->tq_wait_cv);
	}
}

void
nni_taskq_drain(nni_taskq *tq)
{
	nni_mtx_lock(&tq->tq_mtx);
	nni_taskq_drain_locked(tq);
	nni_mtx_unlock(&tq->tq_mtx);
}

void
nni_taskq_fini(nni_taskq *tq)
{
	// First drain the taskq completely.  This is necessary since some
	// tasks that are presently running may need to schedule additional
	// tasks, and we don't want those to block.
	if (tq == NULL) {
		return;
	}
	if (tq->tq_run) {
		nni_mtx_lock(&tq->tq_mtx);
		nni_taskq_drain_locked(tq);

		tq->tq_run = 0;
		nni_cv_wake(&tq->tq_sched_cv);
		nni_mtx_unlock(&tq->tq_mtx);
	}
	for (int i = 0; i < tq->tq_nthreads; i++) {
		nni_thr_fini(&tq->tq_threads[i].tqt_thread);
	}
	nni_cv_fini(&tq->tq_wait_cv);
	nni_cv_fini(&tq->tq_sched_cv);
	nni_mtx_fini(&tq->tq_mtx);
	NNI_FREE_STRUCTS(tq->tq_threads, tq->tq_nthreads);
	NNI_FREE_STRUCT(tq);
}

void
nni_task_dispatch(nni_task *task)
{
	nni_taskq *tq = task->task_tq;

	// If there is no callback to perform, then do nothing!
	// The user will be none the wiser.
	if (task->task_cb == NULL) {
		return;
	}
	nni_mtx_lock(&tq->tq_mtx);
	// It might already be scheduled... if so don't redo it.
	if (!nni_list_active(&tq->tq_tasks, task)) {
		nni_list_append(&tq->tq_tasks, task);
	}
	nni_cv_wake1(&tq->tq_sched_cv); // waking just one waiter is adequate
	nni_mtx_unlock(&tq->tq_mtx);
}

void
nni_task_wait(nni_task *task)
{
	nni_taskq *tq = task->task_tq;

	if (task->task_cb == NULL) {
		return;
	}
	nni_mtx_lock(&tq->tq_mtx);
	for (;;) {
		bool running = false;
		if (nni_list_active(&tq->tq_tasks, task)) {
			running = true;
		} else {
			for (int i = 0; i < tq->tq_nthreads; i++) {
				if (tq->tq_threads[i].tqt_running == task) {
					running = true;
					break;
				}
			}
		}
		if (!running) {
			break;
		}

		tq->tq_waiting = 1;
		nni_cv_wait(&tq->tq_wait_cv);
	}
	nni_mtx_unlock(&tq->tq_mtx);
}

int
nni_task_cancel(nni_task *task)
{
	nni_taskq *tq = task->task_tq;
	bool       running;

	nni_mtx_lock(&tq->tq_mtx);
	running = true;
	for (;;) {
		running = false;
		for (int i = 0; i < tq->tq_nthreads; i++) {
			if (tq->tq_threads[i].tqt_running == task) {
				running = true;
				break;
			}
		}

		if (!running) {
			break;
		}
		// tq->tq_threads[i].tqt_wait = 1;
		tq->tq_waiting++;
		nni_cv_wait(&tq->tq_wait_cv);
	}

	if (nni_list_active(&tq->tq_tasks, task)) {
		nni_list_remove(&tq->tq_tasks, task);
	}
	nni_mtx_unlock(&tq->tq_mtx);
	return (0);
}

void
nni_task_init(nni_taskq *tq, nni_task *task, nni_cb cb, void *arg)
{
	if (tq == NULL) {
		tq = nni_taskq_systq;
	}
	NNI_LIST_NODE_INIT(&task->task_node);
	task->task_cb  = cb;
	task->task_arg = arg;
	task->task_tq  = tq;
}

int
nni_taskq_sys_init(void)
{
	int rv;

	// XXX: Make the "16" = NCPUs * 2
	rv = nni_taskq_init(&nni_taskq_systq, 16);
	return (rv);
}

void
nni_taskq_sys_fini(void)
{
	nni_taskq_fini(nni_taskq_systq);
	nni_taskq_systq = NULL;
}
